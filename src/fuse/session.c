/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include "fuse/session.h"
#include "fuse/bridge.h"
#include "fuse/config.h"
#include "fuse/chatlog.h"
#include "fuse/render.h"
#include "fuse/roster.h"
#include "fuse/transfer.h"
#include "seeder/hubconn.h"
#include "adc/adcconst.h"
#include "adc/message.h"
#include "network/backend.h"
#include "network/network.h"
#include "network/timeout.h"
#include "tools/adcclient.h"
#include "util/log.h"
#include "util/memory.h"

/* For the mode bits on the identity file. system.h brings in <fcntl.h> but not
   this, and on FreeBSD nothing else does either. */
#include <sys/stat.h>

#define FS_CLIENT_DESCRIPTION "filesystem"

static void session_schedule_reconnect(struct fs_session* session);
static void session_schedule_tick(struct fs_session* session);

/** Replace a stored string with a copy of @p value (which may be NULL). */
static void set_string(char** target, const char* value)
{
	hub_free(*target);
	*target = value ? hub_strdup(value) : NULL;
}

/**
 * Take in one BINF.
 *
 * The client library reports a join, but never an update -- it keeps no roster
 * of its own to diff against (see ADC_CLIENT_USER_UPDATE in adcclient.h). The
 * raw line is the only place both are visible, so the roster is driven from
 * there and the join event is left alone. It also means the mount stores the
 * line as it arrived, which is what users/<cid>/inf hands back.
 */
static void session_on_inf(struct fs_session* session, const char* line)
{
	struct adc_message* msg = adc_msg_parse(line, strlen(line));

	if (!msg)
		return;  /* Not ours to complain about: the client library logs it. */

	fs_roster_update(session->roster, msg, time(NULL));
	adc_msg_free(msg);
}

/** The name to write a SID down as: a nick if we know one, the SID if not. */
static void session_name_of(struct fs_session* session, sid_t sid, char* buf, size_t size)
{
	struct fs_roster_user* user;

	/* SID zero is the hub speaking for itself -- a status line, the reply to a
	   !command -- and it is not in the roster, since it never sends an INF
	   with a CID. Writing it down as "AAAA" would be accurate and useless. */
	if (!sid)
	{
		snprintf(buf, size, "%s", session->hub_name ? session->hub_name : "hub");
		return;
	}

	user = fs_roster_by_sid(session->roster, sid);

	if (user && fs_roster_nick(user, buf, size))
		return;

	snprintf(buf, size, "%s", sid_to_string(sid));
}

/**
 * Write one message down.
 *
 * The format is a timestamp, a name and the text, one message per line, so
 * that grep and read(1) work on it without anything having to parse ADC. An
 * action ("/me waves") is marked with a star instead of angle brackets, the
 * convention every DC client already displays.
 */
static void session_log_message(struct fs_chatlog* log, time_t when, const char* prefix,
                                const char* name, const char* text, int action)
{
	char line[FS_CHAT_MAX + MAX_NICK_LEN + 64];
	char stamp[32];

	if (!fs_render_timestamp(when, stamp, sizeof(stamp)))
		stamp[0] = '\0';

	if (action)
		snprintf(line, sizeof(line), "%s %s* %s %s", stamp, prefix, name, text);
	else
		snprintf(line, sizeof(line), "%s %s<%s> %s", stamp, prefix, name, text);

	fs_chatlog_append_line(log, line);
}

/**
 * Note something that happened to the connection itself in the log.
 *
 * Somebody tailing chat/main should be able to tell a quiet hub from one that
 * is not there any more, and a gap in the conversation from a gap in the
 * connection.
 */
static void session_log_event(struct fs_session* session, const char* fmt, ...)
{
	char text[256];
	char line[320];
	char stamp[32];
	va_list args;

	va_start(args, fmt);
	vsnprintf(text, sizeof(text), fmt, args);
	va_end(args);

	if (!fs_render_timestamp(time(NULL), stamp, sizeof(stamp)))
		stamp[0] = '\0';

	snprintf(line, sizeof(line), "%s -- %s", stamp, text);
	fs_chatlog_append_line(session->chat_main, line);
}

static void session_on_message(struct fs_session* session, struct ADC_chat_message* chat)
{
	char name[MAX_NICK_LEN + 1];
	int private_msg = (chat->flags & chat_flags_private) != 0;
	int action = (chat->flags & chat_flags_action) != 0;

	if (!chat->message)
		return;

	session_name_of(session, chat->from_sid, name, sizeof(name));

	session_log_message(private_msg ? session->chat_private : session->chat_main,
	                    time(NULL), "", name, chat->message, action);
}

static void session_on_disconnected(struct fs_session* session)
{
	if (session->state == FS_SESSION_ONLINE)
		session_log_event(session, "disconnected from %s", session->address);

	/* An empty users/ is the truth once the connection is gone. Keeping the
	   last known list would leave a directory that looks live and is not. */
	fs_roster_clear(session->roster);

	/* Nobody is going to answer a download that was waiting on this hub. */
	if (session->transfer)
		fs_transfer_abort_all(session->transfer, -ENOTCONN);

	set_string(&session->tls_version, NULL);
	set_string(&session->tls_cipher, NULL);

	/* What the hub said about itself goes with it, for the same reason: an
	   offline mount should not read like an online one. hub/address survives
	   -- it is what was configured, not what the hub claimed -- and hub/state
	   is there to be looked at. */
	set_string(&session->hub_name, NULL);
	set_string(&session->hub_description, NULL);
	set_string(&session->hub_version, NULL);

	if (session->state == FS_SESSION_FATAL)
		return;

	session->state = FS_SESSION_OFFLINE;

	if (session->running)
		session_schedule_reconnect(session);
}

static int session_callback(struct ADC_client* client, enum ADC_client_callback_type type,
                            struct ADC_client_callback_data* data)
{
	struct fs_session* session = (struct fs_session*) ADC_client_get_ptr(client);

	if (!session)
		return 0;

	switch (type)
	{
		case ADC_CLIENT_CONNECTING:
			session->state = FS_SESSION_CONNECTING;
			break;

		case ADC_CLIENT_LOGGED_IN:
			session->state = FS_SESSION_ONLINE;
			session->backoff = 0;
			LOG_INFO("Logged in to %s as %s", session->address, session->nick);
			session_log_event(session, "connected to %s", session->address);
			session_schedule_tick(session);
			break;

		case ADC_CLIENT_DISCONNECTED:
			session_on_disconnected(session);
			break;

		case ADC_CLIENT_SSL_OK:
			if (data && data->tls_info)
			{
				set_string(&session->tls_version, data->tls_info->version);
				set_string(&session->tls_cipher, data->tls_info->cipher);
			}
			break;

		case ADC_CLIENT_SSL_KEYPRINT_ERROR:
			/* The hub did not present the certificate it was pinned to. That
			   is a configuration error or an interception, never a transient
			   fault, so retrying it would only repeat it. */
			LOG_ERROR("%s did not present the pinned certificate; not retrying", session->address);
			session->state = FS_SESSION_FATAL;
			break;

		case ADC_CLIENT_HUB_INFO:
			if (data && data->hubinfo)
			{
				set_string(&session->hub_name, data->hubinfo->name);
				set_string(&session->hub_description, data->hubinfo->description);
				set_string(&session->hub_version, data->hubinfo->version);
			}
			break;

		case ADC_CLIENT_MESSAGE:
			if (data && data->chat)
				session_on_message(session, data->chat);
			break;

		/* A search result, and the request that follows from it, are the
		   transfer layer's business; the session only knows who is who. */
		case ADC_CLIENT_SEARCH_REP:
			if (data && data->message && session->transfer)
			{
				char* tth = adc_msg_get_named_argument(data->message, ADC_SCH_FLAG_TTH);
				char* size = adc_msg_get_named_argument(data->message, ADC_RES_FLAG_FILE_SIZE);

				if (tth)
					fs_transfer_on_search_result(session->transfer, data->message->source, tth,
						size ? strtoull(size, NULL, 10) : 0);

				hub_free(tth);
				hub_free(size);
			}
			break;

		case ADC_CLIENT_CONNECT_REQ:
			if (data && data->message && session->transfer)
			{
				char* protocol = adc_msg_get_argument(data->message, 0);
				char* port = adc_msg_get_argument(data->message, 1);
				char* token = adc_msg_get_argument(data->message, 2);

				if (protocol && port && token)
					fs_transfer_on_connect_req(session->transfer, data->message->source,
						protocol, (uint16_t) strtoul(port, NULL, 10), token);

				hub_free(protocol);
				hub_free(port);
				hub_free(token);
			}
			break;

		case ADC_CLIENT_USER_QUIT:
			if (data && data->quit)
				fs_roster_remove(session->roster, data->quit->sid);
			break;

		case ADC_CLIENT_RAW_LINE:
			if (data && data->line && strncmp(data->line, "BINF ", 5) == 0)
				session_on_inf(session, data->line);
			break;

		default:
			break;
	}

	return 0;
}

/**
 * Build a chat message and send it.
 *
 * @param to 0 for the main chat (BMSG), or a SID for a private one (DMSG).
 */
static int session_send_message(struct fs_session* session, sid_t to, const char* text)
{
	struct adc_message* msg;
	char* escaped;
	sid_t own = ADC_client_get_sid(session->client);
	int ok;

	if (session->state != FS_SESSION_ONLINE || !own)
		return -ENOTCONN;

	if (!text || !*text)
		return 0;   /* Nothing to say is not an error; it is just nothing. */

	if (strlen(text) > FS_CHAT_MAX)
		return -EMSGSIZE;

	escaped = adc_msg_escape(text);
	if (!escaped)
		return -ENOMEM;

	if (to)
		msg = adc_msg_construct_source_dest(ADC_CMD_DMSG, own, to, strlen(escaped) + 32);
	else
		msg = adc_msg_construct_source(ADC_CMD_BMSG, own, strlen(escaped) + 32);

	if (!msg)
	{
		hub_free(escaped);
		return -ENOMEM;
	}

	/* adc_msg_add_argument() returns 0 for success, not 1. */
	ok = (adc_msg_add_argument(msg, escaped) == 0);
	hub_free(escaped);

	/* PM names the conversation. For one-to-one that is our own SID, the same
	   convention the hub uses for its own command replies. */
	if (ok && to)
	{
		char pm_flag[8];
		snprintf(pm_flag, sizeof(pm_flag), "%s%s", ADC_MSG_FLAG_PRIVATE, sid_to_string(own));
		ok = (adc_msg_add_argument(msg, pm_flag) == 0);
	}

	if (!ok)
	{
		adc_msg_free(msg);
		return -ENOMEM;
	}

	ADC_client_send(session->client, msg);
	adc_msg_free(msg);
	return 0;
}

int fs_session_send_chat(struct fs_session* session, const char* text)
{
	/* No local echo: the hub broadcasts a B message back to its sender, so
	   what we said arrives in chat/main by the same route as everybody else's,
	   and writing it down here as well would double it. */
	return session_send_message(session, 0, text);
}

int fs_session_send_pm(struct fs_session* session, const char* cid, const char* text)
{
	struct fs_roster_user* user = fs_roster_by_cid(session->roster, cid);
	char name[MAX_NICK_LEN + 1];
	int result;

	if (!user)
		return -ENOENT;

	result = session_send_message(session, user->sid, text);
	if (result != 0 || !text || !*text)
		return result;

	/* A D message is delivered to its target and not to its sender, so unlike
	   the main chat this one has to be written down here -- otherwise
	   chat/private would hold half of every conversation. */
	fs_roster_nick(user, name, sizeof(name));
	session_log_message(session->chat_private, time(NULL), "-> ", name, text, 0);
	return 0;
}

int fs_session_peer_by_sid(struct fs_session* session, sid_t sid, struct fs_peer* out)
{
	struct fs_roster_user* user = fs_roster_by_sid(session->roster, sid);
	char* value;

	if (!user || !out)
		return 0;

	memset(out, 0, sizeof(*out));
	out->sid = sid;
	memcpy(out->cid, user->cid, sizeof(out->cid));

	value = adc_msg_get_named_argument(user->inf, ADC_INF_FLAG_SUPPORT);
	if (value)
	{
		snprintf(out->support, sizeof(out->support), "%s", value);
		hub_free(value);
	}

	/* I4 first, then I6: either is the hub's own observation of where this
	   user is, and a peer reachable over both is reachable over v4. */
	value = adc_msg_get_named_argument(user->inf, ADC_INF_FLAG_IPV4_ADDR);
	if (!value)
		value = adc_msg_get_named_argument(user->inf, ADC_INF_FLAG_IPV6_ADDR);

	if (!value)
		return 0;

	if (!ip_convert_to_binary(value, &out->addr))
	{
		hub_free(value);
		return 0;
	}

	hub_free(value);
	return 1;
}

int fs_session_send_search_tth(struct fs_session* session, const char* tth, const char* token)
{
	struct adc_message* msg;
	sid_t own = ADC_client_get_sid(session->client);

	if (session->state != FS_SESSION_ONLINE || !own || !tth)
		return 0;

	/* Broadcast, because the point of searching is not knowing who has it. An
	   exact TTH search is the cheapest question ADC has: a client either holds
	   that hash or does not. */
	msg = adc_msg_construct_source(ADC_CMD_BSCH, own, 64 + MAX_CID_LEN);
	if (!msg)
		return 0;

	if (adc_msg_add_named_argument(msg, ADC_SCH_FLAG_TTH, tth) == -1 ||
	    (token && *token &&
	     adc_msg_add_named_argument_string(msg, ADC_SCH_FLAG_TOKEN, token) == -1))
	{
		adc_msg_free(msg);
		return 0;
	}

	ADC_client_send(session->client, msg);
	adc_msg_free(msg);
	return 1;
}

int fs_session_send_ctm(struct fs_session* session, sid_t to, const char* protocol,
                        uint16_t port, const char* token)
{
	struct adc_message* msg;
	char port_str[8];
	sid_t own = ADC_client_get_sid(session->client);
	int ok;

	if (session->state != FS_SESSION_ONLINE || !own || !to || !protocol || !*protocol ||
	    !token || !*token || !port)
		return 0;

	msg = adc_msg_construct_source_dest(ADC_CMD_DCTM, own, to, 64 + SEED_TOKEN_MAX);
	if (!msg)
		return 0;

	snprintf(port_str, sizeof(port_str), "%u", (unsigned) port);

	ok = (adc_msg_add_argument(msg, protocol) == 0)
	  && (adc_msg_add_argument(msg, port_str) == 0)
	  && (adc_msg_add_argument(msg, token) == 0);

	if (ok)
		ADC_client_send(session->client, msg);

	adc_msg_free(msg);
	return ok;
}

const char* fs_session_own_cid(struct fs_session* session)
{
	return ADC_client_get_cid(session->client);
}

const char* fs_session_state_name(const struct fs_session* session)
{
	switch (session->state)
	{
		case FS_SESSION_CONNECTING: return "connecting";
		case FS_SESSION_ONLINE:     return "online";
		case FS_SESSION_FATAL:      return "failed";
		default:                    return "offline";
	}
}

/** Keep the once-a-second tick going while there is a hub to talk to. */
static void session_schedule_tick(struct fs_session* session)
{
	struct timeout_queue* queue = net_backend_get_timeout_queue();

	if (!queue || !session->timer || !session->transfer)
		return;

	if (!timeout_evt_is_scheduled(session->timer))
		timeout_queue_insert(queue, session->timer, 1);
}

/* ------------------------------------------------------------- reconnecting */

static void session_connect(struct fs_session* session)
{
	session->state = FS_SESSION_CONNECTING;

	if (!ADC_client_connect(session->client, session->address))
	{
		/* A refused URL (a keyprint this build cannot check, say) is not worth
		   retrying either, but a name that does not resolve yet is. */
		LOG_WARN("Unable to connect to %s", session->address);
		session->state = FS_SESSION_OFFLINE;
		session_schedule_reconnect(session);
	}
}

/**
 * One timer for the whole session: the reconnect when offline, and the
 * transfer layer's deadlines and retries the rest of the time. It reschedules
 * itself for a second hence whenever anything is in flight, and stays quiet
 * when there is nothing to do.
 */
static void session_timer_cb(struct timeout_evt* evt)
{
	struct fs_session* session = (struct fs_session*) evt->ptr;

	if (!session->running)
		return;

	if (session->state == FS_SESSION_OFFLINE)
	{
		session_connect(session);
		return;
	}

	if (session->transfer)
	{
		struct timeout_queue* queue = net_backend_get_timeout_queue();

		fs_transfer_tick(session->transfer);

		if (queue && !timeout_evt_is_scheduled(session->timer))
			timeout_queue_insert(queue, session->timer, 1);
	}
}

static void session_schedule_reconnect(struct fs_session* session)
{
	struct timeout_queue* queue = net_backend_get_timeout_queue();

	if (!queue || !session->timer)
		return;

	/* Doubling, so a hub that is down does not get one connect per second for
	   as long as the mount is up. */
	if (!session->backoff)
		session->backoff = FS_RECONNECT_MIN;
	else if (session->backoff < FS_RECONNECT_MAX)
		session->backoff *= 2;

	if (session->backoff > FS_RECONNECT_MAX)
		session->backoff = FS_RECONNECT_MAX;

	LOG_DEBUG("Reconnecting to %s in %d seconds", session->address, (int) session->backoff);

	if (timeout_evt_is_scheduled(session->timer))
		timeout_queue_reschedule(queue, session->timer, session->backoff);
	else
		timeout_queue_insert(queue, session->timer, session->backoff);
}

/* ------------------------------------------------------------------ session */

/**
 * Give this mount an identity that survives a reconnect.
 *
 * Without a fixed PID the client library invents a new one every time it builds
 * an INF, so the CID would change on every reconnect -- and a peer checks the
 * CID in a client connection's CINF against the one the hub advertised. A
 * transfer started after a reconnect would fail that check for no visible
 * reason. Persisting it also means the hub sees the same client across
 * restarts, which is what makes a registered account or a ban work at all.
 *
 * The PID is generated by the client library rather than here: building an INF
 * and taking the PD out of it uses the one generator instead of adding a
 * second.
 */
static void session_fix_identity(struct fs_session* session, const char* dir)
{
	char path[512];
	char pid[MAX_CID_LEN + 8];
	FILE* file;
	size_t len = 0;

	if (!dir || !*dir)
		return;

	snprintf(path, sizeof(path), "%s/identity", dir);
	memset(pid, 0, sizeof(pid));

	file = fopen(path, "r");
	if (file)
	{
		len = fread(pid, 1, MAX_CID_LEN, file);
		fclose(file);

		while (len > 0 && (pid[len - 1] == '\n' || pid[len - 1] == '\r' || pid[len - 1] == ' '))
			pid[--len] = '\0';
	}

	if (len != MAX_CID_LEN)
	{
		struct adc_message* info = ADC_client_build_info(session->client);
		char* value = info ? adc_msg_get_named_argument(info, ADC_INF_FLAG_PRIVATE_ID) : NULL;
		int fd;

		if (!value || strlen(value) != MAX_CID_LEN)
		{
			hub_free(value);
			adc_msg_free(info);
			return;
		}

		memcpy(pid, value, MAX_CID_LEN + 1);
		hub_free(value);
		adc_msg_free(info);

		/* 0600 from the moment it exists: the PID *is* the identity, and a
		   window in which it is world readable is a window in which it can be
		   taken. */
		fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
		if (fd != -1)
		{
			FILE* out = fdopen(fd, "w");
			if (out)
			{
				fprintf(out, "%s\n", pid);
				fclose(out);
			}
			else
			{
				close(fd);
			}
		}
	}

	ADC_client_set_pid(session->client, pid);
}

struct fs_session* fs_session_create(const struct fs_config* config)
{
	struct fs_session* session;
	const char* password;

	if (!config || !config->address || !*config->address || !config->nick)
		return NULL;

	session = (struct fs_session*) hub_malloc_zero(sizeof(struct fs_session));
	if (!session)
		return NULL;

	password = (config->password && *config->password) ? config->password : NULL;

	session->address = hub_strdup(config->address);
	session->nick = hub_strdup(config->nick);
	session->password = password ? hub_strdup(password) : NULL;
	session->roster = fs_roster_create();
	session->chat_main = fs_chatlog_create(0);
	session->chat_private = fs_chatlog_create(0);
	session->timer = (struct timeout_evt*) hub_malloc_zero(sizeof(struct timeout_evt));
	session->mounted = time(NULL);

	if (!session->address || !session->nick || !session->roster || !session->timer ||
	    !session->chat_main || !session->chat_private ||
	    (password && !session->password))
	{
		fs_session_destroy(session);
		return NULL;
	}

	timeout_evt_initialize(session->timer, session_timer_cb, session);

	session->bridge = fs_bridge_create(session);
	if (!session->bridge)
	{
		fs_session_destroy(session);
		return NULL;
	}

	session->client = ADC_client_create(session->nick, FS_CLIENT_DESCRIPTION, session);
	if (!session->client)
	{
		fs_session_destroy(session);
		return NULL;
	}

	ADC_client_set_callback(session->client, session_callback);

	if (session->password)
		ADC_client_set_password(session->client, session->password);

	/* The identity file lives beside the cache, which is the one directory a
	   mount is given. Without one the CID is regenerated per login, which
	   costs transfers rather than the mount itself, so it is not fatal. */
	if (config->cache_dir && *config->cache_dir)
		session_fix_identity(session, config->cache_dir);
	else
	{
		char dir[512];
		if (fs_config_default_cache_dir(dir, sizeof(dir)))
			session_fix_identity(session, dir);
	}

	return session;
}

void fs_session_set_transfer(struct fs_session* session, struct fs_transfer* transfer)
{
	session->transfer = transfer;

	/* This is how the rest of the hub learns the mount is worth dialling.
	   Without TCP4 it is taken for a passive client and never connected to,
	   which would leave it unable to fetch from the passive peers that make up
	   most of a hub. */
	if (transfer)
		ADC_client_set_support(session->client, fs_transfer_support(transfer));
}

void fs_session_destroy(struct fs_session* session)
{
	if (!session)
		return;

	if (session->timer && timeout_evt_is_scheduled(session->timer))
	{
		struct timeout_queue* queue = net_backend_get_timeout_queue();
		if (queue)
			timeout_queue_remove(queue, session->timer);
	}

	if (session->transfer)
		fs_transfer_destroy(session->transfer);

	if (session->client)
		ADC_client_destroy(session->client);

	if (session->bridge)
		fs_bridge_destroy(session->bridge);

	fs_roster_destroy(session->roster);
	fs_chatlog_destroy(session->chat_main);
	fs_chatlog_destroy(session->chat_private);

	hub_free(session->timer);
	hub_free(session->address);
	hub_free(session->nick);
	hub_free(session->password);
	hub_free(session->hub_name);
	hub_free(session->hub_description);
	hub_free(session->hub_version);
	hub_free(session->tls_version);
	hub_free(session->tls_cipher);
	hub_free(session);
}

int fs_session_start(struct fs_session* session)
{
	session->running = 1;
	session_connect(session);
	return 1;
}

void fs_session_run(struct fs_session* session)
{
	while (session->running && net_backend_process())
		; /* Every wake-up is a socket, a timer or the bridge. */

	/* Nothing will answer a filesystem request from here on, and a FUSE thread
	   waiting for one would keep the mount busy for ever. Parked downloads
	   first, since those waiters are not on the bridge's own queue. */
	if (session->transfer)
		fs_transfer_abort_all(session->transfer, -ENOTCONN);

	fs_bridge_shutdown(session->bridge);
}

void fs_session_stop(struct fs_session* session)
{
	if (!session->running)
		return;

	/* Set the flag, then wake the loop so it looks at it: the ADC thread is
	   otherwise blocked in a poll with nothing due, and would not notice until
	   the next timer or packet. */
	session->running = 0;
	fs_bridge_wake(session->bridge);
}

void fs_session_render_ctx(struct fs_session* session, struct fs_render_ctx* ctx)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->hub_state = fs_session_state_name(session);
	ctx->hub_name = session->hub_name;
	ctx->hub_description = session->hub_description;
	ctx->hub_version = session->hub_version;
	ctx->hub_address = session->address;
	ctx->hub_support = ADC_client_hub_support_list(session->client);
	ctx->hub_users = fs_roster_size(session->roster);
	ctx->tls_version = session->tls_version;
	ctx->tls_cipher = session->tls_cipher;

	ctx->my_nick = session->nick;
	ctx->my_cid = ADC_client_get_cid(session->client);
	ctx->my_support = ADC_client_get_support(session->client);
	ctx->my_sid = ADC_client_get_sid(session->client);
}
