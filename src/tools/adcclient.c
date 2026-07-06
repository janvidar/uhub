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

#include "tools/adcclient.h"
#include "util/list.h"

#define ADC_HANDSHAKE "HSUP ADBASE ADTIGR ADPING\n"
#define ADC_CID_SIZE 39
#define BIG_BUFSIZE 32768
#define TIGERSIZE 24
#define MAX_RECV_BUFFER 65536

// #define ADCC_DEBUG
// #define ADC_CLIENT_DEBUG_PROTO

struct ADC_client_global
{
	size_t references;
	struct ssl_context_handle* ctx;
};

static struct ADC_client_global* g_adc_client = NULL;


enum ADC_client_flags
{
	cflag_none = 0,
	cflag_ssl = 1,
	cflag_choke = 2,
	cflag_pipe = 4,
};

struct ADC_client_address
{
	enum Protocol { ADC, ADCS } protocol;
	char* hostname;
	uint16_t port;
};

struct ADC_client
{
	sid_t sid;
	enum ADC_client_state state;
	struct adc_message* info;
	struct ioq_recv* recv_queue;
	struct ioq_send* send_queue;
	adc_client_cb callback;
	adc_client_log_cb log_cb;
	size_t s_offset;
	size_t r_offset;
	struct net_connection* con;
	struct sockaddr_storage addr;
	struct net_connect_handle* connect_job;
	struct ADC_client_address address;
	char* nick;
	char* desc;
	char* password;
	char* ua_product;
	char* ua_version;
	uint64_t share_size;
	uint64_t share_files;
	int track_users;
	struct linked_list* users;    /* struct ADC_user*, keyed by sid  */
	struct ADC_hub_info hubinfo;   /* last IINF, owned strings         */
	struct ADC_client_tls_info tls_info;
	int have_tls;
	int flags;
	void* ptr;
};


static ssize_t ADC_client_recv(struct ADC_client* client);
static void ADC_client_send_info(struct ADC_client* client);
static void ADC_client_send_password(struct ADC_client* client, const char* challenge);
static void ADC_client_on_connected(struct ADC_client* client);
static void ADC_client_on_connected_ssl(struct ADC_client* client);
static void ADC_client_on_disconnected(struct ADC_client* client);
static void ADC_client_on_login(struct ADC_client* client);
static int ADC_client_parse_address(struct ADC_client* client, const char* arg);
static int ADC_client_on_recv_line(struct ADC_client* client, const char* line, size_t length);
static int ADC_client_send_queue(struct ADC_client* client);

static void ADC_client_log(struct ADC_client* client, int level, const char* format, ...)
{
	char logmsg[1024];
	va_list args;
	va_start(args, format);
	vsnprintf(logmsg, sizeof(logmsg), format, args);
	va_end(args);

	if (client->log_cb)
		client->log_cb(client, level, logmsg);
	else
		fprintf(stdout, "* [%p] %s\n", (void*) client, logmsg);
}

/* Retained name for the many internal diagnostic call sites; routes
   through the frontend log sink (or stdout by default). */
#define ADC_client_debug(client, ...) ADC_client_log(client, 5, __VA_ARGS__)

#ifdef ADCC_DEBUG
#define ADC_TRACE fprintf(stderr, "TRACE: %s\n", __PRETTY_FUNCTION__)
#else
#define ADC_TRACE do { } while(0)
#endif

#ifdef ADCC_DEBUG
static const char* ADC_client_state_string[] =
{
	"adc_state_none",
	"adc_state_connecting",
	"adc_state_ssl",
	"adc_state_protocol",
	"adc_state_identify",
	"adc_state_verify",
	"adc_state_normal",
	0
};
#endif

static void ADC_client_set_state(struct ADC_client* client, enum ADC_client_state state)
{
	ADC_TRACE;
	if (client->state != state)
	{
#ifdef ADCC_DEBUG
		ADC_client_debug(client, "Set state %s (was %s)", ADC_client_state_string[(int) state], ADC_client_state_string[(int) client->state]);
#endif
		client->state = state;
	}
}


static void adc_cid_pid(struct ADC_client* client)
{
	ADC_TRACE;
	static uint32_t counter = 0;
	char seed[64];
	char pid[64];
	char cid[64];
	uint64_t tiger_res1[3];
	uint64_t tiger_res2[3];

	/* create cid+pid pair; mix in pid, time and a per-instance counter so
	 * the identity is not a predictable function of the heap pointer alone. */
	memset(seed, 0, 64);
	snprintf(seed, 64, VERSION "%p%d%ld%u", (void*) client, (int) getpid(), (long) time(NULL), ++counter);

	tiger((uint64_t*) seed, strlen(seed), tiger_res1);
	base32_encode((unsigned char*) tiger_res1, TIGERSIZE, pid);
	tiger((uint64_t*) tiger_res1, TIGERSIZE, tiger_res2);
	base32_encode((unsigned char*) tiger_res2, TIGERSIZE, cid);
	cid[ADC_CID_SIZE] = 0;
	pid[ADC_CID_SIZE] = 0;

	adc_msg_add_named_argument(client->info, ADC_INF_FLAG_PRIVATE_ID, pid);
	adc_msg_add_named_argument(client->info, ADC_INF_FLAG_CLIENT_ID, cid);
}

static void event_callback(struct net_connection* con, int events, void *arg)
{
	(void) arg;
	ADC_TRACE;
	struct ADC_client* client = (struct ADC_client*) net_con_get_ptr(con);

	switch (client->state)
	{
		case adc_state_connecting:
			if (events == NET_EVENT_TIMEOUT)
			{
				client->callback(client, ADC_CLIENT_DISCONNECTED, 0);
				return;
			}
			break;

		case adc_state_ssl:
			if (events == NET_EVENT_TIMEOUT)
			{
				client->callback(client, ADC_CLIENT_DISCONNECTED, 0);
				return;
			}

			if (events == NET_EVENT_ERROR)
			{
				ADC_client_on_disconnected(client);
				return;
			}
			else
			{
				ADC_client_on_connected_ssl(client);
			}
			break;

		default:
			if (events & NET_EVENT_READ)
			{
				if (ADC_client_recv(client) == -1)
				{
					ADC_client_on_disconnected(client);
					return; /* connection gone; don't touch it for WRITE below */
				}
			}

			if (events & NET_EVENT_WRITE)
			{
				ADC_client_send_queue(client);
			}
	}
}

#define UNESCAPE_ARG(TMP, TARGET) \
		if (TMP) \
			TARGET = adc_msg_unescape(TMP); \
		else \
			TARGET = NULL; \
		hub_free(TMP);

#define UNESCAPE_ARG_X(TMP, TARGET, SIZE) \
		if (TMP) \
			adc_msg_unescape_to_target(TMP, TARGET, SIZE); \
		else \
			TARGET[0] = '\0'; \
		hub_free(TMP);

#define EXTRACT_NAMED_ARG(MSG, NAME, TARGET) \
		do { \
			char* tmp = adc_msg_get_named_argument(MSG, NAME); \
			UNESCAPE_ARG(tmp, TARGET); \
		} while (0)

#define EXTRACT_NAMED_ARG_X(MSG, NAME, TARGET, SIZE) \
		do { \
			char* tmp = adc_msg_get_named_argument(MSG, NAME); \
			UNESCAPE_ARG_X(tmp, TARGET, SIZE); \
		} while(0)

#define EXTRACT_POS_ARG(MSG, POS, TARGET) \
		do { \
			char* tmp = adc_msg_get_argument(MSG, POS); \
			UNESCAPE_ARG(tmp, TARGET); \
		} while (0)


/* Read a named integer field if present. Returns 1 and stores the value
   via *out when the field exists, 0 otherwise. */
static int adc_msg_named_long(struct adc_message* msg, const char prefix[2], long* out)
{
	char* tmp = adc_msg_get_named_argument(msg, prefix);
	if (!tmp)
		return 0;
	*out = strtol(tmp, NULL, 10);
	hub_free(tmp);
	return 1;
}

static int adc_msg_named_u64(struct adc_message* msg, const char prefix[2], uint64_t* out)
{
	char* tmp = adc_msg_get_named_argument(msg, prefix);
	if (!tmp)
		return 0;
	*out = (uint64_t) strtoull(tmp, NULL, 10);
	hub_free(tmp);
	return 1;
}

/* Overlay whatever INF fields are present in msg onto u. Absent fields are
   left untouched so partial INF updates (e.g. a lone "HN2") do not wipe the
   rest of a known user. */
static void adc_user_apply_inf(struct ADC_user* u, struct adc_message* msg)
{
	long v;
	char* ap;
	char* ve;

	if (adc_msg_has_named_argument(msg, ADC_INF_FLAG_NICK))
		EXTRACT_NAMED_ARG_X(msg, ADC_INF_FLAG_NICK, u->name, sizeof(u->name));
	if (adc_msg_has_named_argument(msg, ADC_INF_FLAG_DESCRIPTION))
		EXTRACT_NAMED_ARG_X(msg, ADC_INF_FLAG_DESCRIPTION, u->description, sizeof(u->description));
	if (adc_msg_has_named_argument(msg, ADC_INF_FLAG_CLIENT_ID))
		EXTRACT_NAMED_ARG_X(msg, ADC_INF_FLAG_CLIENT_ID, u->cid, sizeof(u->cid));
	if (adc_msg_has_named_argument(msg, ADC_INF_FLAG_IPV4_ADDR))
		EXTRACT_NAMED_ARG_X(msg, ADC_INF_FLAG_IPV4_ADDR, u->address, sizeof(u->address));
	if (adc_msg_has_named_argument(msg, ADC_INF_FLAG_IPV6_ADDR))
		EXTRACT_NAMED_ARG_X(msg, ADC_INF_FLAG_IPV6_ADDR, u->address6, sizeof(u->address6));

	/* Compose a human-readable "product version" from AP/VE when either is
	   present. Keep VE as the previous behaviour's fallback. */
	ap = adc_msg_has_named_argument(msg, ADC_INF_FLAG_USER_AGENT_PRODUCT) ?
		adc_msg_get_named_argument(msg, ADC_INF_FLAG_USER_AGENT_PRODUCT) : NULL;
	ve = adc_msg_has_named_argument(msg, ADC_INF_FLAG_USER_AGENT_VERSION) ?
		adc_msg_get_named_argument(msg, ADC_INF_FLAG_USER_AGENT_VERSION) : NULL;
	if (ap || ve)
	{
		char* ap_u = ap ? adc_msg_unescape(ap) : NULL;
		char* ve_u = ve ? adc_msg_unescape(ve) : NULL;
		snprintf(u->version, sizeof(u->version), "%s%s%s",
			ap_u ? ap_u : "", (ap_u && ve_u) ? " " : "", ve_u ? ve_u : "");
		hub_free(ap_u);
		hub_free(ve_u);
	}
	hub_free(ap);
	hub_free(ve);

	if (adc_msg_named_long(msg, ADC_INF_FLAG_IPV4_UDP_PORT, &v)) u->udp4_port = (uint16_t) v;
	if (adc_msg_named_long(msg, ADC_INF_FLAG_IPV6_UDP_PORT, &v)) u->udp6_port = (uint16_t) v;
	if (adc_msg_named_long(msg, ADC_INF_FLAG_CLIENT_TYPE, &v))   u->type = (int) v;
	if (adc_msg_named_long(msg, ADC_INF_FLAG_AWAY, &v))          u->away = (int) v;
	adc_msg_named_u64(msg, ADC_INF_FLAG_SHARED_SIZE, &u->shared_size);
	adc_msg_named_u64(msg, ADC_INF_FLAG_SHARED_FILES, &u->shared_files);
}

static struct ADC_user* userlist_find(struct ADC_client* client, sid_t sid)
{
	struct ADC_user* u;
	if (!client->users)
		return NULL;
	LIST_FOREACH(struct ADC_user*, u, client->users,
	{
		if (u->sid == sid)
			return u;
	});
	return NULL;
}

static void userlist_remove(struct ADC_client* client, sid_t sid)
{
	struct ADC_user* u = userlist_find(client, sid);
	if (u)
	{
		list_remove(client->users, u);
		hub_free(u);
	}
}

static void userlist_clear(struct ADC_client* client)
{
	if (client->users)
		list_clear(client->users, hub_free_handle);
}


static int ADC_client_on_recv_line(struct ADC_client* client, const char* line, size_t length)
{
	struct ADC_chat_message chat;
	struct ADC_client_callback_data data;

	ADC_TRACE;
#ifdef ADC_CLIENT_DEBUG_PROTO
	ADC_client_debug(client, "- LINE: '%s'", line);
#endif

	if (length < 4)
	{
		ADC_client_debug(client, "Unexpected response from hub: '%s'", line);
		return -1;
	}

	/* Parse message */
	struct adc_message* msg = adc_msg_parse(line, length);
	if (!msg)
	{
		ADC_client_debug(client, "WARNING: Message cannot be decoded: \"%s\"", line);
		return -1;
	}

	switch (msg->cmd)
	{
		case ADC_CMD_ISUP:
			break;

		case ADC_CMD_IGPA:
			if (client->state == adc_state_identify || client->state == adc_state_verify)
			{
				char* challenge = adc_msg_get_argument(msg, 0);
				client->callback(client, ADC_CLIENT_PASSWORD_REQ, 0);
				if (challenge)
					ADC_client_send_password(client, challenge);
				hub_free(challenge);
			}
			break;

		case ADC_CMD_ISID:
			if (client->state == adc_state_protocol)
			{
				char* sid = adc_msg_get_argument(msg, 0);
				if (sid)
				{
					client->sid = string_to_sid(sid);
					hub_free(sid);
					client->callback(client, ADC_CLIENT_LOGGING_IN, 0);
					ADC_client_set_state(client, adc_state_identify);
					ADC_client_send_info(client);
				}
			}
			break;

		case ADC_CMD_BMSG:
		case ADC_CMD_EMSG:
		case ADC_CMD_DMSG:
		case ADC_CMD_IMSG:
		{
			chat.from_sid       = msg->source;
			chat.to_sid         = msg->target;
			data.chat = &chat;
			EXTRACT_POS_ARG(msg, 0, chat.message);
			chat.flags = 0;

			if (adc_msg_has_named_argument(msg, ADC_MSG_FLAG_ACTION))
				chat.flags |= chat_flags_action;

			if (adc_msg_has_named_argument(msg, ADC_MSG_FLAG_PRIVATE))
				chat.flags |= chat_flags_private;

			client->callback(client, ADC_CLIENT_MESSAGE, &data);
			hub_free(chat.message);
			break;
		}

		case ADC_CMD_IINF:
		{
			hub_free(client->hubinfo.name);
			hub_free(client->hubinfo.description);
			hub_free(client->hubinfo.version);
			EXTRACT_NAMED_ARG(msg, ADC_INF_FLAG_NICK, client->hubinfo.name);
			EXTRACT_NAMED_ARG(msg, ADC_INF_FLAG_DESCRIPTION, client->hubinfo.description);
			EXTRACT_NAMED_ARG(msg, ADC_INF_FLAG_USER_AGENT_VERSION, client->hubinfo.version);

			data.hubinfo = &client->hubinfo;
			client->callback(client, ADC_CLIENT_HUB_INFO, &data);
			break;
		}

		case ADC_CMD_BSCH:
		case ADC_CMD_FSCH:
		case ADC_CMD_DSCH:
		case ADC_CMD_ESCH:
		{
			struct ADC_search_request req;
			memset(&req, 0, sizeof(req));
			req.from_sid = msg->source;
			EXTRACT_POS_ARG(msg, 0, req.raw);
			EXTRACT_NAMED_ARG_X(msg, ADC_SCH_FLAG_TOKEN, req.token, sizeof(req.token));
			data.search_req = &req;
			client->callback(client, ADC_CLIENT_SEARCH_REQ, &data);
			hub_free(req.raw);
			break;
		}

		case ADC_CMD_BRES:
		case ADC_CMD_DRES:
		case ADC_CMD_ERES:
		case ADC_CMD_FRES:
		{
			struct ADC_search_result res;
			memset(&res, 0, sizeof(res));
			res.from_sid = msg->source;
			EXTRACT_NAMED_ARG(msg, ADC_RES_FLAG_FILE_NAME, res.filename);
			EXTRACT_NAMED_ARG_X(msg, ADC_SCH_FLAG_TTH, res.tth, sizeof(res.tth));
			EXTRACT_NAMED_ARG_X(msg, ADC_RES_FLAG_TOKEN, res.token, sizeof(res.token));
			adc_msg_named_u64(msg, ADC_RES_FLAG_FILE_SIZE, &res.size);
			{
				long v;
				if (adc_msg_named_long(msg, ADC_RES_FLAG_UPLOAD_SLOTS, &v))
					res.slots_free = (int) v;
			}
			data.search_res = &res;
			client->callback(client, ADC_CLIENT_SEARCH_REP, &data);
			hub_free(res.filename);
			break;
		}

		case ADC_CMD_DCTM:
		case ADC_CMD_ECTM:
		{
			struct ADC_connect_request req;
			char* proto;
			char* token;
			memset(&req, 0, sizeof(req));
			req.from_sid = msg->source;
			proto = adc_msg_get_argument(msg, 0);
			if (proto)
			{
				snprintf(req.protocol, sizeof(req.protocol), "%s", proto);
				req.secure = (strstr(proto, "ADCS") != NULL);
				hub_free(proto);
			}
			{
				char* p = adc_msg_get_argument(msg, 1);
				if (p) { req.port = (uint16_t) strtol(p, NULL, 10); hub_free(p); }
			}
			token = adc_msg_get_argument(msg, 2);
			if (token) { snprintf(req.token, sizeof(req.token), "%s", token); hub_free(token); }
			data.connect = &req;
			client->callback(client, ADC_CLIENT_CONNECT_REQ, &data);
			break;
		}

		case ADC_CMD_DRCM:
		case ADC_CMD_ERCM:
		{
			struct ADC_connect_request req;
			char* proto;
			char* token;
			memset(&req, 0, sizeof(req));
			req.from_sid = msg->source;
			proto = adc_msg_get_argument(msg, 0);
			if (proto)
			{
				snprintf(req.protocol, sizeof(req.protocol), "%s", proto);
				req.secure = (strstr(proto, "ADCS") != NULL);
				hub_free(proto);
			}
			token = adc_msg_get_argument(msg, 1);
			if (token) { snprintf(req.token, sizeof(req.token), "%s", token); hub_free(token); }
			data.connect = &req;
			client->callback(client, ADC_CLIENT_REVCONNECT_REQ, &data);
			break;
		}

		case ADC_CMD_BINF:
		{
			if (msg->source == client->sid)
			{
				if (client->state == adc_state_verify || client->state == adc_state_identify)
				{
					ADC_client_on_login(client);
				}
			}
			else
			{
				struct ADC_user stackuser;
				struct ADC_user* user;
				enum ADC_client_event_type ev;

				if (client->track_users)
				{
					user = userlist_find(client, msg->source);
					if (user)
					{
						ev = ADC_CLIENT_USER_UPDATE;
					}
					else if (adc_msg_has_named_argument(msg, ADC_INF_FLAG_CLIENT_ID))
					{
						user = (struct ADC_user*) hub_malloc_zero(sizeof(struct ADC_user));
						user->sid = msg->source;
						list_append(client->users, user);
						ev = ADC_CLIENT_USER_JOIN;
					}
					else
					{
						break; /* partial INF for an unknown user; ignore */
					}
				}
				else
				{
					/* No tracking: report every INF as a JOIN with a transient
					   snapshot. JOIN/UPDATE cannot be told apart without state. */
					if (!adc_msg_has_named_argument(msg, ADC_INF_FLAG_CLIENT_ID))
						break;
					memset(&stackuser, 0, sizeof(stackuser));
					stackuser.sid = msg->source;
					user = &stackuser;
					ev = ADC_CLIENT_USER_JOIN;
				}

				adc_user_apply_inf(user, msg);
				data.user = user;
				client->callback(client, ev, &data);
			}
		}
		break;

		case ADC_CMD_IQUI:
		{
			struct ADC_client_quit_reason reason;
			char* sid = adc_msg_get_argument(msg, 0);
			char* initiator = adc_msg_get_named_argument(msg, ADC_QUI_FLAG_KICK_OPERATOR);
			memset(&reason, 0, sizeof(reason));

			if (sid)
				reason.sid = string_to_sid(sid);
			if (initiator)
				reason.initator = string_to_sid(initiator);
			EXTRACT_NAMED_ARG_X(msg, ADC_QUI_FLAG_MESSAGE, reason.message, sizeof(reason.message));

			if (adc_msg_has_named_argument(msg, ADC_QUI_FLAG_DISCONNECT))
				reason.flags |= 1;

			hub_free(sid);
			hub_free(initiator);

			data.quit = &reason;
			client->callback(client, ADC_CLIENT_USER_QUIT, &data);

			/* Drop the user from the tracked list only after the frontend has
			   been handed the quit event (which still names the sid, not the
			   user record). */
			if (client->track_users)
				userlist_remove(client, reason.sid);
			break;
		}

		case ADC_CMD_ISTA:
		{
			struct ADC_client_status status;
			char* code = adc_msg_get_argument(msg, 0);
			memset(&status, 0, sizeof(status));
			if (code)
			{
				status.code = (int) strtol(code, NULL, 10);
				status.severity = status.code / 100;
				hub_free(code);
			}
			EXTRACT_POS_ARG(msg, 1, status.message);

			data.status = &status;
			if (status.severity == 2 && client->state != adc_state_normal)
				client->callback(client, ADC_CLIENT_LOGIN_ERROR, &data);
			else
				client->callback(client, ADC_CLIENT_PROTOCOL_STATUS, &data);

			hub_free(status.message);
			break;
		}

		default:
			break;
	}

	adc_msg_free(msg);
	return 0;
}

static ssize_t ADC_client_recv(struct ADC_client* client)
{
	static char buf[BIG_BUFSIZE];
	struct ioq_recv* q = client->recv_queue;
	size_t buf_size = ioq_recv_get(q, buf, BIG_BUFSIZE);
	ssize_t size;

	ADC_TRACE;

	if (client->flags & cflag_choke)
		buf_size = 0;
	size = net_con_recv(client->con, buf + buf_size, BIG_BUFSIZE - buf_size);

	if (size > 0)
		buf_size += size;

	if (size < 0)
		return -1;
	else if (size == 0)
		return 0;
	else
	{
		char* lastPos = 0;
		char* start = buf;
		char* pos = 0;
		size_t remaining = buf_size;

		while ((pos = memchr(start, '\n', remaining)))
		{
			lastPos = pos+1;
			pos[0] = '\0';

#ifdef DEBUG_SENDQ
			LOG_DUMP("PROC: \"%s\" (%d)\n", start, (int) (pos - start));
#endif

			if (client->flags & cflag_choke)
				client->flags &= ~cflag_choke;
			else
			{
				if (((pos - start) > 0) && MAX_RECV_BUFFER > (pos - start))
				{
					if (ADC_client_on_recv_line(client, start, pos - start) == -1)
						return -1;
				}
			}

			pos ++;
			remaining -= (pos - start);
			start = pos;
		}

		if (lastPos || remaining)
		{
			if (remaining < (size_t) MAX_RECV_BUFFER)
			{
				ioq_recv_set(q, lastPos ? lastPos : buf, remaining);
			}
			else
			{
				ioq_recv_set(q, 0, 0);
				client->flags |= cflag_choke;
				LOG_WARN("Received message past MAX_RECV_BUFFER (%d), dropping message.", MAX_RECV_BUFFER);
			}
		}
		else
		{
			ioq_recv_set(q, 0, 0);
		}
	}
	return 0;
}

static int ADC_client_send_queue(struct ADC_client* client)
{
	int ret = 0;
	while (ioq_send_get_bytes(client->send_queue))
	{
		ret = ioq_send_send(client->send_queue, client->con);
		if (ret <= 0)
			break;
	}

	if (ret < 0)
		return quit_socket_error;

	if (ioq_send_get_bytes(client->send_queue))
	{
		net_con_update(client->con, NET_EVENT_READ | NET_EVENT_WRITE);
	}
	else
	{
		net_con_update(client->con, NET_EVENT_READ);
	}
	return 0;
}


void ADC_client_send(struct ADC_client* client, struct adc_message* msg)
{
	ADC_TRACE;

	uhub_assert(client->con != NULL);
	uhub_assert(msg->cache && *msg->cache);

	if (ioq_send_is_empty(client->send_queue) && !(client->flags & cflag_pipe))
	{
		/* Perform oportunistic write */
		ioq_send_add(client->send_queue, msg);
		ADC_client_send_queue(client);
	}
	else
	{
		ioq_send_add(client->send_queue, msg);
		if (!(client->flags & cflag_pipe))
			net_con_update(client->con, NET_EVENT_READ | NET_EVENT_WRITE);
	}
}

void ADC_client_send_info(struct ADC_client* client)
{
	ADC_TRACE;
	client->info = adc_msg_construct_source(ADC_CMD_BINF, client->sid, 96);


	adc_msg_add_named_argument_string(client->info, ADC_INF_FLAG_NICK, client->nick);

	if (client->desc)
	{
		adc_msg_add_named_argument_string(client->info, ADC_INF_FLAG_DESCRIPTION, client->desc);
	}

	adc_msg_add_named_argument_string(client->info, ADC_INF_FLAG_USER_AGENT_PRODUCT,
		client->ua_product ? client->ua_product : PRODUCT);
	adc_msg_add_named_argument_string(client->info, ADC_INF_FLAG_USER_AGENT_VERSION,
		client->ua_version ? client->ua_version : VERSION);
	adc_msg_add_named_argument_int(client->info, ADC_INF_FLAG_UPLOAD_SLOTS, 0);
	adc_msg_add_named_argument_uint64(client->info, ADC_INF_FLAG_SHARED_SIZE, client->share_size);
	adc_msg_add_named_argument_uint64(client->info, ADC_INF_FLAG_SHARED_FILES, client->share_files);

	adc_msg_add_named_argument_int(client->info, ADC_INF_FLAG_COUNT_HUB_NORMAL, 1);
	adc_msg_add_named_argument_int(client->info, ADC_INF_FLAG_COUNT_HUB_REGISTER, 0);
	adc_msg_add_named_argument_int(client->info, ADC_INF_FLAG_COUNT_HUB_OPERATOR, 0);

	adc_msg_add_named_argument_int(client->info, ADC_INF_FLAG_DOWNLOAD_SPEED, 5 * 1024 * 1024);
	adc_msg_add_named_argument_int(client->info, ADC_INF_FLAG_UPLOAD_SPEED, 10 * 1024 * 1024);

	adc_cid_pid(client);

	ADC_client_send(client, client->info);
}


static void ADC_client_send_password(struct ADC_client* client, const char* challenge)
{
	struct adc_message* hpas;
	char buf[MAX_PASS_LEN + TIGERSIZE];
	char raw_challenge[TIGERSIZE];
	char response[MAX_CID_LEN + 1];
	uint64_t tiger_res[3];
	size_t password_len;

	ADC_TRACE;

	if (!client->password)
	{
		ADC_client_debug(client, "Password required but none configured.");
		client->callback(client, ADC_CLIENT_LOGIN_ERROR, 0);
		return;
	}

	/* The challenge is a base32-encoded TIGER hash (MAX_CID_LEN chars). */
	if (strlen(challenge) != MAX_CID_LEN)
	{
		ADC_client_debug(client, "Malformed password challenge: \"%s\"", challenge);
		return;
	}

	password_len = strlen(client->password);
	if (password_len > MAX_PASS_LEN)
		password_len = MAX_PASS_LEN;

	base32_decode(challenge, (unsigned char*) raw_challenge, MAX_CID_LEN);

	memcpy(&buf[0], client->password, password_len);
	memcpy(&buf[password_len], raw_challenge, TIGERSIZE);

	tiger((uint64_t*) buf, password_len + TIGERSIZE, tiger_res);
	base32_encode((unsigned char*) tiger_res, TIGERSIZE, response);
	response[MAX_CID_LEN] = 0;

	hpas = adc_msg_construct(ADC_CMD_HPAS, MAX_CID_LEN + 8);
	adc_msg_add_argument(hpas, response);
	ADC_client_set_state(client, adc_state_verify);
	ADC_client_send(client, hpas);
	adc_msg_free(hpas);
}

struct ADC_client* ADC_client_create(const char* nickname, const char* description, void* ptr)
{
	ADC_TRACE;
	struct ADC_client* client = (struct ADC_client*) hub_malloc_zero(sizeof(struct ADC_client));

	ADC_client_set_state(client, adc_state_none);

	client->nick = hub_strdup(nickname);
	client->desc = hub_strdup(description);

	client->send_queue = ioq_send_create();
	client->recv_queue = ioq_recv_create();

	client->track_users = 1;
	client->users = list_create();

	client->ptr = ptr;

	if (!g_adc_client)
	{
		g_adc_client = (struct ADC_client_global*) hub_malloc_zero(sizeof(struct ADC_client_global));
		g_adc_client->ctx = net_ssl_context_create("1.2", "HIGH", "");
	}
	g_adc_client->references++;

	return client;
}

void ADC_client_destroy(struct ADC_client* client)
{
	ADC_TRACE;
	ADC_client_disconnect(client);
	userlist_clear(client);
	list_destroy(client->users);
	ioq_send_destroy(client->send_queue);
	ioq_recv_destroy(client->recv_queue);
	adc_msg_free(client->info);
	hub_free(client->hubinfo.name);
	hub_free(client->hubinfo.description);
	hub_free(client->hubinfo.version);
	hub_free(client->nick);
	hub_free(client->desc);
	hub_free(client->password);
	hub_free(client->ua_product);
	hub_free(client->ua_version);
	hub_free(client->address.hostname);
	hub_free(client);

	if (g_adc_client && g_adc_client->references > 0)
	{
		g_adc_client->references--;
		if (!g_adc_client->references)
		{
			net_ssl_context_destroy(g_adc_client->ctx);
			g_adc_client->ctx = NULL;
			hub_free(g_adc_client);
			g_adc_client = NULL;
		}
	}
}

static void connect_callback(struct net_connect_handle* handle, enum net_connect_status status, struct net_connection* con, void* ptr)
{
	(void) handle;
	struct ADC_client* client = (struct ADC_client*) ptr;
	client->connect_job = NULL;
	switch (status)
	{
		case net_connect_status_ok:
			client->con = con;
			net_con_reinitialize(client->con, event_callback, client, 0);
			ADC_client_on_connected(client);
			break;

		case net_connect_status_host_not_found:
		case net_connect_status_no_address:
		case net_connect_status_dns_error:
		case net_connect_status_refused:
		case net_connect_status_unreachable:
		case net_connect_status_timeout:
		case net_connect_status_socket_error:
			ADC_client_disconnect(client);
			ADC_client_set_state(client, adc_state_none);
			client->callback(client, ADC_CLIENT_DISCONNECTED, 0);
			break;
	}
}

int ADC_client_connect(struct ADC_client* client, const char* address)
{
	ADC_TRACE;
	if (client->state == adc_state_none)
	{
		if (!ADC_client_parse_address(client, address))
			return 0;
	}

	ADC_client_set_state(client, adc_state_connecting);
	client->callback(client, ADC_CLIENT_CONNECTING, 0);
	client->connect_job = net_con_connect(client->address.hostname, client->address.port, connect_callback, client);
	if (!client->connect_job)
	{
		ADC_client_on_disconnected(client);
		return 0;
	}
	return 1;
}

static void ADC_client_send_handshake(struct ADC_client* client)
{
	ADC_TRACE;
	struct adc_message* handshake = adc_msg_create(ADC_HANDSHAKE);

	client->callback(client, ADC_CLIENT_CONNECTED, 0);
	net_con_update(client->con, NET_EVENT_READ);
	ADC_client_send(client, handshake);
	ADC_client_set_state(client, adc_state_protocol);
	adc_msg_free(handshake);
}

static void ADC_client_on_connected(struct ADC_client* client)
{
	ADC_TRACE;
	if (client->flags & cflag_ssl)
	{
		net_con_update(client->con, NET_EVENT_READ | NET_EVENT_WRITE);
		client->callback(client, ADC_CLIENT_SSL_HANDSHAKE, 0);
		ADC_client_set_state(client, adc_state_ssl);
		net_con_ssl_handshake(client->con, net_con_ssl_mode_client, g_adc_client->ctx);
	}
	else
	ADC_client_send_handshake(client);

}

static void ADC_client_on_connected_ssl(struct ADC_client* client)
{
	ADC_TRACE;
	struct ADC_client_callback_data data;

	client->tls_info.version = net_ssl_get_tls_version(client->con);
	client->tls_info.cipher = net_ssl_get_tls_cipher(client->con);
	client->have_tls = 1;
	data.tls_info = &client->tls_info;

	client->callback(client, ADC_CLIENT_SSL_OK, &data);
	ADC_client_send_handshake(client);
}

static void ADC_client_on_disconnected(struct ADC_client* client)
{
	ADC_TRACE;
	if (client->con)
	{
		net_con_close(client->con);
		client->con = 0;
	}
	ADC_client_set_state(client, adc_state_none);
	client->have_tls = 0;
	userlist_clear(client);

	/* Notify the owner that the connection is gone. Without this an unexpected
	   drop (peer reset, recv error) leaves the client with a NULL connection but
	   the owner still believing it is logged in, so the next attempt to send a
	   message trips the uhub_assert(client->con != NULL) in ADC_client_send(). */
	client->callback(client, ADC_CLIENT_DISCONNECTED, 0);
}

static void ADC_client_on_login(struct ADC_client* client)
{
	ADC_TRACE;
	ADC_client_set_state(client, adc_state_normal);
	client->callback(client, ADC_CLIENT_LOGGED_IN, 0);
}

void ADC_client_disconnect(struct ADC_client* client)
{
	ADC_TRACE;
	/* Cancel a still-pending connect (DNS/connect in flight). connect_callback()
	   clears connect_job before it fires and the net layer frees the handle
	   itself afterwards, so a non-NULL connect_job here means the callback has
	   not run yet -- without this the handle outlives the client and the eventual
	   callback dereferences freed memory. */
	if (client->connect_job)
	{
		net_connect_destroy(client->connect_job);
		client->connect_job = 0;
	}

	if (client->con && net_con_get_sd(client->con) != -1)
	{
		net_con_close(client->con);
		client->con = 0;
	}
}

static int ADC_client_parse_address(struct ADC_client* client, const char* arg)
{
	ADC_TRACE;
	const char* hub_address = arg;
	const char* split;
	int ssl = 0;

	if (!arg)
		return 0;

	/* Minimum length of a valid address */
	if (strlen(arg) < 9)
		return 0;

	/* Check for ADC or ADCS */
	if (!strncmp(arg, "adc://", 6))
	{
		client->flags &= ~cflag_ssl;
		client->address.protocol = ADC;
	}
	else if (!strncmp(arg, "adcs://", 7))
	{
		client->flags |= cflag_ssl;
		ssl = 1;
		client->address.protocol = ADCS;
	}
	else
		return 0;

	/* Split hostname and port (if possible) */
	hub_address = arg + 6 + ssl;
	split = strrchr(hub_address, ':');
	if (split == 0 || strlen(split) < 2 || strlen(split) > 6)
		return 0;

	/* Ensure port number is valid (validate before narrowing to uint16_t). */
	long port = strtol(split+1, NULL, 10);
	if (port <= 0 || port > 65535)
		return 0;
	client->address.port = (uint16_t) port;

	client->address.hostname = strndup(hub_address, &split[0] - &hub_address[0]);

	return 1;
}

void ADC_client_set_password(struct ADC_client* client, const char* password)
{
	ADC_TRACE;
	hub_free(client->password);
	client->password = password ? hub_strdup(password) : NULL;
}

void ADC_client_set_callback(struct ADC_client* client, adc_client_cb cb)
{
	ADC_TRACE;
	client->callback = cb;
}

void ADC_client_set_log_callback(struct ADC_client* client, adc_client_log_cb cb)
{
	ADC_TRACE;
	client->log_cb = cb;
}

void ADC_client_set_user_agent(struct ADC_client* client, const char* product, const char* version)
{
	ADC_TRACE;
	hub_free(client->ua_product);
	hub_free(client->ua_version);
	client->ua_product = product ? hub_strdup(product) : NULL;
	client->ua_version = version ? hub_strdup(version) : NULL;
}

void ADC_client_set_share(struct ADC_client* client, uint64_t size, uint64_t files)
{
	ADC_TRACE;
	client->share_size = size;
	client->share_files = files;
}

void ADC_client_set_track_users(struct ADC_client* client, int enable)
{
	ADC_TRACE;
	client->track_users = enable ? 1 : 0;
	if (!enable)
		userlist_clear(client);
}

/* ------------------------------------------------------------------ *
 *  Outbound intent
 * ------------------------------------------------------------------ */

static int ADC_client_can_send(struct ADC_client* client)
{
	/* A session id plus a live connection is enough: once ISID has arrived
	   and INF has been sent (adc_state_identify onward) the hub accepts and
	   relays messages, which is how a peer's INF can reach us -- and be
	   replied to -- before our own login echo completes. */
	return client->con != NULL && client->sid != 0;
}

int ADC_client_say(struct ADC_client* client, const char* text)
{
	char* esc;
	struct adc_message* cmd;
	if (!ADC_client_can_send(client))
		return 0;
	esc = adc_msg_escape(text);
	cmd = adc_msg_construct_source(ADC_CMD_BMSG, client->sid, strlen(esc));
	adc_msg_add_argument(cmd, esc);
	ADC_client_send(client, cmd);
	adc_msg_free(cmd);
	hub_free(esc);
	return 1;
}

int ADC_client_say_me(struct ADC_client* client, const char* text)
{
	char* esc;
	struct adc_message* cmd;
	if (!ADC_client_can_send(client))
		return 0;
	esc = adc_msg_escape(text);
	cmd = adc_msg_construct_source(ADC_CMD_BMSG, client->sid, strlen(esc) + 4);
	adc_msg_add_argument(cmd, esc);
	adc_msg_add_named_argument(cmd, ADC_MSG_FLAG_ACTION, "1");
	ADC_client_send(client, cmd);
	adc_msg_free(cmd);
	hub_free(esc);
	return 1;
}

int ADC_client_pm(struct ADC_client* client, sid_t to, const char* text)
{
	char* esc;
	struct adc_message* cmd;
	if (!ADC_client_can_send(client))
		return 0;
	esc = adc_msg_escape(text);
	cmd = adc_msg_construct_source_dest(ADC_CMD_DMSG, client->sid, to, strlen(esc) + 8);
	adc_msg_add_argument(cmd, esc);
	adc_msg_add_named_argument(cmd, ADC_MSG_FLAG_PRIVATE, sid_to_string(client->sid));
	ADC_client_send(client, cmd);
	adc_msg_free(cmd);
	hub_free(esc);
	return 1;
}

int ADC_client_search(struct ADC_client* client, const char* terms)
{
	struct adc_message* cmd;
	struct linked_list* tokens;
	char* token;
	if (!ADC_client_can_send(client) || !terms)
		return 0;
	cmd = adc_msg_construct_source(ADC_CMD_BSCH, client->sid, strlen(terms) + 8);
	/* terms are already-formed ADC search args ("ANfoo", "TR...", "TOtoken")
	   separated by spaces; each becomes its own message argument. */
	tokens = list_create();
	split_string(terms, " ", tokens, 0);
	LIST_FOREACH(char*, token, tokens,
	{
		if (*token)
			adc_msg_add_argument(cmd, token);
	});
	list_clear(tokens, hub_free_handle);
	list_destroy(tokens);
	ADC_client_send(client, cmd);
	adc_msg_free(cmd);
	return 1;
}

int ADC_client_connect_to_me(struct ADC_client* client, sid_t to, const char* token, uint16_t port, int secure)
{
	struct adc_message* cmd;
	char portbuf[8];
	if (!ADC_client_can_send(client))
		return 0;
	cmd = adc_msg_construct_source_dest(ADC_CMD_DCTM, client->sid, to, 48);
	adc_msg_add_argument(cmd, secure ? "ADCS/1.0" : "ADC/1.0");
	snprintf(portbuf, sizeof(portbuf), "%u", (unsigned) port);
	adc_msg_add_argument(cmd, portbuf);
	adc_msg_add_argument(cmd, token ? token : "");
	ADC_client_send(client, cmd);
	adc_msg_free(cmd);
	return 1;
}

int ADC_client_rev_connect_to_me(struct ADC_client* client, sid_t to, const char* token)
{
	struct adc_message* cmd;
	if (!ADC_client_can_send(client))
		return 0;
	cmd = adc_msg_construct_source_dest(ADC_CMD_DRCM, client->sid, to, 32);
	adc_msg_add_argument(cmd, "ADC/1.0");
	adc_msg_add_argument(cmd, token ? token : "");
	ADC_client_send(client, cmd);
	adc_msg_free(cmd);
	return 1;
}

int ADC_client_set_away(struct ADC_client* client, enum ADC_away_state state)
{
	struct adc_message* cmd;
	if (!ADC_client_can_send(client))
		return 0;
	cmd = adc_msg_construct_source(ADC_CMD_BINF, client->sid, 16);
	adc_msg_add_named_argument_int(cmd, ADC_INF_FLAG_AWAY, (int) state);
	ADC_client_send(client, cmd);
	adc_msg_free(cmd);
	return 1;
}

int ADC_client_update_info(struct ADC_client* client, const char named_field[2], const char* value)
{
	struct adc_message* cmd;
	if (!ADC_client_can_send(client))
		return 0;
	cmd = adc_msg_construct_source(ADC_CMD_BINF, client->sid, (value ? strlen(value) : 0) + 8);
	adc_msg_add_named_argument_string(cmd, named_field, value ? value : "");
	ADC_client_send(client, cmd);
	adc_msg_free(cmd);
	return 1;
}

/* ------------------------------------------------------------------ *
 *  Accessors
 * ------------------------------------------------------------------ */

sid_t ADC_client_get_sid(const struct ADC_client* client)
{
	return client->sid;
}

const char* ADC_client_get_nick(const struct ADC_client* client)
{
	return client->nick;
}

const char* ADC_client_get_description(const struct ADC_client* client)
{
	return client->desc;
}

enum ADC_client_state ADC_client_get_state(const struct ADC_client* client)
{
	return client->state;
}

void* ADC_client_get_ptr(const struct ADC_client* client)
{
	return client->ptr;
}

const struct ADC_hub_info* ADC_client_get_hub_info(const struct ADC_client* client)
{
	return &client->hubinfo;
}

const struct ADC_client_tls_info* ADC_client_get_tls_info(const struct ADC_client* client)
{
	return client->have_tls ? &client->tls_info : NULL;
}

const struct ADC_user* ADC_client_get_user(const struct ADC_client* client, sid_t sid)
{
	return userlist_find((struct ADC_client*) client, sid);
}

size_t ADC_client_user_count(const struct ADC_client* client)
{
	return client->users ? list_size(client->users) : 0;
}

void ADC_client_foreach_user(const struct ADC_client* client, adc_user_iter_cb cb, void* data)
{
	struct ADC_user* u;
	if (!client->users || !cb)
		return;
	LIST_FOREACH(struct ADC_user*, u, client->users,
	{
		cb(u, data);
	});
}
