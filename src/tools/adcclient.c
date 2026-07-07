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


enum ADC_client_state
{
	ps_none, /* Not connected */
	ps_conn, /* Connecting... */
	ps_conn_ssl, /* SSL handshake */
	ps_protocol, /* Have sent HSUP */
	ps_identify, /* Have sent BINF */
	ps_verify, /* Have sent HPAS */
	ps_normal, /* Are fully logged in */
};

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
	size_t s_offset;
	size_t r_offset;
	struct net_connection* con;
	struct sockaddr_storage addr;
	struct net_connect_handle* connect_job;
	struct ADC_client_address address;
	char* nick;
	char* desc;
	char* password;
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

static void ADC_client_debug(struct ADC_client* client, const char* format, ...)
{
	char logmsg[1024];
	va_list args;
	va_start(args, format);
	vsnprintf(logmsg, 1024, format, args);
	va_end(args);
	fprintf(stdout, "* [%p] %s\n", client, logmsg);
}

#ifdef ADCC_DEBUG
#define ADC_TRACE fprintf(stderr, "TRACE: %s\n", __PRETTY_FUNCTION__)
#else
#define ADC_TRACE do { } while(0)
#endif

#ifdef ADCC_DEBUG
static const char* ADC_client_state_string[] =
{
	"ps_none",
	"ps_conn",
	"ps_conn_ssl",
	"ps_protocol",
	"ps_identify",
	"ps_verify",
	"ps_normal",
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
	snprintf(seed, 64, VERSION "%p%d%ld%u", client, (int) getpid(), (long) time(NULL), ++counter);

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
		case ps_conn:
			if (events == NET_EVENT_TIMEOUT)
			{
				client->callback(client, ADC_CLIENT_DISCONNECTED, 0);
				return;
			}
			break;

		case ps_conn_ssl:
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
			if (client->state == ps_identify || client->state == ps_verify)
			{
				char* challenge = adc_msg_get_argument(msg, 0);
				client->callback(client, ADC_CLIENT_PASSWORD_REQ, 0);
				if (challenge)
					ADC_client_send_password(client, challenge);
				hub_free(challenge);
			}
			break;

		case ADC_CMD_ISID:
			if (client->state == ps_protocol)
			{
				char* sid = adc_msg_get_argument(msg, 0);
				if (sid)
				{
					client->sid = string_to_sid(sid);
					hub_free(sid);
					client->callback(client, ADC_CLIENT_LOGGING_IN, 0);
					ADC_client_set_state(client, ps_identify);
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
			struct ADC_hub_info hubinfo;
			EXTRACT_NAMED_ARG(msg, "NI", hubinfo.name);
			EXTRACT_NAMED_ARG(msg, "DE", hubinfo.description);
			EXTRACT_NAMED_ARG(msg, "VE", hubinfo.version);

			struct ADC_client_callback_data data;
			data.hubinfo = &hubinfo;
			client->callback(client, ADC_CLIENT_HUB_INFO, &data);
			hub_free(hubinfo.name);
			hub_free(hubinfo.description);
			hub_free(hubinfo.version);
			break;
		}

		case ADC_CMD_BSCH:
		case ADC_CMD_FSCH:
		{
			client->callback(client, ADC_CLIENT_SEARCH_REQ, 0);
			break;
		}

		case ADC_CMD_BINF:
		{
			if (msg->source == client->sid)
			{
				if (client->state == ps_verify || client->state == ps_identify)
				{
					ADC_client_on_login(client);
				}
			}
			else
			{
				if (adc_msg_has_named_argument(msg, "ID"))
				{
					struct ADC_user user;
					user.sid = msg->source;
					EXTRACT_NAMED_ARG_X(msg, "NI", user.name, sizeof(user.name));
					EXTRACT_NAMED_ARG_X(msg, "DE", user.description, sizeof(user.description));
					EXTRACT_NAMED_ARG_X(msg, "VE", user.version, sizeof(user.version));
					EXTRACT_NAMED_ARG_X(msg, "ID", user.cid, sizeof(user.cid));
					EXTRACT_NAMED_ARG_X(msg, "I4", user.address, sizeof(user.address));

					struct ADC_client_callback_data data;
					data.user = &user;
					client->callback(client, ADC_CLIENT_USER_JOIN, &data);
				}
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
			if (status.severity == 2 && client->state != ps_normal)
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

	adc_msg_add_named_argument_string(client->info, ADC_INF_FLAG_USER_AGENT_PRODUCT, PRODUCT);
	adc_msg_add_named_argument_string(client->info, ADC_INF_FLAG_USER_AGENT_VERSION, VERSION);
	adc_msg_add_named_argument_int(client->info, ADC_INF_FLAG_UPLOAD_SLOTS, 0);
	adc_msg_add_named_argument_int(client->info, ADC_INF_FLAG_SHARED_SIZE, 0);
	adc_msg_add_named_argument_int(client->info, ADC_INF_FLAG_SHARED_FILES, 0);

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
	ADC_client_set_state(client, ps_verify);
	ADC_client_send(client, hpas);
	adc_msg_free(hpas);
}

struct ADC_client* ADC_client_create(const char* nickname, const char* description, void* ptr)
{
	ADC_TRACE;
	struct ADC_client* client = (struct ADC_client*) hub_malloc_zero(sizeof(struct ADC_client));

	ADC_client_set_state(client, ps_none);

	client->nick = hub_strdup(nickname);
	client->desc = hub_strdup(description);

	client->send_queue = ioq_send_create();
	client->recv_queue = ioq_recv_create();

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
	ioq_send_destroy(client->send_queue);
	ioq_recv_destroy(client->recv_queue);
	adc_msg_free(client->info);
	hub_free(client->nick);
	hub_free(client->desc);
	hub_free(client->password);
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
			ADC_client_set_state(client, ps_none);
			client->callback(client, ADC_CLIENT_DISCONNECTED, 0);
			break;
	}
}

int ADC_client_connect(struct ADC_client* client, const char* address)
{
	ADC_TRACE;
	if (client->state == ps_none)
	{
		if (!ADC_client_parse_address(client, address))
			return 0;
	}

	ADC_client_set_state(client, ps_conn);
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
	ADC_client_set_state(client, ps_protocol);
	adc_msg_free(handshake);
}

static void ADC_client_on_connected(struct ADC_client* client)
{
	ADC_TRACE;
	if (client->flags & cflag_ssl)
	{
		net_con_update(client->con, NET_EVENT_READ | NET_EVENT_WRITE);
		client->callback(client, ADC_CLIENT_SSL_HANDSHAKE, 0);
		ADC_client_set_state(client, ps_conn_ssl);
		net_con_ssl_handshake(client->con, net_con_ssl_mode_client, g_adc_client->ctx);
	}
	else
	ADC_client_send_handshake(client);
	
}

static void ADC_client_on_connected_ssl(struct ADC_client* client)
{
	ADC_TRACE;
	struct ADC_client_callback_data data;
	struct ADC_client_tls_info tls_info;
	data.tls_info = &tls_info;

	tls_info.version = net_ssl_get_tls_version(client->con);
	tls_info.cipher = net_ssl_get_tls_cipher(client->con);

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
	ADC_client_set_state(client, ps_none);

	/* Notify the owner that the connection is gone. Without this an unexpected
	   drop (peer reset, recv error) leaves the client with a NULL connection but
	   the owner still believing it is logged in, so the next attempt to send a
	   message trips the uhub_assert(client->con != NULL) in ADC_client_send(). */
	client->callback(client, ADC_CLIENT_DISCONNECTED, 0);
}

static void ADC_client_on_login(struct ADC_client* client)
{
	ADC_TRACE;
	ADC_client_set_state(client, ps_normal);
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

	client->address.hostname = hub_strndup(hub_address, &split[0] - &hub_address[0]);

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

void* ADC_client_get_ptr(const struct ADC_client* client)
{
	return client->ptr;
}
