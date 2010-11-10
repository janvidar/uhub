/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2009, Jan Vidar Krey
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "tools/adcclient.h"

#define ADC_HANDSHAKE "HSUP ADBASE ADTIGR ADPING\n"
#define ADC_CID_SIZE 39
#define BIG_BUFSIZE 32768
#define TIGERSIZE 24

static ssize_t ADC_client_recv(struct ADC_client* client);
static void ADC_client_send_info(struct ADC_client* client);
static void ADC_client_on_connected(struct ADC_client* client);
static void ADC_client_on_disconnected(struct ADC_client* client);
static void ADC_client_on_login(struct ADC_client* client);
static int ADC_client_parse_address(struct ADC_client* client, const char* arg);
static void ADC_client_on_recv_line(struct ADC_client* client, const char* line, size_t length);

static void ADC_client_debug(struct ADC_client* client, const char* format, ...)
{
	char logmsg[1024];
	va_list args;
	va_start(args, format);
	vsnprintf(logmsg, 1024, format, args);
	va_end(args);
	fprintf(stdout, "* [%p] %s\n", client, logmsg);
}

static void ADC_client_set_state(struct ADC_client* client, enum ADC_client_state state)
{
	client->state = state;
}


static void adc_cid_pid(struct ADC_client* client)
{
	char seed[64];
	char pid[64];
	char cid[64];
	uint64_t tiger_res1[3];
	uint64_t tiger_res2[3];

	/* create cid+pid pair */
	memset(seed, 0, 64);
	snprintf(seed, 64, VERSION "%p", client);

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
	struct ADC_client* client = (struct ADC_client*) net_con_get_ptr(con);

	if (events == NET_EVENT_TIMEOUT)
	{
		if (client->state == ps_conn)
		{
			client->callback(client, ADC_CLIENT_DISCONNECTED, 0);
		}
		return;
	}

	if (events & NET_EVENT_READ)
	{
		if (ADC_client_recv(client) == -1)
		{
			ADC_client_on_disconnected(client);
		}
	}

	if (events & NET_EVENT_WRITE)
	{
		if (client->state == ps_conn)
		{
			ADC_client_connect(client, 0);
		}
		else
		{
			/* FIXME: Call send again */
		}
	}
}

#define UNESCAPE_ARG(TMP, TARGET) \
		if (TMP) \
			TARGET = adc_msg_unescape(TMP); \
		else \
			TARGET = NULL; \
		hub_free(TMP);

#define EXTRACT_NAMED_ARG(MSG, NAME, TARGET) \
		do { \
			char* tmp = adc_msg_get_named_argument(MSG, NAME); \
			UNESCAPE_ARG(tmp, TARGET); \
		} while (0)

#define EXTRACT_POS_ARG(MSG, POS, TARGET) \
		do { \
			char* tmp = adc_msg_get_argument(MSG, POS); \
			UNESCAPE_ARG(tmp, TARGET); \
		} while (0)


static void ADC_client_on_recv_line(struct ADC_client* client, const char* line, size_t length)
{
#ifdef ADC_CLIENT_DEBUG_PROTO
	ADC_client_debug(client, "- LINE: '%s'", start);
#endif

	/* Parse message */
	struct adc_message* msg = adc_msg_parse(line, length);
	if (!msg)
	{
		ADC_client_debug(client, "WARNING: Message cannot be decoded: \"%s\"", line);
		return;
	}

	if (length < 4)
	{
		ADC_client_debug(client, "Unexpected response from hub: '%s'", line);
		return;
	}

	switch (msg->cmd)
	{
		case ADC_CMD_ISUP:
			break;

		case ADC_CMD_ISID:
			if (client->state == ps_protocol)
			{
				client->sid = string_to_sid(&line[5]);
				client->callback(client, ADC_CLIENT_LOGGING_IN, 0);
				ADC_client_set_state(client, ps_identify);
				ADC_client_send_info(client);
			}
			break;

		case ADC_CMD_BMSG:
		case ADC_CMD_EMSG:
		case ADC_CMD_DMSG:
		case ADC_CMD_IMSG:
		{
			struct ADC_chat_message chat;
			struct ADC_client_callback_data data;
			chat.from_sid       = msg->source;
			chat.to_sid         = msg->target;
			data.chat = &chat;
			EXTRACT_POS_ARG(msg, 0, chat.message);
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
					EXTRACT_NAMED_ARG(msg, "NI", user.name);
					EXTRACT_NAMED_ARG(msg, "DE", user.description);
					EXTRACT_NAMED_ARG(msg, "VE", user.version);
					EXTRACT_NAMED_ARG(msg, "ID", user.cid);
					EXTRACT_NAMED_ARG(msg, "I4", user.address);

					struct ADC_client_callback_data data;
					data.user = &user;
					client->callback(client, ADC_CLIENT_USER_JOIN, &data);

					hub_free(user.name);
					hub_free(user.description);
					hub_free(user.version);
					hub_free(user.cid);
					hub_free(user.address);
				}
			}
		}

		case ADC_CMD_ISTA:
			/*
			if (strncmp(line, "ISTA 000", 8))
			{
				ADC_client_debug(client, "status: '%s'\n", (start + 9));
			}
			*/
			break;
			
		default:
			break;
	}

	adc_msg_free(msg);
}

static ssize_t ADC_client_recv(struct ADC_client* client)
{
	ssize_t size = net_con_recv(client->con, &client->recvbuf[client->r_offset], ADC_BUFSIZE - client->r_offset);
	if (size <= 0)
		return size;

	client->r_offset += size;
	client->recvbuf[client->r_offset] = 0;

	char* start = client->recvbuf;
	char* pos;
	char* lastPos = 0;
	size_t remaining = client->r_offset;

	while ((pos = memchr(start, '\n', remaining)))
	{
		pos[0] = 0;

		ADC_client_on_recv_line(client, start, pos - start);

		pos++;
		remaining -= (pos - start);
		start = pos;
		lastPos = pos;
	}

	if (lastPos)
	{
		memmove(client->recvbuf, lastPos, remaining);
		client->r_offset = remaining;
	}
	return 0;
}


void ADC_client_send(struct ADC_client* client, char* msg)
{
	int ret = net_con_send(client->con, msg, strlen(msg));

#ifdef ADC_CLIENT_DEBUG_PROTO
	char* dump = strdup(msg);
	dump[strlen(msg) - 1] = 0;
	ADC_client_debug(client, "- SEND: '%s'", dump);
	free(dump);
#endif

	if (ret != strlen(msg))
	{
		if (ret == -1)
		{
			if (net_error() != EWOULDBLOCK)
				ADC_client_on_disconnected(client);
		}
		else
		{
			/* FIXME: Not all data sent! */
			printf("ret (%d) != msg->length (%d)\n", ret, (int) strlen(msg));
		}
	}
}

void ADC_client_send_info(struct ADC_client* client)
{
	char binf[11];
	snprintf(binf, 11, "BINF %s\n", sid_to_string(client->sid));
	client->info = adc_msg_create(binf);

	adc_msg_add_named_argument_string(client->info, ADC_INF_FLAG_NICK, client->nick);

	if (client->desc)
	{
		adc_msg_add_named_argument_string(client->info, ADC_INF_FLAG_DESCRIPTION, client->desc);
	}

	adc_msg_add_named_argument_string(client->info, ADC_INF_FLAG_USER_AGENT, PRODUCT "/" VERSION);

	adc_cid_pid(client);
	ADC_client_send(client, client->info->cache);
}

int ADC_client_create(struct ADC_client* client, const char* nickname, const char* description)
{
	memset(client, 0, sizeof(struct ADC_client));

	int sd = net_socket_create(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sd == -1) return -1;

	client->con = net_con_create();
#if 0
	/* FIXME */
	client->timer = 0; /* FIXME: hub_malloc(sizeof(struct net_timer)); */
#endif
	net_con_initialize(client->con, sd, event_callback, client, 0);
#if 0
	/* FIXME */
	net_timer_initialize(client->timer, timer_callback, client);
#endif
	ADC_client_set_state(client, ps_none);

	client->nick = hub_strdup(nickname);
	client->desc = hub_strdup(description);

	return 0;
}

void ADC_client_destroy(struct ADC_client* client)
{
	ADC_client_disconnect(client);
#if 0
	/* FIXME */
	net_timer_shutdown(client->timer);
#endif
	hub_free(client->timer);
	adc_msg_free(client->info);
	hub_free(client->nick);
	hub_free(client->desc);
	hub_free(client->hub_address);
}

int ADC_client_connect(struct ADC_client* client, const char* address)
{
	if (!client->hub_address)
	{
		if (!ADC_client_parse_address(client, address))
			return 0;
	
		client->callback(client, ADC_CLIENT_CONNECTING, 0);
	}
    
	int ret = net_con_connect(client->con, (struct sockaddr*) &client->addr, sizeof(struct sockaddr_in));
	if (ret == 1)
	{
		ADC_client_on_connected(client);
	}
	else if (ret == 0)
	{
		if (client->state != ps_conn)
		{
			net_con_update(client->con, NET_EVENT_READ | NET_EVENT_WRITE);
			ADC_client_set_state(client, ps_conn);
		}
	}
	else
	{
		ADC_client_on_disconnected(client);
		return 0;
	}
	return 1;
}

static void ADC_client_on_connected(struct ADC_client* client)
{
	if (client->ssl)
	{
		net_con_ssl_handshake(client->con, net_con_ssl_mode_client, NULL);
	}
	else
	{
		net_con_update(client->con, NET_EVENT_READ);
		client->callback(client, ADC_CLIENT_CONNECTED, 0);
		ADC_client_send(client, ADC_HANDSHAKE);
		ADC_client_set_state(client, ps_protocol);
	}
}

static void ADC_client_on_disconnected(struct ADC_client* client)
{
	net_con_close(client->con);
	client->con = 0;
	ADC_client_set_state(client, ps_none);
}

static void ADC_client_on_login(struct ADC_client* client)
{
	ADC_client_set_state(client, ps_normal);
	client->callback(client, ADC_CLIENT_LOGGED_IN, 0);
}

void ADC_client_disconnect(struct ADC_client* client)
{
	if (client->con && net_con_get_sd(client->con) != -1)
	{
		net_con_close(client->con);
		client->con = 0;
	}
}

static int ADC_client_parse_address(struct ADC_client* client, const char* arg)
{
	char* split;
	int ssl = 0;
	struct hostent* dns = 0;
	struct in_addr* addr = 0;

	if (!arg)
		return 0;

	client->hub_address = hub_strdup(arg);

	/* Minimum length of a valid address */
	if (strlen(arg) < 9)
		return 0;

	/* Check for ADC or ADCS */
	if (!strncmp(arg, "adc://", 6))       ssl = 0;
	else if (!strncmp(arg, "adcs://", 7)) ssl = 1;
	else return 0;

	client->ssl = ssl;

	/* Split hostname and port (if possible) */
	split = strrchr(client->hub_address + 6 + ssl, ':');
	if (split == 0 || strlen(split) < 2 || strlen(split) > 6)
		return 0;

	/* Ensure port number is valid */
	int port = strtol(split+1, NULL, 10);
	if (port <= 0 || port > 65535)
		return 0;

	split[0] = 0;

	/* Resolve IP address (FIXME: blocking call) */
	dns = gethostbyname(client->hub_address + 6 + ssl);
	if (dns)
		addr = (struct in_addr*) dns->h_addr_list[0];

	// Initialize the sockaddr struct.
	memset(&client->addr, 0, sizeof(client->addr));
	client->addr.sin_family = AF_INET;
	client->addr.sin_port   = htons(port);
	memcpy(&client->addr.sin_addr, addr, sizeof(struct in_addr));
	return 1;
}

void ADC_client_set_callback(struct ADC_client* client, adc_client_cb cb)
{
	client->callback = cb;
}
