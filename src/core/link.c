/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2013, Jan Vidar Krey
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

#include "uhub.h"

#ifdef LINK_SUPPORT
static int link_send_support(struct hub_link* link);

static void link_net_event(struct net_connection* con, int event, void *arg)
{
	LOG_INFO("link_net_event(), event=%d", event);
	struct hub_link* link = (struct hub_link*) arg;
	struct hub_info* hub = link->hub;
	int ret = 0;

	if (event == NET_EVENT_TIMEOUT)
	{
		LOG_DEBUG("Hub link timeout!");
	}

	if (event & NET_EVENT_READ)
	{
		ret = link_handle_read(link);
		if (ret < 0)
		{
			link_disconnect(link);
			return;
		}
	}

	if (event & NET_EVENT_WRITE)
	{
		ret = link_handle_write(link);
		if (ret < 0)
		{
			link_disconnect(link);
			return;
		}
	}
}

void link_disconnect(struct hub_link* link)
{
	if (link->connection)
		net_con_close(link->connection);
	link->connection = NULL;

	ioq_send_destroy(link->send_queue);
	ioq_recv_destroy(link->recv_queue);
	link->send_queue = NULL;
	link->recv_queue = NULL;

	// FIXME: Notify hub and disconnect users!

	hub_free(link);
}

static struct hub_link* link_create_internal(struct hub_info* hub)
{
	struct hub_link* link = NULL;

	LOG_DEBUG("link_create_internal(), hub=%p");
	link = (struct hub_link*) hub_malloc_zero(sizeof(struct hub_link));
	if (link == NULL)
		return NULL; /* OOM */

	link->send_queue = ioq_send_create();
	link->recv_queue = ioq_recv_create();

	link->hub = hub;
	link->state = state_protocol;
	return link;
}


struct hub_link* link_create(struct hub_info* hub, struct net_connection* con, struct ip_addr_encap* addr)
{
	struct hub_link* link = link_create_internal(hub);
	link->connection = con;
	net_con_reinitialize(link->connection, link_net_event, link, NET_EVENT_READ);
	link->mode = link_mode_server;
	return link;
}

static void link_connect_callback(struct net_connect_handle* handle, enum net_connect_status status, struct net_connection* con, void* ptr)
{
	struct hub_link* link = (struct hub_link*) ptr;
	link->connect_job = NULL;

	LOG_DEBUG("link_connect_callback()");

	switch (status)
	{
		case net_connect_status_ok:
			link->connection = con;
			net_con_reinitialize(link->connection, link_net_event, link, NET_EVENT_READ);
			// FIXME: send handshake here
			link_send_support(link);
			break;

		case net_connect_status_host_not_found:
		case net_connect_status_no_address:
		case net_connect_status_dns_error:
		case net_connect_status_refused:
		case net_connect_status_unreachable:
		case net_connect_status_timeout:
		case net_connect_status_socket_error:
			// FIXME: Unable to connect - start timer and re-try connection establishment!
			break;
	}
}

struct link_address
{
	char host[256];
	uint16_t port;
};

static int link_parse_address(const char* arg, struct link_address* addr)
{
	int port;
	char* split;

	memset(addr, 0, sizeof(struct link_address));

	/* Split hostname and port (if possible) */
	split = strrchr(arg, ':');
	if (split == 0 || strlen(split) < 2 || strlen(split) > 6)
		return 0;

	/* Ensure port number is valid */
	port = strtol(split+1, NULL, 10);
	if (port <= 0 || port > 65535)
		return 0;

	memcpy(addr->host, arg, &split[0] - &arg[0]);
	addr->port = port;
	return 1;
}


struct hub_link* link_connect_uri(struct hub_info* hub, const char* address)
{
	struct link_address link_address;
	if (!link_parse_address(address, &link_address))
	{
		LOG_INFO("Invalid master hub link address");
		return NULL;
	}

	return link_connect(hub, link_address.host, link_address.port);
}


struct hub_link* link_connect(struct hub_info* hub, const char* address, uint16_t port)
{
	struct hub_link* link = link_create_internal(hub);

	LOG_DEBUG("Connecting to master link at %s:%d...", address, port);

	link->mode = link_mode_client;
	link->connect_job = net_con_connect(address, port, link_connect_callback, link);
	if (!link->connect_job)
	{
		// FIXME: Immediate failure!
		LOG_DEBUG("Error connecting to master hub link.");
		link_disconnect(link);
		return NULL;
	}

	return link;
}

static int link_net_io_want_read(struct hub_link* link)
{
	net_con_update(link->connection, NET_EVENT_READ);
}

static int link_net_io_want_write(struct hub_link* link)
{
	net_con_update(link->connection, NET_EVENT_READ | NET_EVENT_WRITE);
}


int link_handle_write(struct hub_link* link)
{
	int ret = 0;
	while (ioq_send_get_bytes(link->send_queue))
	{
		ret = ioq_send_send(link->send_queue, link->connection);
		if (ret <= 0)
			break;
	}

	if (ret < 0)
		return -1; // FIXME! Extract socket error!

	if (ioq_send_get_bytes(link->send_queue))
		link_net_io_want_write(link);
	else
		link_net_io_want_read(link);
	return 0;
}


int link_send_message(struct hub_link* link, struct adc_message* msg)
{
#ifdef DEBUG_SENDQ
	char* data = strndup(msg->cache, msg->length-1);
	LOG_PROTO("[link] send %p: \"%s\"", link, data);
	free(data);
#endif

	if (!link->connection)
		return -1;

	uhub_assert(msg->cache && *msg->cache);

	if (ioq_send_is_empty(link->send_queue) /*&& !user_flag_get(user, flag_pipeline)*/)
	{
		/* Perform oportunistic write */
		ioq_send_add(link->send_queue, msg);
		link_handle_write(link);
	}
	else
	{
// 		if (check_send_queue(hub, user, msg) >= 0)
// 		{
			ioq_send_add(link->send_queue, msg);
// 			if (!user_flag_get(user, flag_pipeline))
			link_net_io_want_write(link);
	}
	return 0;
}

static int link_send_support(struct hub_link* link)
{
	int ret;
	struct adc_message* msg = adc_msg_construct(ADC_CMD_LSUP, 6 + strlen(ADC_PROTO_LINK_SUPPORT));
	adc_msg_add_argument(msg, ADC_PROTO_LINK_SUPPORT);
	ret = link_send_message(link, msg);
	adc_msg_free(msg);
	return ret;
}

static int link_send_welcome(struct hub_link* link)
{
	int ret;
	struct adc_message* info = adc_msg_construct(ADC_CMD_LINF, 128);

	if (!info)
		return -1;

	adc_msg_add_named_argument(info, ADC_INF_FLAG_CLIENT_TYPE, ADC_CLIENT_TYPE_HUB);
	adc_msg_add_named_argument_string(info, ADC_INF_FLAG_USER_AGENT, PRODUCT_STRING);
	adc_msg_add_named_argument_string(info, ADC_INF_FLAG_NICK, link->hub->config->hub_name);
	adc_msg_add_named_argument_string(info, ADC_INF_FLAG_DESCRIPTION, link->hub->config->hub_description);

	ret = link_send_message(link, info);

	link->state = state_normal;
}

static int link_send_auth_response(struct hub_link* link, const char* challenge)
{
	int ret;
	struct adc_message* msg = adc_msg_construct(ADC_CMD_LPAS, 128);

	// FIXME: Solve challenge.

	ret = link_send_message(link, msg);
	adc_msg_free(msg);
	return ret;
}

static int link_send_auth_request(struct hub_link* link)
{
	int ret;
	struct adc_message* msg = adc_msg_construct(ADC_CMD_LGPA, 128);

	// FIXME: Create challenge.
	char buf[64];
	uint64_t tiger_res[3];
	static char tiger_buf[MAX_CID_LEN+1];

	LOG_DEBUG("link_send_auth_request");

	// FIXME: Generate a better nonce scheme.
	snprintf(buf, 64, "%p%d", link, (int) net_con_get_sd(link->connection));

	tiger((uint64_t*) buf, strlen(buf), (uint64_t*) tiger_res);
	base32_encode((unsigned char*) tiger_res, TIGERSIZE, tiger_buf);
	tiger_buf[MAX_CID_LEN] = 0;

	// Add nonce to message
	adc_msg_add_argument(msg, (const char*) tiger_buf);
	ret = link_send_message(link, msg);
	adc_msg_free(msg);
	return ret;
}

static int link_handle_support(struct hub_link* link, struct adc_message* msg)
{
	int ret = 0;

	LOG_DEBUG("link_handle_support");

	if (link->mode == link_mode_server)
	{
		if (link->state == state_protocol)
		{
			ret = link_send_support(link);
			if (ret == 0)
				ret = link_send_auth_request(link);
			link->state = state_verify;
		}
	}
	return ret;
}

static int link_handle_auth_request(struct hub_link* link, struct adc_message* msg)
{
	char* challenge;
	int ret = -1;

	LOG_DEBUG("link_handle_auth_request");

	if (link->state == state_verify)
		return -1;

	if (link->mode == link_mode_client)
	{
		challenge = adc_msg_get_argument(msg, 0);
		ret = link_send_auth_response(link, challenge);
		hub_free(challenge);
	}
	return ret;
}

static int link_handle_auth_response(struct hub_link* link, struct adc_message* msg)
{

	LOG_DEBUG("link_handle_auth_response. link_state=%d", (int) link->state);

	if (link->state != state_verify)
		return -1;

	LOG_DEBUG("State is not verify!");

	if (link->mode == link_mode_server)
	{
		// Check authentication data
		// FIXME: Can involve plug-ins at this point.
		return link_send_welcome(link);
	}
	else
	{
		LOG_DEBUG("Ignoring auth response - We're client mode!");
	}

	return -1;
}

static int link_handle_link_info(struct hub_link* link, struct adc_message* msg)
{
	LOG_DEBUG("link_handle_link_info");
	return 0;
}

static int link_handle_status(struct hub_link* link, struct adc_message* msg)
{
	LOG_DEBUG("link_handle_status");
	return -1;
}

static int link_handle_message(struct hub_link* link, const char* message, size_t length)
{
	int ret = 0;
	struct adc_message* cmd = 0;

	LOG_INFO("link_handle_message(): %s (%d)", message, (int) length);

	// FIXME: is this needed?
	if (link->state == state_cleanup || link->state == state_disconnected)
		return -1;

	cmd = adc_msg_parse(message, length);
	if (!cmd)
	{
		LOG_DEBUG("Unable to parse hub-link message");
		return -1;
	}

	// if (

	switch (cmd->cmd)
	{
		case ADC_CMD_LSUP:
			ret = link_handle_support(link, cmd);
			break;

		case ADC_CMD_LPAS:
			ret = link_handle_auth_response(link, cmd);
			break;

		case ADC_CMD_LGPA:
			ret = link_handle_auth_request(link, cmd);
			break;

		case ADC_CMD_LINF:
			ret = link_handle_link_info(link, cmd);
			break;

		case ADC_CMD_LSTA:
			ret = link_handle_status(link, cmd);
			break;
	}

	adc_msg_free(cmd);
	return ret;
}


static int link_read_message(struct hub_link* link)
{
	char* lastPos = 0;
	char* pos = 0;
	char* start = link->recv_queue->buf;
	size_t remaining = link->recv_queue->size;

	while ((pos = memchr(start, '\n', remaining)))
	{
		lastPos = pos+1;
		pos[0] = '\0';

		if (link->flags & 1)
		{
			 /* FIXME Unset maxbuf flag */
			link->flags = 0;
		}
		else
		{
			if (link_handle_message(link, start, (pos - start)) == -1)
			{
				return -1;
			}
		}

		pos[0] = '\n'; /* FIXME: not needed */
		pos ++;
		remaining -= (pos - start);
		start = pos;
	}

	ioq_recv_consume(link->recv_queue, (start - link->recv_queue->buf));
	return 0;
}

int link_handle_read(struct hub_link* link)
{
	int ret = 0;
	while (1)
	{
		switch (ioq_recv_read(link->recv_queue, link->connection))
		{
			case ioq_recv_ok:
				if (link_read_message(link) < 0)
				{
					// FIXME: propagate protocol error?
					return -1;
				}
				// Parse messages then call again
				break;
				
			case ioq_recv_later:
				return 0;

			case ioq_recv_full:
				link->flags = 1; // FIXME: MAXBUF
				ioq_recv_set(link->recv_queue, 0, 0);
				break;

			case ioq_recv_error:
				return -1; // FIXME: it would be good to signal type of socket error
		}
	}

	return 0;
}


#endif /* LINK_SUPPORT */
