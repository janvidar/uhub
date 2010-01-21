/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2010, Jan Vidar Krey
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

#include <uhub.h>
#include "hubio.h"
#include "probe.h"

/* FIXME: This should not be needed! */
extern struct hub_info* g_hub;

#ifdef DEBUG_SENDQ
void debug_sendq_send(struct hub_user* user, int sent, int total)
{
	LOG_DUMP("SEND: sd=%d, %d/%d bytes\n", user->net.connection.sd, sent, total);
	if (sent == -1)
	{
		int err = net_error();
		LOG_DUMP("    errno: %d - %s\n", err, net_error_string(err));
	}
}

void debug_sendq_recv(struct hub_user* user, int received, int max, const char* buffer)
{
	LOG_DUMP("RECV: %d/%d bytes\n", received, (int) max);
	if (received == -1)
	{
		int err = net_error();
		LOG_DUMP("    errno: %d - %s\n", err, net_error_string(err));
	}
	else if (received > 0)
	{
		char* data = hub_malloc_zero(received + 1);
		memcpy(data, buffer, received);
		LOG_DUMP("RECV: \"%s\"\n", data);
		hub_free(data);
	}
}
#endif

int handle_net_read(struct hub_user* user)
{
	static char buf[MAX_RECV_BUF];
	struct hub_recvq* q = user->recv_queue;
	size_t buf_size = hub_recvq_get(q, buf, MAX_RECV_BUF);
	ssize_t size = net_con_recv(user->connection, buf, MAX_RECV_BUF);

	if (size > 0)
		buf_size += size;

	if (size < 0)
	{
		if (size == -1)
			return quit_disconnected;
		else
			return quit_socket_error;
	}
	else if (size == 0)
	{
		return 0;
	}
	else
	{
		char* lastPos = 0;
		char* start = buf;
		char* pos = 0;
		size_t remaining = buf_size;

		while ((pos = memchr(start, '\n', remaining)))
		{
			lastPos = pos;
			pos[0] = '\0';

#ifdef DEBUG_SENDQ
			LOG_DUMP("PROC: \"%s\" (%d)\n", start, (int) (pos - start));
#endif

			if (user_flag_get(user, flag_maxbuf))
			{
				user_flag_unset(user, flag_maxbuf);
			}
			else
			{
				if (((pos - start) > 0) && g_hub->config->max_recv_buffer > (pos - start))
				{
					if (hub_handle_message(g_hub, user, start, (pos - start)) == -1)
					{
							return quit_protocol_error;
					}
				}
			}

			pos[0] = '\n'; /* FIXME: not needed */
			pos ++;
			remaining -= (pos - start);
			start = pos;
		}

		if (lastPos || remaining)
		{
			if (remaining < g_hub->config->max_recv_buffer)
			{
				hub_recvq_set(q, lastPos ? lastPos : buf, remaining);
			}
			else
			{
				hub_recvq_set(q, 0, 0);
				user_flag_set(user, flag_maxbuf);
				LOG_WARN("Received message past max_recv_buffer, dropping message.");
			}
		}
		else
		{
			hub_recvq_set(q, 0, 0);
		}
	}
	return 0;
}

int handle_net_write(struct hub_user* user)
{
	int ret = 0;
	while (hub_sendq_get_bytes(user->send_queue))
	{
		ret = hub_sendq_send(user->send_queue, user);
		if (ret <= 0)
			break;
	}

	if (ret < 0)
		return quit_socket_error;

	if (hub_sendq_get_bytes(user->send_queue))
	{
		user_net_io_want_write(user);
	}
	else
	{
		user_net_io_want_read(user);
	}
	return 0;
}

void net_event(struct net_connection* con, int event, void *arg)
{
	struct hub_user* user = (struct hub_user*) arg;
	int flag_close = 0;

#ifdef DEBUG_SENDQ
	LOG_TRACE("net_event() : fd=%d, ev=%d, arg=%p", fd, (int) event, arg);
#endif

	if (event == NET_EVENT_TIMEOUT)
	{
		if (user_is_connecting(user))
		{
			hub_disconnect_user(g_hub, user, quit_timeout);
		}
		return;
	}

	if (event & NET_EVENT_READ)
	{
		flag_close = handle_net_read(user);
		if (flag_close)
		{
			hub_disconnect_user(g_hub, user, flag_close);
			return;
		}
	}

	if (event & NET_EVENT_WRITE)
	{
		flag_close = handle_net_write(user);
		if (flag_close)
		{
			hub_disconnect_user(g_hub, user, flag_close);
			return;
		}
	}
}

void net_on_accept(struct net_connection* con, int event, void *arg)
{
	struct hub_info* hub = (struct hub_info*) arg;
	struct hub_probe* probe = 0;
	struct ip_addr_encap ipaddr;
	const char* addr;
	int server_fd = net_con_get_sd(con);

	for (;;)
	{
		int fd = net_accept(server_fd, &ipaddr);
		if (fd == -1)
		{
			if (net_error() == EWOULDBLOCK)
			{
				break;
			}
			else
			{
				LOG_ERROR("Accept error: %d %s", net_error(), strerror(net_error()));
				break;
			}
		}

		addr = ip_convert_to_string(&ipaddr); 

		/* FIXME: Should have a plugin log this */
		LOG_TRACE("Got connection from %s", addr);

		/* FIXME: A plugin should perform this check: is IP banned? */
		if (acl_is_ip_banned(hub->acl, addr))
		{
			LOG_INFO("Denied      [%s] (IP banned)", addr);
			net_con_close(con);
			continue;
		}

		probe = probe_create(hub, fd, &ipaddr);
		if (!probe)
		{
			LOG_ERROR("Unable to create probe after socket accepted. Out of memory?");
			net_con_close(con);
			break;
		}
	}
}

