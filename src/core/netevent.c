/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2014, Jan Vidar Krey
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
#include "ioqueue.h"
#include "probe.h"

int handle_net_read(struct hub_user* user)
{
	static char buf[MAX_RECV_BUF];
	struct ioq_recv* q = user->recv_queue;
	size_t buf_size = ioq_recv_get(q, buf, MAX_RECV_BUF);
	ssize_t size;

	if (user_flag_get(user, flag_maxbuf))
		buf_size = 0;
	size = net_con_recv(user->connection, buf + buf_size, MAX_RECV_BUF - buf_size);

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
			lastPos = pos+1;
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
				if (((pos - start) > 0) && user->hub->config->max_recv_buffer > (pos - start))
				{
					if (hub_handle_message(user->hub, user, start, (pos - start)) == -1)
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
			if (remaining < (size_t) user->hub->config->max_recv_buffer)
			{
				ioq_recv_set(q, lastPos ? lastPos : buf, remaining);
			}
			else
			{
				ioq_recv_set(q, 0, 0);
				user_flag_set(user, flag_maxbuf);
				LOG_WARN("Received message past max_recv_buffer, dropping message.");
			}
		}
		else
		{
			ioq_recv_set(q, 0, 0);
		}
	}
	return 0;
}

int handle_net_write(struct hub_user* user)
{
	int ret = 0;
	while (ioq_send_get_bytes(user->send_queue))
	{
		ret = ioq_send_send(user->send_queue, user->connection);
		if (ret <= 0)
			break;
	}

	if (ret < 0)
		return quit_socket_error;

	if (ioq_send_get_bytes(user->send_queue))
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
	LOG_TRACE("net_event() : fd=%d, ev=%d, arg=%p", con->sd, (int) event, arg);
#endif

	if (event == NET_EVENT_TIMEOUT)
	{
		if (user_is_connecting(user))
		{
			hub_disconnect_user(user->hub, user, quit_timeout);
		}
		return;
	}

	if (event & NET_EVENT_READ)
	{
		flag_close = handle_net_read(user);
		if (flag_close)
		{
			hub_disconnect_user(user->hub, user, flag_close);
			return;
		}
	}

	if (event & NET_EVENT_WRITE)
	{
		flag_close = handle_net_write(user);
		if (flag_close)
		{
			hub_disconnect_user(user->hub, user, flag_close);
			return;
		}
	}
}

void net_on_accept(struct net_connection* con, int event, void *arg)
{
	struct hub_info* hub = (struct hub_info*) arg;
	struct hub_probe* probe = 0;
	struct ip_addr_encap ipaddr;
	int server_fd = net_con_get_sd(con);
	plugin_st status;

	for (;;)
	{
		int fd = net_accept(server_fd, &ipaddr);
		if (fd == -1)
		{
#ifdef WINSOCK
			if (net_error() == WSAEWOULDBLOCK)
#else
			if (net_error() == EWOULDBLOCK)
#endif
			{
				break;
			}
			else
			{
				LOG_ERROR("Accept error: %d %s", net_error(), strerror(net_error()));
				break;
			}
		}

		status = plugin_check_ip_early(hub, &ipaddr);
		if (status == st_deny)
		{
			plugin_log_connection_denied(hub, &ipaddr);
			net_close(fd);
			continue;
		}

		plugin_log_connection_accepted(hub, &ipaddr);

		probe = probe_create(hub, fd, &ipaddr);
		if (!probe)
		{
			LOG_ERROR("Unable to create probe after socket accepted. Out of memory?");
			net_close(fd);
			break;
		}
	}
}

