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

#include "system.h"
#include "uhub_limits.h"
#include "util/log.h"
#include "network/backend.h"
#include "network/connection.h"
#include "network/network.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/netevent.h"
#include "core/plugininvoke.h"
#include "core/ioqueue.h"
#include "core/probe.h"

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
		/* The send queue drained */
		user_flag_unset(user, flag_choke);
		user_net_io_want_read(user);
	}
	return 0;
}

void net_event(struct net_connection* con, int event, void *arg)
{
	(void) con;
	struct hub_user* user = (struct hub_user*) arg;
	int flag_close = 0;

#ifdef DEBUG_SENDQ
	LOG_TRACE("net_event() : fd=%d, ev=%d, arg=%p", con->sd, (int) event, arg);
#endif

	if (event == NET_EVENT_ERROR)
	{
		hub_disconnect_user(user->hub, user, quit_socket_error);
		return;
	}

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
	(void) event;
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

		/*
		 * Enforce a hard ceiling on concurrently tracked connections. This
		 * bounds fd/memory consumption from a flood of (pre-login) connections,
		 * and keeps the descriptor within range of the backend's conns[] table:
		 * net_accept() can hand back an fd >= the table size when the soft fd
		 * limit (RLIMIT_NOFILE) has been raised above the table capacity, which
		 * would otherwise be an out-of-bounds index in the backend. Reject and
		 * close the socket in either case. We continue draining the backlog so
		 * the kernel accept queue empties and the listener stops re-firing.
		 */
		if (net_backend_get_num_connections() >= net_backend_get_max_connections() ||
		    (size_t) fd >= net_backend_get_max_connections())
		{
			LOG_WARN("Connection limit reached (%zu), rejecting connection.", net_backend_get_max_connections());
			net_close(fd);
			continue;
		}

		status = plugin_check_ip_early(hub, &ipaddr);
		if (status == st_deny)
		{
			plugin_log_connection_denied(hub, &ipaddr);
			net_close(fd);
			continue;
		}

		plugin_log_connection_accepted(hub, &ipaddr);

		/*
		 * Enable (tuned) TCP keepalive so a dead or half-open client -- one
		 * that completed login and then vanished without a FIN -- is reaped in
		 * a few minutes rather than lingering indefinitely. There is no
		 * post-login idle timeout (idle lurkers are supported by design), so
		 * this is what bounds abandoned connections past the handshake phase.
		 * Best-effort: failure is non-fatal.
		 */
		net_set_keepalive(fd, 1);

		probe = probe_create(hub, fd, &ipaddr);
		if (!probe)
		{
			LOG_ERROR("Unable to create probe after socket accepted. Out of memory?");
			net_close(fd);
			break;
		}
	}
}

