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

#ifdef USE_EPOLL

static int g_epfd = -1;

struct net_connection
{
	int                  sd;
	uint32_t             flags;
	net_connection_cb    callback;
	struct epoll_event   ev;
	struct timeout_evt*  timeout;
};

struct net_connection* net_con_create()
{
	struct net_connection* con = (struct net_connection*) hub_malloc_zero(sizeof(struct net_connection));
	return con;
}

void net_con_destroy(struct net_connection* con)
{
	hub_free(con);
}

void net_con_initialize(struct net_connection* con, int sd, net_connection_cb callback, const void* ptr, int events)
{
	con->sd = sd;
	con->flags = NET_INITIALIZED;
	con->callback = callback;

	con->ev.events = 0;
	con->ev.data.ptr = (void*) ptr;

	net_set_nonblocking(con->sd, 1);
	net_set_nosigpipe(con->sd, 1);

	if (events & NET_EVENT_READ) con->ev.events |= EPOLLIN;
	if (events & NET_EVENT_WRITE) con->ev.events |= EPOLLOUT;
	if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, con->sd, &con->ev) == -1)
	{
		LOG_WARN("epoll_ctl() add failed.");
	}
}

void net_con_reinitialize(struct net_connection* con, net_connection_cb callback, const void* ptr, int events)
{
	con->callback = callback;
	con->ev.data.ptr = (void*) ptr;
	net_con_update(con, events);
}

void net_con_update(struct net_connection* con, int events)
{
	con->ev.events = 0;
	if (events & NET_EVENT_READ) con->ev.events |= EPOLLIN;
	if (events & NET_EVENT_WRITE) con->ev.events |= EPOLLOUT;

	if (epoll_ctl(g_epfd, EPOLL_CTL_MOD, con->sd, &con->ev) == -1)
	{
		LOG_WARN("epoll_ctl() modify failed.");
	}
}

int net_con_close(struct net_connection* con)
{
	if (!(con->flags & NET_INITIALIZED))
		return 0;

	con->flags &= ~NET_INITIALIZED;
	if (epoll_ctl(g_epfd, EPOLL_CTL_DEL, con->sd, &con->ev) == -1)
	{
		LOG_WARN("epoll_ctl() delete failed.");
	}
	return 0;
}


int net_con_get_sd(struct net_connection* con)
{
	return con->sd;
}

void* net_con_get_ptr(struct net_connection* con)
{
	return con->ev.data.ptr;
}

ssize_t net_con_send(struct net_connection* con, const void* buf, size_t len)
{
	int ret = net_send(con->sd, buf, len, UHUB_SEND_SIGNAL);
	if (ret == -1)
	{
		if (net_error() == EWOULDBLOCK || net_error() == EINTR)
			return 0;
		return -1;
	}
	return ret;
}

ssize_t net_con_recv(struct net_connection* con, void* buf, size_t len)
{
	uhub_assert(con);

#ifdef SSL_SUPPORT
	if (!con->ssl)
	{
#endif
		int ret = net_recv(con->sd, buf, len, 0);
#ifdef NETWORK_DUMP_DEBUG
		LOG_PROTO("net_recv: ret=%d", ret);
#endif
		if (ret == -1)
		{
			if (net_error() == EWOULDBLOCK || net_error() == EINTR)
				return 0;
			return -1;
		}
		return ret;
#ifdef SSL_SUPPORT
	}
	else
	{
		int ret = SSL_read(con->ssl, buf, len);
#ifdef NETWORK_DUMP_DEBUG
		LOG_PROTO("net_recv: ret=%d", ret);
#endif
		if (ret > 0)
		{
			con->last_recv = time(0);
			net_con_flag_unset(con, NET_WANT_SSL_WRITE);
		}
		else
		{
			return handle_openssl_error(con, ret);
		}
		return ret;
	}
#endif
}

ssize_t net_con_peek(struct net_connection* con, void* buf, size_t len)
{
	int ret = net_recv(con->sd, buf, len, MSG_PEEK);
	if (ret == -1)
	{
		if (net_error() == EWOULDBLOCK || net_error() == EINTR)
			return 0;
		return -1;
	}
	return ret;
}

void net_con_set_timeout(struct net_connection* con, int seconds)
{
	uhub_assert(con);
	if (!con->timeout)
	{
		con->timeout = hub_malloc(sizeof(struct timeout_evt));
		timeout_evt_initialize(con->timeout, timeout_callback, con);
	}
}


#endif /* USE_EPOLL */