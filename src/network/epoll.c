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

#include "uhub.h"

#ifdef USE_EPOLL

#include "network/connection.h"
#include "network/common.h"
#include "network/backend.h"

#define EPOLL_EVBUFFER 512

struct net_connection
{
	int                  sd;
	uint32_t             flags;
	net_connection_cb    callback;
	void*                ptr;
	struct epoll_event   ev;
	struct timeout_evt*  timeout;
#ifdef SSL_SUPPORT
	SSL*                 ssl;
	size_t               write_len; /** Length of last SSL_write(), only used if flags is NET_WANT_SSL_READ. */
#endif
};

struct net_backend
{
	int epfd;
	size_t num;
	size_t max;
	struct net_connection** conns;
	struct epoll_event events[EPOLL_EVBUFFER];
	time_t now;
	struct timeout_queue timeout_queue;
};

static struct net_backend* g_backend = 0;

static void net_con_print(const char* prefix, struct net_connection* con)
{
	char buf[512];
	int off = snprintf(buf, 512, "%s: net_connection={ sd=%d, flags=%u, callback=%p, ptr=%p, ev={ events=%s%s, data.ptr=%p }",
		prefix, con->sd, con->flags, con->callback, con->ptr, (con->ev.events & EPOLLIN ? "R" : ""),(con->ev.events & EPOLLOUT ? "W" : "") , con->ev.data.ptr);
	if (con->timeout)
	{
		sprintf(buf + off, ", timeout={ %d seconds left }", (int) (con->timeout->timestamp - g_backend->now));
	}
	else
	{
		sprintf(buf + off, ", timeout=NULL");
	}
	LOG_TRACE(buf);
}

/**
 * Initialize the network backend.
 * Returns 1 on success, or 0 on failure.
 */
int net_backend_initialize()
{
	size_t max = net_get_max_sockets();
	g_backend = hub_malloc(sizeof(struct net_backend));
	g_backend->epfd = epoll_create(max);
	if (g_backend->epfd == -1)
	{
		LOG_WARN("Unable to create epoll socket.");
		return 0;
	}
	
	g_backend->num = 0;
	g_backend->max = max;
	g_backend->conns = hub_malloc_zero(sizeof(struct net_connection*) * max);
	memset(g_backend->events, 0, sizeof(g_backend->events));

	g_backend->now = time(0);
	timeout_queue_initialize(&g_backend->timeout_queue, g_backend->now, 600); /* look max 10 minutes into the future. */
	return 1;
}

/**
 * Shutdown the network connection backend.
 */
void net_backend_shutdown()
{
	close(g_backend->epfd);
	hub_free(g_backend->conns);
	hub_free(g_backend);
}

/**
 * Process the network backend.
 */
int net_backend_process()
{
	int n;
	LOG_TRACE("epoll_wait: fd=%d, events=%x, max=%zu", g_backend->epfd, g_backend->events, MIN(g_backend->num, EPOLL_EVBUFFER));
	int res = epoll_wait(g_backend->epfd, g_backend->events, MIN(g_backend->num, EPOLL_EVBUFFER), 1000);
	if (res == -1)
	{
		LOG_WARN("epoll_wait returned -1");
		return 0;
	}

	for (n = 0; n < res; n++)
	{
		struct net_connection* con = (struct net_connection*) g_backend->events[n].data.ptr;
		int ev = 0;
		if (g_backend->events[n].events & EPOLLIN)  ev |= NET_EVENT_READ;
		if (g_backend->events[n].events & EPOLLOUT) ev |= NET_EVENT_WRITE;
		con->callback(con, ev, con->ptr);
	}
	return 1;
}


struct net_connection* net_con_create()
{
	struct net_connection* con = (struct net_connection*) hub_malloc_zero(sizeof(struct net_connection));
	con->sd = -1;
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
	con->ptr = (void*) ptr;
	con->ev.data.ptr = (void*) con;

	net_set_nonblocking(con->sd, 1);
	net_set_nosigpipe(con->sd, 1);

	if (events & NET_EVENT_READ) con->ev.events |= EPOLLIN;
	if (events & NET_EVENT_WRITE) con->ev.events |= EPOLLOUT;

	g_backend->conns[sd] = con;
	g_backend->num++;

	if (epoll_ctl(g_backend->epfd, EPOLL_CTL_ADD, con->sd, &con->ev) == -1)
	{
		LOG_TRACE("epoll_ctl() add failed.");
	}

	net_con_print("ADD", con);
}

void net_con_reinitialize(struct net_connection* con, net_connection_cb callback, const void* ptr, int events)
{
	con->callback = callback;
	con->ptr = (void*) ptr;
	net_con_update(con, events);
}

void net_con_update(struct net_connection* con, int events)
{
	con->ev.events = 0;
	if (events & NET_EVENT_READ) con->ev.events |= EPOLLIN;
	if (events & NET_EVENT_WRITE) con->ev.events |= EPOLLOUT;

#ifdef SSL_SUPPORT
	if (events & NET_WANT_SSL_WRITE)
		con->flags |= NET_WANT_SSL_WRITE;
	else
		con->flags &= ~NET_WANT_SSL_WRITE;

	if (events & NET_WANT_SSL_READ)
		con->flags |= NET_WANT_SSL_READ;
	else
		con->flags &= ~NET_WANT_SSL_READ;

	if (events & NET_WANT_SSL_ACCEPT)
		con->flags |= NET_WANT_SSL_ACCEPT;
	else
		con->flags &= ~NET_WANT_SSL_ACCEPT;

	if (events & NET_WANT_SSL_CONNECT)
		con->flags |= NET_WANT_SSL_CONNECT;
	else
		con->flags &= ~NET_WANT_SSL_CONNECT;
#endif /* SSL_SUPPORT */

	if (epoll_ctl(g_backend->epfd, EPOLL_CTL_MOD, con->sd, &con->ev) == -1)
	{
		LOG_TRACE("epoll_ctl() modify failed.");
	}
	net_con_print("MOD", con);
}

int net_con_close(struct net_connection* con)
{
	if (!(con->flags & NET_INITIALIZED))
		return 0;

	con->flags &= ~NET_INITIALIZED;

	if (con->sd != -1)
	{
		g_backend->conns[con->sd] = 0;
		g_backend->num--;
	}

	if (timeout_evt_is_scheduled(con->timeout))
	{
		timeout_queue_remove(&g_backend->timeout_queue, con->timeout);
		hub_free(con->timeout);
		con->timeout = 0;
	}

	if (epoll_ctl(g_backend->epfd, EPOLL_CTL_DEL, con->sd, &con->ev) == -1)
	{
		LOG_WARN("epoll_ctl() delete failed.");
	}
	net_con_print("DEL", con);
	return 0;
}

#ifdef SSL_SUPPORT
int net_con_is_ssl(struct net_connection* con)
{

	return con->ssl != 0;
}

SSL* net_con_get_ssl(struct net_connection* con)
{
	return con->ssl;
}

void net_con_set_ssl(struct net_connection* con, SSL* ssl)
{
	con->ssl = ssl;
}
#endif

int net_con_get_sd(struct net_connection* con)
{
	return con->sd;
}

void* net_con_get_ptr(struct net_connection* con)
{
	return con->ptr;
}


void timeout_evt_initialize(struct timeout_evt*, timeout_evt_cb, void* ptr);
void timeout_evt_reset(struct timeout_evt*);
int  timeout_evt_is_scheduled(struct timeout_evt*);

static void timeout_callback(struct timeout_evt* evt)
{
	struct net_connection* con = (struct net_connection*) evt->ptr;
	con->callback(con, NET_EVENT_TIMEOUT, con->ptr);
}


void net_con_set_timeout(struct net_connection* con, int seconds)
{
	if (!con->timeout)
	{
		con->timeout = hub_malloc_zero(sizeof(struct timeout_evt));
		timeout_evt_initialize(con->timeout, timeout_callback, con);
		timeout_queue_insert(&g_backend->timeout_queue, con->timeout, seconds);
	}
	else
	{
		timeout_queue_reschedule(&g_backend->timeout_queue, con->timeout, seconds);
	}
}

void net_con_clear_timeout(struct net_connection* con)
{
	if (con->timeout && timeout_evt_is_scheduled(con->timeout))
	{
		timeout_queue_remove(&g_backend->timeout_queue, con->timeout);
		hub_free(con->timeout);
		con->timeout = 0;
	}
}

#endif /* USE_EPOLL */
