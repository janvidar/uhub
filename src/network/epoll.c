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

struct net_connection_epoll
{
	NET_CON_STRUCT_COMMON
	struct epoll_event ev;
};

struct net_backend
{
	int epfd;
	size_t num;
	size_t max;
	struct net_connection_epoll** conns;
	struct epoll_event events[EPOLL_EVBUFFER];
	time_t now;
	struct timeout_queue timeout_queue;
	struct net_cleanup_handler* cleaner;
};

static struct net_backend* g_backend = 0;

static void net_con_print(const char* prefix, struct net_connection_epoll* con)
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
	g_backend->conns = hub_malloc_zero(sizeof(struct net_connection_epoll*) * max);
	memset(g_backend->events, 0, sizeof(g_backend->events));

	g_backend->now = time(0);
	timeout_queue_initialize(&g_backend->timeout_queue, g_backend->now, 600); /* look max 10 minutes into the future. */
	g_backend->cleaner = net_cleanup_initialize(max);
	return 1;
}

/**
 * Shutdown the network connection backend.
 */
void net_backend_shutdown()
{
	close(g_backend->epfd);
	timeout_queue_shutdown(&g_backend->timeout_queue);
	net_cleanup_shutdown(g_backend->cleaner);
	hub_free(g_backend->conns);
	hub_free(g_backend);
}

/**
 * Process the network backend.
 */
int net_backend_process()
{
	int n;
	size_t secs = timeout_queue_get_next_timeout(&g_backend->timeout_queue, g_backend->now);
	LOG_TRACE("epoll_wait: fd=%d, events=%x, max=%zu, seconds=%d", g_backend->epfd, g_backend->events, MIN(g_backend->num, EPOLL_EVBUFFER), (int) secs);
	int res = epoll_wait(g_backend->epfd, g_backend->events, MIN(g_backend->num, EPOLL_EVBUFFER), secs * 1000);
	if (res == -1)
	{
		LOG_WARN("epoll_wait returned -1");
		return 0;
	}

	g_backend->now = time(0);
	timeout_queue_process(&g_backend->timeout_queue, g_backend->now);

	for (n = 0; n < res; n++)
	{
		struct net_connection_epoll* con = (struct net_connection_epoll*) g_backend->events[n].data.ptr;
		int ev = 0;
		if (g_backend->events[n].events & EPOLLIN)  ev |= NET_EVENT_READ;
		if (g_backend->events[n].events & EPOLLOUT) ev |= NET_EVENT_WRITE;
		net_con_callback((struct net_connection*) con, ev);
	}

	net_cleanup_process(g_backend->cleaner);
	return 1;
}

struct timeout_queue* net_backend_get_timeout_queue()
{
	return &g_backend->timeout_queue;
}

struct net_connection* net_con_create()
{
	struct net_connection* con = (struct net_connection*) hub_malloc_zero(sizeof(struct net_connection_epoll));
	con->sd = -1;
	return con;
}

void net_con_destroy(struct net_connection* con)
{
	hub_free(con);
}

void net_con_initialize(struct net_connection* con_, int sd, net_connection_cb callback, const void* ptr, int events)
{
	struct net_connection_epoll* con = (struct net_connection_epoll*) con_;
	con->sd = sd;
	con->flags = 0;
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

void net_con_update(struct net_connection* con_, int events)
{
	struct net_connection_epoll* con = (struct net_connection_epoll*) con_;
	int newev = 0;
	if (events & NET_EVENT_READ)  newev |= EPOLLIN;
	if (events & NET_EVENT_WRITE) newev |= EPOLLOUT;

	if (newev == con->ev.events)
		return;

	con->ev.events = newev;
	if (epoll_ctl(g_backend->epfd, EPOLL_CTL_MOD, con->sd, &con->ev) == -1)
	{
		LOG_TRACE("epoll_ctl() modify failed.");
	}
	net_con_print("MOD", con);
}

void net_con_close(struct net_connection* con_)
{
	struct net_connection_epoll* con = (struct net_connection_epoll*) con_;
	if (con->flags & NET_CLEANUP)
		return;

	if (con->sd != -1)
	{
		g_backend->conns[con->sd] = 0;
		g_backend->num--;
	}

	net_con_clear_timeout(con_);

	if (epoll_ctl(g_backend->epfd, EPOLL_CTL_DEL, con->sd, &con->ev) == -1)
	{
		LOG_WARN("epoll_ctl() delete failed.");
	}

	net_close(con->sd);
	con->sd = -1;

	net_con_print("DEL", con);
	net_cleanup_delayed_free(g_backend->cleaner, con_);
}

#endif /* USE_EPOLL */
