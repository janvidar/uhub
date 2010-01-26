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

#ifdef USE_KQUEUE

#include "network/connection.h"
#include "network/common.h"
#include "network/backend.h"

#define KQUEUE_EVBUFFER 512

struct net_connection_kqueue
{
	NET_CON_STRUCT_COMMON
	struct kevent ev;
};

struct net_backend
{
	int kqfd;
	size_t num;
	size_t max;
	struct net_connection_epoll** conns;
	struct kevent** changes;
	size_t nchanges;
	struct kevent events[KQUEUE_EVBUFFER];
	time_t now;
	struct timeout_queue timeout_queue;
	struct net_cleanup_handler* cleaner;
};

static struct net_backend* g_backend = 0;


/**
 * Initialize the network backend.
 * Returns 1 on success, or 0 on failure.
 */
int net_backend_initialize()
{
	g_backend = hub_malloc_zero(sizeof(struct net_backend));
	g_backend->kqfd = kqueue();
	if (g_backend->kqfd == -1)
	{
		LOG_WARN("Unable to create epoll socket.");
		return 0;
	}

	size_t max = net_get_max_sockets();
	g_backend->max = max;
	g_backend->conns = hub_malloc_zero(sizeof(struct net_connection_kqueue*) * max);
	g_backend->changes = hub_malloc_zero(sizeof(struct kevent*) * max);

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
	close(g_backend->kqfd);
	timeout_queue_shutdown(&g_backend->timeout_queue);
	net_cleanup_shutdown(g_backend->cleaner);
	hub_free(g_backend->conns);
	hub_free(g_backend->changes);
	hub_free(g_backend);
}

/**
 * Process the network backend.
 */
int net_backend_process()
{

}

struct timeout_queue* net_backend_get_timeout_queue()
{
	return &g_backend->timeout_queue;
}

struct net_connection* net_con_create()
{
	struct net_connection* con = (struct net_connection*) hub_malloc_zero(sizeof(struct net_connection_kqueue));
	con->sd = -1;
	return con;
}

void net_con_destroy(struct net_connection* con)
{
	hub_free(con);
}

void net_con_initialize(struct net_connection* con_, int sd, net_connection_cb callback, const void* ptr, int events)
{
	short filter = 0;
	struct net_connection_kqueue* con = (struct net_connection_kqueue*) con_;
	con->sd = sd;
	con->flags = 0;
	con->callback = callback;
	con->ev.events = 0;
	con->ptr = (void*) ptr;

	net_set_nonblocking(con->sd, 1);
	net_set_nosigpipe(con->sd, 1);

	if  (events & NET_EVENT_READ)  filter |= EVFILT_READ;
	if  (events & NET_EVENT_WRITE) filter |= EVFILT_READ;

	EV_SET(&con->ev, sd, filter, EV_ADD, 0, 0, con);

	g_backend->conns[sd] = con;
	g_backend->num++;
}

void net_con_reinitialize(struct net_connection* con, net_connection_cb callback, const void* ptr, int events)
{
	con->callback = callback;
	con->ptr = (void*) ptr;
	net_con_update(con, events);
}

void net_con_update(struct net_connection* con_, int events)
{
	short filter = 0;
	struct net_connection_kqueue* con = (struct net_connection_kqueue*) con_;

	if  (events & NET_EVENT_READ)  filter |= EVFILT_READ;
	if  (events & NET_EVENT_WRITE) filter |= EVFILT_READ;

	if (filter == con->ev.filter)
		return;

	EV_SET(&con->ev, sd, filter, EV_ADD, 0, 0, con);
}

void net_con_close(struct net_connection* con_)
{
	struct net_connection_epoll* con = (struct net_connection_kqueue*) con_;
	if (con->flags & NET_CLEANUP)
		return;

	if (con->sd != -1)
	{
		g_backend->conns[con->sd] = 0;
		g_backend->num--;
	}

	net_con_clear_timeout(con_);

	EV_SET(&con->ev, sd, 0, EV_DELETE, 0, 0, 0);

	net_close(con->sd);
	con->sd = -1;

	net_cleanup_delayed_free(g_backend->cleaner, con_);
}

#endif /* USE_KQUEUE */
