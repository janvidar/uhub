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

#ifdef USE_SELECT

#include "network/connection.h"
#include "network/common.h"
#include "network/backend.h"

struct net_connection_select
{
	NET_CON_STRUCT_COMMON
};

struct net_backend
{
	size_t num;
	size_t max;
	struct net_connection_select** conns;
	fd_set rfds;
	fd_set wfds;
	time_t now;
	struct timeout_queue timeout_queue;
	struct net_cleanup_handler* cleaner;
};

static struct net_backend* g_backend = 0;

static void net_con_print(const char* prefix, struct net_connection_select* con)
{
	char buf[512];
	int off = snprintf(buf, 512, "%s: net_connection={ sd=%d, flags=%u, callback=%p, ptr=%p, events=%s%s",
		prefix, con->sd, con->flags, con->callback, con->ptr, (con->flags & NET_EVENT_READ ? "R" : ""),(con->flags & NET_EVENT_WRITE ? "W" : ""));
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
	g_backend->num = 0;
	g_backend->max = max;
	g_backend->conns = hub_malloc_zero(sizeof(struct net_connection_select*) * max);
	FD_ZERO(&g_backend->rfds);
	FD_ZERO(&g_backend->wfds);
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
	timeout_queue_shutdown(&g_backend->timeout_queue);
	net_cleanup_shutdown(g_backend->cleaner);
	hub_free(g_backend->conns);
	hub_free(g_backend);
	g_backend = 0;
}

/**
 * Process the network backend.
 */
int net_backend_process()
{
	int n, found, maxfd, res;
	struct timeval tval;
	size_t secs;

	FD_ZERO(&g_backend->rfds);
	FD_ZERO(&g_backend->wfds);

	secs = timeout_queue_get_next_timeout(&g_backend->timeout_queue, g_backend->now);
	tval.tv_sec = secs;
	tval.tv_usec = 0;

	for (n = 0, found = 0; found < g_backend->num && n < g_backend->max; n++)
	{
		struct net_connection_select* con = g_backend->conns[n];
		if (con)
		{
			if (con->flags & NET_EVENT_READ)  FD_SET(con->sd, &g_backend->rfds);
			if (con->flags & NET_EVENT_WRITE) FD_SET(con->sd, &g_backend->wfds);
			found++;
			maxfd = con->sd;
		}
	}

	res = select(maxfd+1, &g_backend->rfds, &g_backend->wfds, 0, &tval);
	g_backend->now = time(0);
	timeout_queue_process(&g_backend->timeout_queue, g_backend->now);

	if (res == -1)
	{
		LOG_WARN("select returned -1");
		return 0;
	}

	for (n = 0, found = 0; found < res && n < (maxfd+1); n++)
	{
		struct net_connection_select* con = g_backend->conns[n];
		if (con)
		{
			int ev = 0;
			if (FD_ISSET(con->sd, &g_backend->rfds)) ev |= NET_EVENT_READ;
			if (FD_ISSET(con->sd, &g_backend->wfds)) ev |= NET_EVENT_WRITE;

			if (ev)
			{
				net_con_callback((struct net_connection*) con, ev);
				found++;
			}
		}
	}

	net_cleanup_process(g_backend->cleaner);
	return 1;
}

struct timeout_queue* net_backend_get_timeout_queue()
{
	if (!g_backend)
		return 0;

	return &g_backend->timeout_queue;
}

struct net_connection* net_con_create()
{
	struct net_connection* con = (struct net_connection*) hub_malloc_zero(sizeof(struct net_connection_select));
	con->sd = -1;
	return con;
}

void net_con_destroy(struct net_connection* con)
{
	hub_free(con);
}

void net_con_initialize(struct net_connection* con_, int sd, net_connection_cb callback, const void* ptr, int events)
{
	struct net_connection_select* con = (struct net_connection_select*) con_;
	con->sd = sd;
	con->flags = events;
	con->callback = callback;
	con->ptr = (void*) ptr;

	net_set_nonblocking(con->sd, 1);
	net_set_nosigpipe(con->sd, 1);

	g_backend->conns[sd] = con;
	g_backend->num++;
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
	con->flags = events;
	net_con_print("MOD", (struct net_connection_select*) con);
}

void net_con_close(struct net_connection* con)
{
	if (con->flags & NET_CLEANUP)
		return;

	if (con->sd != -1)
	{
		g_backend->conns[con->sd] = 0;
		g_backend->num--;
	}

	net_con_clear_timeout(con);

	net_close(con->sd);
	con->sd = -1;

	net_con_print("DEL", (struct net_connection_select*) con);
	net_cleanup_delayed_free(g_backend->cleaner, con);
}

#endif /* USE_SELECT */
