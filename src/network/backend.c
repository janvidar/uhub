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

#include "uhub.h"

#include "network/connection.h"

struct net_backend;
struct net_connection;

struct net_cleanup_handler
{
	size_t num;
	size_t max;
	struct net_connection** queue;
};

struct net_backend
{
	struct net_backend_common common;
	time_t now; /* the time now (used for timeout handling) */
	struct timeout_queue timeout_queue; /* used for timeout handling */
	struct net_cleanup_handler* cleaner; /* handler to cleanup connections at a safe point */
	struct net_backend_handler handler; /* backend event handler */
	struct net_backend* data; /* backend specific data */
};

static struct net_backend* g_backend;


#ifdef USE_EPOLL
extern struct net_backend* net_backend_init_epoll(struct net_backend_handler*, struct net_backend_common*);
#endif

#ifdef USE_KQUEUE
extern struct net_backend* net_backend_init_kqueue(struct net_backend_handler*, struct net_backend_common*);
#endif

#ifdef USE_SELECT
extern struct net_backend* net_backend_init_select(struct net_backend_handler*, struct net_backend_common*);
#endif

static net_backend_init_t net_backend_init_funcs[] = {
#ifdef USE_EPOLL
	net_backend_init_epoll,
#endif
#ifdef USE_KQUEUE
	net_backend_init_kqueue,
#endif
#ifdef USE_SELECT
	net_backend_init_select,
#endif
	0
};

int net_backend_init()
{
	size_t n;
	g_backend = (struct net_backend*) hub_malloc_zero(sizeof(struct net_backend));
	g_backend->common.num = 0;
	g_backend->common.max = net_get_max_sockets();
	g_backend->now = time(0);
	timeout_queue_initialize(&g_backend->timeout_queue, g_backend->now, 120); /* FIXME: max 120 secs! */
	g_backend->cleaner = net_cleanup_initialize(g_backend->common.max);

	for (n = 0; net_backend_init_funcs[n]; n++)
	{
		g_backend->data = net_backend_init_funcs[n](&g_backend->handler, &g_backend->common);
		if (g_backend->data)
		{
			LOG_DEBUG("Initialized %s network backend.", g_backend->handler.backend_name());
			return 1;
		}
	}
	LOG_FATAL("Unable to find a suitable network backend");
	return 0;
}

void net_backend_shutdown()
{
	g_backend->handler.backend_shutdown(g_backend->data);
	timeout_queue_shutdown(&g_backend->timeout_queue);
	net_cleanup_shutdown(g_backend->cleaner);
	hub_free(g_backend);
	g_backend = 0;
}


void net_backend_update(struct net_connection* con, int events)
{
	g_backend->handler.con_mod(g_backend->data, con, events);
}

struct net_connection* net_con_create()
{
	return g_backend->handler.con_create(g_backend->data);
}

struct timeout_queue* net_backend_get_timeout_queue()
{
	if (!g_backend)
		return 0;
	return &g_backend->timeout_queue;
}


/**
 * Process the network backend.
 */
int net_backend_process()
{
	int res = 0;
	size_t secs = timeout_queue_get_next_timeout(&g_backend->timeout_queue, g_backend->now);

	if (g_backend->common.num)
		res = g_backend->handler.backend_poll(g_backend->data, secs * 1000);

	g_backend->now = time(0);
	timeout_queue_process(&g_backend->timeout_queue, g_backend->now);

	if (res == -1)
	{
		LOG_WARN("backend error.");
		return 0;
	}

	// Process pending DNS results
	net_dns_process();

	g_backend->handler.backend_process(g_backend->data, res);

	net_cleanup_process(g_backend->cleaner);
	return 1;
}

time_t net_get_time()
{
	return g_backend->now;
}


void net_con_initialize(struct net_connection* con, int sd, net_connection_cb callback, const void* ptr, int events)
{
	g_backend->handler.con_init(g_backend->data, con, sd, callback, ptr);

	net_set_nonblocking(con->sd, 1);
	net_set_nosigpipe(con->sd, 1);

	g_backend->handler.con_add(g_backend->data, con, events);
	g_backend->common.num++;
}

void net_con_close(struct net_connection* con)
{
	if (con->flags & NET_CLEANUP)
		return;

	g_backend->common.num--;
	net_con_clear_timeout(con);

	g_backend->handler.con_del(g_backend->data, con);

#ifdef SSL_SUPPORT
	if (con->ssl)
		net_ssl_shutdown(con);
#endif /* SSL_SUPPORT */

	net_close(con->sd);
	con->sd = -1;

	net_cleanup_delayed_free(g_backend->cleaner, con);
}

struct net_cleanup_handler* net_cleanup_initialize(size_t max)
{
	struct net_cleanup_handler* handler = (struct net_cleanup_handler*) hub_malloc(sizeof(struct net_cleanup_handler));
	handler->num = 0;
	handler->max = max;
	handler->queue = hub_malloc_zero(sizeof(struct net_connection*) * max);
	return handler;
}

void net_cleanup_shutdown(struct net_cleanup_handler* handler)
{
	net_cleanup_process(handler);
	hub_free(handler->queue);
	hub_free(handler);
}

void net_cleanup_delayed_free(struct net_cleanup_handler* handler, struct net_connection* con)
{
	handler->queue[handler->num++] = con;
	con->flags |= NET_CLEANUP;
}

void net_cleanup_process(struct net_cleanup_handler* handler)
{
	size_t n;
	for (n = 0; n < handler->num; n++)
	{
		struct net_connection* con = handler->queue[n];
		LOG_TRACE("net_cleanup_process: free: %p", con);
		net_con_destroy(con);
	}
	handler->num = 0;
}

