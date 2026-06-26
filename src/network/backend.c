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
#include "util/memory.h"
#include "network/backend.h"
#include "network/network.h"

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
	timeout_queue_initialize(&g_backend->timeout_queue, g_backend->now, TIMEOUT_QUEUE_MAX);
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
/*
 * Event-loop processing-time histogram. We sample the wall-clock span between
 * one backend_poll() returning and the next one being entered: that covers all
 * the work done for a reactor iteration (event dispatch, queued events, deferred
 * writes) and deliberately excludes the blocking poll wait, which would
 * otherwise dominate on an idle hub.
 */
#define LOOP_HIST_NBUCKETS 13
static const double loop_hist_bounds[LOOP_HIST_NBUCKETS] = {
	1e-4, 2.5e-4, 5e-4, 1e-3, 2.5e-3, 5e-3, 1e-2, 2.5e-2, 5e-2, 1e-1, 2.5e-1, 5e-1, 1.0
};
static uint64_t loop_hist_counts[LOOP_HIST_NBUCKETS + 1]; /* last bucket is +Inf */
static double loop_hist_sum;
static uint64_t loop_hist_count;
static struct timespec loop_last_poll_end;
static int loop_timing_active;

static void loop_hist_observe(double seconds)
{
	int i;
	for (i = 0; i < LOOP_HIST_NBUCKETS; i++)
		if (seconds <= loop_hist_bounds[i])
			break;
	loop_hist_counts[i]++;
	loop_hist_sum += seconds;
	loop_hist_count++;
}

void net_backend_get_loop_stats(struct net_loop_stats* out)
{
	out->bounds = loop_hist_bounds;
	out->counts = loop_hist_counts;
	out->n_buckets = LOOP_HIST_NBUCKETS;
	out->sum = loop_hist_sum;
	out->count = loop_hist_count;
}

int net_backend_process()
{
	struct timespec now_ts;
	int res = 0;
	size_t secs;

	/* Close out the previous iteration: the span from the last poll returning to
	   now is the work the reactor did for that iteration (poll wait excluded). */
	clock_gettime(CLOCK_MONOTONIC, &now_ts);
	if (loop_timing_active)
	{
		double work = (double) (now_ts.tv_sec - loop_last_poll_end.tv_sec)
			+ (double) (now_ts.tv_nsec - loop_last_poll_end.tv_nsec) / 1e9;
		if (work >= 0.0)
			loop_hist_observe(work);
	}

	secs = timeout_queue_get_next_timeout(&g_backend->timeout_queue, g_backend->now);

	if (g_backend->common.num)
		res = g_backend->handler.backend_poll(g_backend->data, secs * 1000);

	clock_gettime(CLOCK_MONOTONIC, &loop_last_poll_end);
	loop_timing_active = 1;

	g_backend->now = time(0);
	timeout_queue_process(&g_backend->timeout_queue, g_backend->now);

	if (res == -1)
	{
		LOG_WARN("backend error.");
		return 0;
	}

	// Process pending DNS results
	// net_dns_process();

	g_backend->handler.backend_process(g_backend->data, res);

	net_cleanup_process(g_backend->cleaner);
	return 1;
}

time_t net_get_time()
{
	return g_backend->now;
}

size_t net_backend_get_num_connections()
{
	return g_backend->common.num;
}

size_t net_backend_get_max_connections()
{
	return g_backend->common.max;
}


void net_con_initialize(struct net_connection* con, int sd, net_connection_cb callback, const void* ptr, int events)
{
	g_backend->handler.con_init(g_backend->data, con, sd, callback, ptr);

	net_set_nonblocking(net_con_get_sd(con), 1);
	net_set_nosigpipe(net_con_get_sd(con), 1);

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

	if (con->ssl)
		net_ssl_shutdown(con);

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
	/*
	 * The queue is sized to hold every connection the backend can track
	 * (net_get_max_sockets()), and net_con_close() guards against enqueueing a
	 * connection twice via the NET_CLEANUP flag, so num should never reach max.
	 * Guard anyway: an out-of-bounds write here would corrupt the heap, so on
	 * the should-never-happen overflow we destroy the connection immediately
	 * rather than queueing it.
	 */
	if (handler->num >= handler->max)
	{
		LOG_ERROR("net_cleanup_delayed_free: cleanup queue full (%zu), freeing connection %p immediately", handler->max, (void*) con);
		con->flags |= NET_CLEANUP;
		net_con_destroy(con);
		return;
	}

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

