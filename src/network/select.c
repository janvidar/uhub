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
#include "util/log.h"
#include "util/memory.h"
#include "network/network.h"

#ifdef USE_SELECT

#include "network/connection.h"
#include "network/common.h"
#include "network/backend.h"

/* con->sd is a plain int, but a Windows fd_set stores SOCKET (unsigned), so the
   comparisons inside FD_SET()/FD_ISSET() warn about signed/unsigned mismatch.
   Cast to the platform's descriptor type (SOCKET on WinSock, int elsewhere). */
#ifdef WINSOCK
#define UHUB_SD(con) ((SOCKET) (con)->sd)
#else
#define UHUB_SD(con) ((con)->sd)
#endif

struct net_connection_select
{
	NET_CON_STRUCT_COMMON
};

struct net_backend_select
{
	struct net_connection_select** conns;
	fd_set rfds;
	fd_set wfds;
	fd_set xfds;
	int maxfd;
	size_t max;   /* effective fd ceiling: MIN(common->max, FD_SETSIZE) */
	struct net_backend_common* common;
};

static void net_backend_set_handlers(struct net_backend_handler* handler);

const char* net_backend_name_select()
{
	return "select";
}

int net_backend_poll_select(struct net_backend* data, int ms)
{
	int res;
	size_t n, found;
	struct timeval tval;
	struct net_backend_select* backend = (struct net_backend_select*) data;

	tval.tv_sec = ms / 1000;
	tval.tv_usec = (ms % 1000) * 1000;

	FD_ZERO(&backend->rfds);
	FD_ZERO(&backend->wfds);
	FD_ZERO(&backend->xfds);

	backend->maxfd = -1;
	for (n = 0, found = 0; found < backend->common->num && n < backend->max; n++)
	{
		struct net_connection_select* con = backend->conns[n];
		if (con)
		{
			if (con->flags & NET_EVENT_READ)  FD_SET(UHUB_SD(con), &backend->rfds);
			if (con->flags & NET_EVENT_WRITE) FD_SET(UHUB_SD(con), &backend->wfds);
			found++;
			backend->maxfd = con->sd;
		}
	}
	backend->maxfd++;

	res = select(backend->maxfd, &backend->rfds, &backend->wfds, &backend->xfds, &tval);
	if (res == -1)
	{
		int err = net_error();
		if (err == EINTR)
			return 0;

		/* A hard select() error (typically EBADF from a descriptor closed out
		   from under the set) is persistent: hub_event_loop() calls us again
		   immediately, so returning the error unthrottled spins the CPU at
		   100%. Nap briefly to bound the error rate, then report 0 events. */
		LOG_ERROR("select() failed: %d %s", err, net_error_string(err));
		tval.tv_sec = 0;
		tval.tv_usec = 100000;
		select(0, NULL, NULL, NULL, &tval);
		return 0;
	}

	return res;
}

void net_backend_process_select(struct net_backend* data, int res)
{
	int n, found;
	struct net_backend_select* backend = (struct net_backend_select*) data;
	for (n = 0, found = 0; found < res && n < backend->maxfd; n++)
	{
		struct net_connection_select* con = backend->conns[n];
		if (con)
		{
			int ev = 0;
			if (FD_ISSET(UHUB_SD(con), &backend->rfds)) ev |= NET_EVENT_READ;
			if (FD_ISSET(UHUB_SD(con), &backend->wfds)) ev |= NET_EVENT_WRITE;

			if (ev)
			{
				net_con_callback((struct net_connection*) con, ev);
				found++;
			}
		}
	}
}

struct net_connection* net_con_create_select(struct net_backend* data)
{
	(void) data;
	struct net_connection* con = (struct net_connection*) hub_malloc_zero(sizeof(struct net_connection_select));
	con->sd = -1;
	return con;
}

void net_con_initialize_select(struct net_backend* data, struct net_connection* con_, int sd, net_connection_cb callback, const void* ptr)
{
	(void) data;
	struct net_connection_select* con = (struct net_connection_select*) con_;
	con->sd = sd;
	con->flags = 0;
	con->callback = callback;
	con->ptr = (void*) ptr;
}

void net_con_backend_add_select(struct net_backend* data, struct net_connection* con, int events)
{
	struct net_backend_select* backend = (struct net_backend_select*) data;

	/* Backstop: conns[] is indexed by fd value, and select() cannot address a
	   descriptor at or above FD_SETSIZE regardless of how many sockets the
	   process may otherwise open. backend->max folds both limits together;
	   refuse anything outside it rather than FD_SET() past the fd_set bitmap or
	   index conns[] out of bounds. */
	if (con->sd < 0 || (size_t) con->sd >= backend->max)
	{
		LOG_ERROR("net_con_backend_add_select: fd %d out of range (max %zu)", con->sd, backend->max);
		return;
	}

	backend->conns[con->sd] = (struct net_connection_select*) con;
	con->flags |= (events & (NET_EVENT_READ | NET_EVENT_WRITE));
}


void net_con_backend_mod_select(struct net_backend* data, struct net_connection* con, int events)
{
	(void) data;
	/* events is the full desired interest set, so replace the READ/WRITE bits
	   rather than OR them in. Accumulating would leave NET_EVENT_WRITE latched
	   after the send queue drains, making select() report the socket writable
	   every pass and re-fire the (empty) write handler -- a 100% CPU spin. This
	   mirrors the epoll (mask replace) and kqueue (per-call rebuild) backends. */
	con->flags = (con->flags & ~(NET_EVENT_READ | NET_EVENT_WRITE))
	           | (events & (NET_EVENT_READ | NET_EVENT_WRITE));
}

void net_con_backend_del_select(struct net_backend* data, struct net_connection* con)
{
	struct net_backend_select* backend = (struct net_backend_select*) data;
	/* Mirror the add-time guard: conns[] is indexed by fd value, so an fd that
	   add rejected (>= max) or a connection closed before it was ever given a
	   descriptor (sd == -1) must not index the array, or we corrupt the heap. */
	if (con->sd < 0 || (size_t) con->sd >= backend->max)
		return;
	backend->conns[con->sd] = 0;
}

void net_backend_shutdown_select(struct net_backend* data)
{
	struct net_backend_select* backend = (struct net_backend_select*) data;
	hub_free(backend->conns);
	hub_free(backend);
}

struct net_backend* net_backend_init_select(struct net_backend_handler* handler, struct net_backend_common* common)
{
	struct net_backend_select* backend;

	if (getenv("EVENT_NOSELECT"))
		return 0;

	backend = hub_malloc_zero(sizeof(struct net_backend_select));
	FD_ZERO(&backend->rfds);
	FD_ZERO(&backend->wfds);
	FD_ZERO(&backend->xfds);
	backend->common = common;

	/* select() can only watch descriptors below FD_SETSIZE, so the effective
	   ceiling is the smaller of that and the configured socket limit. Both the
	   conns[] allocation and the add-time guard use this bound. */
	backend->max = common->max < (size_t) FD_SETSIZE ? common->max : (size_t) FD_SETSIZE;
	if (common->max > backend->max)
		LOG_WARN("select backend: %zu sockets requested, but select() caps concurrency at FD_SETSIZE (%d); bounding accepts to %zu.",
			common->max, FD_SETSIZE, backend->max);

	/* Publish the cap as the backend-wide connection limit so the accept path
	   (net_backend_get_max_connections()) refuses connections beyond what
	   select() can watch, instead of accepting fds the add path would reject. */
	common->max = backend->max;

	backend->conns = hub_malloc_zero(sizeof(struct net_connection_select*) * backend->max);
	net_backend_set_handlers(handler);
	return (struct net_backend*) backend;
}

static void net_backend_set_handlers(struct net_backend_handler* handler)
{
	handler->backend_name = net_backend_name_select;
	handler->backend_poll = net_backend_poll_select;
	handler->backend_process = net_backend_process_select;
	handler->backend_shutdown = net_backend_shutdown_select;
	handler->con_create = net_con_create_select;
	handler->con_init = net_con_initialize_select;
	handler->con_add = net_con_backend_add_select;
	handler->con_mod = net_con_backend_mod_select;
	handler->con_del = net_con_backend_del_select;
}

#endif /* USE_SELECT */
