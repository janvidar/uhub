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

struct net_backend_kqueue
{
	int kqfd;
	struct net_connection_kqueue** conns;
	struct kevent** changes;
	size_t nchanges;
	struct kevent events[KQUEUE_EVBUFFER];
	struct net_backend_common* common;
};

static void net_backend_set_handlers(struct net_backend_handler* handler);

const char* net_backend_name_kqueue()
{
	return "kqueue";
}

int net_backend_poll_kqueue(struct net_backend* data, int ms)
{
	int res;
	struct timespec tspec = { 0, };
	struct net_backend_kqueue* backend = (struct net_backend_kqueue*) data;

	tspec.tv_sec = (ms / 1000);
	tspec.tv_nsec = ((ms % 1000) * 1000000); /* FIXME: correct? */

	res = kevent(backend->kqfd, *backend->changes, backend->nchanges, backend->events, KQUEUE_EVBUFFER, &tspec);
	backend->nchanges = 0;

	if (res == -1 && errno == EINTR)
		return 0;
	return res;
}

void net_backend_process_kqueue(struct net_backend* data, int res)
{
	int n;
	struct net_backend_kqueue* backend = (struct net_backend_kqueue*) data;

	for (n = 0; n < res; n++)
	{
		struct net_connection_kqueue* con = (struct net_connection_kqueue*) backend->events[n].udata;
		int ev = 0;
		if (backend->events[n].filter & EVFILT_READ)  ev |= NET_EVENT_READ;
		if (backend->events[n].filter & EVFILT_WRITE) ev |= NET_EVENT_WRITE;
		net_con_callback((struct net_connection*) con, ev);
	}
}

struct net_connection* net_con_create_kqueue(struct net_backend* data)
{
	struct net_connection* con = (struct net_connection*) hub_malloc_zero(sizeof(struct net_connection_kqueue));
	con->sd = -1;
	return con;
}

void net_con_initialize_kqueue(struct net_backend* data, struct net_connection* con_, int sd, net_connection_cb callback, const void* ptr)
{
	struct net_connection_kqueue* con = (struct net_connection_kqueue*) con_;
	con->sd = sd;
	con->flags = 0;
	con->callback = callback;
	con->ptr = (void*) ptr;
}

void net_con_backend_add_kqueue(struct net_backend* data, struct net_connection* con_, int events)
{
	short filter = 0;
	struct net_backend_kqueue* backend = (struct net_backend_kqueue*) data;
	struct net_connection_kqueue* con = (struct net_connection_kqueue*) con_;
	if  (events & NET_EVENT_READ)  filter |= EVFILT_READ;
	if  (events & NET_EVENT_WRITE) filter |= EVFILT_READ;
	EV_SET(&con->ev, con->sd, filter, EV_ADD, 0, 0, con);
	backend->changes[backend->nchanges++] = &con->ev;
	backend->conns[con->sd] = con;
}

void net_con_backend_mod_kqueue(struct net_backend* data, struct net_connection* con_, int events)
{
	short filter = 0;
	struct net_backend_kqueue* backend = (struct net_backend_kqueue*) data;
	struct net_connection_kqueue* con = (struct net_connection_kqueue*) con_;

	if  (events & NET_EVENT_READ)  filter |= EVFILT_READ;
	if  (events & NET_EVENT_WRITE) filter |= EVFILT_READ;

	if (filter == con->ev.filter)
		return;

	EV_SET(&con->ev, con->sd, filter, EV_ADD, 0, 0, con);
	backend->changes[backend->nchanges++] = &con->ev;
}

void net_con_backend_del_kqueue(struct net_backend* data, struct net_connection* con_)
{
	struct net_backend_kqueue* backend = (struct net_backend_kqueue*) data;
	struct net_connection_kqueue* con = (struct net_connection_kqueue*) con_;

	backend->conns[con->sd] = 0;

	/* No need to remove it from the kqueue filter, the kqueue man page says
	   it is automatically removed when the descriptor is closed. */
}

void net_backend_shutdown_kqueue(struct net_backend* data)
{
	struct net_backend_kqueue* backend = (struct net_backend_kqueue*) data;
	close(backend->kqfd);
	hub_free(backend->conns);
	hub_free(backend->changes);
	hub_free(backend);
}

struct net_backend* net_backend_init_kqueue(struct net_backend_handler* handler, struct net_backend_common* common)
{
	struct net_backend_kqueue* backend;

	if (getenv("EVENT_NOKQUEUE"))
		return 0;

	backend = hub_malloc_zero(sizeof(struct net_backend_kqueue));
	backend->kqfd = kqueue();
	if (backend->kqfd == -1)
	{
		LOG_WARN("Unable to create kqueue socket.");
		return 0;
	}

	backend->conns = hub_malloc_zero(sizeof(struct net_connection_kqueue*) * common->max);
	backend->conns = hub_malloc_zero(sizeof(struct net_connection_kqueue*) * common->max);
	backend->changes = hub_malloc_zero(sizeof(struct kevent*) * common->max);
	backend->common = common;

	net_backend_set_handlers(handler);
	return (struct net_backend*) backend;
}

static void net_backend_set_handlers(struct net_backend_handler* handler)
{
	handler->backend_name = net_backend_name_kqueue;
	handler->backend_poll = net_backend_poll_kqueue;
	handler->backend_process = net_backend_process_kqueue;
	handler->backend_shutdown = net_backend_shutdown_kqueue;
	handler->con_create = net_con_create_kqueue;
	handler->con_init = net_con_initialize_kqueue;
	handler->con_add = net_con_backend_add_kqueue;
	handler->con_mod = net_con_backend_mod_kqueue;
	handler->con_del = net_con_backend_del_kqueue;
}

#endif /* USE_KQUEUE */
