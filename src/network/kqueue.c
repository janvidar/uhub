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

#ifdef USE_KQUEUE

#include "network/connection.h"
#include "network/common.h"
#include "network/backend.h"

#define KQUEUE_EVBUFFER 512

struct net_connection_kqueue
{
	NET_CON_STRUCT_COMMON
	struct kevent ev_r;
	struct kevent ev_w;
	int change;
};

struct net_backend_kqueue
{
	int kqfd;
	struct net_connection_kqueue** conns;
	struct kevent* changes;
	int* change_list;
	size_t change_list_len;
	struct kevent events[KQUEUE_EVBUFFER];
	struct net_backend_common* common;
};

#define CHANGE_ACTION_ADD       0x0001
#define CHANGE_ACTION_MOD       0x0002
#define CHANGE_ACTION_DEL       0x0004
#define CHANGE_OP_WANT_READ     0x0100
#define CHANGE_OP_WANT_WRITE    0x0200

static void net_backend_set_handlers(struct net_backend_handler* handler);
static void add_change(struct net_backend_kqueue* backend, struct net_connection_kqueue* con, int actions);
static size_t create_change_list(struct net_backend_kqueue* backend);

const char* net_backend_name_kqueue()
{
	return "kqueue";
}

int net_backend_poll_kqueue(struct net_backend* data, int ms)
{
	int res;
	struct timespec tspec = { 0, };
	struct net_backend_kqueue* backend = (struct net_backend_kqueue*) data;
	size_t changes;

	tspec.tv_sec = (ms / 1000);
	tspec.tv_nsec = ((ms % 1000) * 1000000);

	changes = create_change_list(backend);
	res = kevent(backend->kqfd, backend->changes, changes, backend->events, KQUEUE_EVBUFFER, &tspec);

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
		if (con && con->sd >= 0 && backend->conns[con->sd])
		{
			int ev = 0;
			if (backend->events[n].filter == EVFILT_READ) ev = NET_EVENT_READ;
			else if (backend->events[n].filter == EVFILT_WRITE) ev = NET_EVENT_WRITE;
			net_con_callback((struct net_connection*) con, ev);
		}
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
	struct net_backend_kqueue* backend = (struct net_backend_kqueue*) data;
	struct net_connection_kqueue* con = (struct net_connection_kqueue*) con_;
	int operation;

	backend->conns[con->sd] = con;

	operation = CHANGE_ACTION_ADD;

	if (events & NET_EVENT_READ)
	  operation |= CHANGE_OP_WANT_READ;

	if (events & NET_EVENT_WRITE)
	  operation |= CHANGE_OP_WANT_WRITE;

	add_change(backend, con, operation);
}

void net_con_backend_mod_kqueue(struct net_backend* data, struct net_connection* con_, int events)
{
	struct net_backend_kqueue* backend = (struct net_backend_kqueue*) data;
	struct net_connection_kqueue* con = (struct net_connection_kqueue*) con_;

	int operation = CHANGE_ACTION_ADD;

	if (events & NET_EVENT_READ)
	  operation |= CHANGE_OP_WANT_READ;

	if (events & NET_EVENT_WRITE)
	  operation |= CHANGE_OP_WANT_WRITE;

	add_change(backend, con, operation);
}

void net_con_backend_del_kqueue(struct net_backend* data, struct net_connection* con_)
{
	struct net_backend_kqueue* backend = (struct net_backend_kqueue*) data;
	struct net_connection_kqueue* con = (struct net_connection_kqueue*) con_;

	/* No need to remove it from the kqueue filter, the kqueue man page says
	   it is automatically removed when the descriptor is closed... */
	add_change(backend, con, CHANGE_ACTION_DEL);

	// Unmap the socket descriptor.
	backend->conns[con->sd] = 0;
}

void net_backend_shutdown_kqueue(struct net_backend* data)
{
	struct net_backend_kqueue* backend = (struct net_backend_kqueue*) data;
	close(backend->kqfd);
	hub_free(backend->conns);
	hub_free(backend->changes);
	hub_free(backend->change_list);
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
	backend->changes = hub_malloc_zero(sizeof(struct kevent) * common->max * 2);
	backend->change_list = hub_malloc_zero(sizeof(int) * common->max);
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

static void add_change(struct net_backend_kqueue* backend, struct net_connection_kqueue* con, int actions)
{
	if (actions && !con->change)
	{
		backend->change_list[backend->change_list_len++] = con->sd;
		con->change = actions;
	}
}

static size_t create_change_list(struct net_backend_kqueue* backend)
{
	size_t n = 0;
	size_t changes = 0;
	int sd;
	struct net_connection_kqueue* con;
	unsigned short flags_r = 0;
	unsigned short flags_w = 0;

	for (; n < backend->change_list_len; n++)
	{
		sd = backend->change_list[n];
		con = backend->conns[sd];
		if (con)
		{
			flags_r = 0;
			flags_w = 0;

			if (con->change & CHANGE_ACTION_ADD)
			{
				flags_r |= EV_ADD;
				flags_w |= EV_ADD;
			}

			if (con->change & CHANGE_OP_WANT_READ)
				flags_r |= EV_ENABLE;
			else
				flags_r |= EV_DISABLE;

			if (con->change & CHANGE_OP_WANT_WRITE)
				flags_w |= EV_ENABLE;
			else
				flags_w |= EV_DISABLE;

			if (con->ev_r.flags != flags_r)
			{
				EV_SET(&con->ev_r, sd, EVFILT_READ, flags_r, 0, 0, con);
				memcpy(&backend->changes[changes++], &con->ev_r, sizeof(struct kevent));
			}

			if (con->ev_w.flags != flags_w)
			{
				EV_SET(&con->ev_w, sd, EVFILT_WRITE, flags_w, 0, 0, con);
				memcpy(&backend->changes[changes++], &con->ev_w, sizeof(struct kevent));
			}

			con->change = 0;
		}
		else
		{
			EV_SET(&backend->changes[changes++], sd, EVFILT_READ, EV_DELETE, 0, 0, 0);
			EV_SET(&backend->changes[changes++], sd, EVFILT_READ, EV_DELETE, 0, 0, 0);
		}
	}
	backend->change_list_len = 0;
	return changes;
}

#endif /* USE_KQUEUE */
