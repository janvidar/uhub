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

#ifdef USE_SELECT

#include "network/connection.h"
#include "network/common.h"
#include "network/backend.h"

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
	for (n = 0, found = 0; found < backend->common->num && n < backend->common->max; n++)
	{
		struct net_connection_select* con = backend->conns[n];
		if (con)
		{
			if (con->flags & NET_EVENT_READ)  FD_SET(con->sd, &backend->rfds);
			if (con->flags & NET_EVENT_WRITE) FD_SET(con->sd, &backend->wfds);
			found++;
			backend->maxfd = con->sd;
		}
	}
	backend->maxfd++;

	res = select(backend->maxfd, &backend->rfds, &backend->wfds, &backend->xfds, &tval);
	if (res == -1)
	{
		if (net_error() == EINTR)
			return 0;

		printf("Error: %d\n", net_error());
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
			if (FD_ISSET(con->sd, &backend->rfds)) ev |= NET_EVENT_READ;
			if (FD_ISSET(con->sd, &backend->wfds)) ev |= NET_EVENT_WRITE;

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
	struct net_connection* con = (struct net_connection*) hub_malloc_zero(sizeof(struct net_connection_select));
	con->sd = -1;
	return con;
}

void net_con_initialize_select(struct net_backend* data, struct net_connection* con_, int sd, net_connection_cb callback, const void* ptr)
{
	struct net_connection_select* con = (struct net_connection_select*) con_;
	con->sd = sd;
	con->flags = 0;
	con->callback = callback;
	con->ptr = (void*) ptr;
}

void net_con_backend_add_select(struct net_backend* data, struct net_connection* con, int events)
{
	struct net_backend_select* backend = (struct net_backend_select*) data;
	backend->conns[con->sd] = (struct net_connection_select*) con;
	con->flags |= (events & (NET_EVENT_READ | NET_EVENT_WRITE));
}


void net_con_backend_mod_select(struct net_backend* data, struct net_connection* con, int events)
{
	con->flags |= (events & (NET_EVENT_READ | NET_EVENT_WRITE));
}

void net_con_backend_del_select(struct net_backend* data, struct net_connection* con)
{
	struct net_backend_select* backend = (struct net_backend_select*) data;
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
	backend->conns = hub_malloc_zero(sizeof(struct net_connection_select*) * common->max);
	backend->common = common;
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
