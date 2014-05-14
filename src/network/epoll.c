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

struct net_backend_epoll
{
	int epfd;
	struct net_connection_epoll** conns;
	struct epoll_event events[EPOLL_EVBUFFER];
	struct net_backend_common* common;
};

static void net_backend_set_handlers(struct net_backend_handler* handler);

const char* net_backend_name_epoll()
{
	return "epoll";
}

int net_backend_poll_epoll(struct net_backend* data, int ms)
{
	struct net_backend_epoll* backend = (struct net_backend_epoll*) data;
	int res = epoll_wait(backend->epfd, backend->events, MIN(backend->common->num, EPOLL_EVBUFFER), ms);
	if (res == -1 && errno == EINTR)
		return 0;
	return res;
}

void net_backend_process_epoll(struct net_backend* data, int res)
{
	int n, ev;
	struct net_backend_epoll* backend = (struct net_backend_epoll*) data;
	for (n = 0; n < res; n++)
	{
		struct net_connection_epoll* con = backend->conns[backend->events[n].data.fd];
		if (con)
		{
			ev = 0;
			if (backend->events[n].events & EPOLLIN)  ev |= NET_EVENT_READ;
			if (backend->events[n].events & EPOLLOUT) ev |= NET_EVENT_WRITE;
			net_con_callback((struct net_connection*) con, ev);
		}
	}
}

struct net_connection* net_con_create_epoll(struct net_backend* data)
{
	struct net_connection* con = (struct net_connection*) hub_malloc_zero(sizeof(struct net_connection_epoll));
	con->sd = -1;
	return con;
}

void net_con_initialize_epoll(struct net_backend* data, struct net_connection* con_, int sd, net_connection_cb callback, const void* ptr)
{
	struct net_connection_epoll* con = (struct net_connection_epoll*) con_;
	con->sd = sd;
	con->flags = 0;
	con->callback = callback;
	con->ev.events = 0;
	con->ptr = (void*) ptr;
	con->ev.data.fd = sd;
}

void net_con_backend_add_epoll(struct net_backend* data, struct net_connection* con_, int events)
{
	struct net_backend_epoll* backend = (struct net_backend_epoll*) data;
	struct net_connection_epoll* con = (struct net_connection_epoll*) con_;

	backend->conns[con->sd] = con;

	if (events & NET_EVENT_READ)  con->ev.events |= EPOLLIN;
	if (events & NET_EVENT_WRITE) con->ev.events |= EPOLLOUT;

	if (epoll_ctl(backend->epfd, EPOLL_CTL_ADD, con->sd, &con->ev) == -1)
	{
		LOG_TRACE("epoll_ctl() add failed.");
	}
}

void net_con_backend_mod_epoll(struct net_backend* data, struct net_connection* con_, int events)
{
	struct net_backend_epoll* backend = (struct net_backend_epoll*) data;
	struct net_connection_epoll* con = (struct net_connection_epoll*) con_;

	int newev = 0;
	if (events & NET_EVENT_READ)  newev |= EPOLLIN;
	if (events & NET_EVENT_WRITE) newev |= EPOLLOUT;

	if (newev == con->ev.events)
		return;

	con->ev.events = newev;
	if (epoll_ctl(backend->epfd, EPOLL_CTL_MOD, con->sd, &con->ev) == -1)
	{
		LOG_TRACE("epoll_ctl() modify failed.");
	}
}

void net_con_backend_del_epoll(struct net_backend* data, struct net_connection* con_)
{
	struct net_backend_epoll* backend = (struct net_backend_epoll*) data;
	struct net_connection_epoll* con = (struct net_connection_epoll*) con_;

	backend->conns[con->sd] = 0;

	if (epoll_ctl(backend->epfd, EPOLL_CTL_DEL, con->sd, &con->ev) == -1)
	{
		LOG_WARN("epoll_ctl() delete failed.");
	}
}

void net_backend_shutdown_epoll(struct net_backend* data)
{
	struct net_backend_epoll* backend = (struct net_backend_epoll*) data;
	close(backend->epfd);
	hub_free(backend->conns);
	hub_free(backend);
}

struct net_backend* net_backend_init_epoll(struct net_backend_handler* handler, struct net_backend_common* common)
{
	struct net_backend_epoll* backend;

	if (getenv("EVENT_NOEPOLL"))
		return 0;

	backend = hub_malloc_zero(sizeof(struct net_backend_epoll));
	backend->epfd = epoll_create(common->max);
	if (backend->epfd == -1)
	{
		LOG_WARN("Unable to create epoll socket.");
		hub_free(backend);
		return 0;
	}

	backend->conns = hub_malloc_zero(sizeof(struct net_connection_epoll*) * common->max);
	backend->common = common;

	net_backend_set_handlers(handler);
	return (struct net_backend*) backend;
}

static void net_backend_set_handlers(struct net_backend_handler* handler)
{
	handler->backend_name = net_backend_name_epoll;
	handler->backend_poll = net_backend_poll_epoll;
	handler->backend_process = net_backend_process_epoll;
	handler->backend_shutdown = net_backend_shutdown_epoll;
	handler->con_create = net_con_create_epoll;
	handler->con_init = net_con_initialize_epoll;
	handler->con_add = net_con_backend_add_epoll;
	handler->con_mod = net_con_backend_mod_epoll;
	handler->con_del = net_con_backend_del_epoll;
}

#endif /* USE_EPOLL */
