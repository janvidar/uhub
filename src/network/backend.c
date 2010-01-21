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

#include "network/connection.h"

struct net_cleanup_handler
{
	size_t num;
	size_t max;
	struct net_connection** queue;
};

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
		hub_free(con);
	}
	handler->num = 0;
}

