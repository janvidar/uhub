/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2009, Jan Vidar Krey
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

extern struct hub_info* g_hub;

void net_con_initialize(struct net_connection* con, int sd, const void* ptr, int events)
{
	con->sd = sd;
	con->ptr = (void*) ptr;

	event_set(&con->event, con->sd, events | EV_PERSIST, net_event, con->ptr);
	event_base_set(g_hub->evbase, &con->event);
	event_add(&con->event, 0);
}

void net_con_update(struct net_connection* con, int events)
{
	if (event_pending(&con->event, EV_READ | EV_WRITE, 0) == events)
		return;

	event_del(&con->event);
	event_set(&con->event, con->sd, events | EV_PERSIST, net_event, con->ptr);
	event_add(&con->event, 0);
}

void net_con_close(struct net_connection* con)
{
	if (!event_pending(&con->event, EV_READ | EV_WRITE, 0))
		return;
	event_del(&con->event);
}


