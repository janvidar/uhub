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

static void timeout_callback(struct timeout_evt* evt)
{
	net_con_callback((struct net_connection*) evt->ptr, NET_EVENT_TIMEOUT);
}

void net_con_set_timeout(struct net_connection* con, int seconds)
{
	if (!con->timeout)
	{
		con->timeout = hub_malloc_zero(sizeof(struct timeout_evt));
		timeout_evt_initialize(con->timeout, timeout_callback, con);
		timeout_queue_insert(net_backend_get_timeout_queue(), con->timeout, seconds);
	}
	else
	{
		timeout_queue_reschedule(net_backend_get_timeout_queue(), con->timeout, seconds);
	}
}

void net_con_clear_timeout(struct net_connection* con)
{
	if (con->timeout && timeout_evt_is_scheduled(con->timeout))
	{
		timeout_queue_remove(net_backend_get_timeout_queue(), con->timeout);
		hub_free(con->timeout);
		con->timeout = 0;
	}
}
