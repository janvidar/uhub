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

#ifndef HAVE_UHUB_NETWORK_CONNECTION_H
#define HAVE_UHUB_NETWORK_CONNECTION_H

#include "uhub.h"

struct net_connection
{
	int                  sd;        /** socket descriptor */
	void*                ptr;       /** data pointer */
	struct event         event;     /** libevent struct for read/write events */
#ifdef SSL_SUPPORT
	SSL*                 ssl;       /** SSL handle */
#endif /*  SSL_SUPPORT */
};

extern void net_con_initialize(struct net_connection* con, int sd, const void* ptr, int events);
extern void net_con_update(struct net_connection* con, int events);
extern void net_con_close(struct net_connection* con);


#endif /* HAVE_UHUB_NETWORK_CONNECTION_H */

