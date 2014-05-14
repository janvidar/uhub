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

#ifndef HAVE_UHUB_NET_EVENT_H
#define HAVE_UHUB_NET_EVENT_H

/**
 * Network callback to accept incoming connections.
 */
extern void net_on_accept(struct net_connection* con, int event, void *arg);
extern void net_event(struct net_connection* con, int event, void *arg);

extern int handle_net_read(struct hub_user* user);
extern int handle_net_write(struct hub_user* user);


#endif /* HAVE_UHUB_NET_EVENT_H */

