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

#ifndef HAVE_UHUB_NET_EVENT_H
#define HAVE_UHUB_NET_EVENT_H

/**
 * Network callback for reading data from a socket.
 */
extern void net_on_read(int fd, short ev, void *arg);

/**
 * Network callback for writing data to a socket.
 */
extern void net_on_write(int fd, short ev, void *arg);

/**
 * Network callback for timers.
 */
extern void net_on_read_timeout(int fd, short ev, void* arg);


/**
 * Network callback to accept incoming connections.
 */
extern void net_on_accept(int fd, short ev, void *arg);

#ifdef ADC_UDP_OPERATION
/**
 * Network callback to receive incoming UDP datagram.
 */
extern void net_on_packet(int fd, short ev, void *arg);
#endif


#endif /* HAVE_UHUB_NET_EVENT_H */

