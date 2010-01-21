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

#ifndef HAVE_UHUB_NETWORK_BACKEND_H
#define HAVE_UHUB_NETWORK_BACKEND_H

struct net_cleanup_handler;
struct net_connection;

/**
 * Initialize the network backend.
 * Returns 1 on success, or 0 on failure.
 */
extern int net_backend_initialize();

/**
 * Shutdown the network connection backend.
 */
extern void net_backend_shutdown();

/**
 * Process the network backend.
 */
extern int net_backend_process();

extern struct timeout_queue* net_backend_get_timeout_queue();

struct net_cleanup_handler* net_cleanup_initialize(size_t max);

void net_cleanup_shutdown(struct net_cleanup_handler* handler);

void net_cleanup_delayed_free(struct net_cleanup_handler* handler, struct net_connection* con);

void net_cleanup_process(struct net_cleanup_handler* handler);


#endif /* HAVE_UHUB_NETWORK_BACKEND_H */
