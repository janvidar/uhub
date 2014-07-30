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

#ifndef HAVE_UHUB_NETWORK_BACKEND_H
#define HAVE_UHUB_NETWORK_BACKEND_H

struct net_backend;
struct net_backend_common;
struct net_backend_handler;
struct net_cleanup_handler;
struct net_connection;
typedef void (*net_connection_cb)(struct net_connection*, int event, void* ptr);


typedef struct net_backend* (*net_backend_init_t)(struct net_backend_handler* handler, struct net_backend_common* common);
typedef int (*net_backend_poll)(struct net_backend*, int ms);
typedef void (*net_backend_proc)(struct net_backend*, int res);
typedef void (*net_backend_destroy)(struct net_backend*);

typedef struct net_connection* (*net_con_backend_create)(struct net_backend*);
typedef void (*net_con_backend_init)(struct net_backend*, struct net_connection*, int sd, net_connection_cb callback, const void* ptr);
typedef void (*net_con_backend_add)(struct net_backend*, struct net_connection*, int mask);
typedef void (*net_con_backend_mod)(struct net_backend*, struct net_connection*, int mask);
typedef void (*net_con_backend_del)(struct net_backend*,struct net_connection*);
typedef const char* (*net_con_backend_name)();

struct net_backend_handler
{
	net_con_backend_name backend_name;
	net_backend_poll backend_poll;
	net_backend_proc backend_process;
	net_backend_destroy backend_shutdown;
	net_con_backend_create con_create;
	net_con_backend_init con_init;
	net_con_backend_add con_add;
	net_con_backend_mod con_mod;
	net_con_backend_del con_del;
};

struct net_backend_common
{
	size_t num; /* number of connections monitored by the backend */
	size_t max; /* max number of connections that can be monitored */
};

/**
 * Initialize the network backend.
 * Returns 1 on success, or 0 on failure.
 */
extern int net_backend_init();

/**
 * Shutdown the network connection backend.
 */
extern void net_backend_shutdown();

/**
 * Process the network backend.
 */
extern int net_backend_process();

/**
 * Update the event mask.
 *
 * @param con Connection handle.
 * @param events Event mask (NET_EVENT_*)
 */
extern void net_backend_update(struct net_connection* con, int events);

/**
 * Get the current time.
 */
time_t net_get_time();

extern struct timeout_queue* net_backend_get_timeout_queue();

struct net_cleanup_handler* net_cleanup_initialize(size_t max);

void net_cleanup_shutdown(struct net_cleanup_handler* handler);

void net_cleanup_delayed_free(struct net_cleanup_handler* handler, struct net_connection* con);

void net_cleanup_process(struct net_cleanup_handler* handler);


#endif /* HAVE_UHUB_NETWORK_BACKEND_H */
