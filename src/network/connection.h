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

#define NET_EVENT_TIMEOUT         0x0001
#define NET_EVENT_READ            0x0002
#define NET_EVENT_WRITE           0x0004
#define NET_EVENT_SOCKERROR       0x1000 /* Socket error, closed */
#define NET_EVENT_CLOSED          0x2000 /* Socket closed */

struct net_connection;
struct net_timer;

typedef void (*net_connection_cb)(struct net_connection*, int event, void* ptr);
typedef void (*net_timeout_cb)(struct net_timer*, void* ptr);

struct net_timer
{
	unsigned int         initialized;
	struct event         timeout;
	net_timeout_cb       callback;
	void*                ptr;
};

extern void net_timer_initialize(struct net_timer* timer, net_timeout_cb callback, void* ptr);
extern void net_timer_reset(struct net_timer* timer, int seconds);
extern void net_timer_shutdown(struct net_timer* timer);

struct net_connection
{
	int                  sd;        /** socket descriptor */
	unsigned int         flags;     /** Connection flags */
	void*                ptr;       /** data pointer */
	net_connection_cb    callback;  /** Callback function */
	struct event         event;     /** libevent struct for read/write events */
	struct event         timeout;   /** Used for internal timeout handling */
	struct ip_addr_encap ipaddr;    /** IP address of peer */
	time_t               last_recv; /** Timestamp for last recv() */
	time_t               last_send; /** Timestamp for last send() */
#ifdef SSL_SUPPORT
	SSL*                 ssl;       /** SSL handle */
	size_t               write_len; /** Length of last SSL_write(), only used if flags is NET_WANT_SSL_READ. */
#endif /*  SSL_SUPPORT */
};

extern void net_con_initialize(struct net_connection* con, int sd, struct ip_addr_encap*, net_connection_cb callback, const void* ptr, int events);
extern void net_con_update(struct net_connection* con, int events);
extern void net_con_close(struct net_connection* con);

/**
 * Send data
 *
 * @return returns the number of bytes sent.
 *         0 if no data is sent, and this function should be called again (EWOULDBLOCK/EINTR)
 *        <0 if an error occured, the negative number contains the error code.
 */
extern ssize_t net_con_send(struct net_connection* con, const void* buf, size_t len);

/**
 * Receive data
 *
 * @return returns the number of bytes sent.
 *         0 if no data is sent, and this function should be called again (EWOULDBLOCK/EINTR)
 *        <0 if an error occured, the negative number contains the error code.
 */
extern ssize_t net_con_recv(struct net_connection* con, void* buf, size_t len);

/**
 * Set timeout for connetion.
 *
 * @param seconds the number of seconds into the future.
 */
extern void net_con_set_timeout(struct net_connection* con, int seconds);
extern void net_con_clear_timeout(struct net_connection* con);

/**
 * Returns a string representation of the ipaddr member.
 * NOTE: Static buffer.
 */
extern const char* net_con_get_peer_address(struct net_connection* con);

#ifdef SSL_SUPPORT
/**
 * Start SSL_accept()
 */
extern ssize_t net_con_ssl_accept(struct net_connection*);

/**
 * Start SSL_connect()
 */
extern ssize_t net_con_ssl_connect(struct net_connection*);

#define NET_CON_SSL_MODE_SERVER 1
#define NET_CON_SSL_MODE_CLIENT 2
extern ssize_t net_con_ssl_handshake(struct net_connection* con, int ssl_mode);

#endif /* SSL_SUPPORT */

#endif /* HAVE_UHUB_NETWORK_CONNECTION_H */

