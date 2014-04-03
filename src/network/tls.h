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

#ifndef HAVE_UHUB_NETWORK_TLS_H
#define HAVE_UHUB_NETWORK_TLS_H

#include "uhub.h"

#ifdef SSL_SUPPORT


enum ssl_state
{
	tls_st_none,
	tls_st_error,
	tls_st_accepting,
	tls_st_connecting,
	tls_st_connected,
	tls_st_disconnecting,
};

enum net_con_ssl_mode
{
	net_con_ssl_mode_server,
	net_con_ssl_mode_client,
};

struct ssl_context_handle;

/**
 * Returns a string describing the TLS/SSL provider information
 */
extern const char* net_ssl_get_provider();

/**
 * return 0 if error, 1 on success.
 */
extern int net_ssl_library_init();
extern int net_ssl_library_shutdown();

/**
 * Create a new SSL context.
 */
extern struct ssl_context_handle* net_ssl_context_create();
extern void net_ssl_context_destroy(struct ssl_context_handle* ctx);

/**
 * Return 0 on error, 1 otherwise.
 */
extern int ssl_load_certificate(struct ssl_context_handle* ctx, const char* pem_file);

/**
 * Return 0 on error, 1 otherwise.
 */
extern int ssl_load_private_key(struct ssl_context_handle* ctx, const char* pem_file);

/**
 * Return 0 if private key does not match certificate, 1 if everything is OK.
 */
extern int ssl_check_private_key(struct ssl_context_handle* ctx);

/**
 * Start SSL_accept()
 */
extern ssize_t net_con_ssl_accept(struct net_connection*);

/**
 * Start SSL_connect()
 */
extern ssize_t net_con_ssl_connect(struct net_connection*);

extern ssize_t net_ssl_send(struct net_connection* con, const void* buf, size_t len);
extern ssize_t net_ssl_recv(struct net_connection* con, void* buf, size_t len);

/**
 * Update the event mask. Additional events may be requested depending on the
 * needs of the TLS layer.
 *
 * @param con Connection handle.
 * @param events Event mask (NET_EVENT_*)
 */
extern void net_ssl_update(struct net_connection* con, int events);

extern void net_ssl_shutdown(struct net_connection* con);
extern void net_ssl_destroy(struct net_connection* con);
extern void net_ssl_callback(struct net_connection* con, int events);



extern ssize_t net_con_ssl_handshake(struct net_connection* con, enum net_con_ssl_mode, struct ssl_context_handle* ssl_ctx);
extern int   net_con_is_ssl(struct net_connection* con);

#endif /* SSL_SUPPORT */
#endif /* HAVE_UHUB_NETWORK_TLS_H */

