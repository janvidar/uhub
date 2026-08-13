/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#ifndef HAVE_UHUB_NETWORK_TLS_H
#define HAVE_UHUB_NETWORK_TLS_H

#include "system.h"

struct net_connection;

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
 * Specify a TLS version as a string: "1.2" for TLS 1.2.
 */
extern struct ssl_context_handle* net_ssl_context_create(const char* tls_version, const char* tls_ciphersuite, const char* tls_ciphersuites);
extern void net_ssl_context_destroy(struct ssl_context_handle* ctx);

/**
 * Turn a client context into a *verifying* client context.
 *
 * By default a context performs no peer verification at all, which is fine for
 * the inbound (server) side but means an outbound https connection is trivially
 * interceptable. This installs the three things a real HTTPS client needs:
 *
 *   - the system certificate trust store (SSL_CTX_set_default_verify_paths),
 *   - SSL_VERIFY_PEER, so a chain that does not validate aborts the handshake,
 *   - a required identity: @p hostname must appear in the certificate. A DNS
 *     name is matched against the dNSName SANs (partial wildcards refused); an
 *     IP literal is matched against the iPAddress SANs instead, since matching
 *     it as a name could never succeed.
 *
 * The hostname is remembered on the context and sent as SNI on every client
 * handshake made from it, without which a virtual-hosted server would present
 * its default certificate and fail the identity check. RFC 6066 forbids an IP
 * literal in SNI, so none is sent in that case.
 *
 * Only affects handshakes made with net_con_ssl_mode_client; a context used for
 * inbound connections is unchanged.
 *
 * @return 1 on success, 0 if verification could not be configured -- in which
 *         case the caller must abandon the connection rather than continue
 *         unverified.
 */
extern int net_ssl_context_set_client_verify(struct ssl_context_handle* ctx, const char* hostname);

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
 * Compute the ADC KEYP keyprint of the leaf certificate installed in @p ctx.
 * Writes the NUL-terminated form "SHA256/<base32>" (the SHA256 hash of the
 * certificate's DER encoding, Base32-encoded without padding) into @p out. This
 * is the value advertised as "?kp=" in an adcs:// URL so clients can pin the
 * hub's certificate. A 60-byte buffer is always sufficient.
 *
 * @return 1 on success, 0 if no certificate is loaded or @p out is too small.
 */
extern int net_ssl_get_keyprint(struct ssl_context_handle* ctx, char* out, size_t out_size);

/**
 * Compute the ADC KEYP keyprint of the certificate the *peer* presented on
 * @p con, in the same "SHA256/<base32>" form as net_ssl_get_keyprint(). This is
 * the value to compare against a "?kp=" pinned in a hub URL, and it is only
 * meaningful once the handshake has completed. A 60-byte buffer is always
 * sufficient.
 *
 * @return 1 on success, 0 if @p con is not a TLS connection, the peer sent no
 *         certificate, or @p out is too small. A caller that is pinning a
 *         keyprint must treat 0 as a verification failure, not as "no opinion".
 */
extern int net_ssl_get_peer_keyprint(struct net_connection* con, char* out, size_t out_size);

/**
 * Compare two ADC keyprints.
 *
 * Case-insensitive (base32 and the hash name both are) and written to take the
 * same time whatever the inputs, so a peer cannot learn the expected value one
 * character at a time. Keyprints of differing length are unequal, which is
 * decided up front -- a length is not a secret.
 *
 * @return 1 if the two name the same certificate, 0 otherwise (including when
 *         either is NULL or empty).
 */
extern int net_ssl_keyprint_equal(const char* a, const char* b);

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
extern ssize_t net_ssl_peek(struct net_connection* con, void* buf, size_t len);

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

extern const char* net_ssl_get_tls_version(struct net_connection* con);
extern const char* net_ssl_get_tls_cipher(struct net_connection* con);

#endif /* HAVE_UHUB_NETWORK_TLS_H */

