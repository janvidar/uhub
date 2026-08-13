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

#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "network/connection.h"
#include "network/ipcalc.h"
#include "network/network.h"
#include "network/common.h"
#include "network/tls.h"
#include "network/backend.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>

/*
 * uhub targets OpenSSL >= 3.0 (released 2021) or the contemporaneous
 * LibreSSL >= 3.4. Both ship the opaque-struct API and TLS 1.3 unconditionally,
 * so the code below needs no version shims: TLS1_3_VERSION, the
 * SSL_CTX_set_min_proto_version() interface and SSL_OP_NO_COMPRESSION are always
 * available. LibreSSL reports its own LIBRESSL_VERSION_NUMBER (and masquerades
 * as OpenSSL 2.0.0 via OPENSSL_VERSION_NUMBER), so it is checked separately.
 */
#if defined(LIBRESSL_VERSION_NUMBER)
#  if LIBRESSL_VERSION_NUMBER < 0x3040000fL
#    error "uhub requires LibreSSL >= 3.4.0"
#  endif
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
#  error "uhub requires OpenSSL >= 3.0.0 or LibreSSL >= 3.4.0"
#endif

void net_stats_add_tx(size_t bytes);
void net_stats_add_rx(size_t bytes);
void net_stats_tls_add_accept();
void net_stats_tls_add_errors();
void net_stats_tls_add_accept();


struct net_ssl_openssl
{
	SSL* ssl;
	BIO* bio;
	enum ssl_state state;
	int events;
	int ssl_read_events;
	int ssl_write_events;
	uint32_t flags;
	size_t bytes_rx;
	size_t bytes_tx;
};

struct net_context_openssl
{
	SSL_CTX* ssl;
	char* client_verify_host; /* Identity required of the peer, and the SNI sent, on client handshakes. NULL = no verification. */
};

static struct net_ssl_openssl* get_handle(struct net_connection* con)
{
	uhub_assert(con);
	return (struct net_ssl_openssl*) con->ssl;
}

#ifdef DEBUG
static const char* get_state_str(enum ssl_state state)
{
	switch (state)
	{
		case tls_st_none:			return "tls_st_none";
		case tls_st_error:			return "tls_st_error";
		case tls_st_accepting:		return "tls_st_accepting";
		case tls_st_connecting:		return "tls_st_connecting";
		case tls_st_connected:		return "tls_st_connected";
		case tls_st_disconnecting:	return "tls_st_disconnecting";
	}
	uhub_assert(!"This should not happen - invalid state!");
	return "(UNKNOWN STATE)";
}
#endif

static void net_ssl_set_state(struct net_ssl_openssl* handle, enum ssl_state new_state)
{
	LOG_DEBUG("net_ssl_set_state(): prev_state=%s, new_state=%s", get_state_str(handle->state), get_state_str(new_state));
	handle->state = new_state;
}

const char* net_ssl_get_provider()
{
	return OPENSSL_VERSION_TEXT;
}

int net_ssl_library_init()
{
	/*
	 * OpenSSL >= 1.1.0 and LibreSSL initialize themselves lazily on first use;
	 * the old SSL_library_init() / SSL_load_error_strings() calls are no longer
	 * needed (they are no-op macros on modern OpenSSL).
	 */
	LOG_TRACE("Initializing OpenSSL...");
	return 1;
}

int net_ssl_library_shutdown()
{
	/*
	 * Modern OpenSSL and LibreSSL clean up automatically at process exit, so the
	 * legacy ERR/ENGINE/CONF/EVP teardown is unnecessary (and already compiles to
	 * no-ops on OpenSSL 3.0). Nothing to do here.
	 */
	return 1;
}

static void add_io_stats(struct net_ssl_openssl* handle)
{
	unsigned long num_read = BIO_number_read(handle->bio);
	unsigned long num_write = BIO_number_written(handle->bio);

	if (num_read > handle->bytes_rx)
	{
		net_stats_add_rx(num_read - handle->bytes_rx);
		handle->bytes_rx = num_read;
	}

	if (num_write > handle->bytes_tx)
	{
		net_stats_add_tx(num_write - handle->bytes_tx);
		handle->bytes_tx = num_write;
	}
}

/*
 * Map the configured tls_version string to the matching minimum protocol-version
 * constant. Used with a single TLS_method() context plus
 * SSL_CTX_set_min_proto_version(), which is the modern replacement for selecting
 * a per-version SSL_METHOD and juggling SSL_OP_NO_TLSv1* flags. Returns -1 on an
 * unrecognised version.
 *
 * Only "1.2" and "1.3" are accepted: TLS 1.0/1.1 are deprecated and no longer
 * offered as a configurable floor.
 */
static int tls_version_to_min_proto(const char* tls_version)
{
	if (!tls_version || !*tls_version)
	{
		LOG_ERROR("tls_version is not set.");
		return -1;
	}

	if (!strcmp(tls_version, "1.2"))
		return TLS1_2_VERSION;
	if (!strcmp(tls_version, "1.3"))
		return TLS1_3_VERSION;

	LOG_ERROR("Unsupported tls_version: %s (must be \"1.2\" or \"1.3\")", tls_version);
	return -1;
}

/**
 * List of supported protocols for ALPN.
 * We only support "adc" protocol.
 */
unsigned char alpn_protocols[] = {
     3, 'a', 'd', 'c',
};

/**
 * Callback for the server to select a protocol from the list
 * sent by the client via ALPN.
 */
static int alpn_server_select_protocol(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                                 const unsigned char *in, unsigned int inlen, void *arg)
{
	(void) ssl; (void) arg;
    int res = SSL_select_next_proto((unsigned char **)out, outlen,
                    alpn_protocols, sizeof(alpn_protocols), in, inlen);
    if (res == OPENSSL_NPN_NO_OVERLAP)
    {
        // set default protocol
        *out = alpn_protocols;
        *outlen = 1+alpn_protocols[0];
    }
    return SSL_TLSEXT_ERR_OK;
}

/**
 * Create a new SSL context.
 */
struct ssl_context_handle* net_ssl_context_create(const char* tls_version, const char* tls_ciphersuite, const char* tls_ciphersuites)
{
	struct net_context_openssl* ctx = (struct net_context_openssl*) hub_malloc_zero(sizeof(struct net_context_openssl));
	long flags = 0;
	int min_proto;

	if (!ctx)
		return NULL;

	min_proto = tls_version_to_min_proto(tls_version);
	if (min_proto < 0)
	{
		hub_free(ctx);
		return NULL;
	}

	ctx->ssl = SSL_CTX_new(TLS_method());
	if (!ctx->ssl)
	{
		LOG_ERROR("Unable to create SSL context");
		hub_free(ctx);
		return NULL;
	}

	/* Set the minimum acceptable protocol version; the upper bound is left
	 * open so newer protocols (e.g. TLS 1.3) are used when available. */
	if (!SSL_CTX_set_min_proto_version(ctx->ssl, min_proto))
	{
		LOG_ERROR("Unable to set minimum TLS protocol version.");
		SSL_CTX_free(ctx->ssl);
		hub_free(ctx);
		return NULL;
	}

	SSL_CTX_set_quiet_shutdown(ctx->ssl, 1);

	/* Disable compression to mitigate the CRIME attack. */
	LOG_TRACE("Disabling SSL compression.");
	flags |= SSL_OP_NO_COMPRESSION;

	/* Honour the server's cipher ordering rather than the client's, so the
	 * strongest mutually-supported suite is chosen instead of the client's
	 * preference. Ignored on client contexts. */
	flags |= SSL_OP_CIPHER_SERVER_PREFERENCE;

	/* Refuse client-initiated renegotiation (a DoS/again amplification vector).
	 * TLS 1.3 has no renegotiation; this covers 1.2. Not defined on every
	 * supported provider, so guard it. */
#ifdef SSL_OP_NO_RENEGOTIATION
	flags |= SSL_OP_NO_RENEGOTIATION;
#endif

	SSL_CTX_set_options(ctx->ssl, flags);

	/* Set the preferred TLS 1.2 (and earlier) cipher list. */
	if (SSL_CTX_set_cipher_list(ctx->ssl, tls_ciphersuite) != 1)
	{
		LOG_ERROR("Unable to set cipher suite.");
		SSL_CTX_free(ctx->ssl);
		hub_free(ctx);
		return NULL;
	}

	/* Set the preferred TLS 1.3 cipher suites. These live in a separate
	 * namespace from the list above and are ignored by SSL_CTX_set_cipher_list(),
	 * so without this the tls_ciphersuites option would have no effect. An empty
	 * string is accepted and leaves the library defaults in place. */
	if (tls_ciphersuites && *tls_ciphersuites && SSL_CTX_set_ciphersuites(ctx->ssl, tls_ciphersuites) != 1)
	{
		LOG_ERROR("Unable to set TLS 1.3 cipher suites.");
		SSL_CTX_free(ctx->ssl);
		hub_free(ctx);
		return NULL;
	}

	SSL_CTX_set_alpn_select_cb(ctx->ssl, alpn_server_select_protocol, NULL);

	return (struct ssl_context_handle*) ctx;
}

int net_ssl_context_set_client_verify(struct ssl_context_handle* ctx_, const char* hostname)
{
	struct net_context_openssl* ctx = (struct net_context_openssl*) ctx_;
	X509_VERIFY_PARAM* param;
	char* copy;

	if (!ctx || !ctx->ssl || !hostname || !*hostname)
		return 0;

	if (SSL_CTX_set_default_verify_paths(ctx->ssl) != 1)
	{
		LOG_ERROR("net_ssl_context_set_client_verify: no system certificate trust store: %s",
			ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}

	param = SSL_CTX_get0_param(ctx->ssl);
	if (!param)
	{
		LOG_ERROR("net_ssl_context_set_client_verify: no verification parameters on the context.");
		return 0;
	}

	X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

	/*
	 * An IP literal must be checked against the iPAddress SANs; passed to
	 * set1_host() it would be compared as a DNS name and could never match.
	 * set1_ip_asc() rejects anything that is not an address, which is exactly
	 * the discrimination needed here -- but it leaves an entry on the error
	 * queue when it does, so clear that before the handshake reads it.
	 */
	if (X509_VERIFY_PARAM_set1_ip_asc(param, hostname) != 1)
	{
		ERR_clear_error();
		if (X509_VERIFY_PARAM_set1_host(param, hostname, 0) != 1)
		{
			LOG_ERROR("net_ssl_context_set_client_verify: unable to require the peer identity \"%s\".", hostname);
			return 0;
		}
	}

	copy = hub_strdup(hostname);
	if (!copy)
		return 0;

	SSL_CTX_set_verify(ctx->ssl, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(ctx->ssl, 9);

	hub_free(ctx->client_verify_host);
	ctx->client_verify_host = copy;
	return 1;
}

void net_ssl_context_destroy(struct ssl_context_handle* ctx_)
{
	struct net_context_openssl* ctx = (struct net_context_openssl*) ctx_;
	SSL_CTX_free(ctx->ssl);
	hub_free(ctx->client_verify_host);
	hub_free(ctx);
}

int ssl_load_certificate(struct ssl_context_handle* ctx_, const char* pem_file)
{
	struct net_context_openssl* ctx = (struct net_context_openssl*) ctx_;
	if (SSL_CTX_use_certificate_chain_file(ctx->ssl, pem_file) != 1)
	{
		LOG_ERROR("SSL_CTX_use_certificate_chain_file: %s", ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}

	return 1;
}

int ssl_load_private_key(struct ssl_context_handle* ctx_, const char* pem_file)
{
	struct net_context_openssl* ctx = (struct net_context_openssl*) ctx_;
	if (SSL_CTX_use_PrivateKey_file(ctx->ssl, pem_file, SSL_FILETYPE_PEM) != 1)
	{
		LOG_ERROR("SSL_CTX_use_PrivateKey_file: %s", ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}
	return 1;
}

int ssl_check_private_key(struct ssl_context_handle* ctx_)
{
	struct net_context_openssl* ctx = (struct net_context_openssl*) ctx_;
	if (SSL_CTX_check_private_key(ctx->ssl) != 1)
	{
		LOG_FATAL("SSL_CTX_check_private_key: Private key does not match the certificate public key: %s", ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}
	return 1;
}

/**
 * The shared half of the keyprint accessors: hash @p cert and format the KEYP.
 * Used for both the certificate installed in one of our own contexts and the
 * one a peer presented, which must be fingerprinted identically or the two
 * could never be compared.
 */
static int keyprint_from_x509(X509* cert, const char* who, char* out, size_t out_size)
{
	unsigned char* der = NULL;
	int der_len;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	char b32[(SHA256_DIGEST_LENGTH * 8 + 4) / 5 + 1]; /* 52 base32 chars + NUL */
	int n;

	/* ADC KEYP hashes the DER (ASN.1) encoding of the certificate with SHA256. */
	der_len = i2d_X509(cert, &der);
	if (der_len <= 0 || !der)
	{
		LOG_ERROR("%s: i2d_X509 failed: %s", who, ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}

	SHA256(der, (size_t) der_len, digest);
	OPENSSL_free(der);

	base32_encode(digest, sizeof(digest), b32);

	/* KEYP form: "<hash-name>/<base32>", e.g. "SHA256/G3PJC4F4MQ5KOX...". */
	n = snprintf(out, out_size, "SHA256/%s", b32);
	if (n < 0 || (size_t) n >= out_size)
		return 0;
	return 1;
}

int net_ssl_get_keyprint(struct ssl_context_handle* ctx_, char* out, size_t out_size)
{
	struct net_context_openssl* ctx = (struct net_context_openssl*) ctx_;
	X509* cert;

	if (!ctx || !ctx->ssl || !out || out_size == 0)
		return 0;

	/* The leaf (server) certificate previously installed with
	 * SSL_CTX_use_certificate_chain_file(); SSL_CTX_get0_certificate() returns
	 * an internal pointer we must not free. */
	cert = SSL_CTX_get0_certificate(ctx->ssl);
	if (!cert)
	{
		LOG_ERROR("net_ssl_get_keyprint: no certificate loaded in context.");
		return 0;
	}

	return keyprint_from_x509(cert, "net_ssl_get_keyprint", out, out_size);
}

int net_ssl_get_peer_keyprint(struct net_connection* con, char* out, size_t out_size)
{
	struct net_ssl_openssl* handle;
	X509* cert;
	int ret;

	if (!con || !out || out_size == 0)
		return 0;

	/* Not a TLS connection, or the handshake never got far enough to have a
	   handle: there is no peer certificate to speak of. */
	handle = (struct net_ssl_openssl*) con->ssl;
	if (!handle || !handle->ssl)
		return 0;

	/*
	 * OpenSSL 3.0 renamed this to SSL_get1_peer_certificate() and leaves the
	 * old name only as a deprecated macro; LibreSSL >= 3.4 always has the old
	 * name, and only grew the new one later. Either way the reference returned
	 * is ours to free.
	 */
#if defined(LIBRESSL_VERSION_NUMBER)
	cert = SSL_get_peer_certificate(handle->ssl);
#else
	cert = SSL_get1_peer_certificate(handle->ssl);
#endif
	if (!cert)
		return 0;

	ret = keyprint_from_x509(cert, "net_ssl_get_peer_keyprint", out, out_size);
	X509_free(cert);
	return ret;
}

/** ASCII fold to upper case without branching on the character value. */
static unsigned char keyprint_upper(unsigned char c)
{
	unsigned int d = (unsigned int) ((c - 'a') & 0xff);
	unsigned int is_lower = ((d - 26u) >> 8) & 1u;  /* 1 exactly when c is 'a'..'z' */
	return (unsigned char) (c - (is_lower * 32u));
}

int net_ssl_keyprint_equal(const char* a, const char* b)
{
	size_t len;
	size_t i;
	unsigned char diff = 0;

	if (!a || !b)
		return 0;

	len = strlen(a);
	if (len == 0 || len != strlen(b))
		return 0;

	/* Base32 is case-insensitive and so is the hash name, so both sides are
	   folded; the loop runs to the end regardless of where the first
	   difference is, so nothing is learned from how long the answer took. */
	for (i = 0; i < len; i++)
		diff |= (unsigned char) (keyprint_upper((unsigned char) a[i]) ^ keyprint_upper((unsigned char) b[i]));

	return diff == 0;
}

static int handle_openssl_error(struct net_connection* con, int ret, int read)
{
	struct net_ssl_openssl* handle = get_handle(con);
	int err = SSL_get_error(handle->ssl, ret);
	switch (err)
	{
		case SSL_ERROR_ZERO_RETURN:
			// Not really an error, but SSL was shut down.
			return -1;

		case SSL_ERROR_WANT_READ:
			if (read)
				handle->ssl_read_events = NET_EVENT_READ;
			else
				handle->ssl_write_events = NET_EVENT_READ;
			return 0;

		case SSL_ERROR_WANT_WRITE:
			if (read)
				handle->ssl_read_events = NET_EVENT_WRITE;
			else
				handle->ssl_write_events = NET_EVENT_WRITE;
			return 0;

		case SSL_ERROR_SSL:
			net_ssl_set_state(handle, tls_st_error);
			net_stats_tls_add_error();
			return -2;

		case SSL_ERROR_SYSCALL:
			net_ssl_set_state(handle, tls_st_error);
			net_stats_tls_add_error();
			return -2;
	}

	net_stats_tls_add_error();
	return -2;
}

ssize_t net_con_ssl_accept(struct net_connection* con)
{
	struct net_ssl_openssl* handle = get_handle(con);
	ssize_t ret;
	net_ssl_set_state(handle, tls_st_accepting);

	/* Clear the thread error queue first so SSL_get_error() (via
	 * handle_openssl_error) reflects only this call and does not misread a
	 * stale error left by an earlier operation. */
	ERR_clear_error();
	ret = SSL_accept(handle->ssl);
	LOG_PROTO("SSL_accept() ret=%d", ret);
	if (ret > 0)
	{
		net_con_update(con, NET_EVENT_READ);
		net_ssl_set_state(handle, tls_st_connected);
                net_stats_tls_add_accept();
		return ret;
	}
	return handle_openssl_error(con, ret, 1);
}

ssize_t net_con_ssl_connect(struct net_connection* con)
{
	struct net_ssl_openssl* handle = get_handle(con);
	ssize_t ret;
	net_ssl_set_state(handle, tls_st_connecting);

	/* Clear the thread error queue first (see net_con_ssl_accept). */
	ERR_clear_error();
	ret = SSL_connect(handle->ssl);
	LOG_PROTO("SSL_connect() ret=%d", ret);

	if (ret > 0)
	{
		net_con_update(con, NET_EVENT_READ);
		net_ssl_set_state(handle, tls_st_connected);
                net_stats_tls_add_connect();
		return ret;
	}
	
	ret = handle_openssl_error(con, ret, 1);
	
        if (ret != 0)
            LOG_ERROR("net_con_ssl_connect: ret=%d", ret);
	return ret;
}

ssize_t net_con_ssl_handshake(struct net_connection* con, enum net_con_ssl_mode ssl_mode, struct ssl_context_handle* ssl_ctx)
{
	uhub_assert(con);
	uhub_assert(ssl_ctx);

	struct net_context_openssl* ctx = (struct net_context_openssl*) ssl_ctx;
	struct net_ssl_openssl* handle = (struct net_ssl_openssl*) hub_malloc_zero(sizeof(struct net_ssl_openssl));

	if (!handle)
	{
		LOG_ERROR("Unable to allocate memory for SSL handle");
		return -1;
	}

	handle->ssl = SSL_new(ctx->ssl);
	if (!handle->ssl)
	{
		LOG_ERROR("Unable to create new SSL stream");
		hub_free(handle);
		return -1;
	}

	SSL_set_fd(handle->ssl, con->sd);
	handle->bio = SSL_get_rbio(handle->ssl);
	con->ssl = (struct ssl_handle*) handle;

	if (ssl_mode == net_con_ssl_mode_server)
	{
		return net_con_ssl_accept(con);
	}
	else
	{
		/* Send SNI when the context requires a named identity of the peer: a
		   virtual-hosted server would otherwise answer with its default
		   certificate, which then fails that very check. RFC 6066 forbids a
		   literal address in SNI, so an IP identity sends none. */
		if (ctx->client_verify_host
			&& !ip_is_valid_ipv4(ctx->client_verify_host)
			&& !ip_is_valid_ipv6(ctx->client_verify_host))
		{
			SSL_set_tlsext_host_name(handle->ssl, ctx->client_verify_host);
		}
		return net_con_ssl_connect(con);
	}
}

ssize_t net_ssl_send(struct net_connection* con, const void* buf, size_t len)
{
	struct net_ssl_openssl* handle = get_handle(con);

	LOG_TRACE("net_ssl_send(), state=%d", (int) handle->state);

	if (handle->state == tls_st_error)
		return -2;

	uhub_assert(handle->state == tls_st_connected);
	

	ERR_clear_error();
	ssize_t ret = SSL_write(handle->ssl, buf, len);
	add_io_stats(handle);
	LOG_PROTO("SSL_write(con=%p, buf=%p, len=" PRINTF_SIZE_T ") => %d", con, buf, len, ret);
	if (ret > 0)
		handle->ssl_write_events = 0;
	else
		ret = handle_openssl_error(con, ret, 0);

	net_ssl_update(con, handle->events);  // Update backend only
	return ret;
}

ssize_t net_ssl_recv(struct net_connection* con, void* buf, size_t len)
{
	struct net_ssl_openssl* handle = get_handle(con);
	ssize_t ret;

	if (handle->state == tls_st_error)
		return -2;

	if (handle->state == tls_st_accepting || handle->state == tls_st_connecting)
		return -1;

	uhub_assert(handle->state == tls_st_connected);

	ERR_clear_error();

	ret = SSL_read(handle->ssl, buf, len);
	add_io_stats(handle);
	LOG_PROTO("SSL_read(con=%p, buf=%p, len=" PRINTF_SIZE_T ") => %d", con, buf, len, ret);
	if (ret > 0)
		handle->ssl_read_events = 0;
	else
		ret = handle_openssl_error(con, ret, 1);

	net_ssl_update(con, handle->events);  // Update backend only
	return ret;
}

ssize_t net_ssl_peek(struct net_connection* con, void* buf, size_t len)
{
	struct net_ssl_openssl* handle = get_handle(con);
	ssize_t ret;

	if (handle->state == tls_st_error)
		return -2;

	if (handle->state == tls_st_accepting || handle->state == tls_st_connecting)
		return -1;

	uhub_assert(handle->state == tls_st_connected);

	ERR_clear_error();

	/* Like net_ssl_recv(), but SSL_peek() leaves the decrypted bytes in the SSL
	   buffer so a later SSL_read() (by the user or metrics handler this probe
	   hands off to) still sees them. */
	ret = SSL_peek(handle->ssl, buf, len);
	add_io_stats(handle);
	LOG_PROTO("SSL_peek(con=%p, buf=%p, len=" PRINTF_SIZE_T ") => %d", con, buf, len, ret);
	if (ret > 0)
		handle->ssl_read_events = 0;
	else
		ret = handle_openssl_error(con, ret, 1);

	net_ssl_update(con, handle->events);  // Update backend only
	return ret;
}

void net_ssl_update(struct net_connection* con, int events)
{
	struct net_ssl_openssl* handle = get_handle(con);
	handle->events = events;
	net_backend_update(con, handle->events | handle->ssl_read_events | handle->ssl_write_events);
}

void net_ssl_shutdown(struct net_connection* con)
{
	struct net_ssl_openssl* handle = get_handle(con);
	if (handle)
	{
		SSL_shutdown(handle->ssl);
		SSL_clear(handle->ssl);
	}
}

void net_ssl_destroy(struct net_connection* con)
{
	struct net_ssl_openssl* handle = get_handle(con);
	LOG_TRACE("net_ssl_destroy: %p", con);
	SSL_free(handle->ssl);
	hub_free(handle);
}

void net_ssl_callback(struct net_connection* con, int events)
{
	struct net_ssl_openssl* handle = get_handle(con);
	int ret;

	switch (handle->state)
	{
		case tls_st_none:
			con->callback(con, events, con->ptr);
			break;

		case tls_st_error:
			con->callback(con, NET_EVENT_ERROR, con->ptr);
			break;

		case tls_st_accepting:
			ret = net_con_ssl_accept(con);
			if (ret == 0)
				break; /* handshake still in progress */
			/* Success delivers READ so the connection processes any buffered
			   bytes; a hard error or peer close must deliver ERROR, not READ,
			   mirroring the tls_st_connecting branch below. */
			con->callback(con, (ret > 0) ? NET_EVENT_READ : NET_EVENT_ERROR, con->ptr);
			break;

		case tls_st_connecting:
			ret = net_con_ssl_connect(con);
			if (ret == 0)
				return;

			if (ret > 0)
			{
				LOG_DEBUG("%p SSL connected!", con);
				con->callback(con, NET_EVENT_READ, con->ptr);
			}
			else
			{
				LOG_DEBUG("%p SSL handshake failed!", con);
				con->callback(con, NET_EVENT_ERROR, con->ptr);
			}
			break;

		case tls_st_connected:
			if (handle->ssl_read_events & events)
				events |= NET_EVENT_READ;
			if (handle->ssl_write_events & events)
				events |= NET_EVENT_WRITE;
			con->callback(con, events, con->ptr);
			break;

		case tls_st_disconnecting:
			return;
	}
}

const char* net_ssl_get_tls_version(struct net_connection* con)
{
	struct net_ssl_openssl* handle = get_handle(con);
	return SSL_get_version(handle->ssl);
}

const char* net_ssl_get_tls_cipher(struct net_connection* con)
{
	struct net_ssl_openssl* handle = get_handle(con);
	const SSL_CIPHER *cipher = SSL_get_current_cipher(handle->ssl);
	return SSL_CIPHER_get_name(cipher);
}

