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
#include "network/common.h"
#include "network/tls.h"
#include "network/backend.h"

#ifdef SSL_SUPPORT
#ifdef SSL_USE_OPENSSL

void net_stats_add_tx(size_t bytes);
void net_stats_add_rx(size_t bytes);

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
};

static struct net_ssl_openssl* get_handle(struct net_connection* con)
{
	uhub_assert(con);
	return (struct net_ssl_openssl*) con->ssl;
}

const char* net_ssl_get_provider()
{
	return OPENSSL_VERSION_TEXT;
}

int net_ssl_library_init()
{
	LOG_TRACE("Initializing OpenSSL...");
	SSL_library_init();
	SSL_load_error_strings();
	return 1;
}

int net_ssl_library_shutdown()
{
	ERR_clear_error();
	ERR_remove_state(0);

	ENGINE_cleanup();
	CONF_modules_unload(1);

        ERR_free_strings();
	EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();

	// sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
	return 1;
}

static void add_io_stats(struct net_ssl_openssl* handle)
{
	if (handle->bio->num_read > handle->bytes_rx)
	{
		net_stats_add_rx(handle->bio->num_read - handle->bytes_rx);
		handle->bytes_rx = handle->bio->num_read;
	}

	if (handle->bio->num_write > handle->bytes_tx)
	{
		net_stats_add_tx(handle->bio->num_write - handle->bytes_tx);
		handle->bytes_tx = handle->bio->num_write;
	}
}

static const SSL_METHOD* get_ssl_method(const char* tls_version)
{
	if (!tls_version || !*tls_version)
	{
		LOG_ERROR("tls_version is not set.");
		return 0;
	}

	if (!strcmp(tls_version, "1.0"))
	  return TLSv1_method();
	if (!strcmp(tls_version, "1.1"))
	  return TLSv1_1_method();
	if (!strcmp(tls_version, "1.2"))
	  return TLSv1_2_method();

	LOG_ERROR("Unable to recognize tls_version.");
	return 0;
}

/**
 * Create a new SSL context.
 */
struct ssl_context_handle* net_ssl_context_create(const char* tls_version, const char* tls_ciphersuite)
{
	struct net_context_openssl* ctx = (struct net_context_openssl*) hub_malloc_zero(sizeof(struct net_context_openssl));
	const SSL_METHOD* ssl_method = get_ssl_method(tls_version);

	if (!ssl_method)
	{
		hub_free(ctx);
		return 0;
	}

	ctx->ssl = SSL_CTX_new(ssl_method);

	/* Disable SSLv2 */
	SSL_CTX_set_options(ctx->ssl, SSL_OP_NO_SSLv2);

	// FIXME: Why did we need this again?
	SSL_CTX_set_quiet_shutdown(ctx->ssl, 1);

#ifdef SSL_OP_NO_COMPRESSION
	/* Disable compression */
	LOG_TRACE("Disabling SSL compression."); /* "CRIME" attack */
	SSL_CTX_set_options(ctx->ssl, SSL_OP_NO_COMPRESSION);
#endif

	/* Set preferred cipher suite */
	if (SSL_CTX_set_cipher_list(ctx->ssl, tls_ciphersuite) != 1)
	{
		LOG_ERROR("Unable to set cipher suite.");
		SSL_CTX_free(ctx->ssl);
		hub_free(ctx);
		return 0;
	}

	return (struct ssl_context_handle*) ctx;
}

extern void net_ssl_context_destroy(struct ssl_context_handle* ctx_)
{
	struct net_context_openssl* ctx = (struct net_context_openssl*) ctx_;
	SSL_CTX_free(ctx->ssl);
	hub_free(ctx);
}

int ssl_load_certificate(struct ssl_context_handle* ctx_, const char* pem_file)
{
	struct net_context_openssl* ctx = (struct net_context_openssl*) ctx_;
	if (SSL_CTX_use_certificate_chain_file(ctx->ssl, pem_file) < 0)
	{
		LOG_ERROR("SSL_CTX_use_certificate_chain_file: %s", ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}

	return 1;
}

int ssl_load_private_key(struct ssl_context_handle* ctx_, const char* pem_file)
{
	struct net_context_openssl* ctx = (struct net_context_openssl*) ctx_;
	if (SSL_CTX_use_PrivateKey_file(ctx->ssl, pem_file, SSL_FILETYPE_PEM) < 0)
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

		case SSL_ERROR_SYSCALL:
			handle->state = tls_st_error;
			return -2;
	}

	return -2;
}

ssize_t net_con_ssl_accept(struct net_connection* con)
{
	struct net_ssl_openssl* handle = get_handle(con);
	handle->state = tls_st_accepting;
	ssize_t ret;

	ret = SSL_accept(handle->ssl);
	LOG_PROTO("SSL_accept() ret=%d", ret);
	if (ret > 0)
	{
		net_con_update(con, NET_EVENT_READ);
		handle->state = tls_st_connected;
		return ret;
	}
	return handle_openssl_error(con, ret, tls_st_accepting);
}

ssize_t net_con_ssl_connect(struct net_connection* con)
{
	struct net_ssl_openssl* handle = get_handle(con);
	ssize_t ret;
	handle->state = tls_st_connecting;

	ret = SSL_connect(handle->ssl);
	LOG_PROTO("SSL_connect() ret=%d", ret);

	if (ret > 0)
	{
		handle->state = tls_st_connected;
		net_con_update(con, NET_EVENT_READ);
		return ret;
	}
	return handle_openssl_error(con, ret, tls_st_connecting);
}

ssize_t net_con_ssl_handshake(struct net_connection* con, enum net_con_ssl_mode ssl_mode, struct ssl_context_handle* ssl_ctx)
{
	uhub_assert(con);

	struct net_context_openssl* ctx = (struct net_context_openssl*) ssl_ctx;
	struct net_ssl_openssl* handle = (struct net_ssl_openssl*) hub_malloc_zero(sizeof(struct net_ssl_openssl));

	if (ssl_mode == net_con_ssl_mode_server)
	{
		handle->ssl = SSL_new(ctx->ssl);
		if (!handle->ssl)
		{
			LOG_ERROR("Unable to create new SSL stream\n");
			return -1;
		}
		SSL_set_fd(handle->ssl, con->sd);
		handle->bio = SSL_get_rbio(handle->ssl);
		con->ssl = (struct ssl_handle*) handle;
		return net_con_ssl_accept(con);
	}
	else
	{
		handle->ssl = SSL_new(SSL_CTX_new(TLSv1_method()));
		SSL_set_fd(handle->ssl, con->sd);
		handle->bio = SSL_get_rbio(handle->ssl);
		con->ssl = (struct ssl_handle*) handle;
		return net_con_ssl_connect(con);
	}
}

ssize_t net_ssl_send(struct net_connection* con, const void* buf, size_t len)
{
	struct net_ssl_openssl* handle = get_handle(con);

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

void net_ssl_update(struct net_connection* con, int events)
{
	struct net_ssl_openssl* handle = get_handle(con);
	handle->events = events;
	net_backend_update(con, handle->events | handle->ssl_read_events | handle->ssl_write_events);
}

void net_ssl_shutdown(struct net_connection* con)
{
	struct net_ssl_openssl* handle = get_handle(con);
	SSL_shutdown(handle->ssl);
	SSL_clear(handle->ssl);
}

void net_ssl_destroy(struct net_connection* con)
{
	struct net_ssl_openssl* handle = get_handle(con);
	SSL_free(handle->ssl);
	hub_free(handle);
}

void net_ssl_callback(struct net_connection* con, int events)
{
	struct net_ssl_openssl* handle = get_handle(con);

	switch (handle->state)
	{
		case tls_st_none:
			con->callback(con, events, con->ptr);
			break;

		case tls_st_error:
			con->callback(con, NET_EVENT_READ, con->ptr);
			break;

		case tls_st_accepting:
			if (net_con_ssl_accept(con) != 0)
				con->callback(con, NET_EVENT_READ, con->ptr);
			break;

		case tls_st_connecting:
			if (net_con_ssl_connect(con) != 0)
				con->callback(con, NET_EVENT_READ, con->ptr);
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


#endif /* SSL_USE_OPENSSL */
#endif /* SSL_SUPPORT */

