/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2012, Jan Vidar Krey
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

#ifdef SSL_SUPPORT
#ifdef SSL_USE_OPENSSL

struct net_ssl_openssl
{
	SSL* ssl;
	enum ssl_state state;
};

static struct net_ssl_openssl* get_handle(struct net_connection* con)
{
	uhub_assert(con);
	return (struct net_ssl_openssl*) con->ssl;
}

static int handle_openssl_error(struct net_connection* con, int ret)
{
	struct net_ssl_openssl* handle = get_handle(con);

	int error = SSL_get_error(handle->ssl, ret);
	switch (error)
	{
		case SSL_ERROR_ZERO_RETURN:
			LOG_PROTO("SSL_get_error: ret=%d, error=%d: SSL_ERROR_ZERO_RETURN", ret, error);
			handle->state = tls_st_error;
			return -1;

		case SSL_ERROR_WANT_READ:
			LOG_PROTO("SSL_get_error: ret=%d, error=%d: SSL_ERROR_WANT_READ", ret, error);
			con->flags |= NET_WANT_SSL_READ;
			net_con_update(con, NET_EVENT_READ);
			return 0;

		case SSL_ERROR_WANT_WRITE:
			LOG_PROTO("SSL_get_error: ret=%d, error=%d: SSL_ERROR_WANT_WRITE", ret, error);
			con->flags |= NET_WANT_SSL_WRITE;
			net_con_update(con, NET_EVENT_READ | NET_EVENT_WRITE);
			return 0;

		case SSL_ERROR_SYSCALL:
			LOG_PROTO("SSL_get_error: ret=%d, error=%d: SSL_ERROR_SYSCALL", ret, error);
			/* if ret == 0, connection closed, if ret == -1, check with errno */
			if (ret == 0)
				return -1;
			else
				return -net_error();

		case SSL_ERROR_SSL:
			LOG_PROTO("SSL_get_error: ret=%d, error=%d: SSL_ERROR_SSL", ret, error);
			/* internal openssl error */
			handle->state = tls_st_error;
			return -1;
	}
	return -1;
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
	}
	else
	{
		return handle_openssl_error(con, ret);
	}
	return ret;
}

ssize_t net_con_ssl_connect(struct net_connection* con)
{
	struct net_ssl_openssl* handle = get_handle(con);
	ssize_t ret;
	handle->state = tls_st_connecting;

	ret = SSL_connect(handle->ssl);
#ifdef NETWORK_DUMP_DEBUG
	LOG_PROTO("SSL_connect() ret=%d", ret);
#endif /* NETWORK_DUMP_DEBUG */
	if (ret > 0)
	{
		handle->state = tls_st_connected;
		net_con_update(con, NET_EVENT_READ);
	}
	else
	{
		return handle_openssl_error(con, ret);
	}
	return ret;
}

ssize_t net_con_ssl_handshake(struct net_connection* con, enum net_con_ssl_mode ssl_mode, SSL_CTX* ssl_ctx)
{
	uhub_assert(con);

	struct net_ssl_openssl* handle = (struct net_ssl_openssl*) hub_malloc_zero(sizeof(struct net_ssl_openssl));

	if (ssl_mode == net_con_ssl_mode_server)
	{
		handle->ssl = SSL_new(ssl_ctx);
		if (!handle->ssl)
		{
			LOG_ERROR("Unable to create new SSL stream\n");
			return -1;
		}
		SSL_set_fd(handle->ssl, con->sd);
		con->ssl = (struct ssl_handle*) handle;
		return net_con_ssl_accept(con);
	}
	else
	{
		handle->ssl = SSL_new(SSL_CTX_new(TLSv1_method()));
		SSL_set_fd(handle->ssl, con->sd);
		con->ssl = (struct ssl_handle*) handle;
		return net_con_ssl_connect(con);
	}

}

ssize_t net_ssl_send(struct net_connection* con, const void* buf, size_t len)
{
	struct net_ssl_openssl* handle = get_handle(con);
// 	con->write_len = len;
	ssize_t ret = SSL_write(handle->ssl, buf, len);
	LOG_PROTO("SSL_write(con=%p, buf=%p, len=" PRINTF_SIZE_T ") => %d", con, buf, len, ret);
	if (ret <= 0)
	{
		return handle_openssl_error(con, ret);
	}
	return ret;
}

ssize_t net_ssl_recv(struct net_connection* con, void* buf, size_t len)
{
	struct net_ssl_openssl* handle = get_handle(con);
	ssize_t ret;

	if (handle->state == tls_st_error)
		return -1;

	ret = SSL_read(handle->ssl, buf, len);
	LOG_PROTO("SSL_read(con=%p, buf=%p, len=" PRINTF_SIZE_T ") => %d", con, buf, len, ret);
	if (ret > 0)
	{
		net_con_update(con, NET_EVENT_READ);
	}
	else
	{
		return handle_openssl_error(con, ret);
	}
	return ret;
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
}

void net_ssl_callback(struct net_connection* con, int events)
{
	struct net_ssl_openssl* handle = get_handle(con);

	uint32_t flags = con->flags;
	con->flags &= ~NET_SSL_ANY; /* reset the SSL related flags */

	switch (handle->state)
	{
		case tls_st_none:
			con->callback(con, events, con->ptr);
			break;

		case tls_st_error:
			con->callback(con, NET_EVENT_READ, con->ptr);
			break;

		case tls_st_accepting:
			if (net_con_ssl_accept(con) < 0)
			{
				con->callback(con, NET_EVENT_READ, con->ptr);
			}
			break;

		case tls_st_connecting:
			if (net_con_ssl_connect(con) < 0)
			{
				con->callback(con, NET_EVENT_READ, con->ptr);
			}
			break;

		case tls_st_connected:
			LOG_PROTO("tls_st_connected, events=%s%s, ssl_flags=%s%s", (events & NET_EVENT_READ ? "R" : ""), (events & NET_EVENT_WRITE ? "W" : ""), flags & NET_WANT_SSL_READ ? "R" : "", flags & NET_WANT_SSL_WRITE ? "W" : "");
			if (events & NET_EVENT_WRITE && flags & NET_WANT_SSL_READ)
			{
				con->callback(con, events & NET_EVENT_READ, con->ptr);
				return;
			}

			if (events & NET_EVENT_READ && flags & NET_WANT_SSL_WRITE)
			{
				con->callback(con, events & NET_EVENT_READ, con->ptr);
				return;
			}

			con->callback(con, events, con->ptr);
			break;

		case tls_st_disconnecting:
			return;
	}
}


#endif /* SSL_USE_OPENSSL */
#endif /* SSL_SUPPORT */