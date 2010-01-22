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

#include "uhub.h"
#include "network/common.h"

#ifdef SSL_SUPPORT
static int handle_openssl_error(struct net_connection* con, int ret)
{
	uhub_assert(con);

	int error = SSL_get_error(con->ssl, ret);
	switch (error)
	{
		case SSL_ERROR_ZERO_RETURN:
			LOG_PROTO("SSL_get_error: ret=%d, error=%d: SSL_ERROR_ZERO_RETURN", ret, error);
			return -1;

		case SSL_ERROR_WANT_READ:
			LOG_PROTO("SSL_get_error: ret=%d, error=%d: SSL_ERROR_WANT_READ", ret, error);
			net_con_update(con, NET_EVENT_READ | NET_WANT_SSL_READ);
			return 0;

		case SSL_ERROR_WANT_WRITE:
			LOG_PROTO("SSL_get_error: ret=%d, error=%d: SSL_ERROR_WANT_WRITE", ret, error);
			net_con_update(con, NET_EVENT_READ | NET_EVENT_WRITE | NET_WANT_SSL_WRITE);
			return 0;

		case SSL_ERROR_WANT_CONNECT:
			LOG_PROTO("SSL_get_error: ret=%d, error=%d: SSL_ERROR_WANT_CONNECT", ret, error);
			net_con_update(con, NET_EVENT_READ | NET_EVENT_WRITE | NET_WANT_SSL_CONNECT);
			return 0;

		case SSL_ERROR_WANT_ACCEPT:
			LOG_PROTO("SSL_get_error: ret=%d, error=%d: SSL_ERROR_WANT_ACCEPT", ret, error);
			net_con_update(con, NET_EVENT_READ | NET_EVENT_WRITE | NET_WANT_SSL_ACCEPT);
			return 0;

		case SSL_ERROR_WANT_X509_LOOKUP:
			LOG_PROTO("SSL_get_error: ret=%d, error=%d: SSL_ERROR_WANT_X509_LOOKUP", ret, error);
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
			return -1;
	}

	return -1;
}

ssize_t net_con_ssl_accept(struct net_connection* con)
{
	uhub_assert(con);

	ssize_t ret = SSL_accept(con->ssl);
#ifdef NETWORK_DUMP_DEBUG
	LOG_PROTO("SSL_accept() ret=%d", ret);
#endif
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

ssize_t net_con_ssl_connect(struct net_connection* con)
{
	uhub_assert(con);

	ssize_t ret = SSL_connect(con->ssl);
#ifdef NETWORK_DUMP_DEBUG
	LOG_PROTO("SSL_connect() ret=%d", ret);
#endif
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

ssize_t net_con_ssl_handshake(struct net_connection* con, enum net_con_ssl_mode ssl_mode, SSL_CTX* ssl_ctx)
{
	uhub_assert(con);
	SSL* ssl = 0;

	if (ssl_mode == net_con_ssl_mode_server)
	{
		ssl = SSL_new(ssl_ctx);
		SSL_set_fd(ssl, con->sd);
		net_con_set_ssl(con, ssl);
		return net_con_ssl_accept(con);
	}
	else
	{
		ssl = SSL_new(SSL_CTX_new(TLSv1_method()));
		SSL_set_fd(ssl, con->sd);
		net_con_set_ssl(con, ssl);
		return net_con_ssl_connect(con);
	}
}
#endif /* SSL_SUPPORT */


ssize_t net_con_send(struct net_connection* con, const void* buf, size_t len)
{
	int ret = net_send(con->sd, buf, len, UHUB_SEND_SIGNAL);
	if (ret == -1)
	{
		if (net_error() == EWOULDBLOCK || net_error() == EINTR)
			return 0;
		return -1;
	}
	return ret;
}

ssize_t net_con_recv(struct net_connection* con, void* buf, size_t len)
{
	uhub_assert(con);

#ifdef SSL_SUPPORT
	if (!net_con_is_ssl(con))
	{
#endif
		int ret = net_recv(con->sd, buf, len, 0);
#ifdef NETWORK_DUMP_DEBUG
		LOG_PROTO("net_recv: ret=%d", ret);
#endif
		if (ret == -1)
		{
			if (net_error() == EWOULDBLOCK || net_error() == EINTR)
				return 0;
			return -net_error();
		}
		else if (ret == 0)
		{
			return -1;
		}

		return ret;
#ifdef SSL_SUPPORT
	}
	else
	{
		int ret = SSL_read(con->ssl, buf, len);
#ifdef NETWORK_DUMP_DEBUG
		LOG_PROTO("net_recv: ret=%d", ret);
#endif
		if (ret > 0)
		{
			net_con_update(con, NET_EVENT_READ);
		}
		else
		{
			return -handle_openssl_error(con, ret);
		}
		return ret;
	}
#endif
}

ssize_t net_con_peek(struct net_connection* con, void* buf, size_t len)
{
	int ret = net_recv(con->sd, buf, len, MSG_PEEK);
	if (ret == -1)
	{
		if (net_error() == EWOULDBLOCK || net_error() == EINTR)
			return 0;
		return -net_error();
	}
	else if (ret == 0)
		return -1;
	return ret;
}

#ifdef SSL_SUPPORT
int net_con_is_ssl(struct net_connection* con)
{
	return con->ssl != 0;
}

SSL* net_con_get_ssl(struct net_connection* con)
{
	return con->ssl;
}

void net_con_set_ssl(struct net_connection* con, SSL* ssl)
{
	con->ssl = ssl;
}
#endif /* SSL_SUPPORT */

int net_con_get_sd(struct net_connection* con)
{
	return con->sd;
}

void* net_con_get_ptr(struct net_connection* con)
{
	return con->ptr;
}

void net_con_callback(struct net_connection* con, int events)
{
	if ((con->flags & NET_CLEANUP))
		return;

	if (events == NET_EVENT_TIMEOUT)
	{
		LOG_TRACE("net_con_callback(%p, TIMEOUT", con);
		con->callback(con, events, con->ptr);
		return;
	}

#ifdef SSL_SUPPORT
	if (!con->ssl)
	{
#endif
		con->callback(con, events, con->ptr);
#ifdef SSL_SUPPORT
	}
	else
	{
#ifdef NETWORK_DUMP_DEBUG
		LOG_PROTO("net_con_event: events=%d, con=%p", ev, con);
#endif
		if (events == NET_EVENT_READ && con->flags & NET_WANT_SSL_READ)
		{
			con->callback(con, NET_EVENT_WRITE, con->ptr);
		}
		else if (events == NET_EVENT_WRITE && con->flags & NET_WANT_SSL_WRITE)
		{
			con->callback(con, events & NET_EVENT_READ, con->ptr);
		}
		if (con->flags & NET_WANT_SSL_ACCEPT)
		{
			net_con_ssl_accept(con);
		}
		else if (con->flags & NET_WANT_SSL_CONNECT)
		{
			net_con_ssl_connect(con);
		}
		else
		{
			con->callback(con, events, con->ptr);
		}
	}
#endif
}

