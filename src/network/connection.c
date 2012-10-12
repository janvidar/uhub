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

#ifdef SSL_SUPPORT
void net_stats_add_tx(size_t bytes);
void net_stats_add_rx(size_t bytes);
#endif

ssize_t net_con_send(struct net_connection* con, const void* buf, size_t len)
{
	int ret;
#ifdef SSL_SUPPORT
	if (!con->ssl)
	{
#endif
		ret = net_send(con->sd, buf, len, UHUB_SEND_SIGNAL);
		if (ret == -1)
		{
			if (
#ifdef WINSOCK
				net_error() == WSAEWOULDBLOCK
#else
				net_error() == EWOULDBLOCK 
#endif
				|| net_error() == EINTR)
				return 0;
			return -1;
		}
#ifdef SSL_SUPPORT
	}
	else
	{
		ret = net_ssl_send(con, buf, len);
	}
#endif /* SSL_SUPPORT */
	return ret;
}

ssize_t net_con_recv(struct net_connection* con, void* buf, size_t len)
{
	int ret;
#ifdef SSL_SUPPORT
	if (!con->ssl)
	{
#endif
		ret = net_recv(con->sd, buf, len, 0);
		if (ret == -1)
		{
			if (
#ifdef WINSOCK
				net_error() == WSAEWOULDBLOCK
#else
				net_error() == EWOULDBLOCK
#endif
				|| net_error() == EINTR)
				return 0;
			return -net_error();
		}
		else if (ret == 0)
		{
			return -1;
		}
#ifdef SSL_SUPPORT
	}
	else
	{
		ret = net_ssl_recv(con, buf, len);
	}
#endif /* SSL_SUPPORT */
	return ret;
}

ssize_t net_con_peek(struct net_connection* con, void* buf, size_t len)
{
	int ret = net_recv(con->sd, buf, len, MSG_PEEK);
	if (ret == -1)
	{
		if (
#ifdef WINSOCK
				net_error() == WSAEWOULDBLOCK
#else
				net_error() == EWOULDBLOCK 
#endif
				|| net_error() == EINTR)
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
	return !!con->ssl;
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

void net_con_destroy(struct net_connection* con)
{
#ifdef SSL_SUPPORT
	if (con->ssl)
		net_ssl_destroy(con);
#endif
	hub_free(con);
}

void net_con_callback(struct net_connection* con, int events)
{
	if (con->flags & NET_CLEANUP)
		return;

	if (events == NET_EVENT_TIMEOUT)
	{
		LOG_TRACE("net_con_callback(%p, TIMEOUT)", con);
		con->callback(con, events, con->ptr);
		return;
	}

#ifdef SSL_SUPPORT
	if (!con->ssl)
#endif
		con->callback(con, events, con->ptr);
#ifdef SSL_SUPPORT
	else
		net_ssl_callback(con, events);
#endif
}

