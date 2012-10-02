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

#define NET_WANT_READ             NET_EVENT_READ
#define NET_WANT_WRITE            NET_EVENT_WRITE
#define NET_WANT_ACCEPT           NET_EVENT_READ
#define NET_WANT_SSL_READ         0x0010
#define NET_WANT_SSL_WRITE        0x0020
#define NET_WANT_SSL_ACCEPT       0x0040
#define NET_WANT_SSL_CONNECT      0x0080
#define NET_WANT_SSL_X509_LOOKUP  0x0100

#define NET_CLEANUP               0x8000

#define NET_CON_STRUCT_BASIC \
	int                  sd;        /** socket descriptor */ \
	uint32_t             flags;     /** Connection flags */ \
	void*                ptr;       /** data pointer */ \
	net_connection_cb    callback;  /** Callback function */ \
	struct timeout_evt*  timeout;   /** timeout event handler */

#ifdef SSL_USE_OPENSSL
#define NET_CON_STRUCT_SSL \
	SSL*                 ssl;       /** SSL handle */ \
	uint32_t             ssl_state; /** SSL state */ \
	size_t               write_len; /** Length of last SSL_write(), only used if flags is NET_WANT_SSL_READ. */
#endif

#ifdef SSL_USE_GNUTLS
#define NET_CON_STRUCT_SSL \
	uint32_t             ssl_state; /** SSL state */
#endif

#ifdef SSL_SUPPORT
#define NET_CON_STRUCT_COMMON \
	NET_CON_STRUCT_BASIC \
	NET_CON_STRUCT_SSL
#else
#define NET_CON_STRUCT_COMMON \
	NET_CON_STRUCT_BASIC
#endif /* SSL_SUPPORT */

