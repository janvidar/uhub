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

#define NET_WANT_READ             NET_EVENT_READ
#define NET_WANT_WRITE            NET_EVENT_WRITE
#define NET_WANT_ACCEPT           NET_EVENT_READ

#define NET_SSL_ANY NET_WANT_SSL_READ | NET_WANT_SSL_WRITE | NET_WANT_SSL_ACCEPT | NET_WANT_SSL_CONNECT | NET_WANT_SSL_X509_LOOKUP

struct ssl_handle; /* abstract type */

#define NET_CLEANUP               0x8000

#define NET_CON_STRUCT_BASIC \
	int                  sd;        /** socket descriptor */ \
	uint32_t             flags;     /** Connection flags */ \
	void*                ptr;       /** data pointer */ \
	net_connection_cb    callback;  /** Callback function */ \
	struct timeout_evt*  timeout;   /** timeout event handler */

#define NET_CON_STRUCT_SSL \
	struct ssl_handle* ssl;         /** SSL handle */

#ifdef SSL_SUPPORT
#define NET_CON_STRUCT_COMMON \
	NET_CON_STRUCT_BASIC \
	NET_CON_STRUCT_SSL
#else
#define NET_CON_STRUCT_COMMON \
	NET_CON_STRUCT_BASIC
#endif /* SSL_SUPPORT */

