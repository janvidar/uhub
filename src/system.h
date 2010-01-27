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

#ifndef HAVE_UHUB_SYSTEM_H
#define HAVE_UHUB_SYSTEM_H

#define _FILE_OFFSET_BITS 64

#if USE_REGPARM && __GNUC__ >= 3
#define REGPRM1 __attribute__((regparm(1)))
#define REGPRM2 __attribute__((regparm(2)))
#define REGPRM3 __attribute__((regparm(3)))
#else
#define REGPRM1
#define REGPRM2
#define REGPRM3
#endif

#ifndef FORCEINLINE
#if __GNUC__ < 3
#define FORCEINLINE inline
#else
#define FORCEINLINE inline __attribute__((always_inline))
#endif
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if defined(__CYGWIN__) || defined(__MINGW32__)
#ifndef WINSOCK
#define WINSOCK
#endif
#endif

#ifdef WINSOCK
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if !defined(WIN32)
#include <grp.h>
#include <pwd.h>
#include <sys/resource.h>
#define HAVE_STRNDUP
#define HAVE_MEMMEM
#define HAVE_GETRLIMIT
#endif

/* printf and size_t support */
#if defined(WIN32)
/* Windows uses %Iu for size_t */
#define PRINTF_SIZE_T "%Iu"
#else
#define PRINTF_SIZE_T "%zu"
#endif

#ifdef SSL_SUPPORT
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "../version.h"

#define uhub_assert assert

#ifdef __linux__
#define USE_EPOLL
#define HAVE_BACKEND
#include <sys/epoll.h>
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define USE_KQUEUE
#define HAVE_BACKEND
#include <sys/event.h>
#endif

#ifndef HAVE_BACKEND
#define USE_SELECT
#ifndef WINSOCK
#include <sys/select.h>
#endif
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__sun__)
#undef HAVE_STRNDUP
#undef HAVE_MEMMEM
#endif

#ifdef MSG_NOSIGNAL
#define UHUB_SEND_SIGNAL MSG_NOSIGNAL
#else
#ifdef MSG_NOPIPE
#define UHUB_SEND_SIGNAL MSG_NOPIPE
#else
#define UHUB_SEND_SIGNAL 0
#endif
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))


#endif /* HAVE_UHUB_SYSTEM_H */
