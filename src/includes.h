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

#ifndef HAVE_UHUB_INCLUDES_H
#define HAVE_UHUB_INCLUDES_H

#define _FILE_OFFSET_BITS 64

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifdef WINSOCK
# include <winsock2.h>
# include <ws2tcpip.h>
#else
# include <sys/types.h>
# include <sys/time.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <netinet/in.h>
# include <sys/ioctl.h>
# include <sys/socket.h>
#endif

# include <assert.h>
# include <errno.h>
# include <fcntl.h>

#ifndef __sun__
# include <getopt.h>
# include <stdint.h>
#endif

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if !defined(WIN32)
# include <grp.h>
# include <pwd.h>
# include <sys/resource.h>
#endif

#ifdef SSL_SUPPORT
# include <openssl/ssl.h>
# include <openssl/err.h>
#endif

#ifdef __linux__
# define USE_EPOLL
# include <sys/epoll.h>
#endif

#ifdef BSD_LIKE
# define USE_KQUEUE
# include <sys/event.h>
#endif

#define USE_SELECT
# ifndef WINSOCK
# include <sys/select.h>
#endif

#if !defined(WIN32)
# define HAVE_STRNDUP
# define HAVE_GETRLIMIT
# if !defined(__HAIKU__)
#  define HAVE_MEMMEM
# endif
#endif

#if defined(BSD_LIKE) || defined(__sun__)
# undef HAVE_STRNDUP
# undef HAVE_MEMMEM
#endif

#if defined(WIN32)
/* Windows uses %Iu for size_t */
#define PRINTF_SIZE_T "%Iu"
#else
/* NOTE: does not work for old versions of gcc (like 2.95) */
#define PRINTF_SIZE_T "%zu"
#endif

#define uhub_assert assert


#endif /* HAVE_UHUB_INCLUDES_H */
