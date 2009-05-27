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

#ifndef HAVE_UHUB_COMMON_H
#define HAVE_UHUB_COMMON_H

/* Debugging */
/* #define NETWORK_DUMP_DEBUG */
/* #define MEMORY_DEBUG */

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

#ifndef WIN32
#include <grp.h>
#include <pwd.h>
#define HAVE_STRNDUP
#define HAVE_MEMMEM
#endif

#ifdef SSL_SUPPORT
#include <openssl/ssl.h>
#endif

#include "../version.h"

#define uhub_assert assert

#include <event.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
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


#define SERVER_PORT      1511
#define SERVER_ADDR_IPV6 "::"
#define SERVER_ADDR_IPV4 "0.0.0.0"
#define SERVER_BACKLOG   50

#ifndef WIN32
#define SERVER_CONFIG    "/etc/uhub/uhub.conf"
#define SERVER_ACL_FILE  "/etc/uhub/users.conf"
#else
#define SERVER_CONFIG    "uhub.conf"
#define SERVER_ACL_FILE  "users.conf"
#ifndef stderr
#define stderr stdout
#endif
#endif

#define TIMEOUT_CONNECTED 15
#define TIMEOUT_HANDSHAKE 30
#define TIMEOUT_SENDQ     120
#define TIMEOUT_IDLE      7200
#define TIMEOUT_STATS     60

#define MAX_CLIENTS  512
#define MAX_CID_LEN  39
#define MAX_NICK_LEN 64
#define MAX_UA_LEN   32
#define TIGERSIZE    24

#define MAX_RECV_BUF 65535
#define MAX_SEND_BUF 65535

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#include "adcconst.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#ifdef __cplusplus
extern "C" {
#endif

#include "memory.h"
#include "misc.h"
#include "eventid.h"
#include "eventqueue.h"
#include "ipcalc.h"
#include "list.h"
#include "sid.h"
#include "network.h"
#include "netevent.h"
#include "hubio.h"
#include "auth.h"
#include "tiger.h"
#include "config.h"
#include "log.h"
#include "user.h"
#include "usermanager.h"
#include "message.h"
#include "route.h"
#include "hub.h"
#include "commands.h"
#include "inf.h"
#include "hubevent.h"

#ifdef __cplusplus
}
#endif

#endif /* HAVE_UHUB_COMMON_H */



