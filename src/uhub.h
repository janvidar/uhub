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

#ifndef HAVE_UHUB_COMMON_H
#define HAVE_UHUB_COMMON_H

/* Debugging */
/* #define NETWORK_DUMP_DEBUG */
/* #define MEMORY_DEBUG */
/* #define DEBUG_SENDQ 1 */

#include "system.h"

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
#define TIMEOUT_STATS     10

#define MAX_CID_LEN  39
#define MAX_NICK_LEN 64
#define MAX_PASS_LEN 64
#define MAX_UA_LEN   32
#define TIGERSIZE    24

#define MAX_RECV_BUF 65535
#define MAX_SEND_BUF 65535

#ifdef __cplusplus
extern "C" {
#endif

#include "adc/adcconst.h"

#include "util/cbuffer.h"
#include "util/config_token.h"
#include "util/credentials.h"
#include "util/floodctl.h"
#include "util/getopt.h"
#include "util/list.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "util/tiger.h"
#include "util/threads.h"
#include "util/rbtree.h"

#include "adc/sid.h"
#include "adc/message.h"

#include "network/network.h"
#include "network/connection.h"
#include "network/dnsresolver.h"
#include "network/ipcalc.h"
#include "network/timeout.h"

#include "core/auth.h"
#include "core/config.h"
#include "core/eventid.h"
#include "core/eventqueue.h"
#include "core/netevent.h"
#include "core/ioqueue.h"
#include "core/user.h"
#include "core/usermanager.h"
#include "core/route.h"
#include "core/pluginloader.h"
#include "core/hub.h"
#include "core/command_parser.h"
#include "core/commands.h"
#include "core/inf.h"
#include "core/hubevent.h"
#include "core/plugincallback.h"
#include "core/plugininvoke.h"
#include "core/pluginloader.h"



#ifdef __cplusplus
}
#endif

#endif /* HAVE_UHUB_COMMON_H */



