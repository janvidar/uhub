/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

/*
 * Hub-wide compile-time defaults and tunables: default config file paths,
 * connection/handshake/stats timeouts (seconds) and the socket I/O buffer
 * sizes. These used to live in the src/uhub.h god-header; they have their own
 * header so a translation unit can pull them in without dragging in every
 * module header.
 */

#ifndef HAVE_UHUB_LIMITS_H
#define HAVE_UHUB_LIMITS_H

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

/*
 * Size of the network timeout wheel, in seconds. Timeout events are hashed into
 * the wheel by (timestamp % TIMEOUT_QUEUE_MAX), so this must be at least as
 * large as the longest timeout scheduled above (currently TIMEOUT_SENDQ); a
 * timeout longer than this would alias onto an earlier slot.
 */
#define TIMEOUT_QUEUE_MAX 120

/*
 * Reconnect-delay hints (seconds) advertised to clients in the QUI "TL" flag,
 * telling them how long to wait before reconnecting after a fatal status.
 */
#define RECONNECT_TIME_HUB_FULL 600
#define RECONNECT_TIME_TEMP_BAN 600

#define MAX_RECV_BUF 65535
#define MAX_SEND_BUF 65535

#endif /* HAVE_UHUB_LIMITS_H */
