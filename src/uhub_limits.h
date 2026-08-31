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

/*
 * Installation paths. The build system (CMakeLists.txt / build.zig) derives
 * these from the install prefix and passes them in as -D definitions; the
 * fallbacks below keep a bare compile working and match the historical
 * hardcoded layout.
 *
 * UHUB_PLUGIN_DIR is where the hub looks for its built-in default plugin set
 * (see plugin_load_defaults() in src/core/pluginloader.c), UHUB_CONFIG_DIR
 * holds uhub.conf and friends, and UHUB_STATE_DIR is where the hub keeps
 * state it creates itself -- the default user database.
 */
#ifndef WIN32
#ifndef UHUB_CONFIG_DIR
#define UHUB_CONFIG_DIR "/etc/uhub"
#endif
#ifndef UHUB_PLUGIN_DIR
#define UHUB_PLUGIN_DIR "/usr/lib/uhub"
#endif
#ifndef UHUB_STATE_DIR
#define UHUB_STATE_DIR "/var/lib/uhub"
#endif
#define SERVER_CONFIG UHUB_CONFIG_DIR "/uhub.conf"
#else
/* On Windows everything is relative to the working directory. */
#ifndef UHUB_CONFIG_DIR
#define UHUB_CONFIG_DIR "."
#endif
#ifndef UHUB_PLUGIN_DIR
#define UHUB_PLUGIN_DIR "."
#endif
#ifndef UHUB_STATE_DIR
#define UHUB_STATE_DIR "."
#endif
#define SERVER_CONFIG    "uhub.conf"
#ifndef stderr
#define stderr stdout
#endif
#endif

#define TIMEOUT_CONNECTED 15
#define TIMEOUT_HANDSHAKE 30
#define TIMEOUT_SENDQ     120
#define TIMEOUT_STATS     10
#define TIMEOUT_KEEPALIVE 10

/*
 * Size of the network timeout wheel, in seconds. Timeout events are hashed into
 * the wheel by (timestamp % TIMEOUT_QUEUE_MAX), so this must be at least as
 * large as the longest timeout scheduled above (currently TIMEOUT_SENDQ); a
 * timeout longer than this would alias onto an earlier slot.
 */
#define TIMEOUT_QUEUE_MAX 120

/*
 * TCP keepalive tuning for accepted client connections (net_set_keepalive()):
 * after KEEPALIVE_IDLE seconds of silence begin probing, KEEPALIVE_INTVL apart,
 * up to KEEPALIVE_CNT times before the OS declares the peer dead (~4 min here).
 * This reaps genuinely dead / half-open connections -- a crashed client, a
 * yanked network -- that would otherwise linger indefinitely once past the
 * login handshake timeout, since there is no post-login idle timeout (idle
 * lurkers are supported by design). It probes only silent connections and never
 * disconnects a live one, and being an OS-level timer it is independent of the
 * timeout wheel above (so unbounded by TIMEOUT_QUEUE_MAX).
 */
#define KEEPALIVE_IDLE    120
#define KEEPALIVE_INTVL   30
#define KEEPALIVE_CNT     4

/*
 * Reconnect-delay hints (seconds) advertised to clients in the QUI "TL" flag,
 * telling them how long to wait before reconnecting after a fatal status.
 */
#define RECONNECT_TIME_HUB_FULL 600
#define RECONNECT_TIME_TEMP_BAN 600

#define MAX_RECV_BUF 65535
#define MAX_SEND_BUF 65535

#endif /* HAVE_UHUB_LIMITS_H */
