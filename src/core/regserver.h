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

#ifndef HAVE_UHUB_REGSERVER_H
#define HAVE_UHUB_REGSERVER_H

#include <stdint.h>

/*
 * ADC hub-list registration ("regserver").
 *
 * Many ADC hub lists run a registration server that accepts a single HTTP
 * "POST /register" whose body is the hub's raw ADC IINF line, replies with
 * "202 Accepted", and afterwards lets a pinger periodically connect to the hub
 * to scrape live statistics. When reg_server_enable is set, the hub performs
 * one best-effort POST to reg_server_url at startup so it can be picked up
 * automatically (issue #105).
 *
 * Only static descriptor fields (NI/AP/VE/HH/WS/NE/OW/DE) are submitted; live
 * counters such as user count and shared size are omitted because they are zero
 * at startup and are gathered later by the hub list's pinger.
 *
 * There are no retries and no re-announce: the outcome is logged and that is the
 * end of it.
 */

struct hub_info;

/**
 * Result of parsing a registration-server URL.
 */
struct regserver_url
{
	int use_tls;        /* 1 for https, 0 for http */
	char host[256];     /* hostname or IP literal */
	uint16_t port;      /* TCP port (defaulted by scheme when absent) */
	char path[1024];    /* request path, defaults to "/register" */
};

/**
 * Parse an http(s) URL of the form scheme://host[:port][/path].
 * The port defaults to 80 (http) or 443 (https) and the path defaults to
 * "/register". An IPv6 literal host may be given in brackets ([::1]).
 *
 * @return 1 on success, 0 if the URL is malformed or uses an unsupported scheme.
 */
extern int regserver_parse_url(const char* url, struct regserver_url* out);

/**
 * Normalize a configured hub_address into the adc:// or adcs:// URL advertised
 * in the "HH" field, both to a registration server and to PING-capable clients.
 * Consumers need a reachable ADC URL that includes the port, so this fills in
 * whatever the admin left out:
 *   - the scheme: kept if hub_address already starts with adc:// or adcs://,
 *     otherwise defaulted to adcs:// when use_tls is set, else adc://;
 *   - the port: appended as ":server_port" when the host carries none.
 * A bracketed IPv6 literal ([::1]) is recognized when deciding whether a port
 * is already present.
 *
 * @param hub_address the configured address (may be empty/NULL)
 * @param use_tls     non-zero if the hub listens with TLS (selects the default scheme)
 * @param server_port the hub's listening port, used when hub_address omits one
 * @param out         destination buffer for the NUL-terminated URL
 * @param out_size    size of @p out
 * @return 1 on success, 0 if no address can be formed (empty hub_address, a
 *         non-ADC scheme, or the result does not fit in @p out).
 */
extern int regserver_hub_url(const char* hub_address, int use_tls, int server_port, char* out, size_t out_size);

/**
 * Kick off the one-time registration announce, if reg_server_enable is set and
 * reg_server_url is configured and valid. Safe to call unconditionally at the
 * end of hub startup; it is a no-op when disabled or misconfigured.
 */
extern void regserver_announce(struct hub_info* hub);

/**
 * Cancel a pending connect / close an in-flight connection and free all state.
 * Safe to call when nothing is in flight. Called from hub shutdown.
 */
extern void regserver_cleanup(struct hub_info* hub);

#endif /* HAVE_UHUB_REGSERVER_H */
