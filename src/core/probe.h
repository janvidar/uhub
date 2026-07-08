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

#ifndef HAVE_UHUB_PROBE_H
#define HAVE_UHUB_PROBE_H

#include "network/ipcalc.h"

struct hub_info;
struct net_connection;

struct hub_probe
{
	struct hub_info*        hub;                /** The hub instance this probe belong to */
	struct net_connection*  connection;         /** Connection data */
	struct ip_addr_encap    addr;               /** IP address */
	int                     tls;                /** Set once a TLS handshake has been started on this connection */
	int                     counted;            /** Set if this connection holds a max_connections_per_ip slot for addr */
};

extern struct hub_probe* probe_create(struct hub_info* hub, int sd, struct ip_addr_encap* addr);
extern void probe_destroy(struct hub_probe* probe);

/**
 * Protocol detected from the first bytes of a fresh, not-yet-classified
 * connection.
 */
enum probe_protocol
{
	probe_protocol_incomplete,   /* fewer than 4 bytes seen; need more before deciding */
	probe_protocol_tls,          /* TLS ClientHello */
	probe_protocol_adc,          /* ADC handshake: "HSUP" (login) or "HTCP" (HBRI) */
	probe_protocol_link,         /* hub-to-hub link handshake: "LCHA" */
	probe_protocol_http,         /* HTTP request: "GET " / "POST" / "HEAD" (metrics) */
	probe_protocol_unsupported,  /* none of the above */
};

/**
 * Classify the protocol from the leading bytes peeked off a new connection.
 * Pure: inspects only the buffer, no I/O or connection state, so it is
 * unit-tested directly. `len` is how many bytes are available in `buf`.
 */
extern enum probe_protocol probe_classify(const char* buf, size_t len);

#endif /* HAVE_UHUB_PROBE_H */
