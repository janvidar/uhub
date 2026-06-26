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

#ifndef HAVE_UHUB_METRICS_H
#define HAVE_UHUB_METRICS_H

struct hub_info;
struct net_connection;
struct ip_addr_encap;

/**
 * Take ownership of a freshly-probed HTTP connection and serve the Prometheus
 * metrics endpoint on it. The connection has already been accepted and added to
 * the reactor by the probe; this swaps in the metrics read/write callbacks and
 * drives the request to completion, closing the connection when done.
 *
 * The caller (probe.c) must relinquish ownership of the connection after this
 * call (set its own pointer to NULL) -- the metrics handler now owns it.
 *
 * Only call this when config->metrics_enable is set and config->metrics_token is
 * a non-empty string.
 */
extern void metrics_handle_connection(struct hub_info* hub, struct net_connection* con, struct ip_addr_encap* addr);

#endif /* HAVE_UHUB_METRICS_H */
