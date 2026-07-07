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

#ifndef HAVE_UHUB_IPCOUNT_H
#define HAVE_UHUB_IPCOUNT_H

#include <stddef.h>

struct ip_addr_encap;

/**
 * A tally of currently-open connections per source IP address, used to enforce
 * the max_connections_per_ip limit. Addresses with a zero count are not stored.
 */
struct ip_count;

extern struct ip_count* ipcount_create(void);
extern void ipcount_destroy(struct ip_count* c);

/**
 * Return the number of connections currently counted for the given address
 * (0 if the address is not tracked).
 */
extern size_t ipcount_get(struct ip_count* c, const struct ip_addr_encap* addr);

/** Add one to the count for the given address. */
extern void ipcount_increment(struct ip_count* c, const struct ip_addr_encap* addr);

/** Subtract one from the count for the given address, forgetting it at zero. */
extern void ipcount_decrement(struct ip_count* c, const struct ip_addr_encap* addr);

#endif /* HAVE_UHUB_IPCOUNT_H */
