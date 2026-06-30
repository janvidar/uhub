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

#ifndef HAVE_UHUB_SID_H
#define HAVE_UHUB_SID_H

#include <stdint.h>
#include "adc/adcconst.h"

#define SID_MAX 1048576

struct sid_pool;
struct hub_user;

extern char* sid_to_string(sid_t sid_);
extern sid_t string_to_sid(const char* sid);

extern struct sid_pool* sid_pool_create(sid_t max);

/**
 * Create a SID pool for a federated node: local SIDs are allocated from the
 * window [min, max], while `map_size` covers the whole shared cluster SID space
 * (so remote SIDs inserted by the link layer resolve through the same table).
 */
extern struct sid_pool* sid_pool_create_range(sid_t map_size, sid_t min, sid_t max);

/**
 * Set (or replace) the local allocation window of an existing pool — used to
 * apply a SID window leased dynamically from the cluster after startup. The
 * lookup map is unchanged. Intended for a pool created with an empty window
 * (min=1, max=0), before any local SIDs have been allocated.
 */
extern void sid_pool_set_window(struct sid_pool*, sid_t min, sid_t max);

extern void sid_pool_destroy(struct sid_pool*);

extern sid_t sid_alloc(struct sid_pool*, struct hub_user*);

/**
 * Register a user at a specific, already-assigned SID (e.g. a remote user
 * learned over a link, whose SID belongs to a peer node's window). Does not
 * consume from the local allocation window.
 * @return 1 on success, 0 if the SID is out of range or already in use.
 */
extern int sid_pool_insert(struct sid_pool*, sid_t sid, struct hub_user*);

extern void sid_free(struct sid_pool*, sid_t);
extern struct hub_user* sid_lookup(struct sid_pool*, sid_t);



#endif /* HAVE_UHUB_SID_H */

