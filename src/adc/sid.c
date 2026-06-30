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

#include "system.h"
#include "util/memory.h"
#include "adc/adctypes.h"
#include "adc/sid.h"

const char* BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

char* sid_to_string(sid_t sid_)
{
	/*
	 * Rotate over a small ring of static buffers so two calls in the
	 * same expression don't alias -- e.g. printf("%s -> %s",
	 * sid_to_string(a), sid_to_string(b)) used to print b twice.
	 */
	static char t_sid[8][5];
	static unsigned int slot = 0;
	char* buf = t_sid[slot];
	sid_t sid = (sid_ & 0xFFFFF); /*  20 bits only */
	sid_t A, B, C, D = 0;
	slot = (slot + 1) % 8;
	D     = (sid % 32);
	sid   = (sid - D) / 32;
	C     = (sid % 32);
	sid   = (sid - C) / 32;
	B     = (sid % 32);
	sid   = (sid - B) / 32;
	A     = (sid % 32);
	buf[0] = BASE32_ALPHABET[A];
	buf[1] = BASE32_ALPHABET[B];
	buf[2] = BASE32_ALPHABET[C];
	buf[3] = BASE32_ALPHABET[D];
	buf[4] = 0;
	return buf;
}


sid_t string_to_sid(const char* sid)
{
	sid_t nsid = 0;
	sid_t n, x;
	sid_t factors[] = { 32768, 1024, 32, 1};

	if (!sid || strlen(sid) != 4) return 0;

	for (n = 0; n < 4; n++) {
		for (x = 0; x < strlen(BASE32_ALPHABET); x++)
			if (sid[n] == BASE32_ALPHABET[x]) break;
		if (x == 32) return 0;
		nsid += x * factors[n];
	}
	return nsid;
}

/*
 * SIDs are a four-character base32 value, so the whole space is 32^4 ≈ 1M
 * (SID_MAX); 'AAAA' (0) is reserved for the hub and never handed out. They are
 * a scarce, heavily-reused resource, so the pool is a direct-indexed table.
 *
 * The pool separates the lookup MAP from the allocation WINDOW:
 *  - map_size    entries in `map`, indexable by any SID in [1, map_size).
 *  - [min, max]  the window this node allocates its own (local) SIDs from.
 *
 * For a stand-alone hub the window spans the whole map (sid_pool_create). For a
 * linked/federated node, each node owns a disjoint window of the shared space
 * (sid_pool_create_range) so SIDs stay globally unique across the cluster,
 * while the full map still resolves remote SIDs that the link layer inserts
 * outside the local window. `count` tracks only local (in-window) allocations,
 * and `cursor` rotates the probe so allocation is amortized O(1).
 */

struct sid_pool
{
	sid_t map_size; /* number of entries in `map` */
	sid_t min;      /* first allocatable (local) SID, inclusive */
	sid_t max;      /* last allocatable (local) SID, inclusive */
	sid_t count;    /* SIDs currently allocated within [min, max] */
	sid_t cursor;   /* rotating probe offset within the [min, max] window */
	struct hub_user** map;
};

static struct sid_pool* sid_pool_alloc(sid_t map_size, sid_t min, sid_t max)
{
	struct sid_pool* pool = hub_malloc(sizeof(struct sid_pool));
	if (!pool)
		return 0;

	pool->map_size = map_size;
	pool->min      = (min < 1) ? 1 : min; /* SID 0 is reserved for the hub */
	pool->max      = (max >= map_size) ? (map_size - 1) : max;
	pool->count    = 0;
	pool->cursor   = 0;
	pool->map = hub_malloc_zero(sizeof(struct hub_user*) * map_size);
	if (!pool->map)
	{
		hub_free(pool);
		return 0;
	}
	return pool;
}

struct sid_pool* sid_pool_create(sid_t max)
{
	/* Stand-alone hub: map sized to match, window spans SIDs 1..max. */
	return sid_pool_alloc(max + 1, 1, max);
}

struct sid_pool* sid_pool_create_range(sid_t map_size, sid_t min, sid_t max)
{
	/* Federated node: allocate local SIDs from [min, max] within a map that
	   spans the whole cluster SID space, so remote users inserted later by the
	   link layer resolve through the same lookup table. */
	return sid_pool_alloc(map_size, min, max);
}

void sid_pool_destroy(struct sid_pool* pool)
{
	hub_free(pool->map);
	hub_free(pool);
}

sid_t sid_alloc(struct sid_pool* pool, struct hub_user* user)
{
	sid_t window = pool->max - pool->min + 1;
	sid_t i;

	if (pool->count >= window)
		return 0; /* local window exhausted */

	for (i = 0; i < window; i++)
	{
		sid_t sid = pool->min + ((pool->cursor + i) % window);
		if (!pool->map[sid])
		{
			pool->map[sid] = user;
			pool->cursor = (pool->cursor + i + 1) % window;
			pool->count++;
			return sid;
		}
	}
	return 0; /* unreachable while count < window */
}

int sid_pool_insert(struct sid_pool* pool, sid_t sid, struct hub_user* user)
{
	/* Register a user at a specific, already-assigned SID -- used for remote
	   users learned over a link, whose SID comes from the peer node's window
	   (outside this node's local [min, max], so pool->count is untouched). */
	if (!sid || sid >= pool->map_size)
		return 0; /* out of range */
	if (pool->map[sid])
		return 0; /* SID already in use */
	pool->map[sid] = user;
	return 1;
}

void sid_free(struct sid_pool* pool, sid_t sid)
{
	if (!sid || sid >= pool->map_size)
		return;
	if (!pool->map[sid])
		return;
	pool->map[sid] = 0;
	/* Only local (in-window) allocations are counted; remote SIDs are not. */
	if (sid >= pool->min && sid <= pool->max)
		pool->count--;
}

struct hub_user* sid_lookup(struct sid_pool* pool, sid_t sid)
{
	if (!sid || sid >= pool->map_size)
		return 0;
	return pool->map[sid];
}
