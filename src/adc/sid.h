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

#ifndef HAVE_UHUB_SID_H
#define HAVE_UHUB_SID_H

#define SID_MAX 1048576

extern const char* BASE32_ALPHABET;
extern char* sid_to_string(sid_t sid_);
extern sid_t string_to_sid(const char* sid);

struct sid_map
{
	struct user* ptr;
	struct sid_map* next;
};

/**
 * Session IDs are heavily reused, since they are a fairly scarce
 * resource. Only one (2^10)-1 exist, since it is a four byte base32-encoded
 * value and 'AAAA' (0) is reserved for the hub.
 *
 * Initialize with sid_initialize(), which sets min and max to one, and count to 0.
 *
 * When allocating a session ID:
 * - If 'count' is less than the pool size (max-min), then allocate within the pool
 * - Increase the pool size (see below)
 * - If unable to do that, hub is really full - don't let anyone in!
 *
 * When freeing a session ID:
 * - If the session ID being freed is 'max', then decrease the pool size by one.
 *
 */
struct sid_pool
{
	sid_t min;
	sid_t max;
	sid_t count;
	struct sid_map* map;
};


extern void sid_initialize(struct sid_pool*);
extern sid_t sid_alloc(struct sid_pool*, struct user*);
extern void sid_free(struct sid_pool*, sid_t);



#endif /* HAVE_UHUB_SID_H */

