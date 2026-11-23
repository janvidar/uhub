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

#ifndef HAVE_UHUB_MEMORY_HANDLER_H
#define HAVE_UHUB_MEMORY_HANDLER_H

#include <stddef.h>

/*
 * Allocation never fails: running out of memory logs a fatal message and
 * aborts. Every allocator below (hub_malloc, hub_malloc_zero, hub_realloc,
 * hub_strdup, hub_strndup) returns non-NULL, so callers need not check -- a
 * NULL check that is already there is harmless, it just never fires.
 *
 * This is deliberate. The alternative was a NULL check, and an untested error
 * branch, after each of several hundred allocations, and the hub had a few
 * hundred places that had none: an allocation failure crashed it somewhere
 * arbitrary instead. Every allocation sized by a peer is capped well below
 * anything that could fail, so no client can steer the hub into this.
 */
extern void hub_out_of_memory(size_t size) __attribute__((noreturn));

#define hub_free       free
extern void* hub_malloc(size_t size);
extern void* hub_realloc(void* ptr, size_t size);
extern char* hub_strdup(const char* s);
extern char* hub_strndup(const char* s, size_t n);

extern void* hub_malloc_zero(size_t size);

/*
 * Free callback with a stable address and the exact void(*)(void*) signature
 * required by list_clear() / list_remove_first(). Use this instead of passing
 * the hub_free macro as a function pointer: hub_free is a macro, and its being
 * passable as a function pointer is an accident of how it expands.
 */
extern void hub_free_handle(void* ptr);

#endif /* HAVE_UHUB_MEMORY_HANDLER_H */
