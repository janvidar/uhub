/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2014, Jan Vidar Krey
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

#ifndef HAVE_UHUB_MEMORY_HANDLER_H
#define HAVE_UHUB_MEMORY_HANDLER_H

#ifdef MEMORY_DEBUG

#define hub_malloc     debug_mem_malloc
#define hub_free       debug_mem_free
#define hub_strdup     debug_mem_strdup
#define hub_strndup    debug_mem_strndup
extern void* debug_mem_malloc(size_t size);
extern void  debug_mem_free(void* ptr);
extern char* debug_mem_strdup(const char* s);
extern char* debug_mem_strndup(const char* s, size_t n);

#else

#define hub_malloc     malloc
#define hub_free       free
#define hub_realloc    realloc
#define hub_strdup     strdup
#define hub_strndup    strndup


#endif

extern void* hub_malloc_zero(size_t size);

#endif /* HAVE_UHUB_MEMORY_HANDLER_H */
