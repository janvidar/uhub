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
#include "util/log.h"

void hub_out_of_memory(size_t size)
{
	/* hub_log() formats into stack buffers and writes to an already open log,
	   so it needs no memory of its own. abort() flushes nothing: flush first,
	   or the one line that says why the hub stopped is the one that is lost. */
	LOG_FATAL("Out of memory allocating " PRINTF_SIZE_T " bytes, aborting", size);
	fflush(NULL);
	abort();
}

/* A zero-byte request may legitimately come back NULL; asking for one byte
   instead keeps "NULL means out of memory" true without exception. */
void* hub_malloc(size_t size)
{
	void* ptr = malloc(size ? size : 1);
	if (!ptr)
		hub_out_of_memory(size);
	return ptr;
}

void* hub_realloc(void* ptr, size_t size)
{
	void* newptr = realloc(ptr, size ? size : 1);
	if (!newptr)
		hub_out_of_memory(size);
	return newptr;
}

char* hub_strdup(const char* s)
{
	char* copy = strdup(s);
	if (!copy)
		hub_out_of_memory(strlen(s) + 1);
	return copy;
}

char* hub_strndup(const char* s, size_t n)
{
	char* copy = strndup(s, n);
	if (!copy)
		hub_out_of_memory(strnlen(s, n) + 1);
	return copy;
}

void* hub_malloc_zero(size_t size)
{
	void* data = hub_malloc(size);
	if (data)
	{
		memset(data, 0, size);
	}
	return data;
}

void hub_free_handle(void* ptr)
{
	hub_free(ptr);
}
