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

#include "fuse/chatlog.h"
#include "util/memory.h"

struct fs_chatlog* fs_chatlog_create(size_t capacity)
{
	struct fs_chatlog* log = (struct fs_chatlog*) hub_malloc_zero(sizeof(struct fs_chatlog));

	if (!log)
		return NULL;

	log->capacity = capacity ? capacity : FS_CHATLOG_SIZE;
	log->data = (char*) hub_malloc(log->capacity);

	if (!log->data)
	{
		hub_free(log);
		return NULL;
	}

	return log;
}

void fs_chatlog_destroy(struct fs_chatlog* log)
{
	if (!log)
		return;

	hub_free(log->data);
	hub_free(log);
}

void fs_chatlog_clear(struct fs_chatlog* log)
{
	if (!log)
		return;

	/* The offsets do not go backwards: a reader holding one from before the
	   clear must not be handed unrelated bytes as though they were the ones it
	   asked for. */
	log->used = 0;
	log->head = 0;
	log->base = log->end;
}

void fs_chatlog_append(struct fs_chatlog* log, const char* data, size_t len)
{
	size_t tail;
	size_t first;

	if (!log || !data || !len)
		return;

	/* More than fits: everything already held is going anyway, so keep the
	   last capacity bytes of what has just arrived. */
	if (len >= log->capacity)
	{
		data += len - log->capacity;
		log->end += len - log->capacity;
		len = log->capacity;
		log->used = 0;
		log->head = 0;
		log->base = log->end;
	}

	/* Evict from the front for whatever room is still missing. */
	if (len > log->capacity - log->used)
	{
		size_t evict = len - (log->capacity - log->used);

		log->head = (log->head + evict) % log->capacity;
		log->used -= evict;
		log->base += evict;
	}

	tail = (log->head + log->used) % log->capacity;
	first = log->capacity - tail;
	if (first > len)
		first = len;

	memcpy(&log->data[tail], data, first);
	if (len > first)
		memcpy(log->data, &data[first], len - first);

	log->used += len;
	log->end += len;
}

void fs_chatlog_append_line(struct fs_chatlog* log, const char* line)
{
	size_t start = 0;
	size_t n;

	if (!log || !line)
		return;

	for (n = 0; line[n]; n++)
	{
		if (line[n] != '\n' && line[n] != '\r')
			continue;

		fs_chatlog_append(log, &line[start], n - start);
		fs_chatlog_append(log, " ", 1);
		start = n + 1;
	}

	fs_chatlog_append(log, &line[start], n - start);
	fs_chatlog_append(log, "\n", 1);
}

size_t fs_chatlog_read(const struct fs_chatlog* log, uint64_t offset, char* buf, size_t len)
{
	uint64_t available;
	size_t index;
	size_t first;

	if (!log || !buf || !len || offset >= log->end)
		return 0;

	/* Behind the window: give what is still held, starting at the oldest byte. */
	if (offset < log->base)
		offset = log->base;

	available = log->end - offset;
	if (available < len)
		len = (size_t) available;

	index = (size_t) ((log->head + (offset - log->base)) % log->capacity);
	first = log->capacity - index;
	if (first > len)
		first = len;

	memcpy(buf, &log->data[index], first);
	if (len > first)
		memcpy(&buf[first], log->data, len - first);

	return len;
}

uint64_t fs_chatlog_size(const struct fs_chatlog* log)
{
	return log ? log->end : 0;
}
