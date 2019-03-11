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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include "uhub.h"

#define CBUF_FLAG_CONST_BUFFER 0x01
#define MAX_MSG_LEN 16384

struct cbuffer
{
	size_t capacity;
	size_t size;
	size_t flags;
	char* buf;
};

extern struct cbuffer* cbuf_create(size_t capacity)
{
	struct cbuffer* buf = hub_malloc(sizeof(struct cbuffer));
	buf->capacity = capacity;
	buf->size = 0;
	buf->flags = 0;
	buf->buf = hub_malloc(capacity + 1);
	buf->buf[0] = '\0';
	return buf;
}

struct cbuffer* cbuf_create_const(const char* buffer)
{
	struct cbuffer* buf = hub_malloc(sizeof(struct cbuffer));
	buf->capacity = 0;
	buf->size = strlen(buffer);
	buf->flags = CBUF_FLAG_CONST_BUFFER;
	buf->buf = (char*) buffer;
	return buf;
}

void cbuf_destroy(struct cbuffer* buf)
{
	if (!(buf->flags & CBUF_FLAG_CONST_BUFFER))
	{
		hub_free(buf->buf);
	}
	hub_free(buf);
}

void cbuf_resize(struct cbuffer* buf, size_t capacity)
{
	uhub_assert(buf->flags == 0);
	buf->capacity = capacity;
	buf->buf = hub_realloc(buf->buf, capacity + 1);
}

void cbuf_append_bytes(struct cbuffer* buf, const char* msg, size_t len)
{
	uhub_assert(buf->flags == 0);
	if (buf->size + len >= buf->capacity)
		cbuf_resize(buf, buf->size + len);

	memcpy(buf->buf + buf->size, msg, len);
	buf->size += len;
	buf->buf[buf->size] = '\0';
}

void cbuf_append(struct cbuffer* buf, const char* msg)
{
	size_t len = strlen(msg);
	uhub_assert(buf->flags == 0);
	cbuf_append_bytes(buf, msg, len);
}

void cbuf_append_format(struct cbuffer* buf, const char* format, ...)
{
	static char tmp[MAX_MSG_LEN];
	va_list args;
	int bytes;
	uhub_assert(buf->flags == 0);
	va_start(args, format);
	bytes = vsnprintf(tmp, sizeof(tmp), format, args);
	va_end(args);
	cbuf_append_bytes(buf, tmp, bytes);
}

void cbuf_append_strftime(struct cbuffer* buf, const char* format, const struct tm* tm)
{
	static char tmp[MAX_MSG_LEN];
	int bytes;
	uhub_assert(buf->flags == 0);
	bytes = strftime(tmp, sizeof(tmp), format, tm);
	cbuf_append_bytes(buf, tmp, bytes);
}

const char* cbuf_get(struct cbuffer* buf)
{
	return buf->buf;
}

size_t cbuf_size(struct cbuffer* buf)
{
	return buf->size;
}
