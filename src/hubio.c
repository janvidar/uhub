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

#include "uhub.h"
#include "hubio.h"


struct hub_iobuf* hub_iobuf_create(size_t max_size)
{
	struct hub_iobuf* buf = hub_malloc_zero(sizeof(struct hub_iobuf));
	if (buf)
	{
		buf->buf = hub_malloc(max_size);
		buf->capacity = max_size;
	}
	return buf;
}

void hub_iobuf_destroy(struct hub_iobuf* buf)
{
	if (buf)
	{
		hub_free(buf->buf);
		hub_free(buf);
	}
}

int hub_iobuf_recv(struct hub_iobuf* buf, hub_iobuf_read r, void* data)
{
	int size = r(data, &buf->buf[buf->offset], buf->capacity - buf->offset);
	if (size > 0)
	{
		buf->size += size;
	}
	return size;
}

int hub_iobuf_send(struct hub_iobuf* buf, hub_iobuf_write w, void* data)
{
	int size = w(data, &buf->buf[buf->offset], buf->size - buf->offset);
	if (size > 0)
	{
		buf->offset += size;
	}
	return size;
}

char* hub_iobuf_getline(struct hub_iobuf* buf, size_t* offset, size_t* len, size_t max_size)
{
	size_t x = *offset;
	char* pos = memchr(&buf->buf[x], '\n', (buf->size - x));

	if (pos)
	{
		*len = &pos[0] - &buf->buf[x];
		pos[0] = '\0';
		pos = &buf->buf[x];
		(*offset) += (*len + 1);
	}
	return pos;
}

void hub_iobuf_remove(struct hub_iobuf* buf, size_t n)
{
	assert(buf);
	assert(n <= buf->size);

	buf->offset = 0;

	if (n == buf->size)
	{
		buf->size = 0;
	}

}
