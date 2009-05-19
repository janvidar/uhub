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

#ifndef HAVE_UHUB_HUB_IO_H
#define HAVE_UHUB_HUB_IO_H

/*
 * Used as a basis for receive queue, and send queue.
 */
struct hub_iobuf
{
	char* buf;
	size_t offset;
	size_t size;
	size_t capacity;
};

typedef int (*hub_iobuf_write)(void* desc, const void* buf, size_t len);
typedef int (*hub_iobuf_read)(void* desc, void* buf, size_t len);


/**
 * Create and initialize a io buffer
 */
extern struct hub_iobuf* hub_iobuf_create(size_t max_size);

/**
 * Destroy an io buffer.
 */
extern void hub_iobuf_destroy(struct hub_iobuf*);

/**
 * net_read() from a socket descriptor into a buffer.
 * @return value from net_recv()
 */
extern int hub_iobuf_recv(struct hub_iobuf*, hub_iobuf_read, void* data);

/**
 * net_send() data from a buffer to a socket descriptor.
 * @return value from net_send()
 */
extern int hub_iobuf_send(struct hub_iobuf*, hub_iobuf_write, void* data);

/**
 * Get a line from the buffer
 */
extern char* hub_iobuf_getline(struct hub_iobuf*, size_t* offset, size_t* length, size_t max_size);

/**
 * Removes the first 'n' bytes from the buffer.
 * This will reset the offset and size parameters.
 */
extern void hub_iobuf_remove(struct hub_iobuf* buf, size_t n);

#endif /* HAVE_UHUB_HUB_IO_H */