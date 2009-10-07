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

struct adc_message;
struct linked_list;
typedef int (*hub_recvq_write)(void* desc, const void* buf, size_t len);
typedef int (*hub_recvq_read)(void* desc, void* buf, size_t len);

struct hub_sendq
{
	size_t               size;      /** Size of send queue (in bytes, not messages) */
	size_t               offset;    /** Queue byte offset in the first message. Should be 0 unless a partial write. */
#ifdef SSL_SUPPORT
	size_t               last_send; /** When using SSL, one have to send the exact same buffer and length if a write cannot complete. */
#endif
	struct linked_list*  queue;     /** List of queued messages */
};

struct hub_recvq
{
	char* buf;
	size_t size;
};

/**
 * Create a send queue
 */
extern struct hub_sendq* hub_sendq_create();

/**
 * Destroy a send queue, and delete any queued messages.
 */
extern void hub_sendq_destroy(struct hub_sendq*);

/**
 * Add a message to the send queue.
 */
extern void hub_sendq_add(struct hub_sendq*, struct adc_message* msg);

/**
 * Process the send queue, and send as many messages as possible.
 * @returns -1 on error, 0 if unable to send more, 1 if more can be sent.
 */
extern int  hub_sendq_send(struct hub_sendq*, struct hub_user*);

/**
 * @returns 1 if send queue is empty, 0 otherwise.
 */
extern int hub_sendq_is_empty(struct hub_sendq*);

/**
 * @returns the number of bytes remaining to be sent in the queue.
 */
extern size_t hub_sendq_get_bytes(struct hub_sendq*);



/**
 * Create a receive queue.
 */
extern struct hub_recvq* hub_recvq_create();

/**
 * Destroy a receive queue.
 */
extern void hub_recvq_destroy(struct hub_recvq*);

/**
 * Gets the buffer, copies it into buf and deallocates it.
 * NOTE: bufsize *MUST* be larger than the buffer, otherwise it asserts.
 * @return the number of bytes copied into buf.
 */
extern size_t hub_recvq_get(struct hub_recvq*, void* buf, size_t bufsize);

/**
 * Sets the buffer
 */
extern size_t hub_recvq_set(struct hub_recvq*, void* buf, size_t bufsize);

/**
 * @return 1 if size is zero, 0 otherwise.
 */
extern int hub_recvq_is_empty(struct hub_recvq* buf);



#endif /* HAVE_UHUB_HUB_IO_H */
