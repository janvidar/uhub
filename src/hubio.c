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

// #define SEND_CHUNKS 1

/* FIXME: This should not be needed! */
extern struct hub_info* g_hub;

struct hub_recvq* hub_recvq_create()
{
	struct hub_recvq* q = hub_malloc_zero(sizeof(struct hub_recvq));
	return q;
}

void hub_recvq_destroy(struct hub_recvq* q)
{
	if (q)
	{
		hub_free(q->buf);
		hub_free(q);
	}
}

size_t hub_recvq_get(struct hub_recvq* q, void* buf, size_t bufsize)
{
	assert(bufsize >= q->size);
	if (q->size)
	{
		size_t n = q->size;
		memcpy(buf, q->buf, n);
		hub_free(q->buf);
		q->buf = 0;
		q->size = 0;
		return n;
	}
	return 0;
}

size_t hub_recvq_set(struct hub_recvq* q, void* buf, size_t bufsize)
{
	if (q->buf)
	{
		hub_free(q->buf);
		q->buf = 0;
		q->size = 0;
	}
	
	if (!bufsize)
	{
		return 0;
	}

	q->buf = hub_malloc(bufsize);
	if (!q->buf)
		return 0;

	q->size = bufsize;
	memcpy(q->buf, buf, bufsize);
	return bufsize;
}


struct hub_sendq* hub_sendq_create()
{
	struct hub_sendq* q = hub_malloc_zero(sizeof(struct hub_sendq));
	if (!q)
		return 0;

	q->queue = list_create();
	if (!q->queue)
	{
		hub_free(q);
		return 0;
	}

	return q;
}

static void clear_send_queue_callback(void* ptr)
{
	adc_msg_free((struct adc_message*) ptr);
}

void hub_sendq_destroy(struct hub_sendq* q)
{
	if (q)
	{
		list_clear(q->queue, &clear_send_queue_callback);
		list_destroy(q->queue);
		hub_free(q);
	}
}

void hub_sendq_add(struct hub_sendq* q, struct adc_message* msg_)
{
	struct adc_message* msg = adc_msg_incref(msg_);
	list_append(q->queue, msg);
	q->size += msg->length;
}

void hub_sendq_remove(struct hub_sendq* q, struct adc_message* msg)
{
	list_remove(q->queue, msg);
	q->size  -= msg->length;
	adc_msg_free(msg);
	q->offset = 0;
}

int  hub_sendq_send(struct hub_sendq* q, hub_recvq_write w, void* data)
{
#ifdef SEND_CHUNKS
	int ret = 0;
	int bytes_sent = 0;
	
	struct adc_message* msg = list_get_first(q->queue);
	while (msg)
	{
		size_t len = msg->length - q->offset;
		ret = w(data, &msg->cache[q->offset], len);

		if (ret <= 0) break;

		q->offset += ret;
		bytes_sent += ret;

		if (q->offset < msg->length)
			break;

		hub_sendq_remove(q, msg);
		msg = list_get_first(q->queue);
	}

	return bytes_sent;
#else
	int ret = 0;
	size_t bytes = 0;
	size_t offset = q->offset; // offset into first message.
	size_t remain = 0;
	size_t length = 0;
	char* sbuf = g_hub->sendbuf;
	size_t max_send_buf = 4096;

	/* Copy as many messages possible into global send queue */
	struct adc_message* msg = list_get_first(q->queue);
	while (msg)
	{
		length = MIN(msg->length - offset, (max_send_buf-1) - bytes);
#ifdef DEBUG_SENDQ
		printf("Queued: %d bytes (%d bytes)\n", (int) length, (int) msg->length);
#endif
		
		memcpy(sbuf + bytes, msg->cache + offset, length);
		bytes += length;
		
		if (length < (msg->length - offset))
			break;
		offset = 0;
		msg = list_get_next(q->queue);
	}

	msg = list_get_first(q->queue);
#ifdef DEBUG_SENDQ
	printf("Queued up bytes: %d (first=%d/%d)\n", (int) bytes, (int) q->offset, (msg ? (int) msg->length : 0));
#endif
	/* Send as much as possible */
	ret = w(data, sbuf, bytes);
	
	if (ret > 0)
	{
		/* Remove messages sent */
		offset = q->offset;
		remain = ret;
		
		while (msg)
		{
			length = msg->length - offset;
			if (length >= remain)
			{
				q->offset += remain;
				break;
			}
#ifdef DEBUG_SENDQ
			printf("removing msg %d [%p]\n", (int) msgs, msg);
#endif
			remain -= length;
			hub_sendq_remove(q, msg);
			msg = list_get_next(q->queue);
			offset = 0;
		}
	}
	return ret;
#endif
}

int hub_sendq_is_empty(struct hub_sendq* q)
{
	return q->size == 0;
}

size_t hub_sendq_get_bytes(struct hub_sendq* q)
{
	return q->size - q->offset;
}
