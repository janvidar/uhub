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

#include "uhub.h"

#ifdef DEBUG_SENDQ
static void debug_msg(const char* prefix, struct adc_message* msg)
{
	size_t n;
	char* buf = strdup(msg->cache);
	for (n = 0; n < msg->length; n++)
	{
		if (buf[n] == '\r' || buf[n] == '\n')
			buf[n] = '_';
	}
	LOG_TRACE("%s: [%s] (%d bytes)", prefix, buf, (int) msg->length);
	free(buf);
}
#endif

struct ioq_recv* ioq_recv_create()
{
	struct ioq_recv* q = hub_malloc_zero(sizeof(struct ioq_recv));
	return q;
}

void ioq_recv_destroy(struct ioq_recv* q)
{
	if (q)
	{
		hub_free(q->buf);
		hub_free(q);
	}
}

size_t ioq_recv_get(struct ioq_recv* q, void* buf, size_t bufsize)
{
	uhub_assert(bufsize >= q->size);
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

size_t ioq_recv_set(struct ioq_recv* q, void* buf, size_t bufsize)
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


struct ioq_send* ioq_send_create()
{
	struct ioq_send* q = hub_malloc_zero(sizeof(struct ioq_send));
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

void ioq_send_destroy(struct ioq_send* q)
{
	if (q)
	{
		list_clear(q->queue, &clear_send_queue_callback);
		list_destroy(q->queue);
		hub_free(q);
	}
}

void ioq_send_add(struct ioq_send* q, struct adc_message* msg_)
{
	struct adc_message* msg = adc_msg_incref(msg_);
#ifdef DEBUG_SENDQ
	debug_msg("ioq_send_add", msg);
#endif
	uhub_assert(msg->cache && *msg->cache);
	list_append(q->queue, msg);
	q->size += msg->length;
}

static void ioq_send_remove(struct ioq_send* q, struct adc_message* msg)
{
#ifdef DEBUG_SENDQ
	debug_msg("ioq_send_remove", msg);
#endif
	list_remove(q->queue, msg);
	q->size  -= msg->length;
	adc_msg_free(msg);
	q->offset = 0;
}

int ioq_send_send(struct ioq_send* q, struct net_connection* con)
{
	int ret;
	struct adc_message* msg = list_get_first(q->queue);
	if (!msg) return 0;
	uhub_assert(msg->cache && *msg->cache);
	ret = net_con_send(con, msg->cache + q->offset, msg->length - q->offset);

	if (ret > 0)
	{
		q->offset += ret;
		if (msg->length - q->offset > 0)
			return 0;

		ioq_send_remove(q, msg);
		return 1;
	}
	return ret;
}

int ioq_send_is_empty(struct ioq_send* q)
{
	return (q->size - q->offset) == 0;
}

size_t ioq_send_get_bytes(struct ioq_send* q)
{
	return q->size - q->offset;
}
