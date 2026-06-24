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
#include "adc/message.h"
#include "network/connection.h"
#include "network/tls.h"
#include "core/ioqueue.h"

/* Upper bounds on how much of the send queue is drained in a single syscall:
   the iovec count for plaintext writev(), and the byte span coalesced into the
   scratch buffer for a single TLS SSL_write(). Both are advisory -- the queue is
   drained across multiple ioq_send_send() calls when it exceeds these. */
#define IOQ_COALESCE_MAX_IOV   64
#define IOQ_COALESCE_MAX_BYTES (64 * 1024)

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
		hub_free(q->scratch);
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

/*
 * Drop `sent` bytes from the front of the queue: remove every message that is
 * now fully sent and leave q->offset pointing into the first partially-sent one.
 */
static void ioq_send_consume(struct ioq_send* q, size_t sent)
{
	while (sent > 0)
	{
		struct adc_message* msg = list_get_first(q->queue);
		size_t remain = msg->length - q->offset;
		if (sent >= remain)
		{
			sent -= remain;
			ioq_send_remove(q, msg); /* resets q->offset to 0 */
		}
		else
		{
			q->offset += sent;
			sent = 0;
		}
	}
}

/*
 * Copy the front of the queue (starting at q->offset) into q->scratch at message
 * boundaries, up to IOQ_COALESCE_MAX_BYTES but always at least the first message.
 * Used for TLS, where SSL_write() takes a single contiguous buffer. Returns the
 * number of bytes coalesced, or 0 on allocation failure.
 */
static size_t ioq_coalesce(struct ioq_send* q)
{
	struct adc_message* msg;
	size_t off = q->offset;
	size_t total = 0;
	size_t pos = 0;

	for (msg = list_get_first(q->queue); msg; msg = (struct adc_message*) list_get_next(q->queue))
	{
		size_t span = msg->length - off;
		if (total && total + span > IOQ_COALESCE_MAX_BYTES)
			break;
		total += span;
		off = 0;
	}
	if (total == 0)
		return 0;

	if (q->scratch_cap < total)
	{
		char* buf = hub_realloc(q->scratch, total);
		if (!buf)
			return 0; /* OOM: retried on a later call */
		q->scratch = buf;
		q->scratch_cap = total;
	}

	off = q->offset;
	for (msg = list_get_first(q->queue); msg && pos < total; msg = (struct adc_message*) list_get_next(q->queue))
	{
		size_t span = msg->length - off;
		memcpy(q->scratch + pos, msg->cache + off, span);
		pos += span;
		off = 0;
	}
	return total;
}

int ioq_send_send(struct ioq_send* q, struct net_connection* con)
{
	struct adc_message* msg = list_get_first(q->queue);
	ssize_t ret;

	if (!msg) return 0;
	uhub_assert(msg->cache && *msg->cache);

	if (net_con_is_ssl(con))
	{
		/* TLS: SSL_write() has no iovec form and is all-or-nothing, and a
		   blocked write must be retried with the exact same buffer and length.
		   Coalesce the front messages into a persistent scratch buffer once,
		   pinned by q->last_send, so a retry resends identical bytes even if
		   more messages were queued while we were blocked. */
		if (q->last_send == 0)
		{
			q->last_send = ioq_coalesce(q);
			if (q->last_send == 0)
				return 0; /* OOM */
		}

		ret = net_con_send(con, q->scratch, q->last_send);
		if (ret > 0)
		{
			/* all-or-nothing: ret == q->last_send */
			ioq_send_consume(q, (size_t) ret);
			q->last_send = 0;
			return 1;
		}
		return (int) ret;
	}

#ifdef HAVE_FUNC_WRITEV
	{
		struct iovec iov[IOQ_COALESCE_MAX_IOV];
		size_t requested = 0;
		size_t off = q->offset;
		int n = 0;

		for (; msg && n < IOQ_COALESCE_MAX_IOV; msg = (struct adc_message*) list_get_next(q->queue))
		{
			iov[n].iov_base = msg->cache + off;
			iov[n].iov_len = msg->length - off;
			requested += iov[n].iov_len;
			off = 0;
			n++;
		}

		ret = net_con_writev(con, iov, n);
		if (ret > 0)
		{
			ioq_send_consume(q, (size_t) ret);
			return ((size_t) ret == requested) ? 1 : 0;
		}
		return (int) ret;
	}
#else
	ret = net_con_send(con, msg->cache + q->offset, msg->length - q->offset);
	if (ret > 0)
	{
		q->offset += ret;
		if (msg->length - q->offset > 0)
			return 0;

		ioq_send_remove(q, msg);
		return 1;
	}
	return (int) ret;
#endif
}

int ioq_send_is_empty(struct ioq_send* q)
{
	return (q->size - q->offset) == 0;
}

size_t ioq_send_get_bytes(struct ioq_send* q)
{
	return q->size - q->offset;
}
