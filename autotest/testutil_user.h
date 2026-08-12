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

#ifndef HAVE_UHUB_TESTUTIL_USER_H
#define HAVE_UHUB_TESTUTIL_USER_H

/**
 * A fake user whose send queue can be read back, so a test can assert on the
 * exact bytes the hub decided to send.
 *
 * route_to_user() needs three things and no socket: a non-NULL connection (it
 * refuses to queue for a user without one), a real send queue, and a hub with a
 * write queue to mark the user dirty on. All three are cheap to fake -- the
 * connection is never bound to a file descriptor and is never written to -- and
 * struct ioq_send exposes its message list, so what the hub queued is right
 * there to be inspected.
 *
 * This is header-only because each .tcc is its own translation unit; including
 * it twice in one binary is fine, the functions are static.
 *
 * Everything here is test scaffolding: it allocates with the hub allocator and
 * frees through tu_user_destroy(), and does not go near the login state machine.
 */

#include <string.h>

#include "adc/message.h"
#include "core/hub.h"
#include "core/ioqueue.h"
#include "core/user.h"
#include "network/connection.h"
#include "util/list.h"
#include "util/memory.h"

/* Copy into a fixed-size field, truncating rather than overrunning and always
   terminating. strncpy warns here under -Wstringop-truncation: a CID is exactly
   as long as the field it goes in, so the terminator would be the byte dropped. */
static inline void tu_copy_field(char* dst, size_t size, const char* src)
{
	size_t len;
	if (!src)
		return;
	len = strlen(src);
	if (len > size - 1)
		len = size - 1;
	memcpy(dst, src, len);
	dst[len] = '\0';
}

/**
 * Build a logged-in user with an inspectable send queue.
 *
 * @param hub the hub the user belongs to. May be NULL if nothing will be routed.
 * @return the user, or NULL on allocation failure. Free with tu_user_destroy().
 */
static inline struct hub_user* tu_user_create(struct hub_info* hub, sid_t sid, const char* nick,
                                       const char* cid, enum auth_credentials credentials)
{
	struct hub_user* user = (struct hub_user*) hub_malloc_zero(sizeof(struct hub_user));
	if (!user)
		return NULL;

	user->connection = (struct net_connection*) hub_malloc_zero(sizeof(struct net_connection));
	user->send_queue = ioq_send_create();
	if (!user->connection || !user->send_queue)
	{
		hub_free(user->connection);
		hub_free(user);
		return NULL;
	}

	user->hub = hub;
	user->id.sid = sid;
	user->state = state_normal;
	user->credentials = credentials;
	tu_copy_field(user->id.nick, sizeof(user->id.nick), nick);
	tu_copy_field(user->id.cid, sizeof(user->id.cid), cid);

	return user;
}

/** Number of messages currently queued for the user. */
static inline size_t tu_queue_count(struct hub_user* user)
{
	if (!user || !user->send_queue)
		return 0;
	return list_size(user->send_queue->queue);
}

/**
 * The raw wire line of a queued message, newline included.
 *
 * @return the line, valid until the queue is cleared, or NULL if there is no
 *         message at @p index.
 */
static inline const char* tu_queue_line(struct hub_user* user, size_t index)
{
	struct adc_message* msg;

	if (!user || !user->send_queue)
		return NULL;

	msg = (struct adc_message*) list_get_index(user->send_queue->queue, index);
	return msg ? msg->cache : NULL;
}

/**
 * @return 1 if any queued message's wire line is exactly @p line.
 */
static inline int tu_queue_has(struct hub_user* user, const char* line)
{
	size_t i, n = tu_queue_count(user);
	for (i = 0; i < n; i++)
	{
		const char* queued = tu_queue_line(user, i);
		if (queued && strcmp(queued, line) == 0)
			return 1;
	}
	return 0;
}

/**
 * @return the index of the first queued message starting with @p prefix, or -1.
 */
static inline int tu_queue_find(struct hub_user* user, const char* prefix)
{
	size_t i, n = tu_queue_count(user);
	size_t len = strlen(prefix);
	for (i = 0; i < n; i++)
	{
		const char* queued = tu_queue_line(user, i);
		if (queued && strncmp(queued, prefix, len) == 0)
			return (int) i;
	}
	return -1;
}

/**
 * Drop everything queued so far, so the next assertion starts from empty.
 *
 * The queue has no public "remove one" -- draining it is the socket's job --
 * so this replaces it wholesale, which releases the queued messages' references
 * exactly as a real drain would.
 */
static inline void tu_queue_clear(struct hub_user* user)
{
	if (!user || !user->send_queue)
		return;

	ioq_send_destroy(user->send_queue);
	user->send_queue = ioq_send_create();

	/* A cleared queue is no longer waiting to be written. */
	if (user->hub && user->hub->write_queue && user_flag_get(user, flag_dirty))
	{
		list_remove(user->hub->write_queue, user);
		user_flag_unset(user, flag_dirty);
	}
}

static inline void tu_user_destroy(struct hub_user* user)
{
	if (!user)
		return;

	/* The user may still be marked dirty from a route; take it out of the
	   hub's write queue before the memory goes away. */
	if (user->hub && user->hub->write_queue && user_flag_get(user, flag_dirty))
		list_remove(user->hub->write_queue, user);

	ioq_send_destroy(user->send_queue);
	hub_free(user->connection);
	hub_free(user);
}

#endif /* HAVE_UHUB_TESTUTIL_USER_H */
