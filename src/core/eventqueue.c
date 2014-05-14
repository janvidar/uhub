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

#ifdef EQ_DEBUG
static void eq_debug(const char* prefix, struct event_data* data)
{
	LOG_DUMP(">>> %s: %p, id: %x, flags=%d\n", prefix, data, data->id, data->flags);
}
#endif


int event_queue_initialize(struct event_queue** queue, event_queue_callback callback, void* ptr)
{
	*queue = (struct event_queue*) hub_malloc_zero(sizeof(struct event_queue));
	if (!(*queue))
		return -1;

	(*queue)->q1 = list_create();
	(*queue)->q2 = list_create();

	if (!(*queue)->q1 || !(*queue)->q2)
	{
		list_destroy((*queue)->q1);
		list_destroy((*queue)->q2);
		return -1;
	}

	(*queue)->callback = callback;
	(*queue)->callback_data = ptr;

	return 0;
}


void event_queue_shutdown(struct event_queue* queue)
{
	/* Should be empty at this point! */
	list_destroy(queue->q1);
	list_destroy(queue->q2);
	hub_free(queue);
}

static void event_queue_cleanup_callback(void* ptr)
{
#ifdef EQ_DEBUG
	struct event_data* data = (struct event_data*) ptr;
	eq_debug("NUKE", data);
#endif

	hub_free((struct event_data*) ptr);
}

int event_queue_process(struct event_queue* queue)
{
	struct event_data* data;
	if (queue->locked)
		return 0;

	/* lock primary queue, and handle the primary queue messages. */
	queue->locked = 1;

	LIST_FOREACH(struct event_data*, data, queue->q1,
	{
#ifdef EQ_DEBUG
		eq_debug("EXEC", data);
#endif
		queue->callback(queue->callback_data, data);
	});

	list_clear(queue->q1, event_queue_cleanup_callback);
	uhub_assert(list_size(queue->q1) == 0);

	/* unlock queue */
	queue->locked = 0;

	/* transfer from secondary queue to the primary queue. */
	list_append_list(queue->q1, queue->q2);

	/* if more events exist, schedule it */
	if (list_size(queue->q1))
	{
		return 1;
	}
	return 0;
}

void event_queue_post(struct event_queue* queue, struct event_data* message)
{
	struct linked_list* q = (!queue->locked) ? queue->q1 : queue->q2;
	struct event_data* data;

	data = (struct event_data*) hub_malloc(sizeof(struct event_data));
	if (data)
	{
		data->id    = message->id;
		data->ptr   = message->ptr;
		data->flags = message->flags;

#ifdef EQ_DEBUG
		eq_debug("POST", data);
#endif

		list_append(q, data);
	}
	else
	{
		LOG_ERROR("event_queue_post: OUT OF MEMORY");
	}
}


size_t event_queue_size(struct event_queue* queue)
{
	return list_size(queue->q1) + list_size(queue->q2);
}



