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
 * along wtimeout_evtith this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "uhub.h"

void timeout_evt_initialize(struct timeout_evt* t, timeout_evt_cb cb, void* ptr)
{
	t->callback = cb;
	t->ptr = ptr;
	t->prev = 0;
	t->next = 0;
}

void timeout_evt_reset(struct timeout_evt* t)
{
	t->prev = 0;
	t->next = 0;
}

int timeout_evt_is_scheduled(struct timeout_evt* t)
{
	return t->prev != NULL;
}

void timeout_queue_initialize(struct timeout_queue* t, time_t now, size_t max)
{
	t->last = now;
	t->max = max;
	memset(&t->lock, 0, sizeof(t->lock));
	t->events = hub_malloc_zero(max * sizeof(struct timeout_evt*));
}

void timeout_queue_shutdown(struct timeout_queue* t)
{
	hub_free(t->events);
	t->events = 0;
	t->max = 0;
}

static int timeout_queue_locked(struct timeout_queue* t)
{
	return t->lock.ptr != NULL;
}

static void timeout_queue_lock(struct timeout_queue* t)
{
	t->lock.ptr = t;
}

// unlock and flush the locked events to the main timeout queue.
static void timeout_queue_unlock(struct timeout_queue* t)
{
	struct timeout_evt* evt, *tmp, *first;
	size_t pos;
	t->lock.ptr = NULL;

	evt = t->lock.next;
	while (evt)
	{
		tmp = evt->next;
		pos = evt->timestamp % t->max;
		first = t->events[pos];
		if (first)
		{
			first->prev->next = evt;
			evt->prev = first->prev;
			first->prev = evt;
		}
		else
		{
			t->events[pos] = evt;
			evt->prev = evt;
		}
		evt->next = 0;
		evt = tmp;
	}

	t->lock.next = 0;
	t->lock.prev = 0;
}


size_t timeout_queue_process(struct timeout_queue* t, time_t now)
{
	size_t pos = (size_t) t->last;
	size_t events = 0;
	struct timeout_evt* evt = 0;
	t->last = now;
	timeout_queue_lock(t);
	for (; pos <= now; pos++)
	{
		while ((evt = t->events[pos % t->max]))
		{
			timeout_queue_remove(t, evt);
			evt->callback(evt);
			events++;
		}
	}
	timeout_queue_unlock(t);
	return events;
}

size_t timeout_queue_get_next_timeout(struct timeout_queue* t, time_t now)
{
	size_t seconds = 0;
	while (t->events[(now + seconds) % t->max] == NULL && seconds < t->max)
	{
		seconds++;
	}
	if (seconds == 0)
		return 1;
	return seconds;
}

static void timeout_queue_insert_locked(struct timeout_queue* t, struct timeout_evt* evt)
{
	/* All events point back to the sentinel.
	 * this means the event is considered schedule (see timeout_evt_is_scheduled),
	 * and it is easy to tell if the event is in the wait queue or not.
	 */
	evt->prev = &t->lock;
	evt->next = NULL;

	// The sentinel next points to the first event in the locked queue
	// The sentinel prev points to the last evetnt in the locked queue.
	// NOTE: if prev is != NULL then next also must be != NULL.
	if (t->lock.prev)
	{
		t->lock.prev->next = evt;
		t->lock.prev = evt;
	}
	else
	{
		t->lock.next = evt;
		t->lock.prev = evt;
	}
	return;
}

static void timeout_queue_remove_locked(struct timeout_queue* t, struct timeout_evt* evt)
{
	uhub_assert(evt->prev == &t->lock);
	if (t->lock.next == evt)
	{
		t->lock.next = evt->next;
		if (t->lock.prev == evt)
			t->lock.prev = evt->next;
	}
	else
	{
		struct timeout_evt *prev, *it;
		prev = 0;
		it = t->lock.next;
		while (it)
		{
			prev = it;
			it = it->next;
			if (it == evt)
			{
				prev->next = it->next;
				if (!prev->next)
					t->lock.prev = prev;
			}
		}
	}
	timeout_evt_reset(evt);
}



void timeout_queue_insert(struct timeout_queue* t, struct timeout_evt* evt, size_t seconds)
{
	struct timeout_evt* first;
	size_t pos = ((t->last + seconds) % t->max);
	evt->timestamp = t->last + seconds;
	evt->next = 0;

	if (timeout_queue_locked(t))
	{
		timeout_queue_insert_locked(t, evt);
		return;
	}

	first = t->events[pos];

	if (first)
	{
		uhub_assert(first->timestamp == evt->timestamp);
		first->prev->next = evt;
		evt->prev = first->prev;
		first->prev = evt;
	}
	else
	{
		t->events[pos] = evt;
		evt->prev = evt;
	}
	evt->next = 0;
}

void timeout_queue_remove(struct timeout_queue* t, struct timeout_evt* evt)
{
	size_t pos = (evt->timestamp % t->max);
	struct timeout_evt* first = t->events[pos];

	// Removing a locked event
	if (evt->prev == &t->lock)
	{
		timeout_queue_remove_locked(t, evt);
		return;
	}

	if (!first || !evt->prev)
		return;

	if (first == evt)
	{
		if (first->prev != first)
		{
			t->events[pos] = first->next;
			t->events[pos]->prev = evt->prev;
		}
		else
		{
			t->events[pos] = 0;
		}
	}
	else if (evt == first->prev)
	{
		first->prev = evt->prev;
		evt->prev->next = 0;
	}
	else
	{
		evt->prev->next = evt->next;
		evt->next->prev = evt->prev;
	}
	timeout_evt_reset(evt);
}

void timeout_queue_reschedule(struct timeout_queue* t, struct timeout_evt* evt, size_t seconds)
{
	if (timeout_evt_is_scheduled(evt))
		timeout_queue_remove(t, evt);
	timeout_queue_insert(t, evt, seconds);
}

