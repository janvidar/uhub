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

#ifndef HAVE_UHUB_TIMEOUT_HANDLER_H
#define HAVE_UHUB_TIMEOUT_HANDLER_H

struct timeout_evt;
struct timeout_queue;

typedef void (*timeout_evt_cb)(struct timeout_evt*);

struct timeout_evt
{
	time_t timestamp;
	timeout_evt_cb callback;
	void* ptr;
	struct timeout_evt* prev;
	struct timeout_evt* next;
};

void timeout_evt_initialize(struct timeout_evt*, timeout_evt_cb, void* ptr);
void timeout_evt_reset(struct timeout_evt*);
int  timeout_evt_is_scheduled(struct timeout_evt*);


struct timeout_queue
{
	time_t last;
	size_t max;
	struct timeout_evt lock;
	struct timeout_evt** events;
};

void timeout_queue_initialize(struct timeout_queue*, time_t now, size_t max);
void timeout_queue_shutdown(struct timeout_queue*);
size_t timeout_queue_process(struct timeout_queue*, time_t now);
void timeout_queue_insert(struct timeout_queue*, struct timeout_evt*, size_t seconds);
void timeout_queue_remove(struct timeout_queue*, struct timeout_evt*);
void timeout_queue_reschedule(struct timeout_queue*, struct timeout_evt*, size_t seconds);

size_t timeout_queue_get_next_timeout(struct timeout_queue*, time_t now);

#endif /* HAVE_UHUB_TIMEOUT_HANDLER_H */
