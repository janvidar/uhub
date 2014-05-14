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

#ifndef HAVE_UHUB_EVENT_QUEUE_H
#define HAVE_UHUB_EVENT_QUEUE_H

struct event_data
{
	int id;
	void* ptr;
	int flags;
};

typedef void (*event_queue_callback)(void* callback_data, struct event_data* event_data);

struct event_queue
{
	int locked;
	struct linked_list* q1; /* primary */
	struct linked_list* q2; /* secondary, when primary is locked */
	event_queue_callback callback;
	void* callback_data;
};

extern int event_queue_initialize(struct event_queue** queue, event_queue_callback callback, void* ptr);
extern int event_queue_process(struct event_queue* queue);
extern void event_queue_shutdown(struct event_queue* queue);
extern void event_queue_post(struct event_queue* queue, struct event_data* message);
extern size_t event_queue_size(struct event_queue* queue);

#endif /* HAVE_UHUB_EVENT_QUEUE_H */

