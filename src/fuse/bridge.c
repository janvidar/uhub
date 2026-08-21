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

#include "fuse/bridge.h"
#include "network/notify.h"
#include "util/memory.h"
#include "util/threads.h"
#include "util/log.h"

struct fs_bridge
{
	void* session;
	struct uhub_notify_handle* notify;

	uhub_mutex_t mutex;
	uhub_cond_t cond;         /** Signalled whenever a task is completed. */

	struct fs_task* head;     /** Waiting to run, oldest first. */
	struct fs_task* tail;
	int down;

	int (*interrupted)(void);
};

/** How often a waiter looks up to see whether it is still wanted. */
#define FS_INTERRUPT_POLL_MS 200

static void bridge_drain(struct uhub_notify_handle* handle, void* ptr);

struct fs_bridge* fs_bridge_create(void* session)
{
	struct fs_bridge* bridge = (struct fs_bridge*) hub_malloc_zero(sizeof(struct fs_bridge));
	if (!bridge)
		return NULL;

	bridge->session = session;

	uhub_mutex_init(&bridge->mutex);
	uhub_cond_init(&bridge->cond);

	bridge->notify = net_notify_create(bridge_drain, bridge);
	if (!bridge->notify)
	{
		uhub_cond_destroy(&bridge->cond);
		uhub_mutex_destroy(&bridge->mutex);
		hub_free(bridge);
		return NULL;
	}

	return bridge;
}

void fs_bridge_destroy(struct fs_bridge* bridge)
{
	if (!bridge)
		return;

	fs_bridge_shutdown(bridge);

	if (bridge->notify)
		net_notify_destroy(bridge->notify);

	uhub_cond_destroy(&bridge->cond);
	uhub_mutex_destroy(&bridge->mutex);
	hub_free(bridge);
}

/** NOTE: the mutex must be held. */
static struct fs_task* queue_pop(struct fs_bridge* bridge)
{
	struct fs_task* task = bridge->head;

	if (task)
	{
		bridge->head = task->next;
		if (!bridge->head)
			bridge->tail = NULL;
		task->next = NULL;
	}

	return task;
}

void fs_bridge_complete(struct fs_bridge* bridge, struct fs_task* task, int result)
{
	uhub_mutex_lock(&bridge->mutex);
	task->result = result;
	task->done = 1;
	/* Broadcast, not signal: every waiter shares this one condition variable,
	   and only the task's own waiter can tell that it is the one that woke. */
	uhub_cond_broadcast(&bridge->cond);
	uhub_mutex_unlock(&bridge->mutex);
}

/**
 * Run everything that has been handed over. Called on the ADC thread, from the
 * event loop, whenever the notification pipe is readable.
 */
static void bridge_drain(struct uhub_notify_handle* handle, void* ptr)
{
	struct fs_bridge* bridge = (struct fs_bridge*) ptr;
	struct fs_task* task;

	(void) handle;

	for (;;)
	{
		int result;

		uhub_mutex_lock(&bridge->mutex);
		task = queue_pop(bridge);
		uhub_mutex_unlock(&bridge->mutex);

		if (!task)
			break;

		/* Run it with the lock released: an operation may take a while, may
		   park itself, and has no business serialising the other threads'
		   submissions while it does. */
		result = task->run(bridge->session, task);

		if (result != FS_TASK_PARKED)
			fs_bridge_complete(bridge, task, result);
	}
}

void fs_bridge_set_interrupt_check(struct fs_bridge* bridge, int (*check)(void))
{
	bridge->interrupted = check;
}

/**
 * The task an abandonment runs on the ADC thread.
 *
 * Both this and a completion happen there, so by the time this looks at the
 * target it has either been completed or not, and cannot change underneath.
 */
struct fs_abandon_task
{
	struct fs_task task;
	struct fs_task* target;
};

static int run_abandon(void* session, struct fs_task* task)
{
	struct fs_abandon_task* op = (struct fs_abandon_task*) task;
	struct fs_task* target = op->target;

	if (target->done)
		return 0;   /* It arrived after all; the waiter takes the result. */

	if (target->abandon)
		target->abandon(session, target);

	target->result = -EINTR;
	target->done = 1;
	return 0;
}

int fs_bridge_abandon(struct fs_bridge* bridge, struct fs_task* task)
{
	struct fs_abandon_task op;
	int result;

	memset(&op, 0, sizeof(op));
	op.task.run = run_abandon;
	op.target = task;

	/* Not itself interruptible: it is the thing that ends the waiting. */
	fs_bridge_submit(bridge, &op.task);

	uhub_mutex_lock(&bridge->mutex);
	result = task->done ? task->result : -EINTR;
	uhub_mutex_unlock(&bridge->mutex);

	return result;
}

int fs_bridge_submit(struct fs_bridge* bridge, struct fs_task* task)
{
	int result;

	task->next = NULL;
	task->done = 0;
	task->result = 0;

	uhub_mutex_lock(&bridge->mutex);

	if (bridge->down)
	{
		uhub_mutex_unlock(&bridge->mutex);
		return -ENOTCONN;
	}

	if (bridge->tail)
		bridge->tail->next = task;
	else
		bridge->head = task;
	bridge->tail = task;

	uhub_mutex_unlock(&bridge->mutex);

	/* Outside the lock: this is a write() on a pipe, and the reader takes the
	   lock. */
	net_notify_signal(bridge->notify, 1);

	uhub_mutex_lock(&bridge->mutex);
	while (!task->done)
	{
		/*
		 * A task that cannot park is answered in the time it takes to read a
		 * pointer, so waiting outright costs nothing and polling would only
		 * add wake-ups. One that can park may be waiting on a peer for a
		 * minute, and a reader that has pressed ^C should not be held for the
		 * rest of it.
		 */
		if (!task->abandon || !bridge->interrupted)
		{
			uhub_cond_wait(&bridge->cond, &bridge->mutex);
			continue;
		}

		uhub_cond_timedwait(&bridge->cond, &bridge->mutex, FS_INTERRUPT_POLL_MS);

		if (task->done || !bridge->interrupted())
			continue;

		uhub_mutex_unlock(&bridge->mutex);
		return fs_bridge_abandon(bridge, task);
	}
	result = task->result;
	uhub_mutex_unlock(&bridge->mutex);

	return result;
}

void fs_bridge_wake(struct fs_bridge* bridge)
{
	net_notify_signal(bridge->notify, 1);
}

void fs_bridge_shutdown(struct fs_bridge* bridge)
{
	struct fs_task* task;

	uhub_mutex_lock(&bridge->mutex);

	if (bridge->down)
	{
		uhub_mutex_unlock(&bridge->mutex);
		return;
	}

	bridge->down = 1;

	/* Whoever is waiting for these is waiting for a thread that has stopped. */
	while ((task = queue_pop(bridge)) != NULL)
	{
		task->result = -ENOTCONN;
		task->done = 1;
	}

	uhub_cond_broadcast(&bridge->cond);
	uhub_mutex_unlock(&bridge->mutex);
}

int fs_bridge_is_down(struct fs_bridge* bridge)
{
	int down;

	uhub_mutex_lock(&bridge->mutex);
	down = bridge->down;
	uhub_mutex_unlock(&bridge->mutex);

	return down;
}
