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

#ifndef HAVE_UHUB_FUSE_BRIDGE_H
#define HAVE_UHUB_FUSE_BRIDGE_H

#include "system.h"

struct fs_bridge;
struct fs_task;

/**
 * The one place the two threads meet.
 *
 * uhub's event loop, the ADC client, the roster and the transfer machinery are
 * single threaded and none of it is reentrant; libfuse calls in on its own
 * threads whenever the kernel has a request. So the ADC thread owns all of it
 * and a FUSE thread owns none of it: a filesystem operation is packed into a
 * task, handed over, and waited for.
 *
 * The handover wakes the event loop through net_notify_*, the same self-pipe
 * the DNS resolver uses to get the main thread out of a blocking poll. Polling
 * for work instead -- the way net_dns_process() is called once per loop -- would
 * put the length of one poll timeout in front of every ls.
 *
 * A task is either answered while it is being run (the ordinary case: reading
 * the roster is a memory access) or parked, to be completed later when a
 * download finishes or a timeout fires. The FUSE thread cannot tell the two
 * apart; it blocks until an answer exists either way.
 */

/** Returned by a task that will be completed later. Results are 0 or -errno. */
#define FS_TASK_PARKED 1

/**
 * Run one operation on the ADC thread.
 *
 * @param session the session passed to fs_bridge_create().
 * @param task    the task; the operation's own payload is whatever struct
 *                embeds it.
 * @return 0 or a negative errno when the task is finished, or FS_TASK_PARKED
 *         when fs_bridge_complete() will be called for it later.
 */
typedef int (*fs_task_fn)(void* session, struct fs_task* task);

struct fs_task
{
	fs_task_fn run;

	/**
	 * Detach a parked task, for a request that is being given up on.
	 *
	 * Called on the ADC thread, and only for a task that is still parked, so
	 * whoever holds a pointer to it can drop that pointer before the waiter's
	 * stack goes away. Leave it NULL for a task that never parks.
	 */
	fs_task_fn abandon;

	int result;            /** 0 or -errno; valid once @c done is set. */
	int done;

	/**
	 * The bridge's queue link while queued, and the parker's to use once the
	 * task has parked -- fs_transfer_want() chains everybody waiting for the
	 * same hash through it. Not touched by the bridge after run() has parked
	 * the task.
	 */
	struct fs_task* next;
};

/**
 * Set up a task: the function to run it, and no abandon hook.
 *
 * Every field the bridge reads is set here, so a caller cannot leave one as
 * whatever was on the stack. A task that can park sets @c abandon afterwards.
 */
static inline void fs_task_init(struct fs_task* task, fs_task_fn run)
{
	task->run = run;
	task->abandon = NULL;
	task->result = 0;
	task->done = 0;
	task->next = NULL;
}

/**
 * @param session passed to every task's run function. Not owned.
 * @return NULL if the notification handle could not be created.
 */
extern struct fs_bridge* fs_bridge_create(void* session);

extern void fs_bridge_destroy(struct fs_bridge* bridge);

/**
 * Hand @p task to the ADC thread and wait for its answer. Called on a FUSE
 * thread.
 *
 * @return the task's result, or -ENOTCONN once the bridge has been shut down.
 */
extern int fs_bridge_submit(struct fs_bridge* bridge, struct fs_task* task);

/**
 * Answer a parked task. Called on the ADC thread.
 *
 * The task is the waiter's stack memory and is dead the moment this returns:
 * it may be freed under the caller before the next instruction.
 */
extern void fs_bridge_complete(struct fs_bridge* bridge, struct fs_task* task, int result);

/**
 * Fail everything queued and refuse everything to come, with -ENOTCONN.
 *
 * The ADC thread calls this when it stops. A FUSE thread blocked on a task
 * whose answer will now never arrive would otherwise hang the mount, and an
 * unmount cannot proceed while a request is in flight.
 *
 * Tasks already parked belong to whoever parked them; this does not touch
 * them, so a parked task must be failed by its owner during teardown.
 */
extern void fs_bridge_shutdown(struct fs_bridge* bridge);

/**
 * Give up on a request the caller is no longer waiting for.
 *
 * The FUSE thread calls this when the kernel says its request has been
 * interrupted -- a reader hitting ^C on a download that has not arrived. The
 * detaching itself happens on the ADC thread, so a task cannot be abandoned
 * and completed at the same time, and the waiter's stack is never written to
 * after this returns.
 *
 * @return the task's result if it completed after all, or -EINTR.
 */
extern int fs_bridge_abandon(struct fs_bridge* bridge, struct fs_task* task);

/**
 * Say how to ask whether the current request has been interrupted.
 *
 * The bridge polls this while waiting. It exists so that bridge.c needs to know
 * nothing about libfuse; fs.c passes fuse_interrupted().
 */
extern void fs_bridge_set_interrupt_check(struct fs_bridge* bridge, int (*check)(void));

/**
 * Wake the event loop without submitting anything.
 *
 * The ADC thread spends its time blocked in a poll, so a flag another thread
 * sets is not noticed until something happens on a socket. This is how the
 * flag gets looked at. Safe from any thread.
 */
extern void fs_bridge_wake(struct fs_bridge* bridge);

/** Has fs_bridge_shutdown() been called? Safe from either thread. */
extern int fs_bridge_is_down(struct fs_bridge* bridge);

#endif /* HAVE_UHUB_FUSE_BRIDGE_H */
