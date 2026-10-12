#include "core/eventqueue.h"

/*
 * Each test makes its own queue and shuts it down again, so each one runs
 * alone or in any order.
 */

static int eq_val;

static void eq_callback(void* callback_data, struct event_data* event_data)
{
	(void) callback_data;
	eq_val += event_data->id;
}

static struct event_queue* eq_start(void)
{
	struct event_queue* eq = 0;
	eq_val = 0;
	if (event_queue_initialize(&eq, eq_callback, &eq_val) != 0)
		return NULL;
	return eq;
}

/* The queue must be empty to shut down, as the hub leaves it: drain it first. */
static void eq_stop(struct event_queue* eq)
{
	event_queue_process(eq);
	event_queue_shutdown(eq);
}

static void eq_post(struct event_queue* eq, int id)
{
	struct event_data message;
	message.id  = id;
	message.ptr = &message;
	message.flags = message.id * 2;
	event_queue_post(eq, &message);
}

EXO_TEST(eventqueue_init_1, {
	struct event_queue* eq = eq_start();
	int ok = eq && event_queue_size(eq) == 0;
	eq_stop(eq);
	return ok;
});

EXO_TEST(eventqueue_init_2, {
	struct event_queue* eq = eq_start();
	/* hack */
	int ok = eq->callback_data == &eq_val && eq->callback == eq_callback && eq->q1 && eq->q2 && !eq->locked;
	eq_stop(eq);
	return ok;
});

EXO_TEST(eventqueue_post_1, {
	struct event_queue* eq = eq_start();
	int ok;
	eq_post(eq, 0x1001);
	ok = event_queue_size(eq) == 1;
	eq_stop(eq);
	return ok;
});

EXO_TEST(eventqueue_process_1, {
	struct event_queue* eq = eq_start();
	int ok;
	eq_post(eq, 0x1001);
	event_queue_process(eq);
	ok = eq_val == 0x1001;
	eq_stop(eq);
	return ok;
});

/* Processing empties the queue. */
EXO_TEST(eventqueue_size_1, {
	struct event_queue* eq = eq_start();
	int ok;
	eq_post(eq, 0x1001);
	event_queue_process(eq);
	ok = event_queue_size(eq) == 0;
	eq_stop(eq);
	return ok;
});

EXO_TEST(eventqueue_post_2, {
	struct event_queue* eq = eq_start();
	int ok;
	eq_post(eq, 0x1002);
	ok = event_queue_size(eq) == 1;
	eq_stop(eq);
	return ok;
});

/* Posting does not deliver anything by itself. */
EXO_TEST(eventqueue_size_2, {
	struct event_queue* eq = eq_start();
	int ok;
	eq_post(eq, 0x1002);
	ok = event_queue_size(eq) == 1 && eq_val == 0;
	eq_stop(eq);
	return ok;
});

EXO_TEST(eventqueue_post_3, {
	struct event_queue* eq = eq_start();
	int ok;
	eq_post(eq, 0x1002);
	eq_post(eq, 0x1003);
	ok = event_queue_size(eq) == 2;
	eq_stop(eq);
	return ok;
});

EXO_TEST(eventqueue_size_3, {
	struct event_queue* eq = eq_start();
	int ok;
	eq_post(eq, 0x1002);
	eq_post(eq, 0x1003);
	ok = event_queue_size(eq) == 2 && eq_val == 0;
	eq_stop(eq);
	return ok;
});

/* Both queued events are delivered by one process call. */
EXO_TEST(eventqueue_process_2, {
	struct event_queue* eq = eq_start();
	int ok;
	eq_post(eq, 0x1002);
	eq_post(eq, 0x1003);
	event_queue_process(eq);
	ok = eq_val == 0x2005;
	eq_stop(eq);
	return ok;
});

EXO_TEST(eventqueue_size_4, {
	struct event_queue* eq = eq_start();
	int ok;
	eq_post(eq, 0x1002);
	eq_post(eq, 0x1003);
	event_queue_process(eq);
	ok = event_queue_size(eq) == 0;
	eq_stop(eq);
	return ok;
});

/* Shutting down once the queue has been drained. */
EXO_TEST(eventqueue_shutdown_1, {
	struct event_queue* eq = eq_start();
	eq_post(eq, 0x1001);
	event_queue_process(eq);
	event_queue_shutdown(eq);
	return 1;
});
