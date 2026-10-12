#include "system.h"
#include "util/memory.h"
#include "network/timeout.h"

/*
 * Each test starts a fresh queue with timer_start() and shuts it down again
 * with timer_stop(), so each one runs alone or in any order.
 */

#define MAX_EVENTS 15
static struct timeout_queue* g_queue;
static time_t g_now;
static size_t g_max;
static struct timeout_evt g_events[MAX_EVENTS];

static size_t g_triggered;

static void timeout_cb(struct timeout_evt* t)
{
	(void) t;
	g_triggered++;
}

/*
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
	struct timeout_evt** events;
};

void timeout_queue_initialize(struct timeout_queue*, time_t now, size_t max);
void timeout_queue_shutdown(struct timeout_queue*);
size_t timeout_queue_process(struct timeout_queue*, time_t now);
void timeout_queue_insert(struct timeout_queue*, struct timeout_evt*, size_t seconds);
void timeout_queue_remove(struct timeout_queue*, struct timeout_evt*);
void timeout_queue_reschedule(struct timeout_queue*, struct timeout_evt*, size_t seconds);

size_t timeout_queue_get_next_timeout(struct timeout_queue*, time_t now);
*/


static int timer_start(void)
{
	size_t n;
	g_queue = hub_malloc_zero(sizeof(struct timeout_queue));
	g_now = 0;
	g_max = 5;
	g_triggered = 0;
	timeout_queue_initialize(g_queue, g_now, g_max);

	memset(g_events, 0,  sizeof(g_events));
	for (n = 0; n < MAX_EVENTS; n++)
	{
		timeout_evt_initialize(&g_events[n], timeout_cb, &g_events[n]);
	}

	return g_queue != NULL;
}

static void timer_stop(void)
{
	timeout_queue_shutdown(g_queue);
	hub_free(g_queue);
	g_queue = NULL;
}

/* Five events, due in 0..4 seconds. */
static int timer_add_5(void)
{
	timeout_queue_insert(g_queue, &g_events[0], 0);
	timeout_queue_insert(g_queue, &g_events[1], 1);
	timeout_queue_insert(g_queue, &g_events[2], 2);
	timeout_queue_insert(g_queue, &g_events[3], 3);
	timeout_queue_insert(g_queue, &g_events[4], 4);

	return (g_events[0].prev != NULL &&
			g_events[1].prev != NULL &&
			g_events[2].prev != NULL &&
			g_events[3].prev != NULL &&
			g_events[4].prev != NULL);
}

EXO_TEST(timer_setup, {
	int ok = timer_start();
	timer_stop();
	return ok;
});

/* Nothing queued: the next timeout is the queue's horizon. */
EXO_TEST(timer_check_timeout_0, {
	int ok = timer_start() && timeout_queue_get_next_timeout(g_queue, g_now) == g_max;
	timer_stop();
	return ok;
});

EXO_TEST(timer_add_event_1, {
	int ok = timer_start();
	timeout_queue_insert(g_queue, &g_events[0], 2);
	ok = ok && g_events[0].prev != NULL;
	timer_stop();
	return ok;
});

EXO_TEST(timer_check_timeout_1, {
	int ok = timer_start();
	timeout_queue_insert(g_queue, &g_events[0], 2);
	ok = ok && timeout_queue_get_next_timeout(g_queue, g_now) == 2;
	timer_stop();
	return ok;
});

EXO_TEST(timer_remove_event_1, {
	int ok = timer_start();
	timeout_queue_insert(g_queue, &g_events[0], 2);
	timeout_queue_remove(g_queue, &g_events[0]);
	ok = ok && g_events[0].prev == NULL;
	timer_stop();
	return ok;
});

EXO_TEST(timer_check_timeout_2, {
	int ok = timer_start();
	timeout_queue_insert(g_queue, &g_events[0], 2);
	timeout_queue_remove(g_queue, &g_events[0]);
	ok = ok && timeout_queue_get_next_timeout(g_queue, g_now) == g_max;
	timer_stop();
	return ok;
});

/* test re-removing an event - should not crash! */
EXO_TEST(timer_remove_event_1_no_crash, {
	int ok = timer_start();
	timeout_queue_insert(g_queue, &g_events[0], 2);
	timeout_queue_remove(g_queue, &g_events[0]);
	timeout_queue_remove(g_queue, &g_events[0]);
	ok = ok && g_events[0].prev == NULL;
	timer_stop();
	return ok;
});

EXO_TEST(timer_add_5_events_1, {
	int ok = timer_start() && timer_add_5();
	timer_stop();
	return ok;
});

EXO_TEST(timer_check_5_events_1, {
	int ok = timer_start() && timer_add_5()
		&& timeout_queue_get_next_timeout(g_queue, g_now) == 1;
	timer_stop();
	return ok;
});

EXO_TEST(timer_process_5_events_1, {
	int ok = timer_start() && timer_add_5();
	g_now = 4;
	ok = ok && timeout_queue_process(g_queue, g_now) == g_triggered && g_triggered > 0;
	timer_stop();
	return ok;
});

/* Shutting down with events still queued. */
EXO_TEST(timer_shutdown, {
	if (!timer_start())
		return 0;
	timer_add_5();
	timer_stop();
	return 1;
});
