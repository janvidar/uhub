#include <uhub.h>

#define MAX_EVENTS 15
static struct timeout_queue* g_queue;
static time_t g_now;
static size_t g_max;
static struct timeout_evt g_events[MAX_EVENTS];

static size_t g_triggered;

static void timeout_cb(struct timeout_evt* t)
{
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


EXO_TEST(timer_setup,{
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
});


EXO_TEST(timer_check_timeout_0,{
	return timeout_queue_get_next_timeout(g_queue, g_now) == g_max;
});


EXO_TEST(timer_add_event_1,{
	timeout_queue_insert(g_queue, &g_events[0], 2);
	return g_events[0].prev != NULL;
});

EXO_TEST(timer_check_timeout_1,{
	return timeout_queue_get_next_timeout(g_queue, g_now) == 2;
});

EXO_TEST(timer_remove_event_1,{
	timeout_queue_remove(g_queue, &g_events[0]);
	return g_events[0].prev == NULL;
});

EXO_TEST(timer_check_timeout_2,{
	return timeout_queue_get_next_timeout(g_queue, g_now) == g_max;
});

/* test re-removing an event - should not crash! */
EXO_TEST(timer_remove_event_1_no_crash,{
	timeout_queue_remove(g_queue, &g_events[0]);
	return g_events[0].prev == NULL;
});

EXO_TEST(timer_add_5_events_1,{
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
});

EXO_TEST(timer_check_5_events_1,{
	return timeout_queue_get_next_timeout(g_queue, g_now) == 1;
});

EXO_TEST(timer_process_5_events_1,{
	g_now = 4;
	return timeout_queue_process(g_queue, g_now) == g_triggered;
});

EXO_TEST(timer_shutdown,{
	timeout_queue_shutdown(g_queue);
	hub_free(g_queue);
	return 1;
});
