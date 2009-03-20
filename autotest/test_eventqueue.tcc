#include <uhub.h>

static struct event_queue* eq;
static int eq_val;

static void eq_callback(void* callback_data, struct event_data* event_data)
{
	eq_val += event_data->id;
}

EXO_TEST(eventqueue_init_1, {
	eq = 0;
	eq_val = 0;
	return event_queue_initialize(&eq, eq_callback, &eq_val) == 0 && event_queue_size(eq) == 0;
});

EXO_TEST(eventqueue_init_2, {
	/* hack */
	return eq->callback_data == &eq_val && eq->callback == eq_callback && eq->q1 && eq->q2 && !eq->locked;
});

EXO_TEST(eventqueue_post_1, {
	struct event_data message;
	message.id  = 0x1001;
	message.ptr = &message;
	message.flags = message.id * 2;
	event_queue_post(eq, &message);
	return event_queue_size(eq) == 1;
});

EXO_TEST(eventqueue_process_1, {
	event_queue_process(eq);
	return eq_val == 0x1001;
});

EXO_TEST(eventqueue_size_1, {
	eq_val = 0;
	return event_queue_size(eq) == 0;
});

EXO_TEST(eventqueue_post_2, {
	struct event_data message;
	message.id  = 0x1002;
	message.ptr = &message;
	message.flags = message.id * 2;
	event_queue_post(eq, &message);
	return event_queue_size(eq) == 1;
});

EXO_TEST(eventqueue_size_2, {
	eq_val = 0;
	return event_queue_size(eq) == 1;
});


EXO_TEST(eventqueue_post_3, {
	struct event_data message;
	message.id  = 0x1003;
	message.ptr = &message;
	message.flags = message.id * 2;
	event_queue_post(eq, &message);
	return event_queue_size(eq) == 2;
});

EXO_TEST(eventqueue_size_3, {
	eq_val = 0;
	return event_queue_size(eq) == 2;
});

EXO_TEST(eventqueue_process_2, {
	event_queue_process(eq);
	return eq_val == 0x2005;
});

EXO_TEST(eventqueue_size_4, {
	eq_val = 0;
	return event_queue_size(eq) == 0;
});

EXO_TEST(eventqueue_shutdown_1, {
	event_queue_shutdown(eq);
	return 1;
});


