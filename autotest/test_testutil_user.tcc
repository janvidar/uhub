#include "core/config.h"
#include "core/hub.h"
#include "core/route.h"
#include "core/usermanager.h"
#include "network/network.h"
#include "testutil_user.h"

/* Proves the send-queue harness itself: route a message through the real
   route_to_user() and read back exactly what was queued. Everything that
   asserts on the hub's output relies on this working. */

static struct hub_info* tu_hub = 0;
static struct hub_user* tu_a = 0;

EXO_TEST(testutil_setup, {
	net_initialize();
	tu_hub = (struct hub_info*) hub_malloc_zero(sizeof(struct hub_info));
	if (!tu_hub)
		return 0;
	tu_hub->config = (struct hub_config*) hub_malloc_zero(sizeof(struct hub_config));
	if (!tu_hub->config)
		return 0;
	config_defaults(tu_hub->config);
	tu_hub->users = uman_init(0, 1);
	tu_hub->write_queue = list_create();
	tu_a = tu_user_create(tu_hub, 1, "tester", "AN7ZMSLIEBL53OPTM7WXGSTXUS3XOY6KQS5LBGX", auth_cred_guest);
	return tu_hub->users && tu_hub->write_queue && tu_a;
});

EXO_TEST(testutil_queue_starts_empty, {
	return tu_queue_count(tu_a) == 0 && tu_queue_line(tu_a, 0) == 0;
});

EXO_TEST(testutil_route_queues_message, {
	struct adc_message* msg = adc_msg_create("IMSG Hello\\sWorld!");
	int routed = route_to_user(tu_hub, tu_a, msg);
	adc_msg_free(msg);
	return routed == 1 && tu_queue_count(tu_a) == 1;
});

EXO_TEST(testutil_queue_line_is_the_wire_line, {
	const char* line = tu_queue_line(tu_a, 0);
	return line && !strcmp(line, "IMSG Hello\\sWorld!\n");
});

EXO_TEST(testutil_queue_has_exact_match, {
	return tu_queue_has(tu_a, "IMSG Hello\\sWorld!\n")
		&& !tu_queue_has(tu_a, "IMSG Hello\\sWorld!");
});

EXO_TEST(testutil_queue_find_by_prefix, {
	return tu_queue_find(tu_a, "IMSG") == 0 && tu_queue_find(tu_a, "ISTA") == -1;
});

/* Routing marks the user dirty so the event loop flushes it at the end of the
   iteration; the harness has to unwind that when it clears the queue. */
EXO_TEST(testutil_route_marks_user_dirty, {
	return user_flag_get(tu_a, flag_dirty) && list_size(tu_hub->write_queue) == 1;
});

EXO_TEST(testutil_queue_clear, {
	tu_queue_clear(tu_a);
	return tu_queue_count(tu_a) == 0
		&& !user_flag_get(tu_a, flag_dirty)
		&& list_size(tu_hub->write_queue) == 0;
});

EXO_TEST(testutil_queue_preserves_order, {
	struct adc_message* one = adc_msg_create("ISTA 000 one");
	struct adc_message* two = adc_msg_create("ISTA 000 two");
	route_to_user(tu_hub, tu_a, one);
	route_to_user(tu_hub, tu_a, two);
	adc_msg_free(one);
	adc_msg_free(two);
	return tu_queue_count(tu_a) == 2
		&& !strcmp(tu_queue_line(tu_a, 0), "ISTA 000 one\n")
		&& !strcmp(tu_queue_line(tu_a, 1), "ISTA 000 two\n");
});

/* A user without a connection is a remote (federated) user or one on its way
   out; route_to_user must not queue for it. */
EXO_TEST(testutil_no_connection_is_not_queued, {
	struct adc_message* msg = adc_msg_create("IMSG nope");
	struct net_connection* con = tu_a->connection;
	int routed;
	tu_queue_clear(tu_a);
	tu_a->connection = 0;
	routed = route_to_user(tu_hub, tu_a, msg);
	tu_a->connection = con;
	adc_msg_free(msg);
	return routed == 0 && tu_queue_count(tu_a) == 0;
});

EXO_TEST(testutil_teardown, {
	tu_user_destroy(tu_a);
	tu_a = 0;
	uman_shutdown(tu_hub->users);
	list_destroy(tu_hub->write_queue);
	hub_free(tu_hub->config);
	hub_free(tu_hub);
	tu_hub = 0;
	/* Paired with the net_initialize() in setup: the suite shares one process,
	   and leaving the backend up breaks whichever file initialises it next. */
	return net_destroy() == 0;
});
