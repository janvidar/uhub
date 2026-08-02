#include "system.h"
#include "util/memory.h"
#include "network/connection.h"
#include "core/ioqueue.h"
#include "core/user.h"

static struct hub_user* ka_user = 0;
static struct net_connection* ka_con = 0;

#define KA_NOW ((time_t) 1000000)

static void ka_set_idle(int age)
{
	ka_con->last_send = KA_NOW - age;
}

static void ka_set_quiet(int age)
{
	ka_con->last_recv = KA_NOW - age;
}

EXO_TEST(keepalive_setup, {
	ka_user = (struct hub_user*) hub_malloc_zero(sizeof(struct hub_user));
	ka_con = (struct net_connection*) hub_malloc_zero(sizeof(struct net_connection));
	if (!ka_user || !ka_con)
		return 0;
	ka_user->send_queue = ioq_send_create();
	if (!ka_user->send_queue)
		return 0;
	ka_user->connection = ka_con;
	ka_user->state = state_normal;
	ka_set_idle(600);
	return 1;
});

EXO_TEST(keepalive_due_when_idle, {
	return user_keepalive_due(ka_user, KA_NOW, 120) == 1;
});

EXO_TEST(keepalive_due_at_exact_interval, {
	ka_set_idle(120);
	return user_keepalive_due(ka_user, KA_NOW, 120) == 1;
});

EXO_TEST(keepalive_not_due_below_interval, {
	ka_set_idle(119);
	return user_keepalive_due(ka_user, KA_NOW, 120) == 0;
});

EXO_TEST(keepalive_not_due_when_just_written, {
	ka_set_idle(0);
	return user_keepalive_due(ka_user, KA_NOW, 120) == 0;
});

EXO_TEST(keepalive_disabled_by_zero_interval, {
	ka_set_idle(600);
	return user_keepalive_due(ka_user, KA_NOW, 0) == 0;
});

EXO_TEST(keepalive_disabled_by_negative_interval, {
	return user_keepalive_due(ka_user, KA_NOW, -1) == 0;
});

EXO_TEST(keepalive_skips_user_logging_in, {
	ka_user->state = state_identify;
	return user_keepalive_due(ka_user, KA_NOW, 120) == 0;
});

EXO_TEST(keepalive_skips_disconnecting_user, {
	ka_user->state = state_cleanup;
	return user_keepalive_due(ka_user, KA_NOW, 120) == 0;
});

EXO_TEST(keepalive_skips_user_without_connection, {
	ka_user->state = state_normal;
	ka_user->connection = 0;
	if (user_keepalive_due(ka_user, KA_NOW, 120) != 0)
		return 0;
	ka_user->connection = ka_con;
	return 1;
});

EXO_TEST(keepalive_skips_remote_user, {
	ka_user->origin_link = (struct hub_link*) ka_con;
	if (user_keepalive_due(ka_user, KA_NOW, 120) != 0)
		return 0;
	ka_user->origin_link = 0;
	return 1;
});

EXO_TEST(keepalive_skips_user_with_queued_data, {
	ka_user->send_queue->size = 42;
	return user_keepalive_due(ka_user, KA_NOW, 120) == 0;
});

EXO_TEST(keepalive_due_when_queue_drained, {
	ka_user->send_queue->size = 42;
	ka_user->send_queue->offset = 42;
	if (user_keepalive_due(ka_user, KA_NOW, 120) != 1)
		return 0;
	ka_user->send_queue->size = 0;
	ka_user->send_queue->offset = 0;
	return 1;
});

EXO_TEST(silent_not_when_recently_heard_from, {
	ka_set_quiet(30);
	return user_is_silent(ka_user, KA_NOW, 120) == 0;
});

EXO_TEST(silent_at_exact_threshold, {
	ka_set_quiet(120);
	return user_is_silent(ka_user, KA_NOW, 120) == 1;
});

EXO_TEST(silent_when_long_quiet, {
	ka_set_quiet(600);
	return user_is_silent(ka_user, KA_NOW, 120) == 1;
});

EXO_TEST(silent_ignores_hub_writes, {
	ka_set_quiet(600);
	ka_set_idle(0);
	return user_is_silent(ka_user, KA_NOW, 120) == 1;
});

EXO_TEST(silent_never_for_remote_user, {
	ka_user->origin_link = (struct hub_link*) ka_con;
	if (user_is_silent(ka_user, KA_NOW, 120) != 0)
		return 0;
	ka_user->origin_link = 0;
	return 1;
});

EXO_TEST(keepalive_teardown, {
	ioq_send_destroy(ka_user->send_queue);
	hub_free(ka_con);
	hub_free(ka_user);
	ka_user = 0;
	ka_con = 0;
	return 1;
});
