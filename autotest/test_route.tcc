#include "system.h"
#include "network/network.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/usermanager.h"
#include "core/route.h"

/*
 * Unit tests for route.c's send-queue ceiling, the slow-reader / send-queue
 * exhaustion cap. The hard limit is MAX(max_send_buffer floor, max_recv_buffer
 * per connected user), so a user that drains slowly is allowed more headroom as
 * the hub fills, but never less than the floor; the soft limit is fixed.
 */

static struct hub_info* rt_hub = 0;

EXO_TEST(route_setup, {
	net_initialize();
	rt_hub = (struct hub_info*) hub_malloc_zero(sizeof(struct hub_info));
	if (!rt_hub)
		return 0;
	rt_hub->config = (struct hub_config*) hub_malloc_zero(sizeof(struct hub_config));
	rt_hub->users = uman_init(0, 1);
	if (!rt_hub->config || !rt_hub->users)
		return 0;
	config_defaults(rt_hub->config);
	/* Explicit, round values so the expected ceilings are unambiguous. */
	rt_hub->config->max_send_buffer = 1000;
	rt_hub->config->max_recv_buffer = 100;
	rt_hub->config->max_send_buffer_soft = 500;
	return 1;
});

/* No users: the hard limit is the configured floor. */
EXO_TEST(route_maxq_floor_zero_users, {
	rt_hub->users->count = 0;
	return get_max_send_queue(rt_hub) == 1000;
});

/* Many users: the per-user term (100 * 20 = 2000) exceeds the floor and wins. */
EXO_TEST(route_maxq_scales_with_users, {
	rt_hub->users->count = 20;
	return get_max_send_queue(rt_hub) == 2000;
});

/* Few users: the per-user term (100 * 5 = 500) is below the floor, so the
   floor is kept. */
EXO_TEST(route_maxq_floor_respected, {
	rt_hub->users->count = 5;
	return get_max_send_queue(rt_hub) == 1000;
});

/* The soft (choke) limit is the fixed configured value. */
EXO_TEST(route_maxq_soft_is_fixed, {
	rt_hub->users->count = 999;
	return get_max_send_queue_soft(rt_hub) == 500;
});

EXO_TEST(route_teardown, {
	if (rt_hub)
	{
		uman_shutdown(rt_hub->users);
		free_config(rt_hub->config);
		hub_free(rt_hub->config);
		hub_free(rt_hub);
	}
	rt_hub = 0;
	net_destroy();
	return 1;
});
