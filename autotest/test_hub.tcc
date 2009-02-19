#include <uhub.h>

static struct hub_config g_config;
static struct acl_handle g_acl;
static struct hub_info* g_hub;

/*
static void create_test_user()
{
	if (g_user)
		return;

	g_user = (struct user*) malloc(sizeof(struct user));
	memset(g_user, 0, sizeof(struct user));
	memcpy(g_user->id.nick, "exotic-tester", 13);
	g_user->sid = 1;
}
*/

EXO_TEST(hub_net_startup, {
	return (net_initialize() != -1);
});

EXO_TEST(hub_config_initialize, {
	config_defaults(&g_config);
	return 1;
});

EXO_TEST(hub_acl_initialize, {
	return (acl_initialize(&g_config, &g_acl) != -1);
});

EXO_TEST(hub_service_initialize, {
	g_hub = hub_start_service(&g_config);
	return g_hub ? 1 : 0;
});

EXO_TEST(hub_variables_startup, {
	hub_set_variables(g_hub, &g_acl);
	return 1;
});

/*** HUB IS OPERATIONAL HERE! ***/

EXO_TEST(hub_variables_shutdown, {
	hub_free_variables(g_hub);
	return 1;
});

EXO_TEST(hub_acl_shutdown, {
	acl_shutdown(&g_acl);
	return 1;
});

EXO_TEST(hub_config_shutdown, {
	free_config(&g_config);
	return 1;
});

EXO_TEST(hub_service_shutdown, {
	if (g_hub)
	{
		hub_shutdown_service(g_hub);
		return 1;
	}
	return 0;
});

EXO_TEST(hub_net_shutdown, {
	return (net_shutdown() != -1);
});
