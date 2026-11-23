#include "network/network.h"
#include "core/auth.h"
#include "core/config.h"
#include "core/hub.h"
#include "util/memory.h"
#include "testutil_net.h"

/*
 * Starting and stopping the hub service. Each test brings up what it needs and
 * takes it down again, so each one runs alone or in any order.
 */

EXO_SETUP({
	return test_net_acquire();
});

EXO_TEARDOWN({
	test_net_release();
	return 1;
});

static void hub_test_config(struct hub_config* config)
{
	config_defaults(config);
	config->server_port = 65111;
	/* TLS is required by default, and a hub that cannot create its own
	   certificate (no state directory in a build tree) then refuses to start.
	   Hand it the test pair instead. */
	hub_free(config->tls_certificate);
	hub_free(config->tls_private_key);
	config->tls_certificate = hub_strdup(UHUB_TEST_DIR "/tls-test-cert.pem");
	config->tls_private_key = hub_strdup(UHUB_TEST_DIR "/tls-test-key.pem");
}

EXO_TEST(hub_config_initialize, {
	struct hub_config config;
	hub_test_config(&config);
	free_config(&config);
	return 1;
});

EXO_TEST(hub_acl_initialize, {
	struct hub_config config;
	struct acl_handle acl;
	int ok;
	hub_test_config(&config);
	ok = acl_initialize(&config, &acl) != -1;
	acl_shutdown(&acl);
	free_config(&config);
	return ok;
});

/* The whole life of the service: start it, hand it its variables, take them
   back, stop it. */
EXO_TEST(hub_service_lifecycle, {
	struct hub_config config;
	struct acl_handle acl;
	struct hub_info* hub;

	hub_test_config(&config);
	if (acl_initialize(&config, &acl) == -1)
	{
		free_config(&config);
		return 0;
	}

	hub = hub_start_service(&config);
	if (hub)
	{
		hub_set_variables(hub, &acl);
		/*** HUB IS OPERATIONAL HERE! ***/
		hub_free_variables(hub);
	}

	acl_shutdown(&acl);
	free_config(&config);
	if (!hub)
		return 0;
	hub_shutdown_service(hub);
	return 1;
});
