#include "system.h"
#include "util/list.h"
#include "util/memory.h"
#include "core/auth.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/pluginloader.h"
#include "core/usermanager.h"
#include "plugin_api/handle.h"

/*
 * hub_apply_ban() against fake storage plugins: the ban always applies in
 * memory, and a store that refuses to keep it is reported rather than
 * swallowed -- the silent refusal is what hid #138.
 */

#define HB_CID "3AGHMAASJA2RFNM22AA6753V7B7DYEPNTIWHBAY"

static struct hub_config hb_config;
static struct acl_handle hb_acl;
static struct uhub_plugins hb_plugins;
static struct hub_info hb_hub;
static struct plugin_handle hb_store;
static int hb_stored;

static plugin_st hb_store_refuse(struct plugin_handle* p, const struct ban_info* ban)
{
	(void) p; (void) ban;
	return st_deny;
}

static plugin_st hb_store_accept(struct plugin_handle* p, const struct ban_info* ban)
{
	(void) p; (void) ban;
	hb_stored++;
	return st_allow;
}

static void hb_cleanup(void)
{
	if (hb_hub.acl)
		acl_shutdown(&hb_acl);
	if (hb_hub.users)
		uman_shutdown(hb_hub.users);
	if (hb_plugins.loaded)
	{
		list_clear(hb_plugins.loaded, NULL);
		list_destroy(hb_plugins.loaded);
	}
	memset(&hb_hub, 0, sizeof(hb_hub));
	memset(&hb_plugins, 0, sizeof(hb_plugins));
}

/* A hub with an ACL, an empty user list and the given storage plugin (NULL:
   no storage plugin at all). */
static int hb_fresh(plugin_st (*store)(struct plugin_handle*, const struct ban_info*))
{
	hb_cleanup();

	memset(&hb_hub, 0, sizeof(hb_hub));
	memset(&hb_plugins, 0, sizeof(hb_plugins));
	memset(&hb_store, 0, sizeof(hb_store));
	hb_stored = 0;

	if (acl_initialize(&hb_config, &hb_acl) != 0)
		return 0;
	hb_hub.acl = &hb_acl;
	hb_hub.config = &hb_config;
	hb_hub.users = uman_init(0, 1);
	if (!hb_hub.users)
		return 0;

	hb_plugins.loaded = list_create();
	if (store)
	{
		hb_store.funcs.auth_ban_add = store;
		list_append(hb_plugins.loaded, &hb_store);
	}
	hb_hub.plugins = &hb_plugins;
	return 1;
}

EXO_SETUP({
	config_defaults(&hb_config);
	/* No deny list of the host's leaking in. */
	hub_free(hb_config.file_acl);
	hb_config.file_acl = hub_strdup("/nonexistent/uhub-test-users.conf");
	return 1;
});

EXO_TEARDOWN({
	hb_cleanup();
	free_config(&hb_config);
	return 1;
});

EXO_TEST(hub_ban_without_store, {
	if (!hb_fresh(NULL))
		return 0;
	return hub_apply_ban(&hb_hub, HB_CID, "Eviluser", 0, NULL, 0) == 0
		&& acl_is_cid_banned(&hb_acl, HB_CID);
});

EXO_TEST(hub_ban_stored, {
	if (!hb_fresh(hb_store_accept))
		return 0;
	return hub_apply_ban(&hb_hub, HB_CID, "Eviluser", 0, NULL, 0) == 0
		&& hb_stored == 1
		&& acl_is_cid_banned(&hb_acl, HB_CID);
});

/* Refused by the store: reported, and still in force until a restart. */
EXO_TEST(hub_ban_store_refused, {
	if (!hb_fresh(hb_store_refuse))
		return 0;
	return hub_apply_ban(&hb_hub, HB_CID, "Eviluser", 0, NULL, 0) == -1
		&& acl_is_cid_banned(&hb_acl, HB_CID);
});
