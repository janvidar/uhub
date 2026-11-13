#include "system.h"
#include "util/list.h"
#include "util/memory.h"
#include "core/hub.h"
#include "core/plugincallback.h"
#include "core/pluginloader.h"
#include "core/user.h"
#include "plugin_api/handle.h"

/*
 * Per-user plugin data (set_user_data / get_user_data) against the real hub
 * callback table, through a plugin handle that is wired up the way the loader
 * does it but has no shared object behind it.
 *
 * The users here are not in any user list on purpose: a user still logging in,
 * or one that has quit and awaits destruction, is not either, and the data a
 * plugin left on it must still be released when the plugin is unloaded.
 */

static struct hub_info pd_hub;
static int pd_cleanups;

static void pd_cleanup(struct plugin_handle* plugin, void* data)
{
	(void) plugin;
	pd_cleanups++;
	hub_free(data);
}

static struct plugin_handle* pd_plugin_create(void)
{
	struct plugin_handle* handle = (struct plugin_handle*) hub_malloc_zero(sizeof(struct plugin_handle));
	struct uhub_plugin* plugin = (struct uhub_plugin*) hub_malloc_zero(sizeof(struct uhub_plugin));
	struct plugin_hub_internals* internals = (struct plugin_hub_internals*) hub_malloc_zero(sizeof(struct plugin_hub_internals));
	if (!handle || !plugin || !internals)
	{
		hub_free(handle);
		hub_free(plugin);
		hub_free(internals);
		return NULL;
	}
	internals->hub = &pd_hub;
	internals->callback_data = plugin_callback_data_create();
	plugin->internals = internals;
	handle->handle = plugin;
	plugin_register_callback_functions(handle);
	return handle;
}

static void pd_plugin_destroy(struct plugin_handle* handle)
{
	struct plugin_hub_internals* internals;
	if (!handle)
		return;
	internals = get_internals(handle);
	plugin_user_data_purge_owner(&pd_hub, handle);
	plugin_callback_data_destroy(handle, internals->callback_data);
	hub_free(internals);
	hub_free(handle->handle);
	hub_free(handle);
}

/* A user the plugin can attach data to, held by no user list. */
static struct hub_user* pd_user_create(void)
{
	return (struct hub_user*) hub_malloc_zero(sizeof(struct hub_user));
}

/* What user_destroy() does with plugin data, then the memory. */
static void pd_user_destroy(struct hub_user* user)
{
	plugin_user_data_destroy(user);
	hub_free(user);
}

static int pd_attach(struct plugin_handle* plugin, struct hub_user* user)
{
	void* data = hub_malloc_zero(16);
	if (!data)
		return 0;
	plugin->hub.set_user_data(plugin, (struct plugin_user*) user, data, pd_cleanup);
	return plugin->hub.get_user_data(plugin, (struct plugin_user*) user) == data;
}

/* Unloading a plugin releases what it left on a user outside the user list. */
EXO_TEST(plugin_data_purge_reaches_unlisted_user, {
	struct plugin_handle* plugin = pd_plugin_create();
	struct hub_user* user = pd_user_create();
	int ok = plugin && user && pd_attach(plugin, user);
	pd_cleanups = 0;
	if (ok)
	{
		plugin_user_data_purge_owner(&pd_hub, plugin);
		ok = pd_cleanups == 1 && !plugin->hub.get_user_data(plugin, (struct plugin_user*) user);
	}
	pd_user_destroy(user);
	ok = ok && pd_cleanups == 1; /* not run a second time */
	pd_plugin_destroy(plugin);
	return ok;
});

/* A user destroyed first is forgotten by the plugin, so the unload does not
   reach into freed memory (ASan would say so). */
EXO_TEST(plugin_data_destroyed_user_forgotten, {
	struct plugin_handle* plugin = pd_plugin_create();
	struct hub_user* user = pd_user_create();
	int ok = plugin && user && pd_attach(plugin, user);
	pd_cleanups = 0;
	pd_user_destroy(user);
	ok = ok && pd_cleanups == 1;
	pd_plugin_destroy(plugin);
	return ok && pd_cleanups == 1;
});

/* So is a user whose data the plugin cleared itself. */
EXO_TEST(plugin_data_cleared_user_forgotten, {
	struct plugin_handle* plugin = pd_plugin_create();
	struct hub_user* user = pd_user_create();
	int ok = plugin && user && pd_attach(plugin, user);
	pd_cleanups = 0;
	if (ok)
		plugin->hub.set_user_data(plugin, (struct plugin_user*) user, NULL, NULL);
	ok = ok && pd_cleanups == 1;
	pd_user_destroy(user);
	pd_plugin_destroy(plugin);
	return ok && pd_cleanups == 1;
});

/* Unloading one plugin leaves another plugin's data on the same user alone. */
EXO_TEST(plugin_data_purge_only_own, {
	struct plugin_handle* a = pd_plugin_create();
	struct plugin_handle* b = pd_plugin_create();
	struct hub_user* user = pd_user_create();
	int ok = a && b && user && pd_attach(a, user) && pd_attach(b, user);
	pd_cleanups = 0;
	if (ok)
	{
		plugin_user_data_purge_owner(&pd_hub, a);
		ok = pd_cleanups == 1
			&& !a->hub.get_user_data(a, (struct plugin_user*) user)
			&& b->hub.get_user_data(b, (struct plugin_user*) user);
	}
	pd_user_destroy(user);
	ok = ok && pd_cleanups == 2;
	pd_plugin_destroy(a);
	pd_plugin_destroy(b);
	return ok;
});
