/**
 * This is a minimal example plugin for uhub.
 */

#include "plugin_api/handle.h"
#include "plugin_api/command_api.h"
#include "util/memory.h"

struct example_plugin_data
{
	struct plugin_command_handle* example;
};

static int example_command_handler(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	plugin->hub.send_message(plugin, user, "Hello from mod_example.");
	return 1;
}

static void command_register(struct plugin_handle* plugin)
{
	struct example_plugin_data* data = (struct example_plugin_data*) hub_malloc(sizeof(struct example_plugin_data));
	data->example = hub_malloc_zero(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(data->example, (void*) data, "example", "", auth_cred_guest, example_command_handler, "This is an example command that is added dynamically by loading the mod_example plug-in.");
	plugin->hub.command_add(plugin, data->example);
	plugin->ptr = data;
}

static void command_unregister(struct plugin_handle* plugin)
{
	struct example_plugin_data* data = (struct example_plugin_data*) plugin->ptr;

	plugin->hub.command_del(plugin, data->example);
	hub_free(data->example);

	hub_free(data);
	plugin->ptr = NULL;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	PLUGIN_INITIALIZE(plugin, "Example plugin", "1.0", "A simple example plugin");
	command_register(plugin);
	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	command_unregister(plugin);
	return 0;
}

