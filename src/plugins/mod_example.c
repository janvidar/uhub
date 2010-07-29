/**
 * This is a minimal example plugin for uhub.
 */

#include "plugin_api/handle.h"

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	plugin->name = "Example plugin";
	plugin->version = "1.0";
	plugin->description = "A simple example plugin";
	plugin->ptr = NULL;
	plugin->plugin_api_version = PLUGIN_API_VERSION;
	plugin->plugin_funcs_size = sizeof(struct plugin_funcs);
	memset(&plugin->funcs, 0, sizeof(struct plugin_funcs));

	puts("plugin register");
	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	/* No need to do anything! */
	puts("plugin unregister");
	return 0;
}

