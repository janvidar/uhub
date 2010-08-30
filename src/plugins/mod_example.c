/**
 * This is a minimal example plugin for uhub.
 */

#include "plugin_api/handle.h"

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	PLUGIN_INITIALIZE(plugin, "Example plugin", "1.0", "A simple example plugin");
	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	/* No need to do anything! */
	return 0;
}

