/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2014, Jan Vidar Krey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
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
	return 0;
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

