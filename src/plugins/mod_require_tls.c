/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2018, Jan Vidar Krey
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
	struct plugin_command_handle* redirect;
};



int plugin_register(struct plugin_handle* plugin, const char* config)
{
	PLUGIN_INITIALIZE(plugin, "TLS redirect plugin", "1.0", "A simple redirect to TLS plug-in");
	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	return 0;
}

