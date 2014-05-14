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
#include "util/memory.h"

static plugin_st on_search_result(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to, const char* search_data)
{
	if (to->credentials >= auth_cred_user)
		return st_default;
	return st_deny;
}

static plugin_st on_search(struct plugin_handle* plugin, struct plugin_user* user, const char* search_data)
{
	// Registered users are allowed to search.
	if (user->credentials >= auth_cred_user)
		return st_default;
	return st_deny;
}

static plugin_st on_p2p_connect(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to)
{
	if (from->credentials >= auth_cred_user)
		return st_default;
	return st_deny;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	PLUGIN_INITIALIZE(plugin, "No guest downloading", "0.1", "This plug-in only allows registered users to search and initiate transfers.");
	plugin->ptr = NULL;
	plugin->funcs.on_search = on_search;
	plugin->funcs.on_search_result = on_search_result;
	plugin->funcs.on_p2p_connect = on_p2p_connect;
	// plugin->funcs.on_p2p_revconnect = on_p2p_connect;
	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	return 0;
}

