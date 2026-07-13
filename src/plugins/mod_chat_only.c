/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include "plugin_api/handle.h"
#include "util/memory.h"

enum Warnings
{
	WARN_SEARCH         = 0x01, ///<<< "Warn about searching."
	WARN_CONNECT        = 0x02, ///<<< "Warn about connecting to a user"
	WARN_EXTRA          = 0x08, ///<<< "Warn about unknown protocol data."
};

// Per-user state, stored in the hub's per-user plugin slot and freed on user
// destroy. Tracks which one-time warnings have already been sent.
struct user_info
{
	int warnings;   // Bitmask of warnings already sent. @see enum Warnings.
};

struct chat_only_data
{
	int operator_override;   // operators are allowed to override these limitations.
};

static struct chat_only_data* co_initialize()
{
	struct chat_only_data* data = (struct chat_only_data*) hub_malloc_zero(sizeof(struct chat_only_data));
	if (!data)
		return NULL;
	data->operator_override = 1; // operators may still search and connect (default on).
	return data;
}

static void co_shutdown(struct chat_only_data* data)
{
	hub_free(data);
}

static void free_user_info(struct plugin_handle* plugin, void* data)
{
	(void) plugin;
	hub_free(data);
}

static struct user_info* get_user_info(struct plugin_handle* plugin, struct plugin_user* user)
{
	struct user_info* u = (struct user_info*) plugin->hub.get_user_data(plugin, user);
	if (!u)
	{
		u = (struct user_info*) hub_malloc_zero(sizeof(struct user_info));
		if (!u)
			return NULL;
		plugin->hub.set_user_data(plugin, user, u, free_user_info);
	}
	return u;
}

static plugin_st on_search_result(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to, const char* search_data)
{
	(void) plugin; (void) from; (void) to; (void) search_data;
	return st_deny;
}

static plugin_st on_search(struct plugin_handle* plugin, struct plugin_user* user, const char* search_data)
{
	(void) search_data;
	struct chat_only_data* data = (struct chat_only_data*) plugin->ptr;
	struct user_info* info;

	if (user->credentials >= auth_cred_operator && data->operator_override)
		return st_allow;

	info = get_user_info(plugin, user);
	if (info && !(info->warnings & WARN_SEARCH))
	{
		plugin->hub.send_status_message(plugin, user, 000, "Searching is disabled. This is a chat only hub.");
		info->warnings |= WARN_SEARCH;
	}
	return st_deny;
}

static plugin_st on_p2p_connect(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to)
{
	(void) to;
	struct chat_only_data* data = (struct chat_only_data*) plugin->ptr;
	struct user_info* info;

	if (from->credentials >= auth_cred_operator && data->operator_override)
		return st_allow;

	info = get_user_info(plugin, from);
	if (info && !(info->warnings & WARN_CONNECT))
	{
		plugin->hub.send_status_message(plugin, from, 000, "Connection setup denied. This is a chat only hub.");
		info->warnings |= WARN_CONNECT;
	}
	return st_deny;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	(void) config;
	PLUGIN_INITIALIZE(plugin, "Chat only hub", "1.0", "Disables connection setup, search and results.");
	plugin->ptr = co_initialize();
	if (!plugin->ptr)
		return -1;

	plugin->funcs.on_search = on_search;
	plugin->funcs.on_search_result = on_search_result;
	plugin->funcs.on_p2p_connect = on_p2p_connect;
	plugin->funcs.on_p2p_revconnect = on_p2p_connect;

	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	co_shutdown((struct chat_only_data*) plugin->ptr);
	return 0;
}

