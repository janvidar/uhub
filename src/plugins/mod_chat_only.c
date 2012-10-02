/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2012, Jan Vidar Krey
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

enum Warnings
{
	WARN_SEARCH         = 0x01, ///<<< "Warn about searching."
	WARN_CONNECT        = 0x02, ///<<< "Warn about connecting to a user"
	WARN_EXTRA          = 0x08, ///<<< "Warn about unknown protocol data."
};

struct user_info
{
	sid_t sid;      // The SID of the user
	int warnings;   // The number of denies (used to track wether or not a warning should be sent). @see enum Warnings.
};

struct chat_only_data
{
	size_t num_users;        // number of users tracked.
	size_t max_users;        // max users (hard limit max 1M users due to limitations in the SID (20 bits)).
	struct user_info* users; // array of max_users
	int operator_override;   // operators are allowed to override these limitations.
};

static struct chat_only_data* co_initialize()
{
	struct chat_only_data* data = (struct chat_only_data*) hub_malloc(sizeof(struct chat_only_data));
	data->num_users = 0;
	data->max_users = 512;
	data->users = hub_malloc_zero(sizeof(struct user_info) * data->max_users);
	return data;
}

static void co_shutdown(struct chat_only_data* data)
{
	if (data)
	{
		hub_free(data->users);
		hub_free(data);
	}
}

static struct user_info* get_user_info(struct chat_only_data* data, sid_t sid)
{
	struct user_info* u;

	// resize buffer if needed.
	if (sid >= data->max_users)
	{
		u = hub_malloc_zero(sizeof(struct user_info) * (sid + 1));
		memcpy(u, data->users, data->max_users);
		hub_free(data->users);
		data->users = u;
		data->max_users = sid + 1;
		u = NULL;
	}

	u = &data->users[sid];

	// reset counters if the user was not previously known.
	if (!u->sid)
	{
		u->sid = sid;
		u->warnings = 0;
		data->num_users++;
	}
	return u;
}

static plugin_st on_search_result(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to, const char* search_data)
{
	return st_deny;
}

static plugin_st on_search(struct plugin_handle* plugin, struct plugin_user* user, const char* search_data)
{
	struct chat_only_data* data = (struct chat_only_data*) plugin->ptr;
	struct user_info* info = get_user_info(data, user->sid);

	if (user->credentials >= auth_cred_operator && data->operator_override)
		return st_allow;

	if (!(info->warnings & WARN_SEARCH))
	{
		plugin->hub.send_status_message(plugin, user, 000, "Searching is disabled. This is a chat only hub.");
		info->warnings |= WARN_SEARCH;
	}
	return st_deny;
}

static plugin_st on_p2p_connect(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to)
{
	struct chat_only_data* data = (struct chat_only_data*) plugin->ptr;
	struct user_info* info = get_user_info(data, from->sid);

	if (from->credentials >= auth_cred_operator && data->operator_override)
		return st_allow;

	if (!(info->warnings & WARN_CONNECT))
	{
		plugin->hub.send_status_message(plugin, from, 000, "Connection setup denied. This is a chat only hub.");
		info->warnings |= WARN_CONNECT;
	}
	return st_deny;
}

static void on_user_login(struct plugin_handle* plugin, struct plugin_user* user)
{
	struct chat_only_data* data = (struct chat_only_data*) plugin->ptr;
	/*struct user_info* info = */
	get_user_info(data, user->sid);
}

static void on_user_logout(struct plugin_handle* plugin, struct plugin_user* user, const char* reason)
{
	struct chat_only_data* data = (struct chat_only_data*) plugin->ptr;
	struct user_info* info = get_user_info(data, user->sid);
	if (info->sid)
		data->num_users--;
	info->warnings = 0;
	info->sid = 0;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	PLUGIN_INITIALIZE(plugin, "Chat only hub", "1.0", "Disables connection setup, search and results.");
	plugin->ptr = co_initialize();

	plugin->funcs.on_search = on_search;
	plugin->funcs.on_search_result = on_search_result;
	plugin->funcs.on_p2p_connect = on_p2p_connect;
	plugin->funcs.on_p2p_revconnect = on_p2p_connect;
	plugin->funcs.on_user_login = on_user_login;
	plugin->funcs.on_user_logout = on_user_logout;

	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	co_shutdown((struct chat_only_data*) plugin->ptr);
	return 0;
}

