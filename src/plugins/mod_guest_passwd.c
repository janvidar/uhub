/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
 * Copyright (C) 2020, Tim Schlueter
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

/*
 * A shared password for guests: a hub for people who were told the password,
 * without an account for each of them.
 *
 * It answers the account lookup for every nick with a guest-level record
 * carrying the shared password. The hub challenges for a password whenever a
 * lookup finds a record, so a guest has to know it, and is still a guest once
 * in. A real account from another auth plugin always beats that record, so
 * where this plugin sits in the plugins file does not matter (see
 * plugin_auth_get_user in core/plugininvoke.c).
 */

#include "plugin_api/handle.h"
#include "util/config_token.h"
#include "util/memory.h"
#include "util/misc.h"

struct guest_passwd_data
{
	char password[MAX_PASS_LEN + 1];
};

static struct guest_passwd_data* parse_config(const char* line, struct plugin_handle* plugin)
{
	struct guest_passwd_data* data = (struct guest_passwd_data*) hub_malloc_zero(sizeof(struct guest_passwd_data));
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char* token = cfg_token_get_first(tokens);

	if (!data)
	{
		plugin->error_msg = "Out of memory";
		cfg_tokens_free(tokens);
		return NULL;
	}

	while (token)
	{
		struct cfg_settings* setting = cfg_settings_split(token);
		const char* key;
		const char* value;

		if (!setting)
		{
			plugin->error_msg = "Unable to parse startup parameters";
			goto fail;
		}

		key = cfg_settings_get_key(setting);
		value = cfg_settings_get_value(setting);

		if (strcmp(key, "password") == 0)
		{
			/* Longer than a client could ever send back. */
			if (strlen(value) > MAX_PASS_LEN)
			{
				plugin->error_msg = "The guest password is too long";
				cfg_settings_free(setting);
				goto fail;
			}
			uhub_strlcpy(data->password, value, sizeof(data->password));
		}
		else
		{
			plugin->error_msg = "Unknown startup parameters given";
			cfg_settings_free(setting);
			goto fail;
		}

		cfg_settings_free(setting);
		token = cfg_token_get_next(tokens);
	}
	cfg_tokens_free(tokens);

	if (!*data->password)
	{
		plugin->error_msg = "No password is given, use password=<password>";
		hub_free(data);
		return NULL;
	}
	return data;

fail:
	cfg_tokens_free(tokens);
	hub_free(data);
	return NULL;
}

static plugin_st get_user(struct plugin_handle* plugin, const char* nickname, struct auth_info* info)
{
	struct guest_passwd_data* data = (struct guest_passwd_data*) plugin->ptr;

	memset(info, 0, sizeof(*info));
	uhub_strlcpy(info->nickname, nickname, sizeof(info->nickname));
	uhub_strlcpy(info->password, data->password, sizeof(info->password));
	info->credentials = auth_cred_guest;
	return st_allow;
}

PLUGIN_API int plugin_register(struct plugin_handle* plugin, const char* config)
{
	PLUGIN_INITIALIZE(plugin, "Guest password plugin", "1.0", "Guests must give a shared password to log in.");

	plugin->funcs.auth_get_user = get_user;

	plugin->ptr = parse_config(config, plugin);
	return plugin->ptr ? 0 : -1;
}

PLUGIN_API int plugin_unregister(struct plugin_handle* plugin)
{
	hub_free(plugin->ptr);
	plugin->ptr = NULL;
	return 0;
}
