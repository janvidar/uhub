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

/*
 * Example flood-action plugin.
 *
 * The hub itself does the *detection*: it counts events against the configured
 * flood_ctl_* thresholds and raises an on_flood_detected event. This plugin
 * decides the *action*. It keeps a per-user strike counter and escalates:
 *
 *   - strikes below the limit  -> st_default: let the hub drop the message and
 *                                 send its configured msg_user_flood_* warning.
 *   - strike reaches the limit -> disconnect the user and return st_deny so the
 *                                 hub drops the offending message quietly.
 *   - operators (optional)     -> st_allow: never throttled by this plugin.
 *
 * It is intentionally small; it exists to document the on_flood_detected
 * contract rather than to be a full anti-abuse system.
 */

#include "plugin_api/handle.h"
#include "util/config_token.h"
#include "util/memory.h"
#include "util/misc.h"

struct flood_data
{
	int grace;                  // Flood events tolerated (hub warns) before the user is disconnected.
	int operator_override;      // Non-zero: operators and above are never acted upon.
};

// Per-user strike counter, stored in the hub's per-user plugin slot and freed
// automatically when the user is destroyed (no SID bookkeeping, no stale reuse).
struct user_strikes
{
	int strikes;
};

static void free_user_strikes(struct plugin_handle* plugin, void* data)
{
	(void) plugin;
	hub_free(data);
}

static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

static const char* flood_type_name(enum plugin_flood_type type)
{
	switch (type)
	{
		case flood_type_chat:    return "chat";
		case flood_type_connect: return "connect";
		case flood_type_search:  return "search";
		case flood_type_update:  return "update";
		case flood_type_extras:  return "protocol";
	}
	return "unknown";
}

static struct user_strikes* get_user_strikes(struct plugin_handle* plugin, struct plugin_user* user)
{
	struct user_strikes* info = (struct user_strikes*) plugin->hub.get_user_data(plugin, user);
	if (!info)
	{
		info = (struct user_strikes*) hub_malloc_zero(sizeof(struct user_strikes));
		if (!info)
			return NULL;
		plugin->hub.set_user_data(plugin, user, info, free_user_strikes);
	}
	return info;
}

static plugin_st on_flood_detected(struct plugin_handle* plugin, struct plugin_user* user, enum plugin_flood_type type)
{
	struct flood_data* data = (struct flood_data*) plugin->ptr;
	struct user_strikes* info;

	// Leave operators alone if configured to do so.
	if (data->operator_override && user->credentials >= auth_cred_operator)
		return st_allow;

	info = get_user_strikes(plugin, user);
	if (!info)
		return st_default;
	info->strikes++;

	if (info->strikes >= data->grace)
	{
		char msg[160];
		snprintf(msg, sizeof(msg), "Disconnected: repeated %s flooding.", flood_type_name(type));
		plugin->hub.send_status_message(plugin, user, 000, msg);
		plugin->hub.user_disconnect(plugin, user);
		return st_deny; // We handled it; drop the message quietly.
	}

	// Below the limit: let the hub apply its built-in drop + warning.
	return st_default;
}

static struct flood_data* parse_config(const char* line, struct plugin_handle* plugin)
{
	struct flood_data* data = (struct flood_data*) hub_malloc_zero(sizeof(struct flood_data));
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char* token = cfg_token_get_first(tokens);

	if (!data)
	{
		cfg_tokens_free(tokens);
		set_error_message(plugin, "Out of memory");
		return 0;
	}

	data->grace = 3;
	data->operator_override = 1;

	while (token)
	{
		struct cfg_settings* setting = cfg_settings_split(token);

		if (!setting)
		{
			set_error_message(plugin, "Unable to parse startup parameters");
			cfg_tokens_free(tokens);
			hub_free(data);
			return 0;
		}

		if (strcmp(cfg_settings_get_key(setting), "grace") == 0)
		{
			data->grace = uhub_atoi(cfg_settings_get_value(setting));
			if (data->grace < 1)
				data->grace = 1;
		}
		else if (strcmp(cfg_settings_get_key(setting), "operator_override") == 0)
		{
			data->operator_override = uhub_atoi(cfg_settings_get_value(setting));
		}
		else
		{
			set_error_message(plugin, "Unknown startup parameters given");
			cfg_settings_free(setting);
			cfg_tokens_free(tokens);
			hub_free(data);
			return 0;
		}

		cfg_settings_free(setting);
		token = cfg_token_get_next(tokens);
	}
	cfg_tokens_free(tokens);
	return data;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	struct flood_data* data;
	PLUGIN_INITIALIZE(plugin, "Flood action plugin", "1.0", "Disconnects users after repeated hub-detected floods.");

	data = parse_config(config, plugin);
	if (!data)
		return -1;

	plugin->ptr = data;
	plugin->funcs.on_flood_detected = on_flood_detected;
	/* Per-user strike counters are freed by the hub on user destroy (and on
	   plugin unload), so no logout hook or teardown bookkeeping is needed. */

	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	struct flood_data* data = (struct flood_data*) plugin->ptr;
	hub_free(data);
	return 0;
}
