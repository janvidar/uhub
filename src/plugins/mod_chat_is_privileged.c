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
 * Restrict who may write in main chat and who may send private messages,
 * based on a per-message credential threshold. This is the plugin counterpart
 * to the built-in chat_is_privileged option, adding private-message control
 * (the "pm_is_privileged" ask in issue #114) so a hub can defend against
 * private-message spam from guests.
 *
 * Parameters (each is a minimum credential: none/guest/reg/user/op/admin/...):
 *   allow_mainchat    minimum credential to write in main chat   (default: guest)
 *   allow_privchat    minimum credential to send a private msg   (default: guest)
 *   allow_op_contact  minimum credential to PM an operator/admin (default: guest)
 *
 * allow_op_contact applies when the *recipient* is an operator or above, and is
 * normally left at (or below) allow_privchat so ordinary users can always reach
 * staff even while peer-to-peer private messaging is locked down.
 */

#include "plugin_api/handle.h"
#include "util/memory.h"
#include "util/config_token.h"

enum Warnings
{
	WARN_MAINCHAT = 0x01, // A main-chat denial notice has been sent.
	WARN_PRIVCHAT = 0x02, // A private-chat denial notice has been sent.
};

// Per-user state, stored in the hub's per-user plugin slot and freed on user
// destroy. Tracks which one-time warnings have already been sent.
struct user_info
{
	int warnings;
};

struct chat_data
{
	enum auth_credentials allow_privchat;	// minimum credentials to allow using private chat
	enum auth_credentials allow_op_contact; // minimum credentials to allow private chat to operators (including super and admins).
	enum auth_credentials allow_mainchat;	// minimum credentials to allow using main chat
};

static void set_error_message(struct plugin_handle *plugin, const char *msg)
{
	plugin->error_msg = msg;
}

// Parse a "key=value" credential setting into *out, or flag a config error.
// Returns 1 on success, 0 on an invalid credential string.
static int parse_cred(struct plugin_handle *plugin, struct cfg_settings *setting, enum auth_credentials *out)
{
	if (auth_string_to_cred(cfg_settings_get_value(setting), out))
		return 1;
	set_error_message(plugin, "Invalid credential value for startup parameter");
	return 0;
}

static struct chat_data *parse_config(struct plugin_handle *plugin, const char *line)
{
	struct chat_data *data = (struct chat_data *)hub_malloc_zero(sizeof(struct chat_data));
	struct cfg_tokens *tokens = cfg_tokenize(line);
	char *token = cfg_token_get_first(tokens);

	if (!data)
	{
		cfg_tokens_free(tokens);
		set_error_message(plugin, "Out of memory");
		return 0;
	}

	// defaults
	data->allow_mainchat = auth_cred_guest;
	data->allow_op_contact = auth_cred_guest;
	data->allow_privchat = auth_cred_guest;

	while (token)
	{
		struct cfg_settings *setting = cfg_settings_split(token);
		int ok = 1;

		if (!setting)
		{
			set_error_message(plugin, "Unable to parse startup parameters");
			cfg_tokens_free(tokens);
			hub_free(data);
			return 0;
		}

		if (strcmp(cfg_settings_get_key(setting), "allow_mainchat") == 0)
			ok = parse_cred(plugin, setting, &data->allow_mainchat);
		else if (strcmp(cfg_settings_get_key(setting), "allow_privchat") == 0)
			ok = parse_cred(plugin, setting, &data->allow_privchat);
		else if (strcmp(cfg_settings_get_key(setting), "allow_op_contact") == 0)
			ok = parse_cred(plugin, setting, &data->allow_op_contact);
		else
		{
			set_error_message(plugin, "Unknown startup parameters given");
			ok = 0;
		}

		cfg_settings_free(setting);

		if (!ok)
		{
			cfg_tokens_free(tokens);
			hub_free(data);
			return 0;
		}

		token = cfg_token_get_next(tokens);
	}
	cfg_tokens_free(tokens);

	return data;
}

static void free_user_info(struct plugin_handle *plugin, void *data)
{
	(void) plugin;
	hub_free(data);
}

static struct user_info *get_user_info(struct plugin_handle *plugin, struct plugin_user *user)
{
	struct user_info *u = (struct user_info *) plugin->hub.get_user_data(plugin, user);
	if (!u)
	{
		u = (struct user_info *) hub_malloc_zero(sizeof(struct user_info));
		if (!u)
			return NULL;
		plugin->hub.set_user_data(plugin, user, u, free_user_info);
	}
	return u;
}

// Send a one-time notice to the user when a message is denied, tracked per
// warning bit so we do not repeat it on every blocked message.
static void warn_once(struct plugin_handle *plugin, struct plugin_user *user, int bit, const char *msg)
{
	struct user_info *info = get_user_info(plugin, user);
	if (info && !(info->warnings & bit))
	{
		plugin->hub.send_status_message(plugin, user, 000, msg);
		info->warnings |= bit;
	}
}

plugin_st on_chat_msg(struct plugin_handle *plugin, struct plugin_user *from, const char *message)
{
	struct chat_data *data = (struct chat_data *)plugin->ptr;
	(void) message;
	if (from->credentials >= data->allow_mainchat)
		return st_default;
	warn_once(plugin, from, WARN_MAINCHAT, "Main chat is reserved for privileged users.");
	return st_deny;
}

plugin_st on_private_msg(struct plugin_handle *plugin, struct plugin_user *from, struct plugin_user *to, const char *message)
{
	struct chat_data *data = (struct chat_data *)plugin->ptr;
	(void) message;

	// Messages addressed to an operator (or above) use the op-contact
	// threshold, so ordinary users can still reach staff even when
	// peer-to-peer private messaging is restricted.
	enum auth_credentials required =
		(to->credentials >= auth_cred_operator) ? data->allow_op_contact : data->allow_privchat;

	if (from->credentials >= required)
		return st_default;
	warn_once(plugin, from, WARN_PRIVCHAT, "Private messaging is reserved for privileged users.");
	return st_deny;
}

int plugin_register(struct plugin_handle *plugin, const char *config)
{
	PLUGIN_INITIALIZE(plugin, "Privileged chat hub", "1.0", "Restricts main chat and private messaging to privileged users.");
	plugin->ptr = parse_config(plugin, config);
	if (!plugin->ptr)
		return -1;

	plugin->funcs.on_chat_msg = on_chat_msg;
	plugin->funcs.on_private_msg = on_private_msg;

	return 0;
}

int plugin_unregister(struct plugin_handle *plugin)
{
	struct chat_data *data = (struct chat_data *)plugin->ptr;
	hub_free(data);
	return 0;
}
