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
 * Self-service registration commands (!regme / !passwd).
 *
 * This is a business-logic plugin: it owns the self-registration policy but
 * stores nothing itself. It reaches user records through the hub's storage
 * accessors (plugin->hub.auth_get_user / auth_register_user / auth_update_user),
 * which route to whatever auth storage plugin is loaded (mod_auth_sqlite today,
 * a future mod_auth_<backend> tomorrow). Load it alongside a storage plugin.
 */

#include "plugin_api/command_api.h"
#include "plugin_api/handle.h"
#include "util/cbuffer.h"
#include "util/memory.h"

struct selfreg_data
{
	struct plugin_command_handle* cmd_regme;
	struct plugin_command_handle* cmd_passwd;
};

/*
 * Validate a user-supplied password. Returns 1 if acceptable, 0 otherwise. The
 * 'p' command argument type already rejects whitespace, so we only guard against
 * an empty password or one that exceeds the storage limit.
 */
static int valid_password(const char* pass)
{
	size_t len;
	if (!pass)
		return 0;
	len = strlen(pass);
	if (len == 0 || len > MAX_PASS_LEN)
		return 0;
	return 1;
}

static int command_regme_handler(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(256);
	struct plugin_command_arg_data* arg = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	const char* pass = arg ? arg->data.string : NULL;
	struct auth_info info;

	if (!valid_password(pass))
	{
		cbuf_append_format(buf, "*** %s: Password must be 1-%d characters and contain no spaces.", cmd->prefix, MAX_PASS_LEN);
		plugin->hub.send_message(plugin, user, cbuf_get(buf));
		cbuf_destroy(buf);
		return 0;
	}

	if (user->credentials >= auth_cred_user)
	{
		cbuf_append_format(buf, "*** %s: You are already logged in as a registered user.", cmd->prefix);
		plugin->hub.send_message(plugin, user, cbuf_get(buf));
		cbuf_destroy(buf);
		return 0;
	}

	if (plugin->hub.auth_get_user(plugin, user->nick, &info))
	{
		cbuf_append_format(buf, "*** %s: The nick \"%s\" is already registered.", cmd->prefix, user->nick);
		plugin->hub.send_message(plugin, user, cbuf_get(buf));
		cbuf_destroy(buf);
		return 0;
	}

	memset(&info, 0, sizeof(info));
	snprintf(info.nickname, sizeof(info.nickname), "%s", user->nick);
	snprintf(info.password, sizeof(info.password), "%s", pass);
	info.credentials = auth_cred_user;

	if (plugin->hub.auth_register_user(plugin, &info))
	{
		cbuf_append_format(buf,
			"*** %s: Registered nick \"%s\". To log in: set this password in your "
			"client, then disconnect and reconnect to the hub.",
			cmd->prefix, user->nick);
	}
	else
	{
		cbuf_append_format(buf,
			"*** %s: Registration failed. Please try again later or contact an operator.",
			cmd->prefix);
	}
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	return 0;
}

static int command_passwd_handler(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(256);
	struct plugin_command_arg_data* arg = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	const char* pass = arg ? arg->data.string : NULL;
	struct auth_info info;

	if (user->credentials < auth_cred_user)
	{
		cbuf_append_format(buf, "*** %s: Only registered users can change their password.", cmd->prefix);
		plugin->hub.send_message(plugin, user, cbuf_get(buf));
		cbuf_destroy(buf);
		return 0;
	}

	if (!valid_password(pass))
	{
		cbuf_append_format(buf, "*** %s: Password must be 1-%d characters and contain no spaces.", cmd->prefix, MAX_PASS_LEN);
		plugin->hub.send_message(plugin, user, cbuf_get(buf));
		cbuf_destroy(buf);
		return 0;
	}

	/* Load the existing record so the credential level is preserved across the update. */
	if (!plugin->hub.auth_get_user(plugin, user->nick, &info))
	{
		cbuf_append_format(buf, "*** %s: Could not find your registration. Contact an operator.", cmd->prefix);
		plugin->hub.send_message(plugin, user, cbuf_get(buf));
		cbuf_destroy(buf);
		return 0;
	}

	strncpy(info.password, pass, MAX_PASS_LEN);
	info.password[MAX_PASS_LEN] = '\0';

	if (plugin->hub.auth_update_user(plugin, &info))
		cbuf_append_format(buf, "*** %s: Password updated. Use the new password the next time you log in.", cmd->prefix);
	else
		cbuf_append_format(buf, "*** %s: Password change failed. Please try again later.", cmd->prefix);
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	return 0;
}

PLUGIN_API int plugin_register(struct plugin_handle* plugin, const char* config)
{
	struct selfreg_data* data;
	(void) config;
	PLUGIN_INITIALIZE(plugin, "Self-registration plugin", "1.0", "Self-service !regme / !passwd commands (requires an auth storage plugin).");

	data = (struct selfreg_data*) hub_malloc_zero(sizeof(struct selfreg_data));
	if (!data)
		return -1;
	data->cmd_regme = (struct plugin_command_handle*) hub_malloc_zero(sizeof(struct plugin_command_handle));
	data->cmd_passwd = (struct plugin_command_handle*) hub_malloc_zero(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(data->cmd_regme, plugin, "regme", "p", auth_cred_guest, command_regme_handler, "Register your current nick with a password.");
	PLUGIN_COMMAND_INITIALIZE(data->cmd_passwd, plugin, "passwd", "p", auth_cred_user, command_passwd_handler, "Change the password of your registered nick.");
	plugin->hub.command_add(plugin, data->cmd_regme);
	plugin->hub.command_add(plugin, data->cmd_passwd);
	plugin->ptr = data;
	return 0;
}

PLUGIN_API int plugin_unregister(struct plugin_handle* plugin)
{
	struct selfreg_data* data = (struct selfreg_data*) plugin->ptr;
	if (data)
	{
		if (data->cmd_regme)
		{
			plugin->hub.command_del(plugin, data->cmd_regme);
			hub_free(data->cmd_regme);
		}
		if (data->cmd_passwd)
		{
			plugin->hub.command_del(plugin, data->cmd_passwd);
			hub_free(data->cmd_passwd);
		}
		hub_free(data);
	}
	plugin->ptr = NULL;
	return 0;
}
