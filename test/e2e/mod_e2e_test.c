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
 * A tiny plugin used only by the end-to-end tests (test/e2e/run_plugin_e2e.sh)
 * to exercise plugin-facing hooks that are otherwise hard to drive:
 *
 *  - on_validate_nick: rejects the reserved nick "denynick" at login.
 *  - on_validate_cid : wired for completeness (shares the login code path with
 *                      nick validation). A CID can be denied via the config
 *                      parameter "deny_cid=<cid>"; empty by default.
 *  - on_chat_msg     : chat-keyword triggers for the plugin ban/unban hub-funcs:
 *      "PLZBANME"        -> hub.ban_user(sender)   (a plugin-driven ban)
 *      "PLZUNBAN <nick>" -> hub.unban(<nick>)      (operator only)
 */

#include "plugin_api/handle.h"
#include "util/memory.h"
#include <string.h>

static plugin_st on_validate_nick(struct plugin_handle* plugin, const char* nick)
{
	(void) plugin;
	if (nick && strcasecmp(nick, "denynick") == 0)
		return st_deny;
	return st_default;
}

static plugin_st on_validate_cid(struct plugin_handle* plugin, const char* cid)
{
	const char* deny = (const char*) plugin->ptr;
	if (deny && *deny && cid && strcasecmp(cid, deny) == 0)
		return st_deny;
	return st_default;
}

static plugin_st on_chat_msg(struct plugin_handle* plugin, struct plugin_user* from, const char* message)
{
	if (!message)
		return st_default;

	if (strcmp(message, "PLZBANME") == 0)
	{
		plugin->hub.ban_user(plugin, from, 0, "requested via PLZBANME");   /* permanent, cluster-wide, disconnect */
		return st_deny;
	}
	if (strncmp(message, "PLZUNBAN ", 9) == 0)
	{
		if (from->credentials >= auth_cred_operator)
			plugin->hub.unban(plugin, message + 9);
		return st_deny;
	}
	return st_default;
}

PLUGIN_API int plugin_register(struct plugin_handle* plugin, const char* config)
{
	const char* deny_cid = "";
	PLUGIN_INITIALIZE(plugin, "E2E test plugin", "1.0",
		"Test hooks: on_validate_nick/cid and plugin-driven ban/unban.");

	/* Accept an optional "deny_cid=<cid>" parameter for the on_validate_cid path. */
	if (config && strncmp(config, "deny_cid=", 9) == 0)
		deny_cid = config + 9;
	plugin->ptr = hub_strdup(deny_cid);

	plugin->funcs.on_validate_nick = on_validate_nick;
	plugin->funcs.on_validate_cid = on_validate_cid;
	plugin->funcs.on_chat_msg = on_chat_msg;
	return 0;
}

PLUGIN_API int plugin_unregister(struct plugin_handle* plugin)
{
	hub_free(plugin->ptr);
	plugin->ptr = NULL;
	return 0;
}
