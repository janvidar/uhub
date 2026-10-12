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
 * Operator account management (!useradd / !userdel / !usermod / !userpass /
 * !userlist). The command set follows Tim Schlueter's mod_users from the
 * modelrockettier fork.
 *
 * Like mod_selfregister this is a business-logic plugin: it stores nothing
 * itself and reaches accounts through the hub's storage accessors, so it works
 * with whichever auth storage plugin is loaded.
 *
 * One rule governs every command: an operator can only create, change or
 * delete accounts below their own level, and can only hand out levels below
 * it. That keeps a second account from being a way up, and keeps operators of
 * equal standing from removing each other. Accounts at or above an operator's
 * own level -- their own included -- are managed with uhub-passwd, or by
 * someone ranked higher.
 */

#include "plugin_api/command_api.h"
#include "plugin_api/handle.h"
#include "util/cbuffer.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"

/* !userlist stops after this many accounts; a pattern narrows it down. */
#define USERS_LIST_MAX 200

struct users_data
{
	struct plugin_command_handle* cmd_useradd;
	struct plugin_command_handle* cmd_userdel;
	struct plugin_command_handle* cmd_usermod;
	struct plugin_command_handle* cmd_userpass;
	struct plugin_command_handle* cmd_userlist;
};

/* Same rule as mod_selfregister's: the 'p' argument already rejects spaces. */
static int valid_password(const char* pass)
{
	size_t len;
	if (!pass)
		return 0;
	len = strlen(pass);
	return len > 0 && len <= MAX_PASS_LEN;
}

static int valid_nick(const char* nick)
{
	size_t len;
	if (!nick)
		return 0;
	len = strlen(nick);
	return len > 0 && len <= MAX_NICK_LEN;
}

/* Levels an account can hold. none and guest are what a nick without an
   account already is, and link is not a login. */
static int grantable(enum auth_credentials cred)
{
	switch (cred)
	{
		case auth_cred_user:
		case auth_cred_bot:
		case auth_cred_ubot:
		case auth_cred_operator:
		case auth_cred_opbot:
		case auth_cred_opubot:
		case auth_cred_super:
		case auth_cred_admin:
			return 1;
		default:
			return 0;
	}
}

static void reply(struct plugin_handle* plugin, struct plugin_user* user, struct cbuffer* buf)
{
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
}

static const char* string_arg(struct plugin_handle* plugin, struct plugin_command* cmd)
{
	struct plugin_command_arg_data* arg = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	return arg ? arg->data.string : NULL;
}

/*
 * Look up the account an operator wants to act on and check they may. On
 * failure the reason has been appended to buf and 0 is returned.
 */
static int find_account(struct plugin_handle* plugin, struct plugin_user* actor, struct plugin_command* cmd,
	const char* nick, struct auth_info* info, struct cbuffer* buf)
{
	enum auth_credentials own = plugin->hub.get_user_credentials(plugin, actor);

	if (!valid_nick(nick) || !plugin->hub.auth_get_user(plugin, nick, info) || info->credentials < auth_cred_user)
	{
		cbuf_append_format(buf, "*** %s: No account named \"%s\".", cmd->prefix, nick ? nick : "");
		return 0;
	}

	if (strcasecmp(info->nickname, plugin->hub.get_user_nick(plugin, actor)) == 0)
	{
		cbuf_append_format(buf, "*** %s: You cannot change your own account this way.", cmd->prefix);
		return 0;
	}

	if (info->credentials >= own)
	{
		cbuf_append_format(buf, "*** %s: \"%s\" is a %s account; you can only manage accounts below your own level.",
			cmd->prefix, info->nickname, auth_cred_to_string(info->credentials));
		return 0;
	}

	return 1;
}

static int check_grant(struct plugin_handle* plugin, struct plugin_user* actor, struct plugin_command* cmd,
	enum auth_credentials cred, struct cbuffer* buf)
{
	enum auth_credentials own = plugin->hub.get_user_credentials(plugin, actor);

	if (!grantable(cred))
	{
		cbuf_append_format(buf, "*** %s: An account cannot have the level \"%s\".", cmd->prefix, auth_cred_to_string(cred));
		return 0;
	}

	if (cred >= own)
	{
		cbuf_append_format(buf, "*** %s: You can only give out levels below your own (%s).",
			cmd->prefix, auth_cred_to_string(own));
		return 0;
	}

	return 1;
}

/* Tell a connected user something about their account. */
static struct plugin_user* notify(struct plugin_handle* plugin, const char* nick, const char* message)
{
	struct plugin_user* target = plugin->hub.get_user_by_nick(plugin, nick);
	if (target)
		plugin->hub.send_message(plugin, target, message);
	return target;
}

static int command_useradd(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(256);
	const char* nick = string_arg(plugin, cmd);
	const char* pass = string_arg(plugin, cmd);
	struct plugin_command_arg_data* arg = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_credentials);
	enum auth_credentials cred = arg ? arg->data.credentials : auth_cred_user;
	const char* actor = plugin->hub.get_user_nick(plugin, user);
	struct auth_info info;

	if (!valid_nick(nick))
	{
		cbuf_append_format(buf, "*** %s: A nick must be 1-%d characters.", cmd->prefix, MAX_NICK_LEN);
		reply(plugin, user, buf);
		return 0;
	}

	if (!valid_password(pass))
	{
		cbuf_append_format(buf, "*** %s: Password must be 1-%d characters and contain no spaces.", cmd->prefix, MAX_PASS_LEN);
		reply(plugin, user, buf);
		return 0;
	}

	if (!check_grant(plugin, user, cmd, cred, buf))
	{
		reply(plugin, user, buf);
		return 0;
	}

	if (plugin->hub.auth_get_user(plugin, nick, &info) && info.credentials >= auth_cred_user)
	{
		cbuf_append_format(buf, "*** %s: \"%s\" is already registered.", cmd->prefix, info.nickname);
		reply(plugin, user, buf);
		return 0;
	}

	memset(&info, 0, sizeof(info));
	uhub_strlcpy(info.nickname, nick, sizeof(info.nickname));
	uhub_strlcpy(info.password, pass, sizeof(info.password));
	info.credentials = cred;

	if (!plugin->hub.auth_register_user(plugin, &info))
	{
		cbuf_append_format(buf, "*** %s: Could not register \"%s\".", cmd->prefix, nick);
		reply(plugin, user, buf);
		return 0;
	}

	LOG_INFO("mod_users: %s registered \"%s\" as %s", actor, nick, auth_cred_to_string(cred));

	/* A guest already using the nick gets the account on their next login. */
	{
		struct cbuffer* note = cbuf_create(128);
		cbuf_append_format(note, "*** An account has been created for your nick by %s. "
			"Set its password in your client and reconnect to log in.", actor);
		notify(plugin, info.nickname, cbuf_get(note));
		cbuf_destroy(note);
	}

	cbuf_append_format(buf, "*** %s: Registered \"%s\" as %s.", cmd->prefix, nick, auth_cred_to_string(cred));
	reply(plugin, user, buf);
	return 0;
}

static int command_userdel(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(256);
	const char* nick = string_arg(plugin, cmd);
	const char* actor = plugin->hub.get_user_nick(plugin, user);
	struct auth_info info;
	struct plugin_user* target;

	if (!find_account(plugin, user, cmd, nick, &info, buf))
	{
		reply(plugin, user, buf);
		return 0;
	}

	if (!plugin->hub.auth_delete_user(plugin, &info))
	{
		cbuf_append_format(buf, "*** %s: Could not delete \"%s\".", cmd->prefix, info.nickname);
		reply(plugin, user, buf);
		return 0;
	}

	LOG_INFO("mod_users: %s deleted the %s account \"%s\"", actor, auth_cred_to_string(info.credentials), info.nickname);

	/* Credentials are settled at login, so a user still online keeps whatever
	   the account gave them until they leave. Make them leave. */
	target = plugin->hub.get_user_by_nick(plugin, info.nickname);
	if (target && plugin->hub.get_user_credentials(plugin, target) >= auth_cred_user)
	{
		struct cbuffer* note = cbuf_create(128);
		cbuf_append_format(note, "*** Your account has been deleted by %s.", actor);
		plugin->hub.send_message(plugin, target, cbuf_get(note));
		cbuf_destroy(note);
		plugin->hub.user_disconnect(plugin, target);
		cbuf_append_format(buf, "*** %s: Deleted \"%s\" and disconnected them.", cmd->prefix, info.nickname);
	}
	else
	{
		cbuf_append_format(buf, "*** %s: Deleted \"%s\".", cmd->prefix, info.nickname);
	}
	reply(plugin, user, buf);
	return 0;
}

static int command_usermod(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(256);
	const char* nick = string_arg(plugin, cmd);
	struct plugin_command_arg_data* arg = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_credentials);
	const char* actor = plugin->hub.get_user_nick(plugin, user);
	enum auth_credentials old_cred;
	enum auth_credentials cred;
	struct auth_info info;
	struct plugin_user* target;
	const char* moved;

	if (!arg)
	{
		cbuf_append_format(buf, "*** %s: Missing the new level.", cmd->prefix);
		reply(plugin, user, buf);
		return 0;
	}
	cred = arg->data.credentials;

	if (!find_account(plugin, user, cmd, nick, &info, buf) || !check_grant(plugin, user, cmd, cred, buf))
	{
		reply(plugin, user, buf);
		return 0;
	}

	old_cred = info.credentials;
	if (old_cred == cred)
	{
		cbuf_append_format(buf, "*** %s: \"%s\" is already %s.", cmd->prefix, info.nickname, auth_cred_to_string(cred));
		reply(plugin, user, buf);
		return 0;
	}

	info.credentials = cred;
	if (!plugin->hub.auth_update_user(plugin, &info))
	{
		cbuf_append_format(buf, "*** %s: Could not change \"%s\".", cmd->prefix, info.nickname);
		reply(plugin, user, buf);
		return 0;
	}

	moved = (cred > old_cred) ? "promoted" : "demoted";
	LOG_INFO("mod_users: %s %s \"%s\" from %s to %s", actor, moved, info.nickname,
		auth_cred_to_string(old_cred), auth_cred_to_string(cred));

	target = plugin->hub.get_user_by_nick(plugin, info.nickname);
	if (target && plugin->hub.get_user_credentials(plugin, target) >= auth_cred_user)
	{
		struct cbuffer* note = cbuf_create(128);
		if (cred < old_cred)
		{
			/* Same reason as !userdel: the old level lasts as long as the
			   session does. */
			cbuf_append_format(note, "*** You have been demoted to %s by %s. Please reconnect.",
				auth_cred_to_string(cred), actor);
			plugin->hub.send_message(plugin, target, cbuf_get(note));
			plugin->hub.user_disconnect(plugin, target);
			cbuf_append_format(buf, "*** %s: Demoted \"%s\" to %s and disconnected them.",
				cmd->prefix, info.nickname, auth_cred_to_string(cred));
		}
		else
		{
			cbuf_append_format(note, "*** You have been promoted to %s by %s. Reconnect to use it.",
				auth_cred_to_string(cred), actor);
			plugin->hub.send_message(plugin, target, cbuf_get(note));
			cbuf_append_format(buf, "*** %s: Promoted \"%s\" to %s; it takes effect when they reconnect.",
				cmd->prefix, info.nickname, auth_cred_to_string(cred));
		}
		cbuf_destroy(note);
	}
	else
	{
		cbuf_append_format(buf, "*** %s: %s \"%s\" to %s.", cmd->prefix,
			(cred > old_cred) ? "Promoted" : "Demoted", info.nickname, auth_cred_to_string(cred));
	}
	reply(plugin, user, buf);
	return 0;
}

static int command_userpass(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(256);
	const char* nick = string_arg(plugin, cmd);
	const char* pass = string_arg(plugin, cmd);
	const char* actor = plugin->hub.get_user_nick(plugin, user);
	struct auth_info info;

	if (!find_account(plugin, user, cmd, nick, &info, buf))
	{
		reply(plugin, user, buf);
		return 0;
	}

	if (!valid_password(pass))
	{
		cbuf_append_format(buf, "*** %s: Password must be 1-%d characters and contain no spaces.", cmd->prefix, MAX_PASS_LEN);
		reply(plugin, user, buf);
		return 0;
	}

	uhub_strlcpy(info.password, pass, sizeof(info.password));
	if (!plugin->hub.auth_update_user(plugin, &info))
	{
		cbuf_append_format(buf, "*** %s: Could not change the password of \"%s\".", cmd->prefix, info.nickname);
		reply(plugin, user, buf);
		return 0;
	}

	LOG_INFO("mod_users: %s changed the password of \"%s\"", actor, info.nickname);

	{
		struct cbuffer* note = cbuf_create(128);
		cbuf_append_format(note, "*** Your password has been changed by %s. "
			"Use the new one the next time you log in.", actor);
		notify(plugin, info.nickname, cbuf_get(note));
		cbuf_destroy(note);
	}

	cbuf_append_format(buf, "*** %s: Changed the password of \"%s\".", cmd->prefix, info.nickname);
	reply(plugin, user, buf);
	return 0;
}

struct userlist_state
{
	const char* pattern;
	struct auth_info* entries;
	size_t count;
	size_t capacity;
	int oom;
};

/* Case-insensitive substring match; an empty pattern matches everything. */
static int nick_matches(const char* nick, const char* pattern)
{
	size_t plen = strlen(pattern);
	for (; *nick; nick++)
		if (strncasecmp(nick, pattern, plen) == 0)
			return 1;
	return plen == 0;
}

static void userlist_collect(const struct auth_info* user, void* ptr)
{
	struct userlist_state* state = (struct userlist_state*) ptr;

	if (state->oom || user->credentials < auth_cred_user)
		return;
	if (state->pattern && !nick_matches(user->nickname, state->pattern))
		return;

	if (state->count == state->capacity)
	{
		size_t capacity = state->capacity ? state->capacity * 2 : 32;
		struct auth_info* grown = (struct auth_info*) hub_malloc(capacity * sizeof(struct auth_info));
		if (!grown)
		{
			state->oom = 1;
			return;
		}
		if (state->count)
			memcpy(grown, state->entries, state->count * sizeof(struct auth_info));
		hub_free(state->entries);
		state->entries = grown;
		state->capacity = capacity;
	}

	memcpy(&state->entries[state->count], user, sizeof(struct auth_info));
	state->count++;
}

/* Highest level first, then by nick. */
static int userlist_compare(const void* a, const void* b)
{
	const struct auth_info* x = (const struct auth_info*) a;
	const struct auth_info* y = (const struct auth_info*) b;
	if (x->credentials != y->credentials)
		return (x->credentials > y->credentials) ? -1 : 1;
	return strcasecmp(x->nickname, y->nickname);
}

static int command_userlist(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(512);
	struct userlist_state state;
	size_t shown;
	size_t i;

	memset(&state, 0, sizeof(state));
	state.pattern = string_arg(plugin, cmd);

	if (plugin->hub.auth_list_users(plugin, userlist_collect, &state) < 0)
	{
		cbuf_append_format(buf, "*** %s: No loaded auth plugin can list its accounts.", cmd->prefix);
		reply(plugin, user, buf);
		return 0;
	}

	if (state.oom)
	{
		cbuf_append_format(buf, "*** %s: Out of memory.", cmd->prefix);
		hub_free(state.entries);
		reply(plugin, user, buf);
		return 0;
	}

	if (!state.count)
	{
		if (state.pattern)
			cbuf_append_format(buf, "*** %s: No accounts match \"%s\".", cmd->prefix, state.pattern);
		else
			cbuf_append_format(buf, "*** %s: There are no accounts.", cmd->prefix);
		reply(plugin, user, buf);
		return 0;
	}

	qsort(state.entries, state.count, sizeof(struct auth_info), userlist_compare);

	cbuf_append_format(buf, "*** %s: %d account%s", cmd->prefix, (int) state.count, state.count == 1 ? "" : "s");
	if (state.pattern)
		cbuf_append_format(buf, " matching \"%s\"", state.pattern);
	cbuf_append(buf, ":\n");

	shown = state.count < USERS_LIST_MAX ? state.count : USERS_LIST_MAX;
	for (i = 0; i < shown; i++)
		cbuf_append_format(buf, "%-9s %s\n", auth_cred_to_string(state.entries[i].credentials), state.entries[i].nickname);
	if (shown < state.count)
		cbuf_append_format(buf, "... and %d more; give a pattern to narrow the list.\n", (int) (state.count - shown));

	hub_free(state.entries);
	reply(plugin, user, buf);
	return 0;
}

static struct plugin_command_handle* add_command(struct plugin_handle* plugin, const char* prefix, const char* args,
	plugin_command_handler handler, const char* description)
{
	struct plugin_command_handle* cmd = (struct plugin_command_handle*) hub_malloc_zero(sizeof(struct plugin_command_handle));
	if (!cmd)
		return NULL;
	PLUGIN_COMMAND_INITIALIZE(cmd, plugin, prefix, args, auth_cred_operator, handler, description);
	plugin->hub.command_add(plugin, cmd);
	return cmd;
}

static void del_command(struct plugin_handle* plugin, struct plugin_command_handle* cmd)
{
	if (!cmd)
		return;
	plugin->hub.command_del(plugin, cmd);
	hub_free(cmd);
}

PLUGIN_API int plugin_unregister(struct plugin_handle* plugin);

PLUGIN_API int plugin_register(struct plugin_handle* plugin, const char* config)
{
	struct users_data* data;
	(void) config;
	PLUGIN_INITIALIZE(plugin, "User management plugin", "1.0", "Operator commands to add, delete, change and list accounts (requires an auth storage plugin).");

	data = (struct users_data*) hub_malloc_zero(sizeof(struct users_data));
	if (!data)
		return -1;
	plugin->ptr = data;

	data->cmd_useradd  = add_command(plugin, "useradd",  "np?C", command_useradd,  "Register an account (level defaults to user).");
	data->cmd_userdel  = add_command(plugin, "userdel",  "n",    command_userdel,  "Delete an account.");
	data->cmd_usermod  = add_command(plugin, "usermod",  "nC",   command_usermod,  "Change the level of an account.");
	data->cmd_userpass = add_command(plugin, "userpass", "np",   command_userpass, "Change the password of an account.");
	data->cmd_userlist = add_command(plugin, "userlist", "?n",   command_userlist, "List accounts, optionally those whose nick contains a pattern.");

	if (!data->cmd_useradd || !data->cmd_userdel || !data->cmd_usermod || !data->cmd_userpass || !data->cmd_userlist)
	{
		plugin_unregister(plugin);
		plugin->error_msg = "Out of memory";
		return -1;
	}
	return 0;
}

PLUGIN_API int plugin_unregister(struct plugin_handle* plugin)
{
	struct users_data* data = (struct users_data*) plugin->ptr;
	if (data)
	{
		del_command(plugin, data->cmd_useradd);
		del_command(plugin, data->cmd_userdel);
		del_command(plugin, data->cmd_usermod);
		del_command(plugin, data->cmd_userpass);
		del_command(plugin, data->cmd_userlist);
		hub_free(data);
	}
	plugin->ptr = NULL;
	return 0;
}
