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

#include "util/list.h"
#include "util/log.h"
#include "core/hub.h"
#include "core/config.h"
#include "core/plugininvoke.h"
#include "core/pluginloader.h"
#include "plugin_api/handle.h"

#define PLUGIN_DEBUG(hub, name) LOG_PLUGIN("Invoke %s on %d plugins", name, (hub->plugins ? (int) list_size(hub->plugins->loaded) : -1));


/* Uses the reentrant LIST_FOREACH_SAFE with a local cursor: a hook invoked here
   may call back into the hub (e.g. on_flood_detected -> ban_user -> plugin_ban_add)
   and trigger a nested INVOKE over the same list. A shared cursor would corrupt
   the outer walk; the per-call cursor keeps them independent. */
#define INVOKE(HUB, FUNCNAME, CODE) \
	PLUGIN_DEBUG(HUB, # FUNCNAME) \
	if (HUB->plugins && HUB->plugins->loaded) \
	{ \
		struct plugin_handle* plugin;\
		struct node* plugin_cursor; \
		LIST_FOREACH_SAFE(struct plugin_handle*, plugin, HUB->plugins->loaded, plugin_cursor, \
		{ \
			if (plugin->funcs.FUNCNAME) \
				CODE \
		}); \
	}

#define PLUGIN_INVOKE_STATUS_1(HUB, FUNCNAME, ARG1) \
	do { \
		plugin_st status = st_default; \
		INVOKE(HUB, FUNCNAME, { \
			status = plugin->funcs.FUNCNAME(plugin, ARG1); \
			if (status != st_default) \
				break; \
		}); \
		return status; \
	} while(0)

#define PLUGIN_INVOKE_STATUS_2(HUB, FUNCNAME, ARG1, ARG2) \
	do { \
		plugin_st status = st_default; \
		INVOKE(HUB, FUNCNAME, { \
			status = plugin->funcs.FUNCNAME(plugin, ARG1, ARG2); \
			if (status != st_default) \
				break; \
		}); \
		return status; \
	} while(0)

#define PLUGIN_INVOKE_STATUS_3(HUB, FUNCNAME, ARG1, ARG2, ARG3) \
	do { \
		plugin_st status = st_default; \
		INVOKE(HUB, FUNCNAME, { \
			status = plugin->funcs.FUNCNAME(plugin, ARG1, ARG2, ARG3); \
			if (status != st_default) \
				break; \
		}); \
		return status; \
	} while(0)

#define PLUGIN_INVOKE_1(HUB, FUNCNAME, ARG1) INVOKE(HUB, FUNCNAME, { plugin->funcs.FUNCNAME(plugin, ARG1); })
#define PLUGIN_INVOKE_2(HUB, FUNCNAME, ARG1, ARG2) INVOKE(HUB, FUNCNAME, { plugin->funcs.FUNCNAME(plugin, ARG1, ARG2); })
#define PLUGIN_INVOKE_3(HUB, FUNCNAME, ARG1, ARG2, ARG3) INVOKE(HUB, FUNCNAME, { plugin->funcs.FUNCNAME(plugin, ARG1, ARG2, ARG3); })


static struct plugin_user* convert_user_type(struct hub_user* user)
{
	struct plugin_user* puser = (struct plugin_user*) user;
	return puser;
}

plugin_st plugin_check_ip_early(struct hub_info* hub, struct ip_addr_encap* addr)
{
	PLUGIN_INVOKE_STATUS_1(hub, on_check_ip_early, addr);
}

plugin_st plugin_check_ip_late(struct hub_info* hub, struct hub_user* who, struct ip_addr_encap* addr)
{
	struct plugin_user* user = convert_user_type(who);
	PLUGIN_INVOKE_STATUS_2(hub, on_check_ip_late, user, addr);
}

plugin_st plugin_check_nick(struct hub_info* hub, const char* nick)
{
	PLUGIN_INVOKE_STATUS_1(hub, on_validate_nick, nick);
}

plugin_st plugin_check_cid(struct hub_info* hub, const char* cid)
{
	PLUGIN_INVOKE_STATUS_1(hub, on_validate_cid, cid);
}

plugin_st plugin_change_nick(struct hub_info* hub, struct hub_user* who, const char* new_nick)
{
	struct plugin_user* user = convert_user_type(who);
	PLUGIN_INVOKE_STATUS_2(hub, on_change_nick, user, new_nick);
}

void plugin_hub_started(struct hub_info* hub)
{
	struct plugin_hub_info info;
	info.description = hub->config ? hub->config->hub_description : NULL;
	PLUGIN_INVOKE_1(hub, on_hub_started, &info);
}

void plugin_hub_shutdown(struct hub_info* hub)
{
	struct plugin_hub_info info;
	info.description = hub->config ? hub->config->hub_description : NULL;
	PLUGIN_INVOKE_1(hub, on_hub_shutdown, &info);
}

void plugin_log_connection_accepted(struct hub_info* hub, struct ip_addr_encap* ipaddr)
{
	PLUGIN_INVOKE_1(hub, on_connection_accepted, ipaddr);
}

void plugin_log_connection_denied(struct hub_info* hub, struct ip_addr_encap* ipaddr)
{
	PLUGIN_INVOKE_1(hub, on_connection_refused, ipaddr);
}

void plugin_log_user_login_success(struct hub_info* hub, struct hub_user* who)
{
	struct plugin_user* user = convert_user_type(who);
	PLUGIN_INVOKE_1(hub, on_user_login, user);
}

void plugin_log_user_login_error(struct hub_info* hub, struct hub_user* who, const char* reason)
{
	struct plugin_user* user = convert_user_type(who);
	PLUGIN_INVOKE_2(hub, on_user_login_error, user, reason);
}

void plugin_log_user_logout(struct hub_info* hub, struct hub_user* who, const char* reason)
{
	struct plugin_user* user = convert_user_type(who);
	PLUGIN_INVOKE_2(hub, on_user_logout, user, reason);
}

void plugin_log_user_nick_change(struct hub_info* hub, struct hub_user* who, const char* new_nick)
{
	struct plugin_user* user = convert_user_type(who);
	PLUGIN_INVOKE_2(hub, on_user_nick_change, user, new_nick);
}

void plugin_log_user_update_error(struct hub_info* hub, struct hub_user* who, const char* reason)
{
	struct plugin_user* user = convert_user_type(who);
	PLUGIN_INVOKE_2(hub, on_user_update_error, user, reason);
}

void plugin_log_chat_message(struct hub_info* hub, struct hub_user* who, const char* message, int flags)
{
	struct plugin_user* user = convert_user_type(who);
	PLUGIN_INVOKE_3(hub, on_user_chat_message, user, message, flags);
}

plugin_st plugin_handle_chat_message(struct hub_info* hub, struct hub_user* from, const char* message, int flags)
{
	(void) flags;
	struct plugin_user* user = convert_user_type(from);
	PLUGIN_INVOKE_STATUS_2(hub, on_chat_msg, user, message);
}

plugin_st plugin_handle_private_message(struct hub_info* hub, struct hub_user* from, struct hub_user* to, const char* message, int flags)
{
	(void) flags;
	struct plugin_user* user1 = convert_user_type(from);
	struct plugin_user* user2 = convert_user_type(to);
	PLUGIN_INVOKE_STATUS_3(hub, on_private_msg, user1, user2, message);
}

plugin_st plugin_handle_search(struct hub_info* hub, struct hub_user* from, const char* data)
{
	struct plugin_user* user = convert_user_type(from);
	PLUGIN_INVOKE_STATUS_2(hub, on_search, user, data);
}

plugin_st plugin_handle_search_result(struct hub_info* hub, struct hub_user* from, struct hub_user* to, const char* data)
{
	struct plugin_user* user1 = convert_user_type(from);
	struct plugin_user* user2 = convert_user_type(to);
	PLUGIN_INVOKE_STATUS_3(hub, on_search_result, user1, user2, data);
}

plugin_st plugin_handle_connect(struct hub_info* hub, struct hub_user* from, struct hub_user* to)
{
	struct plugin_user* user1 = convert_user_type(from);
	struct plugin_user* user2 = convert_user_type(to);
	PLUGIN_INVOKE_STATUS_2(hub, on_p2p_connect, user1, user2);
}

plugin_st plugin_handle_revconnect(struct hub_info* hub, struct hub_user* from, struct hub_user* to)
{
	struct plugin_user* user1 = convert_user_type(from);
	struct plugin_user* user2 = convert_user_type(to);
	PLUGIN_INVOKE_STATUS_2(hub, on_p2p_revconnect, user1, user2);
}

plugin_st plugin_flood_detected(struct hub_info* hub, struct hub_user* who, enum plugin_flood_type type)
{
	struct plugin_user* user = convert_user_type(who);
	PLUGIN_INVOKE_STATUS_2(hub, on_flood_detected, user, type);
}

plugin_st plugin_auth_get_user(struct hub_info* hub, const char* nickname, struct auth_info* info)
{
	PLUGIN_INVOKE_STATUS_2(hub, auth_get_user, nickname, info);
}

plugin_st plugin_auth_register_user(struct hub_info* hub, struct auth_info* info)
{
	PLUGIN_INVOKE_STATUS_1(hub, auth_register_user, info);
}

plugin_st plugin_auth_update_user(struct hub_info* hub, struct auth_info* info)
{
	PLUGIN_INVOKE_STATUS_1(hub, auth_update_user, info);
}

plugin_st plugin_auth_delete_user(struct hub_info* hub, struct auth_info* info)
{
	PLUGIN_INVOKE_STATUS_1(hub, auth_delete_user, info);
}

plugin_st plugin_ban_add(struct hub_info* hub, const struct ban_info* ban)
{
	PLUGIN_INVOKE_STATUS_1(hub, auth_ban_add, ban);
}

plugin_st plugin_ban_del(struct hub_info* hub, const struct ban_info* ban)
{
	PLUGIN_INVOKE_STATUS_1(hub, auth_ban_del, ban);
}

plugin_st plugin_is_banned(struct hub_info* hub, struct hub_user* who, time_t* expiry, char* reason)
{
	struct plugin_user* user = convert_user_type(who);
	*expiry = 0;
	if (reason)
		reason[0] = '\0';
	PLUGIN_INVOKE_STATUS_3(hub, auth_is_banned, user, expiry, reason);
}
