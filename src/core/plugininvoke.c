/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2010, Jan Vidar Krey
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

#include "uhub.h"
#include "plugin_api/handle.h"

#define PLUGIN_DEBUG(hub, name) printf("Invoke %s on %d plugins\n",name, (int) (hub->plugins ? list_size(hub->plugins->loaded) : -1));


#define INVOKE(HUB, FUNCNAME, CODE) \
	PLUGIN_DEBUG(HUB, # FUNCNAME) \
	if (HUB->plugins && HUB->plugins->loaded) \
	{ \
		struct plugin_handle* plugin = (struct plugin_handle*) list_get_first(HUB->plugins->loaded); \
		while (plugin) \
		{ \
			if (plugin->funcs.FUNCNAME) \
				CODE \
			plugin = (struct plugin_handle*) list_get_next(HUB->plugins->loaded); \
		} \
	}

#define PLUGIN_INVOKE_STATUS_1(HUB, FUNCNAME, ARG1) \
	plugin_st status = st_default; \
	INVOKE(HUB, FUNCNAME, { \
		status = plugin->funcs.FUNCNAME(plugin, ARG1); \
		if (status != st_default) \
			break; \
	}); \
	return status

#define PLUGIN_INVOKE_STATUS_2(HUB, FUNCNAME, ARG1, ARG2) \
	plugin_st status = st_default; \
	INVOKE(HUB, FUNCNAME, { \
		status = plugin->funcs.FUNCNAME(plugin, ARG1, ARG2); \
		if (status != st_default) \
			break; \
	}); \
	return status

#define PLUGIN_INVOKE_STATUS_3(HUB, FUNCNAME, ARG1, ARG2, ARG3) \
	plugin_st status = st_default; \
	INVOKE(HUB, FUNCNAME, { \
		status = plugin->funcs.FUNCNAME(plugin, ARG1, ARG2, ARG3); \
		if (status != st_default) \
			break; \
	}); \
	return status

#define PLUGIN_INVOKE_1(HUB, FUNCNAME, ARG1) \
	INVOKE(HUB, FUNCNAME, { \
		plugin->funcs.FUNCNAME(plugin, ARG1); \
	})

#define PLUGIN_INVOKE_2(HUB, FUNCNAME, ARG1, ARG2) \
	INVOKE(HUB, FUNCNAME, { \
		plugin->funcs.FUNCNAME(plugin, ARG1, ARG2); \
	})

static void convert_user_type(struct plugin_user* puser, struct hub_user* user)
{
	puser->sid  = user->id.sid;
	puser->nick = user->id.nick;
	puser->cid  = user->id.cid;
	puser->addr = user->id.addr;
	puser->credentials = user->credentials;
}

plugin_st plugin_check_ip_early(struct hub_info* hub, struct ip_addr_encap* addr)
{
	PLUGIN_INVOKE_STATUS_1(hub, login_check_ip_early, addr);
}

plugin_st plugin_check_ip_late(struct hub_info* hub, struct ip_addr_encap* addr)
{
	PLUGIN_INVOKE_STATUS_1(hub, login_check_ip_late, addr);
}

void plugin_log_connection_accepted(struct hub_info* hub, struct ip_addr_encap* ipaddr)
{
	const char* addr = ip_convert_to_string(ipaddr);
	LOG_TRACE("Got connection from %s", addr);
}

void plugin_log_connection_denied(struct hub_info* hub, struct ip_addr_encap* ipaddr)
{
	const char* addr = ip_convert_to_string(ipaddr);
	LOG_INFO("Denied connection from %s", addr);
}

void plugin_log_user_login_success(struct hub_info* hub, struct hub_user* who)
{
	struct plugin_user user;
	convert_user_type(&user, who);
	PLUGIN_INVOKE_1(hub, on_user_login, &user);
}

void plugin_log_user_login_error(struct hub_info* hub, struct hub_user* who, const char* reason)
{
	struct plugin_user user;
	convert_user_type(&user, who);
	PLUGIN_INVOKE_2(hub, on_user_login_error, &user, reason);
}

void plugin_log_user_logout(struct hub_info* hub, struct hub_user* who, const char* reason)
{
	struct plugin_user user;
	convert_user_type(&user, who);
	PLUGIN_INVOKE_2(hub, on_user_logout, &user, reason);
}

void plugin_log_user_nick_change(struct hub_info* hub, struct hub_user* who, const char* new_nick)
{
	struct plugin_user user;
	convert_user_type(&user, who);
	PLUGIN_INVOKE_2(hub, on_user_nick_change, &user, new_nick);
}

void plugin_log_user_update_error(struct hub_info* hub, struct hub_user* who, const char* reason)
{
	struct plugin_user user;
	convert_user_type(&user, who);
	PLUGIN_INVOKE_2(hub, on_user_update_error, &user, reason);
} 

plugin_st plugin_handle_chat_message(struct hub_info* hub, struct hub_user* from, const char* message, int flags)
{
	struct plugin_user user;
	convert_user_type(&user, from);
	PLUGIN_INVOKE_STATUS_2(hub, on_chat_msg, &user, message);
}

plugin_st plugin_handle_private_message(struct hub_info* hub, struct hub_user* from, struct hub_user* to, const char* message, int flags)
{
	struct plugin_user user1;
	struct plugin_user user2;
	convert_user_type(&user1, from);
	convert_user_type(&user2, to);
	PLUGIN_INVOKE_STATUS_3(hub, on_private_msg, &user1, &user2, message);
}

plugin_st plugin_handle_search(struct hub_info* hub, struct hub_user* from, const char* data)
{
	struct plugin_user user;
	convert_user_type(&user, from);
	PLUGIN_INVOKE_STATUS_2(hub, on_search, &user, data);
}

plugin_st plugin_handle_connect(struct hub_info* hub, struct hub_user* from, struct hub_user* to)
{
	struct plugin_user user1;
	struct plugin_user user2;
	convert_user_type(&user1, from);
	convert_user_type(&user2, to);
	PLUGIN_INVOKE_STATUS_2(hub, on_p2p_connect, &user1, &user2);
}

plugin_st plugin_handle_revconnect(struct hub_info* hub, struct hub_user* from, struct hub_user* to)
{
	struct plugin_user user1;
	struct plugin_user user2;
	convert_user_type(&user1, from);
	convert_user_type(&user2, to);
	PLUGIN_INVOKE_STATUS_2(hub, on_p2p_revconnect, &user1, &user2);
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
