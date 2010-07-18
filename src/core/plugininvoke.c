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

#define PLUGIN_INVOKE(HUB, FUNCNAME, CODE) \
	if (HUB->plugins && HUB->plugins->loaded) \
	{ \
		struct uhub_plugin_handle* plugin = (struct uhub_plugin_handle*) list_get_first(HUB->plugins->loaded); \
		while (plugin) \
		{ \
			if (plugin->funcs.FUNCNAME) \
				CODE \
			plugin = (struct uhub_plugin_handle*) list_get_next(HUB->plugins->loaded); \
		} \
	}

#define PLUGIN_INVOKE_STATUS(HUB, FUNCNAME, ARGS) \
	plugin_st status = st_default; \
	PLUGIN_INVOKE(HUB, FUNCNAME, { \
		status = plugin->funcs.FUNCNAME ARGS ; \
		if (status != st_default) \
			break; \
	}); \
	return status


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
	PLUGIN_INVOKE_STATUS(hub, login_check_ip_early, (addr));
}

plugin_st plugin_check_ip_late(struct hub_info* hub, struct ip_addr_encap* addr)
{
	PLUGIN_INVOKE_STATUS(hub, login_check_ip_late, (addr));
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

void plugin_log_user_login_success(struct hub_info* hub, struct hub_user* user)
{

}

void plugin_log_user_login_error(struct hub_info* hub, struct hub_user* user)
{
}

void plugin_log_user_logout(struct hub_info* hub, struct hub_user* user)
{
}

plugin_st plugin_handle_chat_message(struct hub_info* hub, struct hub_user* from, const char* message, int flags)
{
	return st_default;
}

plugin_st plugin_handle_private_message(struct hub_info* hub, struct hub_user* from, struct hub_user* to, const char* message, int flags)
{
	return st_default;
}

plugin_st plugin_handle_search(struct hub_info* hub, struct hub_user* user, const char* data)
{
	return st_default;
}

plugin_st plugin_handle_connect(struct hub_info* hub, struct hub_user* from, struct hub_user* to)
{
	return st_default;
}

plugin_st plugin_handle_revconnect(struct hub_info* hub, struct hub_user* from, struct hub_user* to)
{
	return st_default;
}


