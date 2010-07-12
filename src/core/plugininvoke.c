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

plugin_st plugin_check_ip_early(struct hub_info* hub, struct ip_addr_encap* addr)
{
	plugin_st status = st_default;
	PLUGIN_INVOKE(hub, login_check_ip_early, {
		status = plugin->funcs.login_check_ip_early(addr);
		if (status != st_default)
			break;
	});
	return status;
}

plugin_st plugin_check_ip_late(struct hub_info* hub, struct ip_addr_encap* addr)
{
	plugin_st status = st_default;
	PLUGIN_INVOKE(hub, login_check_ip_late, {
		status = plugin->funcs.login_check_ip_late(addr);
		if (status != st_default)
			break;
	});
	return status;
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


static void convert_user_to_plugin_user(struct plugin_user* puser, struct hub_user* user)
{
	puser->sid  = user->id.sid;
	puser->nick = user->id.nick;
	puser->cid  = user->id.cid;
	puser->addr = user->id.addr;
	puser->credentials = user->credentials;
}
