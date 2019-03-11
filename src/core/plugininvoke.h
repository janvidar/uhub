/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2014, Jan Vidar Krey
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

#ifndef HAVE_UHUB_PLUGIN_INVOKE_H
#define HAVE_UHUB_PLUGIN_INVOKE_H

#include "uhub.h"
#include "plugin_api/handle.h"

struct hub_info;
struct ip_addr_encap;

/* All log related functions */
void plugin_log_connection_accepted(struct hub_info* hub, struct ip_addr_encap* addr);
void plugin_log_connection_denied(struct hub_info* hub, struct ip_addr_encap* addr);
void plugin_log_user_login_success(struct hub_info* hub, struct hub_user* user);
void plugin_log_user_login_error(struct hub_info* hub, struct hub_user* user, const char* reason);
void plugin_log_user_logout(struct hub_info* hub, struct hub_user* user, const char* reason);
void plugin_log_user_nick_change(struct hub_info* hub, struct hub_user* user, const char* new_nick);
void plugin_log_user_update_error(struct hub_info* hub, struct hub_user* user, const char* reason);
void plugin_log_chat_message(struct hub_info* hub, struct hub_user* from, const char* message, int flags);

/* IP ban related */
plugin_st plugin_check_ip_early(struct hub_info* hub, struct ip_addr_encap* addr);
plugin_st plugin_check_ip_late(struct hub_info* hub, struct hub_user* user, struct ip_addr_encap* addr);

/* Nickname allow/deny handling */
plugin_st plugin_check_nickname_valid(struct hub_info* hub, const char* nick);
plugin_st plugin_check_nickname_reserved(struct hub_info* hub, const char* nick);

/* Handle chat messages */
plugin_st plugin_handle_chat_message(struct hub_info* hub, struct hub_user* from, const char* message, int flags);
plugin_st plugin_handle_private_message(struct hub_info* hub, struct hub_user* from, struct hub_user* to, const char* message, int flags);

/* Handle searches */
plugin_st plugin_handle_search(struct hub_info* hub, struct hub_user* user, const char* data);
plugin_st plugin_handle_search_result(struct hub_info* hub, struct hub_user* from, struct hub_user* to, const char* data);

/* Handle p2p connections */
plugin_st plugin_handle_connect(struct hub_info* hub, struct hub_user* from, struct hub_user* to);
plugin_st plugin_handle_revconnect(struct hub_info* hub, struct hub_user* from, struct hub_user* to);

/* Authentication related */
plugin_st plugin_auth_get_user(struct hub_info* hub, const char* nickname, struct auth_info* info);
plugin_st plugin_auth_register_user(struct hub_info* hub, struct auth_info* user);
plugin_st plugin_auth_update_user(struct hub_info* hub, struct auth_info* user);
plugin_st plugin_auth_delete_user(struct hub_info* hub, struct auth_info* user);

#endif // HAVE_UHUB_PLUGIN_INVOKE_H

