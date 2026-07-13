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

#ifndef HAVE_UHUB_PLUGIN_INVOKE_H
#define HAVE_UHUB_PLUGIN_INVOKE_H

#include "plugin_api/handle.h"

struct hub_info;
struct hub_user;
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

/* Login-time nick/CID validation. A plugin returning st_deny rejects the login. */
plugin_st plugin_check_nick(struct hub_info* hub, const char* nick);
plugin_st plugin_check_cid(struct hub_info* hub, const char* cid);

/* A logged-in user wants to change nick. st_allow permits the (local) rename;
   st_deny/st_default leaves it disallowed (the hub's default). */
plugin_st plugin_change_nick(struct hub_info* hub, struct hub_user* user, const char* new_nick);

/* Hub lifecycle notifications (no interception). */
void plugin_hub_started(struct hub_info* hub);
void plugin_hub_shutdown(struct hub_info* hub);

/* Handle chat messages */
plugin_st plugin_handle_chat_message(struct hub_info* hub, struct hub_user* from, const char* message, int flags);
plugin_st plugin_handle_private_message(struct hub_info* hub, struct hub_user* from, struct hub_user* to, const char* message, int flags);

/* Handle searches */
plugin_st plugin_handle_search(struct hub_info* hub, struct hub_user* user, const char* data);
plugin_st plugin_handle_search_result(struct hub_info* hub, struct hub_user* from, struct hub_user* to, const char* data);

/* Handle p2p connections */
plugin_st plugin_handle_connect(struct hub_info* hub, struct hub_user* from, struct hub_user* to);
plugin_st plugin_handle_revconnect(struct hub_info* hub, struct hub_user* from, struct hub_user* to);

/* A flood was detected by the hub; let plugins decide the action. */
plugin_st plugin_flood_detected(struct hub_info* hub, struct hub_user* user, enum plugin_flood_type type);

/* Authentication related */
plugin_st plugin_auth_get_user(struct hub_info* hub, const char* nickname, struct auth_info* info);
plugin_st plugin_auth_register_user(struct hub_info* hub, struct auth_info* user);
plugin_st plugin_auth_update_user(struct hub_info* hub, struct auth_info* user);
plugin_st plugin_auth_delete_user(struct hub_info* hub, struct auth_info* user);

/* Ban storage/retention. The hub persists bans through a storage plugin and asks
   at login whether a user is banned. plugin_is_banned returns st_deny if any
   plugin reports the user as banned. */
plugin_st plugin_ban_add(struct hub_info* hub, const struct ban_info* ban);
plugin_st plugin_ban_del(struct hub_info* hub, const struct ban_info* ban);
/* reason, if non-NULL, must point to a MAX_BAN_REASON-byte buffer; on st_deny it
   receives the ban reason ("" if none). */
plugin_st plugin_is_banned(struct hub_info* hub, struct hub_user* user, time_t* expiry, char* reason);

#endif // HAVE_UHUB_PLUGIN_INVOKE_H

