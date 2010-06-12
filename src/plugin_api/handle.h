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

#include "system.h"
#include "util/ipcalc.h"

#define PLUGIN_API_VERSION 0

#ifndef MAX_NICK_LEN
#define MAX_NICK_LEN 64
#endif

#ifndef MAX_PASS_LEN
#define MAX_PASS_LEN 64
#endif

struct ip_addr_encap;

struct plugin_user
{
	unsigned int sid;
	const char* nick;
	const char* cid;
	struct ip_addr_encap addr;
};

enum plugin_status
{
	st_default = 0,    /* Use default */
	st_allow = 1,      /* Allow action */
	st_deny = -1,      /* Deny action */
	st_restrict = -2,  /* Further action required */
};

typedef enum plugin_status plugin_st;

enum auth_credentials
{
	auth_cred_none,                 /**<<< "User has no credentials (not yet logged in)" */
	auth_cred_bot,                  /**<<< "User is a robot" */
	auth_cred_guest,                /**<<< "User is a guest (unregistered user)" */
	auth_cred_user,                 /**<<< "User is identified as a registered user" */
	auth_cred_operator,             /**<<< "User is identified as a hub operator" */
	auth_cred_super,                /**<<< "User is a super user" (not used) */
	auth_cred_link,                 /**<<< "User is a link (not used currently)" */
	auth_cred_admin,                /**<<< "User is identified as a hub administrator/owner" */
};

struct auth_info
{
	char nickname[MAX_NICK_LEN+1];
	char password[MAX_PASS_LEN+1];
	enum auth_credentials credentials;
};

typedef plugin_st (*on_connect_t)(struct ip_addr_encap*);
typedef plugin_st (*on_chat_msg_t)(struct plugin_user* from, const char* message);
typedef plugin_st (*on_private_msg_t)(struct plugin_user* from, struct plugin_user* to, const char* message);
typedef plugin_st (*on_search_t)(struct plugin_user* from, const char* data);
typedef plugin_st (*on_p2p_connect_t)(struct plugin_user* from, struct plugin_user* to);
typedef plugin_st (*on_p2p_revconnect_t)(struct plugin_user* from, struct plugin_user* to);
typedef void (*on_user_login_t)(struct plugin_user*);
typedef void (*on_user_logout_t)(struct plugin_user*);
typedef plugin_st (*on_validate_nick_t)(const char* nick);
typedef plugin_st (*on_validate_cid_t)(const char* cid);
typedef plugin_st (*on_change_nick_t)(struct plugin_user*, const char* new_nick);
typedef int (*auth_get_user_t)(const char* nickname, struct auth_info* info);
typedef plugin_st (*auth_register_user_t)(struct auth_info* user);
typedef plugin_st (*auth_update_user_t)(struct auth_info* user);
typedef plugin_st (*auth_delete_user_t)(struct auth_info* user);

struct plugin_funcs
{
	// Users logging in and out
	on_connect_t            on_connect;
	on_user_login_t         on_user_login;
	on_user_logout_t        on_user_logout;
	on_change_nick_t        on_user_change_nick;

	// Activity events
	on_chat_msg_t           on_chat_msg;
	on_private_msg_t        on_private_msg;
	on_search_t             on_search;
	on_p2p_connect_t        on_p2p_connect;
	on_p2p_revconnect_t     on_p2p_revconnect;

	// Authentication
	auth_get_user_t         auth_get_user;
	auth_register_user_t    auth_register_user;
	auth_update_user_t      auth_update_user;
	auth_delete_user_t      auth_delete_user;
};

struct uhub_plugin_handle
{
	struct uhub_plugin* handle;     /* Must NOT be modified by the plugin */
	const char* name;               /* plugin name */
	const char* version;            /* plugin version */
	const char* description;        /* plugin description */
	void* ptr;                      /* Plugin specific data */
	size_t plugin_api_version;      /* Plugin API version */
	size_t plugin_funcs_size;       /* Size of the plugin funcs */
	struct plugin_funcs funcs;
};

/**
 * Implemented by the plugin.
 *
 * @param handle[out] Sets all information by the plugin
 * @param config A configuration string
 * @return 0 on success, -1 on error.
 */
extern int plugin_register(struct uhub_plugin_handle* handle, const char* config);

/**
 * @return 0 on success, -1 on error.
 */
extern int plugin_unregister(struct uhub_plugin_handle*);

typedef int (*plugin_register_f)(struct uhub_plugin_handle* handle, const char* config);
typedef int (*plugin_unregister_f)(struct uhub_plugin_handle*);
