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

#ifndef HAVE_UHUB_PLUGIN_HANDLE_H
#define HAVE_UHUB_PLUGIN_HANDLE_H

#include "system.h"
#include "util/credentials.h"
#include "util/ipcalc.h"

#define PLUGIN_API_VERSION 0

#ifndef MAX_NICK_LEN
#define MAX_NICK_LEN 64
#endif

#ifndef MAX_PASS_LEN
#define MAX_PASS_LEN 64
#endif

struct plugin_user
{
	unsigned int sid;
	const char* nick;
	const char* cid;
	struct ip_addr_encap addr;
	enum auth_credentials credentials;
};

enum plugin_status
{
	st_default = 0,    /* Use default */
	st_allow = 1,      /* Allow action */
	st_deny = -1,      /* Deny action */
};

typedef enum plugin_status plugin_st;

struct auth_info
{
	char nickname[MAX_NICK_LEN+1];
	char password[MAX_PASS_LEN+1];
	enum auth_credentials credentials;
};

typedef plugin_st (*on_chat_msg_t)(struct plugin_user* from, const char* message);
typedef plugin_st (*on_private_msg_t)(struct plugin_user* from, struct plugin_user* to, const char* message);
typedef plugin_st (*on_search_t)(struct plugin_user* from, const char* data);
typedef plugin_st (*on_p2p_connect_t)(struct plugin_user* from, struct plugin_user* to);
typedef plugin_st (*on_p2p_revconnect_t)(struct plugin_user* from, struct plugin_user* to);

typedef void (*on_user_connect_t)(struct ip_addr_encap*);
typedef void (*on_user_login_t)(struct plugin_user*);
typedef void (*on_user_login_error_t)(struct plugin_user*, const char* reason);
typedef void (*on_user_logout_t)(struct plugin_user*, const char* reason);
typedef void (*on_user_nick_change_t)(struct plugin_user*, const char* new_nick);
typedef void (*on_user_update_error_t)(struct plugin_user*, const char* reason);

typedef plugin_st (*on_change_nick_t)(struct plugin_user*, const char* new_nick);

typedef plugin_st (*on_check_ip_early_t)(struct ip_addr_encap*);
typedef plugin_st (*on_check_ip_late_t)(struct ip_addr_encap*);
typedef plugin_st (*on_validate_nick_t)(const char* nick);
typedef plugin_st (*on_validate_cid_t)(const char* cid);

typedef int (*auth_get_user_t)(const char* nickname, struct auth_info* info);
typedef plugin_st (*auth_register_user_t)(struct auth_info* user);
typedef plugin_st (*auth_update_user_t)(struct auth_info* user);
typedef plugin_st (*auth_delete_user_t)(struct auth_info* user);

struct plugin_funcs
{
	// Log events for users
	on_user_connect_t       on_user_connect;     /* A user has connected to the hub */
	on_user_login_t         on_user_login;       /* A user has successfully logged in to the hub */
	on_user_login_error_t   on_user_login_error; /* A user has failed to log in to the hub */
	on_user_logout_t        on_user_logout;      /* A user has logged out of the hub (was previously logged in) */
	on_user_nick_change_t   on_user_nick_change; /* A user has changed nickname */
	on_user_update_error_t  on_user_update_error;/* A user has failed to update - nickname, etc. */

	// Activity events (can be intercepted and refused by a plugin)
	on_chat_msg_t           on_chat_msg;         /* A public chat message is about to be sent (can be intercepted) */
	on_private_msg_t        on_private_msg;      /* A public chat message is about to be sent (can be intercepted) */
	on_search_t             on_search;           /* A search is about to be sent (can be intercepted) */
	on_p2p_connect_t        on_p2p_connect;      /* A user is about to connect to another user (can be intercepted) */
	on_p2p_revconnect_t     on_p2p_revconnect;   /* A user is about to connect to another user (can be intercepted) */

	// Authentication actions.
	auth_get_user_t         auth_get_user;       /* Get authentication info from plugin */
	auth_register_user_t    auth_register_user;  /* Register user */
	auth_update_user_t      auth_update_user;    /* Update a registered user */
	auth_delete_user_t      auth_delete_user;    /* Delete a registered user */

	// Login check functions
	on_check_ip_early_t     login_check_ip_early;
	on_check_ip_late_t      login_check_ip_late;

};

struct uhub_plugin_handle
{
	struct uhub_plugin* handle;     /* Must NOT be modified by the plugin */
	const char* name;               /* plugin name */
	const char* version;            /* plugin version */
	const char* description;        /* plugin description */
	void* ptr;                      /* Plugin specific data */
	const char* error_msg;          /* Error message for registration error. */
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

#endif /* HAVE_UHUB_PLUGIN_HANDLE_H */
