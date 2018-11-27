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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef HAVE_UHUB_PLUGIN_HANDLE_H
#define HAVE_UHUB_PLUGIN_HANDLE_H

/**
 * This file describes the interface a uhub uses to interact with plugins.
 */

#include "system.h"
#include "util/credentials.h"
#include "network/ipcalc.h"
#include "plugin_api/types.h"
#include "plugin_api/command_api.h"

typedef void (*on_connection_accepted_t)(struct plugin_handle*, struct ip_addr_encap*);
typedef void (*on_connection_refused_t)(struct plugin_handle*, struct ip_addr_encap*);

typedef void (*on_user_login_t)(struct plugin_handle*, struct plugin_user*);
typedef void (*on_user_login_error_t)(struct plugin_handle*, struct plugin_user*, const char* reason);
typedef void (*on_user_logout_t)(struct plugin_handle*, struct plugin_user*, const char* reason);
typedef void (*on_user_nick_change_t)(struct plugin_handle*, struct plugin_user*, const char* new_nick);
typedef void (*on_user_update_error_t)(struct plugin_handle*, struct plugin_user*, const char* reason);
typedef void (*on_user_chat_msg_t)(struct plugin_handle*, struct plugin_user*, const char* message, int flags);

typedef void (*on_hub_started_t)(struct plugin_handle*, struct plugin_hub_info*);
typedef void (*on_hub_reloaded_t)(struct plugin_handle*, struct plugin_hub_info*);
typedef void (*on_hub_shutdown_t)(struct plugin_handle*, struct plugin_hub_info*);
typedef void (*on_hub_error_t)(struct plugin_handle*, struct plugin_hub_info*, const char* message);

typedef plugin_st (*on_check_ip_early_t)(struct plugin_handle*, struct ip_addr_encap*);
typedef plugin_st (*on_check_ip_late_t)(struct plugin_handle*, struct plugin_user*, struct ip_addr_encap*);
typedef plugin_st (*on_validate_nick_t)(struct plugin_handle*, const char* nick);
typedef plugin_st (*on_validate_cid_t)(struct plugin_handle*, const char* cid);
typedef plugin_st (*on_change_nick_t)(struct plugin_handle*, struct plugin_user*, const char* new_nick);

typedef plugin_st (*on_chat_msg_t)(struct plugin_handle*, struct plugin_user* from, const char* message);
typedef plugin_st (*on_private_msg_t)(struct plugin_handle*, struct plugin_user* from, struct plugin_user* to, const char* message);
typedef plugin_st (*on_search_t)(struct plugin_handle*, struct plugin_user* from, const char* data);
typedef plugin_st (*on_search_result_t)(struct plugin_handle*, struct plugin_user* from, struct plugin_user* to, const char* data);
typedef plugin_st (*on_p2p_connect_t)(struct plugin_handle*, struct plugin_user* from, struct plugin_user* to);
typedef plugin_st (*on_p2p_revconnect_t)(struct plugin_handle*, struct plugin_user* from, struct plugin_user* to);

typedef plugin_st (*auth_get_user_t)(struct plugin_handle*, const char* nickname, struct auth_info* info);
typedef plugin_st (*auth_register_user_t)(struct plugin_handle*, struct auth_info* user);
typedef plugin_st (*auth_update_user_t)(struct plugin_handle*, struct auth_info* user);
typedef plugin_st (*auth_delete_user_t)(struct plugin_handle*, struct auth_info* user);

/**
 * These are callbacks used for the hub to invoke functions in plugins.
 * The marked ones are not being called yet.
 */
struct plugin_funcs
{
	// Log events for connections
	on_connection_accepted_t on_connection_accepted; /* Someone successfully connected to the hub */
	on_connection_refused_t  on_connection_refused;  /* Someone was refused connection to the hub */

	// Log events for users
	on_user_login_t         on_user_login;       /* A user has successfully logged in to the hub */
	on_user_login_error_t   on_user_login_error; /* A user has failed to log in to the hub */
	on_user_logout_t        on_user_logout;      /* A user has logged out of the hub (was previously logged in) */
/* ! */	on_user_nick_change_t   on_user_nick_change; /* A user has changed nickname */
	on_user_update_error_t  on_user_update_error;/* A user has failed to update - nickname, etc. */
	on_user_chat_msg_t      on_user_chat_message;/* A user has sent a public chat message */

	// Log hub events
/* ! */	on_hub_started_t        on_hub_started;      /* Triggered just after plugins are loaded and the hub is started. */
/* ! */	on_hub_reloaded_t       on_hub_reloaded;     /* Triggered immediately after hub configuration is reloaded. */
/* ! */	on_hub_shutdown_t       on_hub_shutdown;     /* Triggered just before the hub is being shut down and before plugins are unloaded. */
/* ! */	on_hub_error_t          on_hub_error;        /* Triggered for log-worthy error messages */

	// Activity events (can be intercepted and refused/accepted by a plugin)
	on_check_ip_early_t     on_check_ip_early;   /* A user has just connected (can be intercepted) */
/* ! */	on_check_ip_late_t      on_check_ip_late;    /* A user has logged in (can be intercepted) */
/* ! */	on_change_nick_t        on_change_nick;      /* A user wants to change his nick (can be intercepted) */
	on_chat_msg_t           on_chat_msg;         /* A public chat message is about to be sent (can be intercepted) */
	on_private_msg_t        on_private_msg;      /* A public chat message is about to be sent (can be intercepted) */
	on_search_t             on_search;           /* A search is about to be sent (can be intercepted) */
	on_search_result_t      on_search_result;    /* A search result is about to be sent (can be intercepted) */
	on_p2p_connect_t        on_p2p_connect;      /* A user is about to connect to another user (can be intercepted) */
	on_p2p_revconnect_t     on_p2p_revconnect;   /* A user is about to connect to another user (can be intercepted) */

	// Authentication actions.
	auth_get_user_t         auth_get_user;       /* Get authentication info from plugin */
	auth_register_user_t    auth_register_user;  /* Register user */
	auth_update_user_t      auth_update_user;    /* Update a registered user */
	auth_delete_user_t      auth_delete_user;    /* Delete a registered user */

};

struct plugin_command_handle;
struct plugin_command;
struct plugin_command_arg_data;

typedef int (*hfunc_send_message)(struct plugin_handle*, struct plugin_user* user, const char* message);
typedef int (*hfunc_send_broadcast_message)(struct plugin_handle*, const char* message);
typedef int (*hfunc_send_status)(struct plugin_handle*, struct plugin_user* to, int code, const char* message);
typedef int (*hfunc_user_disconnect)(struct plugin_handle*, struct plugin_user* user);
typedef int (*hfunc_command_add)(struct plugin_handle*, struct plugin_command_handle*);
typedef int (*hfunc_command_del)(struct plugin_handle*, struct plugin_command_handle*);

typedef size_t (*hfunc_command_arg_reset)(struct plugin_handle*, struct plugin_command*);
typedef struct plugin_command_arg_data* (*hfunc_command_arg_next)(struct plugin_handle*, struct plugin_command*, enum plugin_command_arg_type);

typedef size_t (*hfunc_get_usercount)(struct plugin_handle*);

typedef char* (*hfunc_get_hub_name)(struct plugin_handle*);
typedef void  (*hfunc_set_hub_name)(struct plugin_handle*, const char*);
typedef char* (*hfunc_get_hub_description)(struct plugin_handle*);
typedef void  (*hfunc_set_hub_description)(struct plugin_handle*, const char*);

/**
 * These are functions created and initialized by the hub and which can be used
 * by plugins to access functionality internal to the hub.
 */
struct plugin_hub_funcs
{
	hfunc_send_message send_message;
	hfunc_send_broadcast_message send_broadcast_message;
	hfunc_send_status send_status_message;
	hfunc_user_disconnect user_disconnect;
	hfunc_command_add command_add;
	hfunc_command_del command_del;
	hfunc_command_arg_reset command_arg_reset;
	hfunc_command_arg_next command_arg_next;
	hfunc_get_usercount get_usercount;
	hfunc_get_hub_name get_name;
	hfunc_set_hub_name set_name;
	hfunc_get_hub_description get_description;
	hfunc_set_hub_description set_description;
};

struct plugin_handle
{
	struct uhub_plugin* handle;     /* Must NOT be modified by the plugin */
	const char* name;               /* plugin name */
	const char* version;            /* plugin version */
	const char* description;        /* plugin description */
	void* ptr;                      /* Plugin specific data */
	const char* error_msg;          /* Error message for registration error. */
	size_t plugin_api_version;      /* Plugin API version */
	size_t plugin_funcs_size;       /* Size of the plugin funcs */
	struct plugin_funcs funcs;      /* Table of functions that can be implemented by a plugin */
	struct plugin_hub_funcs hub;    /* Table of core hub functions that can be used by a plugin */
};


#define PLUGIN_INITIALIZE(PTR, NAME, VERSION, DESCRIPTION) \
	do { \
		PTR->name = NAME; \
		PTR->version = VERSION; \
		PTR->description = DESCRIPTION; \
		PTR->ptr = NULL; \
		PTR->error_msg = NULL; \
		PTR->plugin_api_version = PLUGIN_API_VERSION; \
		PTR->plugin_funcs_size = sizeof(struct plugin_funcs); \
		memset(&PTR->funcs, 0, sizeof(struct plugin_funcs)); \
	} while (0)

/**
 * Implemented by the plugin.
 *
 * @param handle[out] Sets all information by the plugin
 * @param config A configuration string
 * @return 0 on success, -1 on error.
 */
PLUGIN_API int plugin_register(struct plugin_handle* handle, const char* config);

/**
 * @return 0 on success, -1 on error.
 */
PLUGIN_API int plugin_unregister(struct plugin_handle*);

typedef int (*plugin_register_f)(struct plugin_handle* handle, const char* config);
typedef int (*plugin_unregister_f)(struct plugin_handle*);

#endif /* HAVE_UHUB_PLUGIN_HANDLE_H */
