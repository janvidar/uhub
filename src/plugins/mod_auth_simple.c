/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2010, Jan Vidar Krey
 */

#include "plugin_api/handle.h"
#include "util/memory.h"
#include "util/list.h"
#include "util/ipcalc.h"


struct user_access_info
{
	char* username;
	char* password;
	enum auth_credentials credentials;
};

struct acl_list
{
	struct linked_list* users; /* see struct user_access_info */
};

static void free_user_access_info(void* ptr)
{
	struct user_access_info* info = (struct user_access_info*) ptr;
	hub_free(info->username);
	hub_free(info->password);
	hub_free(info);
}

static struct acl_list* load_acl(const char* filename)
{
	struct acl_list* list = (struct acl_list*) hub_malloc(sizeof(struct acl_list));
	struct linked_list* users = list_create();

	if (!list || !users)
	{
		list_destroy(users);
		hub_free(list);
		return 0;
	}

	list->users = users;
	return list;
}

static void unload_acl(struct acl_list* list)
{
	if (!list)
		return;

	list_clear(list->users, free_user_access_info);
	list_destroy(list->users);
	hub_free(list);
}


int plugin_register(struct uhub_plugin_handle* plugin, const char* config)
{
	plugin->name = "File authentication plugin";
	plugin->version = "0.1";
	plugin->description = "Simple authentication plugin that authenticates users based on a file.";
	plugin->plugin_api_version = PLUGIN_API_VERSION;
	plugin->plugin_funcs_size = sizeof(struct plugin_funcs);
	memset(&plugin->funcs, 0, sizeof(struct plugin_funcs));

	plugin->ptr = load_acl(config);	

/*
	plugin->funcs.on_connect = log_connect;
	plugin->funcs.on_user_login = log_user_login;
	plugin->funcs.on_user_logout = log_user_logout;
	plugin->funcs.on_user_change_nick = log_change_nick;
*/
	return 0;
}

int plugin_unregister(struct uhub_plugin_handle* plugin)
{
	unload_acl(plugin->ptr);
	return 0;
}

