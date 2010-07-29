/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2010, Jan Vidar Krey
 */

#include "plugin_api/handle.h"
#include "util/memory.h"
#include "util/list.h"
#include "util/ipcalc.h"
#include "util/misc.h"
#include "util/log.h"
#include "util/config_token.h"

static void set_error_message(struct uhub_plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

struct acl_list
{
	struct linked_list* users;
};

void insert_user(struct linked_list* users, const char* nick, const char* pass, enum auth_credentials cred)
{
	struct auth_info* data = (struct auth_info*) hub_malloc_zero(sizeof(struct auth_info));
	strncpy(data->nickname, nick, MAX_NICK_LEN);
	strncpy(data->password, pass, MAX_PASS_LEN);
	data->credentials = cred;
	list_append(users, data);
}

static int parse_line(char* line, int line_count, void* ptr_data)
{
	struct linked_list* users = (struct linked_list*) ptr_data;
	struct cfg_tokens* tokens = cfg_tokenize(line);
	enum auth_credentials cred;

	if (cfg_token_count(tokens) == 0)
		return 0;

	if (cfg_token_count(tokens) < 2)
		return -1;

	char* credential = cfg_token_get_first(tokens);
	char* username   = cfg_token_get_next(tokens);
	char* password   = cfg_token_get_next(tokens);

	if (strcmp(credential,      "admin")) cred = auth_cred_admin;
	else if (strcmp(credential, "super")) cred = auth_cred_super;
	else if (strcmp(credential, "op")) cred = auth_cred_operator;
	else if (strcmp(credential, "reg")) cred = auth_cred_user;
	else
		return -1;

	insert_user(users, username, password, cred);
	cfg_tokens_free(tokens);
	return 0;
}


static struct acl_list* load_acl(const char* filename, struct uhub_plugin_handle* handle)
{
	struct acl_list* list = (struct acl_list*) hub_malloc(sizeof(struct acl_list));
	struct linked_list* users = list_create();

	if (!list || !users)
	{
		list_destroy(users);
		hub_free(list);
		set_error_message(handle, "Unable to allocate memory");
		return 0;
	}

	if (!filename || !*filename)
	{
		list_destroy(users);
		hub_free(list);
		set_error_message(handle, "No configuration file given");
		return 0;
	}

	if (users)
	{
		if (file_read_lines(filename, users, &parse_line) == -1)
		{
			fprintf(stderr, "Unable to load %s\n", filename);
			set_error_message(handle, "Unable to load file");
		}
	}

	list->users = users;
	return list;
}

static void unload_acl(struct acl_list* list)
{
	if (!list)
		return;

	list_clear(list->users, hub_free);
	list_destroy(list->users);
	hub_free(list);
}

static int get_user(const char* nickname, struct auth_info* info)
{
	return 0;
}

static plugin_st register_user(struct auth_info* user)
{
	/* Read only mode - so rejected */
	return st_deny;
}

static plugin_st update_user(struct auth_info* user)
{
	/* Read only mode - so rejected */
	return st_deny;
}

static plugin_st delete_user(struct auth_info* user)
{
	/* Read only mode - so rejected */
	return st_deny;
}

int plugin_register(struct uhub_plugin_handle* plugin, const char* config)
{
	plugin->name = "File authentication plugin";
	plugin->version = "0.1";
	plugin->description = "Authenticated users based on a read-only text file.";
	plugin->plugin_api_version = PLUGIN_API_VERSION;
	plugin->plugin_funcs_size = sizeof(struct plugin_funcs);
	memset(&plugin->funcs, 0, sizeof(struct plugin_funcs));

	// Authentication actions.
	plugin->funcs.auth_get_user = get_user;
	plugin->funcs.auth_register_user = register_user;
	plugin->funcs.auth_update_user = update_user;
	plugin->funcs.auth_delete_user = delete_user;

	plugin->ptr = load_acl(config, plugin);
	if (plugin->ptr)
		return 0;
	return -1;
}

int plugin_unregister(struct uhub_plugin_handle* plugin)
{
	set_error_message(plugin, 0);
	unload_acl(plugin->ptr);
	return 0;
}

