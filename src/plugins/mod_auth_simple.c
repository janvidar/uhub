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

#include "plugin_api/handle.h"
#include "util/memory.h"
#include "util/list.h"
#include "util/misc.h"
#include "util/log.h"
#include "util/config_token.h"

static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

struct acl_data
{
	struct linked_list* users;
	char* file;
	int readonly;
	int exclusive;
};

static void insert_user(struct linked_list* users, const char* nick, const char* pass, enum auth_credentials cred)
{
	struct auth_info* data = (struct auth_info*) hub_malloc_zero(sizeof(struct auth_info));
	strncpy(data->nickname, nick, MAX_NICK_LEN);
	strncpy(data->password, pass, MAX_PASS_LEN);
	data->credentials = cred;
	list_append(users, data);
}

static void free_acl(struct acl_data* data)
{
	if (!data)
		return;

	if (data->users)
	{
		list_clear(data->users, hub_free);
		list_destroy(data->users);
	}
	hub_free(data->file);
	hub_free(data);
}

static struct acl_data* parse_config(const char* line)
{
	struct acl_data* data = (struct acl_data*) hub_malloc_zero(sizeof(struct acl_data));
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char* token = cfg_token_get_first(tokens);

	if (!data)
		return 0;

	// set defaults
	data->readonly = 1;
	data->exclusive = 0;
	data->users = list_create();

	while (token)
	{
		char* split = strchr(token, '=');
		size_t len = strlen(token);
		size_t key = split ? (split - token) : len;
		if (key == 4 && strncmp(token, "file", 4) == 0)
		{
			if (data->file)
				hub_free(data->file);
			data->file = strdup(split + 1);
		}
		else if (key == 8 && strncmp(token, "readonly", 8) == 0)
		{
			if (!string_to_boolean(split + 1, &data->readonly))
				data->readonly = 1;
		}
		else if (key == 9 && strncmp(token, "exclusive", 9) == 0)
		{
			if (!string_to_boolean(split + 1, &data->exclusive))
				data->exclusive = 1;
		}
		else
		{
			cfg_tokens_free(tokens);
			free_acl(data);
			return 0;
		}

		token = cfg_token_get_next(tokens);
	}

	cfg_tokens_free(tokens);
	return data;
}

static int parse_line(char* line, int line_count, void* ptr_data)
{
	struct linked_list* users = (struct linked_list*) ptr_data;
	struct cfg_tokens* tokens = cfg_tokenize(line);
	enum auth_credentials cred;
	char* credential;
	char* username;
	char* password;

	if (cfg_token_count(tokens) == 0)
	{
		cfg_tokens_free(tokens);
		return 0;
	}

	if (cfg_token_count(tokens) < 2)
	{
		cfg_tokens_free(tokens);
		return -1;
	}

	credential = cfg_token_get_first(tokens);
	username   = cfg_token_get_next(tokens);
	password   = cfg_token_get_next(tokens);

	if (!auth_string_to_cred(credential, &cred))
	{
		cfg_tokens_free(tokens);
		return -1;
	}

	insert_user(users, username, password, cred);
	cfg_tokens_free(tokens);
	return 0;
}

static struct acl_data* load_acl(const char* config, struct plugin_handle* handle)
{

	struct acl_data* data = parse_config(config);

	if (!data)
		return 0;

	if (!data->file || !*data->file)
	{
		free_acl(data); data = 0;
		set_error_message(handle, "No configuration file given, missing \"file=<filename>\" configuration option.");
		return 0;
	}

	if (file_read_lines(data->file, data->users, &parse_line) == -1)
	{
		fprintf(stderr, "Unable to load %s\n", data->file);
		set_error_message(handle, "Unable to load file");
	}

	return data;
}

static void unload_acl(struct acl_data* data)
{
	free_acl(data);
}

static plugin_st get_user(struct plugin_handle* plugin, const char* nickname, struct auth_info* data)
{
	struct acl_data* acl = (struct acl_data*) plugin->ptr;
	struct auth_info* info;
	LIST_FOREACH(struct auth_info*, info, acl->users,
	{
		if (strcasecmp((char*)info->nickname, nickname) == 0)
		{
			memcpy(data, info, sizeof(struct auth_info));
			return st_allow;
		}
	});
	if (acl->exclusive)
		return st_deny;
	return st_default;
}

static plugin_st register_user(struct plugin_handle* plugin, struct auth_info* user)
{
	struct acl_data* acl = (struct acl_data*) plugin->ptr;
	if (acl->exclusive)
		return st_deny;
	return st_default;
}

static plugin_st update_user(struct plugin_handle* plugin, struct auth_info* user)
{
	struct acl_data* acl = (struct acl_data*) plugin->ptr;
	if (acl->exclusive)
		return st_deny;
	return st_default;
}

static plugin_st delete_user(struct plugin_handle* plugin, struct auth_info* user)
{
	struct acl_data* acl = (struct acl_data*) plugin->ptr;
	if (acl->exclusive)
		return st_deny;
	return st_default;
}

PLUGIN_API int plugin_register(struct plugin_handle* plugin, const char* config)
{
	PLUGIN_INITIALIZE(plugin, "File authentication plugin", "0.1", "Authenticate users based on a read-only text file.");

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

PLUGIN_API int plugin_unregister(struct plugin_handle* plugin)
{
	set_error_message(plugin, 0);
	unload_acl(plugin->ptr);
	return 0;
}

