/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2010, Jan Vidar Krey
 */

#include "plugin_api/handle.h"
#include <sqlite3.h>
#include "util/memory.h"
#include "util/list.h"
#include "util/ipcalc.h"
#include "util/misc.h"
#include "util/log.h"
#include "util/config_token.h"


static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

struct sql_data
{
	int exclusive;
	sqlite3* db;
};

static struct sql_data* parse_config(const char* line, struct plugin_handle* plugin)
{
	struct sql_data* data = (struct sql_data*) hub_malloc_zero(sizeof(struct sql_data));
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char* token = cfg_token_get_first(tokens);

	if (!data)
		return 0;

	while (token)
	{

		char* split = strchr(token, '=');
		size_t len = strlen(token);
		size_t key = split ? (split - token) : len;
		if (key == 4 && strncmp(token, "file", 4) == 0 && data->db == 0)
		{
			if (sqlite3_open(split + 1, &data->db))
			{
				cfg_tokens_free(tokens);
				hub_free(data);
				return 0;
			}
		}
		else if (key == 9 && strncmp(token, "exclusive", 9) == 0)
		{
			if (!string_to_boolean(split + 1, &data->exclusive))
				data->exclusive = 1;
		}
		else
		{
			set_error_message(plugin, "Unable to parse startup parameters");
			cfg_tokens_free(tokens);
			hub_free(data);
			return 0;
		}
		token = cfg_token_get_next(tokens);
	}

	cfg_tokens_free(tokens);
	return data;
}

static const char* sql_escape_string(const char* str)
{
	static char out[1024];
	size_t i = 0;
	size_t n = 0;
	for (; n < strlen(str); n++)
	{
		if (str[n] == '\'' || str[n] == '\\')
			out[i++] = '\\';
		out[i++] = str[n];
	}
	return out;
}

static int get_user_callback(void* ptr, int argc, char **argv, char **colName){
	struct auth_info* data = (struct auth_info*) ptr;
	int i;
	for(i=0; i<argc; i++) {
		if (strcmp(colName[i], "nickname") == 0)
			strncpy(data->nickname, argv[i], MAX_NICK_LEN);
		else if (strcmp(colName[i], "password") == 0)
			strncpy(data->password, argv[i], MAX_PASS_LEN);
		else if (strcmp(colName[i], "credentials") == 0)
		{
			auth_string_to_cred(colName[i], &data->credentials);
		}
	}
	return 0;
}

static plugin_st get_user(struct plugin_handle* plugin, const char* nickname, struct auth_info* data)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	char query[1024];
	char* errMsg;
	int rc;

	snprintf(query, sizeof(query), "SELECT * FROM users WHERE nickname='%s';", sql_escape_string(nickname));
	memset(data, 0, sizeof(struct auth_info));

	rc = sqlite3_exec(sql->db, query , get_user_callback, data, &errMsg);
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", errMsg);
		sqlite3_free(errMsg);
	}

	return st_allow;
}

static plugin_st register_user(struct plugin_handle* plugin, struct auth_info* user)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	if (sql->exclusive)
		return st_deny;
	return st_default;
}

static plugin_st update_user(struct plugin_handle* plugin, struct auth_info* user)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	if (sql->exclusive)
		return st_deny;
	return st_default;
}

static plugin_st delete_user(struct plugin_handle* plugin, struct auth_info* user)
{
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	if (sql->exclusive)
		return st_deny;
	return st_default;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	plugin->name = "SQLite authentication plugin";
	plugin->version = "0.1";
	plugin->description = "Authenticate users based on a SQLite database.";
	plugin->plugin_api_version = PLUGIN_API_VERSION;
	plugin->plugin_funcs_size = sizeof(struct plugin_funcs);
	memset(&plugin->funcs, 0, sizeof(struct plugin_funcs));

	// Authentication actions.
	plugin->funcs.auth_get_user = get_user;
	plugin->funcs.auth_register_user = register_user;
	plugin->funcs.auth_update_user = update_user;
	plugin->funcs.auth_delete_user = delete_user;

	plugin->ptr = parse_config(config, plugin);
	if (plugin->ptr)
		return 0;
	return -1;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	set_error_message(plugin, 0);
	struct sql_data* sql = (struct sql_data*) plugin->ptr;
	sqlite3_close(sql->db);
	hub_free(sql);
	return 0;
}

