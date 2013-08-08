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
#include "plugin_api/command_api.h"
#include "util/config_token.h"
#include <sqlite3.h>
#include "util/memory.h"
#include "util/misc.h"
#include "util/list.h"
#include "util/cbuffer.h"

#define MAX_HISTORY_SIZE 16384

struct chat_history_data
{
	size_t history_max;	///<<< "the maximum number of chat messages kept in history."
	size_t history_default;	///<<< "the default number of chat messages returned if no limit was provided"
	size_t history_connect;	///<<< "the number of chat messages provided when users connect to the hub."
	sqlite3* db;		///<<< "The chat history storage database."
	struct plugin_command_handle* command_history_handle;		///<<< "A handle to the !history command."
	struct plugin_command_handle* command_historycleanup_handle;	///<<< "A handle to the !historycleanup command."
};

struct chat_history_line
{
	char message[MAX_HISTORY_SIZE];
	char from[MAX_NICK_LEN];
	char time[20];
};

static int null_callback(void* ptr, int argc, char **argv, char **colName) { return 0; }

static const char* sql_escape_string(const char* str)
{
	static char out[MAX_HISTORY_SIZE];
	size_t i = 0;
	size_t n = 0;
	for (; n < strlen(str); n++)
	{
		if (str[n] == '\'')
			out[i++] = '\'';
		out[i++] = str[n];
	}
	out[i++] = '\0';
	return out;
}

static int sql_execute(struct chat_history_data* sql, int (*callback)(void* ptr, int argc, char **argv, char **colName), void* ptr, const char* sql_fmt, ...)
{
	va_list args;
	char query[MAX_HISTORY_SIZE];
	char* errMsg;
	int rc;

	va_start(args, sql_fmt);
	vsnprintf(query, sizeof(query), sql_fmt, args);

	rc = sqlite3_exec(sql->db, query, callback, ptr, &errMsg);
	if (rc != SQLITE_OK)
	{
		sqlite3_free(errMsg);
		return -rc;
	}

	rc = sqlite3_changes(sql->db);
	return rc;
}

static void create_tables(struct plugin_handle* plugin)
{
	const char* table_create = "CREATE TABLE IF NOT EXISTS chat_history"
		"("
			"from_nick CHAR,"
			"message TEXT,"
			"time TIMESTAMP DEFAULT (DATETIME('NOW'))"
		");";

	struct chat_history_data* data = (struct chat_history_data*) plugin->ptr;
	sql_execute(data, null_callback, NULL, table_create);
}
/**
 * Add a chat message to history.
 */
static void history_add(struct plugin_handle* plugin, struct plugin_user* from, const char* message, int flags)
{
	struct chat_history_data* data = (struct chat_history_data*) plugin->ptr;
	char* history_line = strdup(sql_escape_string(message));
	char* history_nick = strdup(sql_escape_string(from->nick));

	sql_execute(data, null_callback, NULL, "INSERT INTO chat_history (from_nick, message) VALUES('%s', '%s');DELETE FROM chat_history WHERE time <= (SELECT time FROM chat_history ORDER BY time DESC LIMIT %d,1);", history_nick, history_line, data->history_max);

	hub_free(history_line);
	hub_free(history_nick);
}

/**
 * Obtain messages from the chat history as a linked list
 */

static int get_messages_callback(void* ptr, int argc, char **argv, char **colName)
{
	struct linked_list* messages = (struct linked_list*) ptr;
	struct chat_history_line* line = hub_malloc(sizeof(struct chat_history_line));
	int i = 0;
	
	memset(line, 0, sizeof(struct chat_history_line));
	
	for (; i < argc; i++) {
		if (strcmp(colName[i], "from_nick") == 0)
			strncpy(line->from, argv[i], MAX_NICK_LEN);
		else if (strcmp(colName[i], "message") == 0)
			strncpy(line->message, argv[i], MAX_HISTORY_SIZE);
		else if (strcmp(colName[i], "time") == 0)
			strncpy(line->time, argv[i], 20);
	}
	
	list_append(messages, line);
	
	return 0;
}

void user_login(struct plugin_handle* plugin, struct plugin_user* user)
{
	struct chat_history_data* data = (struct chat_history_data*) plugin->ptr;
	struct cbuffer* buf = NULL;
	struct linked_list* found = (struct linked_list*) list_create();
	
	sql_execute(data, get_messages_callback, found, "SELECT * FROM chat_history ORDER BY time DESC LIMIT 0,%d;", (int) data->history_connect);

	if (data->history_connect > 0 && list_size(found) > 0)
	{
		buf = cbuf_create(MAX_HISTORY_SIZE);
		cbuf_append(buf, "Chat history:\n\n");
		struct chat_history_line* history_line;
		history_line = (struct chat_history_line*) list_get_last(found);
		while (history_line)
		{
			cbuf_append_format(buf, "[%s] <%s> %s\n", history_line->time, history_line->from, history_line->message);
			list_remove(found, history_line);
			hub_free(history_line);
			history_line = (struct chat_history_line*) list_get_last(found);
		}
		plugin->hub.send_message(plugin, user, cbuf_get(buf));
		cbuf_destroy(buf);
	}
	list_clear(found, &hub_free);
	list_destroy(found);
}

/**
 * The callback function for handling the !history command.
 */
static int command_history(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct chat_history_data* data = (struct chat_history_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(MAX_HISTORY_SIZE);
	struct linked_list* found = (struct linked_list*) list_create();
	struct plugin_command_arg_data* arg = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_integer);
	int maxlines;

	if (arg)
		maxlines = arg->data.integer;
	else
		maxlines = data->history_default;

	sql_execute(data, get_messages_callback, found, "SELECT * FROM chat_history ORDER BY time DESC LIMIT 0,%d;", maxlines);

	size_t linecount = list_size(found);

	if (linecount > 0)
	{
		cbuf_append_format(buf, "*** %s: Chat History:\n\n", cmd->prefix);
		struct chat_history_line* history_line;
		history_line = (struct chat_history_line*) list_get_last(found);
		while (history_line)
		{
			cbuf_append_format(buf, "[%s] <%s> %s\n", history_line->time, history_line->from, history_line->message);
			list_remove(found, history_line);
			hub_free(history_line);
			history_line = (struct chat_history_line*) list_get_last(found);
		}
	}
	else
	{
		cbuf_append_format(buf, "*** %s: No messages found.", cmd->prefix);
	}

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	list_clear(found, &hub_free);
	list_destroy(found);

	return 0;
}

static int command_historycleanup(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct chat_history_data* data = (struct chat_history_data*) plugin->ptr;
	struct cbuffer* buf = cbuf_create(128);
	int rc = 0;

	rc = sql_execute(data, null_callback, NULL, "DELETE FROM chat_history;");
 
	if (!rc)
		cbuf_append_format(buf, "*** %s: Unable to clean chat history table.", cmd->prefix);
	else
		cbuf_append_format(buf, "*** %s: Cleaned chat history table.", cmd->prefix);

	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);

	return 0;
}

static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

static struct chat_history_data* parse_config(const char* line, struct plugin_handle* plugin)
{
	struct chat_history_data* data = (struct chat_history_data*) hub_malloc_zero(sizeof(struct chat_history_data));
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char* token = cfg_token_get_first(tokens);

	uhub_assert(data != NULL);

	data->history_max = 200;
	data->history_default = 25;
	data->history_connect = 5;

	while (token)
	{
		struct cfg_settings* setting = cfg_settings_split(token);

		if (!setting)
		{
			set_error_message(plugin, "Unable to parse startup parameters");
			cfg_tokens_free(tokens);
			hub_free(data);
			return 0;
		}

		if (strcmp(cfg_settings_get_key(setting), "file") == 0)
		{
			if (!data->db)
			{
				if (sqlite3_open(cfg_settings_get_value(setting), &data->db))
				{
					cfg_tokens_free(tokens);
					cfg_settings_free(setting);
					hub_free(data);
					set_error_message(plugin, "Unable to open database file");
					return 0;
				}
			}
		}
		else if (strcmp(cfg_settings_get_key(setting), "history_max") == 0)
		{
			data->history_max = (size_t) uhub_atoi(cfg_settings_get_value(setting));
		}
		else if (strcmp(cfg_settings_get_key(setting), "history_default") == 0)
		{
			data->history_default = (size_t) uhub_atoi(cfg_settings_get_value(setting));
		}
		else if (strcmp(cfg_settings_get_key(setting), "history_connect") == 0)
		{
			data->history_connect = (size_t) uhub_atoi(cfg_settings_get_value(setting));
		}
		else
		{
			set_error_message(plugin, "Unknown startup parameters given");
			cfg_tokens_free(tokens);
			cfg_settings_free(setting);
			hub_free(data);
			return 0;
		}

		cfg_settings_free(setting);
		token = cfg_token_get_next(tokens);
	}
	cfg_tokens_free(tokens);
	return data;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	struct chat_history_data* data;
	PLUGIN_INITIALIZE(plugin, "SQLite chat history plugin", "1.0", "Provide a global chat history log.");

	plugin->funcs.on_user_chat_message = history_add;
	plugin->funcs.on_user_login = user_login;
	data = parse_config(config, plugin);
	
	if (!data)
		return -1;

	plugin->ptr = data;

	create_tables(plugin);

	data->command_history_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(data->command_history_handle, plugin, "history", "?N", auth_cred_guest, &command_history, "Show chat message history.");
	plugin->hub.command_add(plugin, data->command_history_handle);

	data->command_historycleanup_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(data->command_historycleanup_handle, plugin, "historycleanup", "", auth_cred_admin, &command_historycleanup, "Clean chat message history.");
	plugin->hub.command_add(plugin, data->command_historycleanup_handle);

	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	struct chat_history_data* data = (struct chat_history_data*) plugin->ptr;

	if (data)
	{
		sqlite3_close(data->db);

		plugin->hub.command_del(plugin, data->command_history_handle);
		plugin->hub.command_del(plugin, data->command_historycleanup_handle);
		hub_free(data->command_history_handle);
		hub_free(data->command_historycleanup_handle);
		hub_free(data);
	}

	return 0;
}

