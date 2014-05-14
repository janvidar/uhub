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
#include "util/memory.h"
#include "util/misc.h"
#include "util/list.h"
#include "util/cbuffer.h"

#define MAX_HISTORY_SIZE 16384

struct chat_history_data
{
	size_t history_max;      ///<<< "the maximum number of chat messages kept in history."
	size_t history_default;  ///<<< "the default number of chat messages returned if no limit was provided"
	size_t history_connect;  ///<<< "the number of chat messages provided when users connect to the hub."
	struct linked_list* chat_history; ///<<< "The chat history storage."
	struct plugin_command_handle* command_history_handle; ///<<< "A handle to the !history command."
};

/**
 * Add a chat message to history.
 */
static void history_add(struct plugin_handle* plugin, struct plugin_user* from, const char* message, int flags)
{
	size_t loglen = strlen(message) + strlen(from->nick) + 13;
	struct chat_history_data* data = (struct chat_history_data*) plugin->ptr;
	char* log = hub_malloc(loglen + 1);

	snprintf(log, loglen, "%s <%s> %s\n", get_timestamp(time(NULL)), from->nick, message);
	log[loglen] = '\0';
	list_append(data->chat_history, log);
	while (list_size(data->chat_history) > data->history_max)
	{
		list_remove_first(data->chat_history, hub_free);
	}
}

/**
 * Obtain 'num' messages from the chat history and append them to outbuf.
 *
 * @return the number of messages added to the buffer.
 */
static size_t get_messages(struct chat_history_data* data, size_t num, struct cbuffer* outbuf)
{
	struct linked_list* messages = data->chat_history;
	char* message;
	int skiplines = 0;
	size_t lines = 0;
	size_t total = list_size(messages);

	if (total == 0)
		return 0;

	if (num <= 0 || num > total)
		num = total;

	if (num != total)
		skiplines = total - num;

	cbuf_append(outbuf, "\n");
	LIST_FOREACH(char*, message, messages,
	{
		if (--skiplines < 0)
		{
			cbuf_append(outbuf, message);
			lines++;
		}
	});
	cbuf_append(outbuf, "\n");
	return lines;
}

void user_login(struct plugin_handle* plugin, struct plugin_user* user)
{
	struct chat_history_data* data = (struct chat_history_data*) plugin->ptr;
	struct cbuffer* buf = NULL;
	// size_t messages = 0;

	if (data->history_connect > 0 && list_size(data->chat_history) > 0)
	{
		buf = cbuf_create(MAX_HISTORY_SIZE);
		cbuf_append(buf, "Chat history:\n");
		get_messages(data, data->history_connect, buf);
		plugin->hub.send_message(plugin, user, cbuf_get(buf));
		cbuf_destroy(buf);
	}
}

/**
 * Send a status message back to the user who issued the !history command.
 */
static int command_status(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd, struct cbuffer* buf)
{
	struct cbuffer* msg = cbuf_create(cbuf_size(buf) + strlen(cmd->prefix) + 8);
	cbuf_append_format(msg, "*** %s: %s", cmd->prefix, cbuf_get(buf));
	plugin->hub.send_message(plugin, user, cbuf_get(msg));
	cbuf_destroy(msg);
	cbuf_destroy(buf);
	return 0;
}

/**
 * The callback function for handling the !history command.
 */
static int command_history(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf;
	struct chat_history_data* data = (struct chat_history_data*) plugin->ptr;
	struct plugin_command_arg_data* arg = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_integer);
	int maxlines;

	if (!list_size(data->chat_history))
		return command_status(plugin, user, cmd, cbuf_create_const("No messages."));

	if (arg)
		maxlines = arg->data.integer;
	else
		maxlines = data->history_default;

	buf = cbuf_create(MAX_HISTORY_SIZE);
	cbuf_append_format(buf, "*** %s: Chat History:\n", cmd->prefix);
	get_messages(data, maxlines, buf);

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
	data->chat_history = list_create();

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

		if (strcmp(cfg_settings_get_key(setting), "history_max") == 0)
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
	PLUGIN_INITIALIZE(plugin, "Chat history plugin", "1.0", "Provide a global chat history log.");

	plugin->funcs.on_user_chat_message = history_add;
	plugin->funcs.on_user_login = user_login;
	data = parse_config(config, plugin);
	if (!data)
		return -1;

	plugin->ptr = data;

	data->command_history_handle = (struct plugin_command_handle*) hub_malloc(sizeof(struct plugin_command_handle));
	PLUGIN_COMMAND_INITIALIZE(data->command_history_handle, plugin, "history", "?N", auth_cred_guest, &command_history, "Show chat message history.");
	plugin->hub.command_add(plugin, data->command_history_handle);

	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	struct chat_history_data* data = (struct chat_history_data*) plugin->ptr;

	if (data)
	{
		list_clear(data->chat_history, &hub_free);
		list_destroy(data->chat_history);

		plugin->hub.command_del(plugin, data->command_history_handle);
		hub_free(data->command_history_handle);
		hub_free(data);
	}

	return 0;
}

