/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2011, Jan Vidar Krey
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

#include "uhub.h"
#include "plugin_api/command_api.h"

struct plugin_callback_data
{
	struct linked_list* commands;
};

static struct plugin_callback_data* get_callback_data(struct plugin_handle* plugin)
{
	return get_internals(plugin)->callback_data;
}

static int plugin_command_dispatch(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct plugin_handle* plugin = (struct plugin_handle*) cmd->ptr;
	struct plugin_callback_data* data = get_callback_data(plugin);
	struct plugin_command_handle* cmdh;
	struct plugin_user* puser = (struct plugin_user*) user; // FIXME: Use a proper conversion function instead.
	struct plugin_command* pcommand = (struct plugin_command*) cmd; // FIXME: Use a proper conversion function instead.

	LOG_PLUGIN("plugin_command_dispatch: cmd=%s", cmd->prefix);

	LIST_FOREACH(struct plugin_command_handle*, cmdh, data->commands,
	{
		if (strcmp(cmdh->prefix, cmd->prefix) == 0)
			return cmdh->handler(plugin, puser, pcommand);
	});
	return 0;
}

static struct hub_user* convert_user_type(struct plugin_user* user)
{
	struct hub_user* huser = (struct hub_user*) user;
	return huser;
}

static int cbfunc_send_message(struct plugin_handle* plugin, struct plugin_user* user, const char* message)
{
	char* buffer = adc_msg_escape(message);
	struct adc_message* command = adc_msg_construct(ADC_CMD_IMSG, strlen(buffer) + 6);
	adc_msg_add_argument(command, buffer);
	route_to_user(plugin_get_hub(plugin), convert_user_type(user), command);
	adc_msg_free(command);
	hub_free(buffer);
	return 1;
}

static int cbfunc_send_status(struct plugin_handle* plugin, struct plugin_user* user, int code, const char* message)
{
	char code_str[4];
	char* buffer = adc_msg_escape(message);
	struct adc_message* command = adc_msg_construct(ADC_CMD_ISTA, strlen(buffer) + 10);
	snprintf(code_str, sizeof(code_str), "%03d", code);
	adc_msg_add_argument(command, code_str);
	adc_msg_add_argument(command, buffer);
	route_to_user(plugin_get_hub(plugin), convert_user_type(user), command);
	adc_msg_free(command);
	hub_free(buffer);
	return 1;
}

static int cbfunc_user_disconnect(struct plugin_handle* plugin, struct plugin_user* user)
{
	hub_disconnect_user(plugin_get_hub(plugin), convert_user_type(user), quit_kicked);
	return 0;
}

static int cbfunc_command_add(struct plugin_handle* plugin, struct plugin_command_handle* cmdh)
{
	struct plugin_callback_data* data = get_callback_data(plugin);
	struct command_handle* command = (struct command_handle*) hub_malloc_zero(sizeof(struct command_handle));

	command->prefix = cmdh->prefix;
	command->length = cmdh->length;
	command->args = cmdh->args;
	command->cred = cmdh->cred;
	command->description = cmdh->description;
	command->origin = cmdh->origin;
	command->handler = plugin_command_dispatch;

	cmdh->internal_handle = command;
	list_append(data->commands, cmdh);
	command_add(plugin_get_hub(plugin)->commands, command, (void*) plugin);
	printf("*** Add plugin command: %s (%p, %p)\n", command->prefix, command, cmdh);
	return 0;
}

static int cbfunc_command_del(struct plugin_handle* plugin, struct plugin_command_handle* cmdh)
{
	struct plugin_callback_data* data = get_callback_data(plugin);
	struct command_handle* command = (struct command_handle*) cmdh->internal_handle;

	printf("*** Del plugin command: %s (%p, %p)\n", command->prefix, command, cmdh);
	list_remove(data->commands, cmdh);
	command_del(plugin_get_hub(plugin)->commands, command);
	hub_free(command);
	cmdh->internal_handle = NULL;
	return 0;
}

size_t cbfunc_command_arg_reset(struct plugin_handle* plugin, struct plugin_command* cmd)
{
	// TODO: Use proper function for rewriting for plugin_command -> hub_command
	return hub_command_arg_reset((struct hub_command*) cmd);
}

struct plugin_command_arg_data* cbfunc_command_arg_next(struct plugin_handle* plugin, struct plugin_command* cmd, enum plugin_command_arg_type t)
{
	// TODO: Use proper function for rewriting for plugin_command -> hub_command
	return (struct plugin_command_arg_data*) hub_command_arg_next((struct hub_command*) cmd, (enum hub_command_arg_type) t);
}

static char* cbfunc_get_hub_name(struct plugin_handle* plugin)
{
	struct hub_info* hub = plugin_get_hub(plugin);
	char* str_encoded = adc_msg_get_named_argument(hub->command_info, ADC_INF_FLAG_NICK);
	char* str = adc_msg_unescape(str_encoded);
	hub_free(str_encoded);
	return str;
}

static char* cbfunc_get_hub_description(struct plugin_handle* plugin)
{
	struct hub_info* hub = plugin_get_hub(plugin);
	char* str_encoded = adc_msg_get_named_argument(hub->command_info, ADC_INF_FLAG_DESCRIPTION);
	char* str = adc_msg_unescape(str_encoded);
	hub_free(str_encoded);
	return str;
}

static void cbfunc_set_hub_name(struct plugin_handle* plugin, const char* str)
{
	struct hub_info* hub = plugin_get_hub(plugin);
	struct adc_message* command;
	char* new_str = adc_msg_escape(str ? str : hub->config->hub_name);

	adc_msg_replace_named_argument(hub->command_info, ADC_INF_FLAG_NICK, new_str);
		
	// Broadcast hub name
	command = adc_msg_construct(ADC_CMD_IINF, (strlen(new_str) + 8));
	adc_msg_add_named_argument(command, ADC_INF_FLAG_NICK, new_str);
	route_to_all(hub, command);

	adc_msg_free(command);
	hub_free(new_str);
}

static void cbfunc_set_hub_description(struct plugin_handle* plugin, const char* str)
{
	struct hub_info* hub = plugin_get_hub(plugin);
	struct adc_message* command;
	char* new_str = adc_msg_escape(str ? str : hub->config->hub_description);

	adc_msg_replace_named_argument(hub->command_info, ADC_INF_FLAG_DESCRIPTION, new_str);
		
	// Broadcast hub description
	command = adc_msg_construct(ADC_CMD_IINF, (strlen(new_str) + 8));
	adc_msg_add_named_argument(command, ADC_INF_FLAG_DESCRIPTION, new_str);
	route_to_all(hub, command);

	adc_msg_free(command);
	hub_free(new_str);
}

void plugin_register_callback_functions(struct plugin_handle* handle)
{
	handle->hub.send_message = cbfunc_send_message;
	handle->hub.send_status_message = cbfunc_send_status;
	handle->hub.user_disconnect = cbfunc_user_disconnect;
	handle->hub.command_add = cbfunc_command_add;
	handle->hub.command_del = cbfunc_command_del;
	handle->hub.command_arg_reset = cbfunc_command_arg_reset;
	handle->hub.command_arg_next = cbfunc_command_arg_next;
	handle->hub.get_name = cbfunc_get_hub_name;
	handle->hub.set_name = cbfunc_set_hub_name;
	handle->hub.get_description = cbfunc_get_hub_description;
	handle->hub.set_description = cbfunc_set_hub_description;
}

void plugin_unregister_callback_functions(struct plugin_handle* handle)
{
}

struct plugin_callback_data* plugin_callback_data_create()
{
	struct plugin_callback_data* data = (struct plugin_callback_data*) hub_malloc_zero(sizeof(struct plugin_callback_data));
	LOG_PLUGIN("plugin_callback_data_create()");
	data->commands = list_create();
	return data;
}

void plugin_callback_data_destroy(struct plugin_handle* plugin, struct plugin_callback_data* data)
{
	LOG_PLUGIN("plugin_callback_data_destroy()");
	if (data->commands)
	{
		// delete commands not deleted by the plugin itself:
		struct plugin_command_handle* cmd;
		while ( (cmd = list_get_first(data->commands)) )
			cbfunc_command_del(plugin, cmd);
		list_destroy(data->commands);
	}

	hub_free(data);
}
