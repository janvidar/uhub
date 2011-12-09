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
	struct plugin_callback_data* data;
	uhub_assert(plugin && plugin->handle && plugin->handle->internals);
	data = (struct plugin_callback_data*) plugin->handle->internals;
	return data;
}

static int plugin_command_dispatch(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	struct plugin_handle* plugin = (struct plugin_handle*) handle->ptr;
	struct plugin_callback_data* data = get_callback_data(plugin);
	struct plugin_command_handle* cmdh;
	struct plugin_user* puser = (struct plugin_user*) user; // FIXME: Use a proper conversion function instead.
	struct plugin_command* pcommand = (struct plugin_command*) cmd; // FIXME: Use a proper conversion function instead.

	LOG_PLUGIN("plugin_command_dispatch: cmd=%s", cmd->prefix);

	cmdh = (struct plugin_command_handle*) list_get_first(data->commands);
	while (cmdh)
	{
		if (cmdh->length != cmd->prefix_len)
			continue;

		if (strcmp(cmdh->prefix, cmd->prefix) == 0)
			return cmdh->handler(plugin, puser, pcommand);

		cmdh = (struct plugin_command_handle*) list_get_next(data->commands);
	}
	return 0;
}

struct plugin_callback_data* plugin_callback_data_create()
{
	LOG_PLUGIN("plugin_callback_data_create()");
	struct plugin_callback_data* data = (struct plugin_callback_data*) hub_malloc_zero(sizeof(struct plugin_callback_data));
	data->commands = list_create();
	return data;
}

void plugin_callback_data_destroy(struct plugin_callback_data* data)
{
	LOG_PLUGIN("plugin_callback_data_destroy()");
	if (data->commands)
	{
		uhub_assert(list_size(data->commands) == 0);
		list_destroy(data->commands);
	}

	hub_free(data);
}

static struct hub_user* convert_user_type(struct plugin_user* user)
{
	struct hub_user* huser = (struct hub_user*) user;
	return huser;
}

static int cbfunc_send_message(struct plugin_handle* plugin, struct plugin_user* user, const char* message)
{
//	struct plugin_callback_data* data = get_callback_data(plugin);
	char* buffer = adc_msg_escape(message);
	struct adc_message* command = adc_msg_construct(ADC_CMD_IMSG, strlen(buffer) + 6);
	adc_msg_add_argument(command, buffer);
	route_to_user(plugin_get_hub(plugin), convert_user_type(user), command);
	adc_msg_free(command);
	hub_free(buffer);
	return 1;
}


static int cbfunc_user_disconnect(struct plugin_handle* plugin, struct plugin_user* user)
{
	// struct plugin_callback_data* data = get_callback_data(plugin);
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

	cmdh->internal_handle = data;
	list_append(data->commands, cmdh);
	command_add(plugin_get_hub(plugin)->commands, command, (void*) plugin);
	return 0;
}

static int cbfunc_command_del(struct plugin_handle* plugin, struct plugin_command_handle* cmdh)
{
	struct plugin_callback_data* data = get_callback_data(plugin);
	struct command_handle* command = (struct command_handle*) cmdh->internal_handle;

	list_remove(data->commands, cmdh);
	cmdh->internal_handle = 0;

	command_del(plugin_get_hub(plugin)->commands, (void*) command);

	return 0;
}


void plugin_register_callback_functions(struct plugin_handle* handle)
{
	handle->hub.send_message = cbfunc_send_message;
	handle->hub.user_disconnect = cbfunc_user_disconnect;
	handle->hub.command_add = cbfunc_command_add;
	handle->hub.command_del = cbfunc_command_del;
}

void plugin_unregister_callback_functions(struct plugin_handle* handle)
{
}
