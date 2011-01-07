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

struct plugin_callback_data
{
	struct linked_list* commands;
};

/*
static struct plugin_callback_data* get_callback_data(struct plugin_handle* plugin)
{
	uhub_assert(plugin && plugin->handle && plugin->handle->callback_data);
	struct plugin_callback_data* data = (struct plugin_callback_data*) plugin->handle->callback_data;
	return data;
}
*/

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
//	struct plugin_callback_data* data = get_callback_data(plugin);
	return 0;
}

static int cbfunc_command_del(struct plugin_handle* plugin, struct plugin_command_handle* cmdh)
{
//	struct plugin_callback_data* data = get_callback_data(plugin);
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
