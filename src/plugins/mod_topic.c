/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2012, Jan Vidar Krey
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
#include "util/memory.h"
#include "util/cbuffer.h"

struct topic_plugin_data
{
	struct plugin_command_handle* topic;
	struct plugin_command_handle* cleartopic;
	struct plugin_command_handle* showtopic;
};

static int command_topic_handler(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct plugin_command_arg_data* arg = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);

	plugin->hub.set_description(plugin, arg ? arg->data.string : NULL);
	cbuf_append_format(buf, "*** %s: Topic set to \"%s\"", cmd->prefix, arg->data.string);
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	return 0;
}

static int command_cleartopic_handler(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	plugin->hub.set_description(plugin, NULL);
	cbuf_append_format(buf, "*** %s: Topic cleared.", cmd->prefix);
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	return 0;
}

static int command_showtopic_handler(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	char* topic = plugin->hub.get_description(plugin);
	cbuf_append_format(buf, "*** %s: Current topic is: \"%s\"", cmd->prefix, topic);
	plugin->hub.send_message(plugin, user, cbuf_get(buf));
	cbuf_destroy(buf);
	hub_free(topic);
	return 0;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	struct topic_plugin_data* data = (struct topic_plugin_data*) hub_malloc(sizeof(struct topic_plugin_data));

	data->topic = (struct plugin_command_handle*) hub_malloc_zero(sizeof(struct plugin_command_handle));
	data->cleartopic = (struct plugin_command_handle*) hub_malloc_zero(sizeof(struct plugin_command_handle));
	data->showtopic = (struct plugin_command_handle*) hub_malloc_zero(sizeof(struct plugin_command_handle));

	PLUGIN_INITIALIZE(plugin, "Topic plugin", "1.0", "Add commands for changing the hub topic (description)");

	PLUGIN_COMMAND_INITIALIZE(data->topic, (void*) data, "topic", "+m", auth_cred_operator, command_topic_handler, "Set new topic");
	PLUGIN_COMMAND_INITIALIZE(data->cleartopic, (void*) data, "cleartopic", "", auth_cred_operator, command_cleartopic_handler, "Clear the current topic");
	PLUGIN_COMMAND_INITIALIZE(data->showtopic, (void*) data, "showtopic", "", auth_cred_guest, command_showtopic_handler, "Shows the current topic");

	plugin->hub.command_add(plugin, data->topic);
	plugin->hub.command_add(plugin, data->cleartopic);
	plugin->hub.command_add(plugin, data->showtopic);
	plugin->ptr = data;


	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	struct topic_plugin_data* data = (struct topic_plugin_data*) plugin->ptr;

	plugin->hub.command_del(plugin, data->topic);
	plugin->hub.command_del(plugin, data->cleartopic);
	plugin->hub.command_del(plugin, data->showtopic);
	hub_free(data->topic);
	hub_free(data->cleartopic);
	hub_free(data->showtopic);
	hub_free(data);
	plugin->ptr = NULL;
	return 0;
}

