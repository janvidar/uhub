/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include "plugin_api/handle.h"
#include "plugin_api/command_api.h"
#include "util/memory.h"
#include "util/cbuffer.h"

struct topic_plugin_data
{
	struct plugin_command_handle* topic;
	struct plugin_command_handle* resettopic;
	struct plugin_command_handle* showtopic;
};

/**
 * Reply with the topic, either as rich text (RTF0) or as the plain quoted form.
 * The topic is operator supplied text, so the rich variant has to escape it --
 * which is also why the two variants cannot share a string and be handed to
 * send_rich_message()'s built-in fallback.
 */
static void send_topic_reply(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd, const char* label, const char* plain_label, const char* topic)
{
	struct cbuffer* buf = cbuf_create(128);

	if (plugin->hub.user_supports_rich_text(plugin, user))
	{
		cbuf_append_format(buf, "**%s:** ", label);
		cbuf_append_markdown(buf, topic);
		plugin->hub.send_rich_message(plugin, user, cbuf_get(buf));
	}
	else
	{
		cbuf_append_format(buf, "*** %s: %s \"%s\"", cmd->prefix, plain_label, topic);
		plugin->hub.send_message(plugin, user, cbuf_get(buf));
	}
	cbuf_destroy(buf);
}

static int command_topic_handler(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct plugin_command_arg_data* arg = plugin->hub.command_arg_next(plugin, cmd, plugin_cmd_arg_type_string);
	char* topic = arg ? arg->data.string : "";

	plugin->hub.set_description(plugin, topic);
	send_topic_reply(plugin, user, cmd, "Topic set to", "Topic set to", topic);
	return 0;
}

static int command_resettopic_handler(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	plugin->hub.set_description(plugin, NULL);

	if (plugin->hub.user_supports_rich_text(plugin, user))
	{
		cbuf_append(buf, "**Topic reset.**");
		plugin->hub.send_rich_message(plugin, user, cbuf_get(buf));
	}
	else
	{
		cbuf_append_format(buf, "*** %s: Topic reset.", cmd->prefix);
		plugin->hub.send_message(plugin, user, cbuf_get(buf));
	}
	cbuf_destroy(buf);
	return 0;
}

static int command_showtopic_handler(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	char* topic = plugin->hub.get_description(plugin);
	send_topic_reply(plugin, user, cmd, "Current topic", "Current topic is:", topic);
	hub_free(topic);
	return 0;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	(void) config;
	struct topic_plugin_data* data = (struct topic_plugin_data*) hub_malloc_zero(sizeof(struct topic_plugin_data));

	PLUGIN_INITIALIZE(plugin, "Topic plugin", "1.0", "Add commands for changing the hub topic (description)");

	if (!data)
	{
		plugin->error_msg = "Out of memory";
		return -1;
	}

	data->topic = (struct plugin_command_handle*) hub_malloc_zero(sizeof(struct plugin_command_handle));
	data->resettopic = (struct plugin_command_handle*) hub_malloc_zero(sizeof(struct plugin_command_handle));
	data->showtopic = (struct plugin_command_handle*) hub_malloc_zero(sizeof(struct plugin_command_handle));

	if (!data->topic || !data->resettopic || !data->showtopic)
	{
		hub_free(data->topic);
		hub_free(data->resettopic);
		hub_free(data->showtopic);
		hub_free(data);
		plugin->error_msg = "Out of memory";
		return -1;
	}

	PLUGIN_COMMAND_INITIALIZE(data->topic, plugin, "topic", "+m", auth_cred_operator, command_topic_handler, "Set new topic");
	PLUGIN_COMMAND_INITIALIZE(data->resettopic, plugin, "resettopic", "", auth_cred_operator, command_resettopic_handler, "Set topic to default");
	PLUGIN_COMMAND_INITIALIZE(data->showtopic, plugin, "showtopic", "", auth_cred_guest, command_showtopic_handler, "Shows the current topic");

	plugin->hub.command_add(plugin, data->topic);
	plugin->hub.command_add(plugin, data->resettopic);
	plugin->hub.command_add(plugin, data->showtopic);
	plugin->ptr = data;


	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	struct topic_plugin_data* data = (struct topic_plugin_data*) plugin->ptr;

	plugin->hub.command_del(plugin, data->topic);
	plugin->hub.command_del(plugin, data->resettopic);
	plugin->hub.command_del(plugin, data->showtopic);
	hub_free(data->topic);
	hub_free(data->resettopic);
	hub_free(data->showtopic);
	hub_free(data);
	plugin->ptr = NULL;
	return 0;
}

