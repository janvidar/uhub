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

#include "system.h"
#include "adc/adcconst.h"
#include "adc/sid.h"
#include "util/cbuffer.h"
#include "util/memory.h"
#include "util/ipcalc.h"
#include "plugin_api/handle.h"
#include "plugin_api/command_api.h"

#include "util/misc.h"
#include "util/config_token.h"
#include <syslog.h>

#define MAX_WELCOME_SIZE 16384

struct welcome_data
{
	char* motd_file;
	char* motd;
	char* rules_file;
	char* rules;
	struct plugin_command_handle* cmd_motd;
	struct plugin_command_handle* cmd_rules;
};

static int command_handler_motd(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd);
static int command_handler_rules(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd);

static char* read_file(const char* filename)
{
	char* str;
	char buf[MAX_WELCOME_SIZE];
	int fd = open(filename, O_RDONLY);
	int ret;

	if (fd == -1)
		return NULL;

	ret = read(fd, buf, MAX_WELCOME_SIZE);
	close(fd);

	buf[ret > 0 ? ret : 0] = 0;
	str = strdup(buf);

	return str;
}

int read_motd(struct welcome_data* data)
{
	data->motd = read_file(data->motd_file);
	return !!data->motd;
}

int read_rules(struct welcome_data* data)
{
	data->rules = read_file(data->rules_file);
	return !!data->rules;
}

static void free_welcome_data(struct welcome_data* data)
{
	if (!data)
		return;

	hub_free(data->cmd_motd);
	hub_free(data->motd_file);
	hub_free(data->motd);
	hub_free(data->cmd_rules);
	hub_free(data->rules_file);
	hub_free(data->rules);
	hub_free(data);
}


static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

static struct welcome_data* parse_config(const char* line, struct plugin_handle* plugin)
{
	struct welcome_data* data = (struct welcome_data*) hub_malloc_zero(sizeof(struct welcome_data));
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char* token = cfg_token_get_first(tokens);

	if (!data)
		return 0;

	while (token)
	{
		struct cfg_settings* setting = cfg_settings_split(token);

		if (!setting)
		{
			set_error_message(plugin, "Unable to parse startup parameters");
			goto cleanup_parse_error;
		}

		if (strcmp(cfg_settings_get_key(setting), "motd") == 0)
		{
			data->motd_file = strdup(cfg_settings_get_value(setting));
			if (!read_motd(data))
			{
				set_error_message(plugin, "Unable to read motd file.");
				cfg_settings_free(setting);
				goto cleanup_parse_error;
			}

			data->cmd_motd = hub_malloc_zero(sizeof(struct plugin_command_handle));
			PLUGIN_COMMAND_INITIALIZE(data->cmd_motd, (void*) data, "msg", "", auth_cred_guest, command_handler_motd, "Show the message of the day.");
		}
		else if (strcmp(cfg_settings_get_key(setting), "rules") == 0)
		{
			data->rules_file = strdup(cfg_settings_get_value(setting));
			if (!read_rules(data))
			{
				set_error_message(plugin, "Unable to read rules file.");
				cfg_settings_free(setting);
				goto cleanup_parse_error;
			}

			data->cmd_rules = hub_malloc_zero(sizeof(struct plugin_command_handle));
			PLUGIN_COMMAND_INITIALIZE(data->cmd_rules, (void*) data, "rule", "", auth_cred_guest, command_handler_rules, "Show the hub rules.");
		}
		else
		{
			set_error_message(plugin, "Unknown startup parameters given");
			cfg_settings_free(setting);
			goto cleanup_parse_error;
		}

		cfg_settings_free(setting);
		token = cfg_token_get_next(tokens);
	}

	cfg_tokens_free(tokens);
	return data;

cleanup_parse_error:
	cfg_tokens_free(tokens);
	free_welcome_data(data);
	return 0;
}


static struct cbuffer* parse_message(struct plugin_user* user, const char* msg)
{
	struct cbuffer* buf = cbuf_create(strlen(msg));
	const char* start = msg;
	const char* offset = NULL;
	time_t timestamp = time(NULL);
	struct tm* now = localtime(&timestamp);

	while ((offset = strchr(start, '%')))
	{
		cbuf_append_bytes(buf, start, (offset - start));

		offset++;
		switch (offset[0])
		{
			case 'n':
				cbuf_append(buf, user->nick);
				break;

			case 'a':
				cbuf_append(buf, ip_convert_to_string(&user->addr));
				break;

			case '%':
				cbuf_append(buf, "%");
				break;

			case 'H':
				cbuf_append_strftime(buf, "%H", now);
				break;

			case 'I':
				cbuf_append_strftime(buf, "%I", now);
				break;

			case 'P':
				cbuf_append_strftime(buf, "%P", now);
				break;

			case 'p':
				cbuf_append_strftime(buf, "%p", now);
				break;

			case 'M':
				cbuf_append_strftime(buf, "%M", now);
				break;

			case 'S':
				cbuf_append_strftime(buf, "%S", now);
				break;
		}

		start = offset + 1;
	}

	if (*start)
		cbuf_append(buf, start);

	return buf;
}

static void send_motd(struct plugin_handle* plugin, struct plugin_user* user)
{
	struct welcome_data* data = (struct welcome_data*) plugin->ptr;
	struct cbuffer* buf = NULL;
	if (data->motd)
	{
		buf = parse_message(user, data->motd);
		plugin->hub.send_message(plugin, user, cbuf_get(buf));
		cbuf_destroy(buf);
	}
}

static void send_rules(struct plugin_handle* plugin, struct plugin_user* user)
{
	struct welcome_data* data = (struct welcome_data*) plugin->ptr;
	struct cbuffer* buf = NULL;
	if (data->rules)
	{
		buf = parse_message(user, data->rules);
		plugin->hub.send_message(plugin, user, cbuf_get(buf));
		cbuf_destroy(buf);
	}
}

static void on_user_login(struct plugin_handle* plugin, struct plugin_user* user)
{
	send_motd(plugin, user);
}

static int command_handler_motd(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	send_motd(plugin, user);
	return 1;
}

static int command_handler_rules(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_command* cmd)
{
	send_rules(plugin, user);
	return 1;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	struct welcome_data* data;
	PLUGIN_INITIALIZE(plugin, "Welcome plugin", "0.1", "Sends a welcome message to users when they log into the hub.");
	data = parse_config(config, plugin);

	if (!data)
		return -1;

	plugin->ptr = data;
	plugin->funcs.on_user_login = on_user_login;

	if (data->cmd_motd)
		plugin->hub.command_add(plugin, data->cmd_motd);

	if (data->cmd_rules)
		plugin->hub.command_add(plugin, data->cmd_rules);

	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	struct welcome_data* data = (struct welcome_data*) plugin->ptr;

	if (data->cmd_motd)
		plugin->hub.command_del(plugin, data->cmd_motd);

	if (data->cmd_rules)
		plugin->hub.command_del(plugin, data->cmd_rules);

	free_welcome_data(data);
	return 0;
}

