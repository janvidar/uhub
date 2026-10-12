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

/*
 * Announces users joining and leaving the hub. Modelled on Tim Schlueter's
 * mod_joins from the modelrockettier fork.
 *
 * The hub raises on_user_logout only for a user who completed the login, so a
 * failed login (a wrong password, a refused nick) is never announced as a
 * departure.
 */

#include "plugin_api/handle.h"
#include "util/cbuffer.h"
#include "util/config_token.h"
#include "util/memory.h"

/* A join or leave message file is read up to this many bytes. */
#define JOINS_MAX_MESSAGE 1024

#define JOINS_DEFAULT_JOIN  "*** %n joined."
#define JOINS_DEFAULT_LEAVE "*** %n left."

struct joins_data
{
	char* join_message;   /* NULL: joins are not announced */
	char* leave_message;  /* NULL: departures are not announced */
	enum auth_credentials min_notify;
};

static char* read_message_file(const char* filename)
{
	char buf[JOINS_MAX_MESSAGE + 1];
	size_t len;
	FILE* fp = fopen(filename, "rb");

	if (!fp)
		return NULL;
	len = fread(buf, 1, JOINS_MAX_MESSAGE, fp);
	fclose(fp);
	buf[len] = '\0';

	/* A file usually ends in a newline; the message should not. */
	while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
		buf[--len] = '\0';
	return hub_strdup(buf);
}

static void free_data(struct joins_data* data)
{
	if (!data)
		return;
	hub_free(data->join_message);
	hub_free(data->leave_message);
	hub_free(data);
}

/* "none" turns the message off; anything else names a file to read it from. */
static int set_message(char** message, const char* value)
{
	hub_free(*message);
	*message = NULL;
	if (!strcmp(value, "none"))
		return 1;
	*message = read_message_file(value);
	return *message != NULL;
}

static struct joins_data* parse_config(const char* line, struct plugin_handle* plugin)
{
	struct joins_data* data = (struct joins_data*) hub_malloc_zero(sizeof(struct joins_data));
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char* token = cfg_token_get_first(tokens);

	if (!data)
	{
		plugin->error_msg = "Out of memory";
		cfg_tokens_free(tokens);
		return NULL;
	}

	data->join_message = hub_strdup(JOINS_DEFAULT_JOIN);
	data->leave_message = hub_strdup(JOINS_DEFAULT_LEAVE);
	data->min_notify = auth_cred_guest;

	while (token)
	{
		struct cfg_settings* setting = cfg_settings_split(token);
		const char* key;
		const char* value;
		int ok;

		if (!setting)
		{
			plugin->error_msg = "Unable to parse startup parameters";
			goto fail;
		}

		key = cfg_settings_get_key(setting);
		value = cfg_settings_get_value(setting);

		if (!strcmp(key, "join"))
		{
			ok = set_message(&data->join_message, value);
			if (!ok)
				plugin->error_msg = "Unable to read the join message file";
		}
		else if (!strcmp(key, "leave"))
		{
			ok = set_message(&data->leave_message, value);
			if (!ok)
				plugin->error_msg = "Unable to read the leave message file";
		}
		else if (!strcmp(key, "min_notify"))
		{
			ok = auth_string_to_cred(value, &data->min_notify);
			if (!ok)
				plugin->error_msg = "Unknown credentials for min_notify";
		}
		else
		{
			ok = 0;
			plugin->error_msg = "Unknown startup parameters given";
		}

		cfg_settings_free(setting);
		if (!ok)
			goto fail;
		token = cfg_token_get_next(tokens);
	}
	cfg_tokens_free(tokens);
	return data;

fail:
	cfg_tokens_free(tokens);
	free_data(data);
	return NULL;
}

/*
 * Fill in a message template:
 *   %n nick, %c credentials, %r why the user left ("" on a join), %% a "%",
 *   %H %I %M %S %P %p the time, as in mod_welcome.
 * An unknown code, or a "%" at the very end, is copied as it stands.
 */
static struct cbuffer* format_message(struct plugin_handle* plugin, struct plugin_user* user, const char* template_text, const char* reason)
{
	struct cbuffer* buf = cbuf_create(strlen(template_text) + 32);
	const char* p;
	time_t timestamp = time(NULL);
	struct tm* now = localtime(&timestamp);

	for (p = template_text; *p; p++)
	{
		if (*p != '%' || !p[1])
		{
			cbuf_append_bytes(buf, p, 1);
			continue;
		}

		switch (*++p)
		{
			case 'n': cbuf_append(buf, plugin->hub.get_user_nick(plugin, user)); break;
			case 'c': cbuf_append(buf, auth_cred_to_string(plugin->hub.get_user_credentials(plugin, user))); break;
			case 'r': cbuf_append(buf, reason ? reason : ""); break;
			case '%': cbuf_append(buf, "%"); break;
			case 'H': cbuf_append_strftime(buf, "%H", now); break;
			case 'I': cbuf_append_strftime(buf, "%I", now); break;
			case 'M': cbuf_append_strftime(buf, "%M", now); break;
			case 'S': cbuf_append_strftime(buf, "%S", now); break;
			case 'P': cbuf_append_strftime(buf, "%P", now); break;
			case 'p': cbuf_append_strftime(buf, "%p", now); break;
			default:
				cbuf_append_bytes(buf, p - 1, 2);
				break;
		}
	}
	return buf;
}

static void announce(struct plugin_handle* plugin, struct plugin_user* user, const char* template_text, const char* reason)
{
	struct joins_data* data = (struct joins_data*) plugin->ptr;
	struct cbuffer* buf = format_message(plugin, user, template_text, reason);
	plugin->hub.send_chat(plugin, data->min_notify, auth_cred_admin, cbuf_get(buf));
	cbuf_destroy(buf);
}

static void on_user_login(struct plugin_handle* plugin, struct plugin_user* user)
{
	struct joins_data* data = (struct joins_data*) plugin->ptr;
	if (data->join_message)
		announce(plugin, user, data->join_message, NULL);
}

static void on_user_logout(struct plugin_handle* plugin, struct plugin_user* user, const char* reason)
{
	struct joins_data* data = (struct joins_data*) plugin->ptr;
	if (data->leave_message)
		announce(plugin, user, data->leave_message, reason);
}

PLUGIN_API int plugin_register(struct plugin_handle* plugin, const char* config)
{
	PLUGIN_INITIALIZE(plugin, "Joins plugin", "1.0", "Announces users joining and leaving the hub.");

	plugin->ptr = parse_config(config, plugin);
	if (!plugin->ptr)
		return -1;

	plugin->funcs.on_user_login = on_user_login;
	plugin->funcs.on_user_logout = on_user_logout;
	return 0;
}

PLUGIN_API int plugin_unregister(struct plugin_handle* plugin)
{
	free_data((struct joins_data*) plugin->ptr);
	plugin->ptr = NULL;
	return 0;
}
