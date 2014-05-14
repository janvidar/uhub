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

#include "system.h"
#include "adc/adcconst.h"
#include "adc/sid.h"
#include "util/memory.h"
#include "network/ipcalc.h"
#include "plugin_api/handle.h"

#include "util/misc.h"
#include "util/config_token.h"
#ifndef WIN32
#include <syslog.h>
#endif

struct ip_addr_encap;

struct log_data
{
	enum {
		mode_file,
		mode_syslog
	} logmode;
	char* logfile;
	int fd;
};

static void reset(struct log_data* data)
{
	/* set defaults */
	data->logmode = mode_file;
	data->logfile = NULL;
	data->fd = -1;
}

static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}

static int log_open_file(struct plugin_handle* plugin, struct log_data* data)
{
	int flags = O_CREAT | O_APPEND | O_WRONLY;
	data->fd = open(data->logfile, flags, 0664);
	return (data->fd != -1);
}

#ifndef WIN32
static int log_open_syslog(struct plugin_handle* plugin)
{
	openlog("uhub", 0, LOG_USER);
	return 1;
}
#endif

static struct log_data* parse_config(const char* line, struct plugin_handle* plugin)
{
	struct log_data* data = (struct log_data*) hub_malloc(sizeof(struct log_data));
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char* token = cfg_token_get_first(tokens);

	if (!data)
		return 0;

	reset(data);

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
			data->logfile = strdup(cfg_settings_get_value(setting));
			data->logmode = mode_file;
		}
#ifndef WIN32
		else if (strcmp(cfg_settings_get_key(setting), "syslog") == 0)
		{
			int use_syslog = 0;
			if (!string_to_boolean(cfg_settings_get_value(setting), &use_syslog))
			{
				data->logmode = (use_syslog) ? mode_syslog : mode_file;
			}
		}
#endif
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

	if (data->logmode == mode_file)
	{
		if ((data->logmode == mode_file && !data->logfile))
		{
			set_error_message(plugin, "No log file is given, use file=<path>");
			hub_free(data);
			return 0;
		}

		if (!log_open_file(plugin, data))
		{
			hub_free(data->logfile);
			hub_free(data);
			set_error_message(plugin, "Unable to open log file");
			return 0;
		}
	}
#ifndef WIN32
	else
	{
		if (!log_open_syslog(plugin))
		{
			hub_free(data->logfile);
			hub_free(data);
			set_error_message(plugin, "Unable to open syslog");
			return 0;
		}
	}
#endif
	return data;
}

static void log_close(struct log_data* data)
{
	if (data->logmode == mode_file)
	{
		hub_free(data->logfile);
		close(data->fd);
	}
#ifndef WIN32
	else
	{
		closelog();
	}
#endif
	hub_free(data);
}

static void log_message(struct log_data* data, const char *format, ...)
{
	static char logmsg[1024];
	struct tm *tmp;
	time_t t;
	va_list args;
	ssize_t size = 0;

	if (data->logmode == mode_file)
	{
		t = time(NULL);
		tmp = localtime(&t);
		strftime(logmsg, 32, "%Y-%m-%d %H:%M:%S ", tmp);

		va_start(args, format);
		size = vsnprintf(logmsg + 20, 1004, format, args);
		va_end(args);

		if (write(data->fd, logmsg, size + 20) < (size+20))
		{
			fprintf(stderr, "Unable to write full log. Error=%d: %s\n", errno, strerror(errno));
		}
		else
		{
#ifdef WIN32
			_commit(data->fd);
#else
#if defined _POSIX_SYNCHRONIZED_IO && _POSIX_SYNCHRONIZED_IO > 0
			fdatasync(data->fd);
#else
			fsync(data->fd);
#endif
#endif
		}
	}
#ifndef WIN32
	else
	{
		va_start(args, format);
		vsyslog(LOG_INFO, format, args);
		va_end(args);
	}
#endif
}

static void log_user_login(struct plugin_handle* plugin, struct plugin_user* user)
{
	const char* cred = auth_cred_to_string(user->credentials);
	const char* addr = ip_convert_to_string(&user->addr);

	log_message(plugin->ptr, "LoginOK     %s/%s %s \"%s\" (%s) \"%s\"\n", sid_to_string(user->sid), user->cid, addr, user->nick, cred, user->user_agent);
}

static void log_user_login_error(struct plugin_handle* plugin, struct plugin_user* user, const char* reason)
{
	const char* addr = ip_convert_to_string(&user->addr);
	log_message(plugin->ptr, "LoginError  %s/%s %s \"%s\" (%s) \"%s\"\n", sid_to_string(user->sid), user->cid, addr, user->nick, reason, user->user_agent);
}

static void log_user_logout(struct plugin_handle* plugin, struct plugin_user* user, const char* reason)
{
	const char* addr = ip_convert_to_string(&user->addr);
	log_message(plugin->ptr, "Logout      %s/%s %s \"%s\" (%s) \"%s\"\n", sid_to_string(user->sid), user->cid, addr, user->nick, reason, user->user_agent);
}

static void log_change_nick(struct plugin_handle* plugin, struct plugin_user* user, const char* new_nick)
{
	const char* addr = ip_convert_to_string(&user->addr);
	log_message(plugin->ptr, "NickChange  %s/%s %s \"%s\" -> \"%s\"\n", sid_to_string(user->sid), user->cid, addr, user->nick, new_nick);
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	PLUGIN_INITIALIZE(plugin, "Logging plugin", "1.0", "Logs users entering and leaving the hub.");

	plugin->funcs.on_user_login = log_user_login;
	plugin->funcs.on_user_login_error = log_user_login_error;
	plugin->funcs.on_user_logout = log_user_logout;
	plugin->funcs.on_user_nick_change = log_change_nick;

	plugin->ptr = parse_config(config, plugin);
	if (!plugin->ptr)
		return -1;
	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	/* No need to do anything! */
	log_close(plugin->ptr);
	return 0;
}

