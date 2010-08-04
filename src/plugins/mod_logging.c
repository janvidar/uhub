/**
 * This is a minimal example plugin for uhub.
 */

#include "system.h"
#include "adc/adcconst.h"
#include "adc/sid.h"
#include "util/memory.h"
#include "util/ipcalc.h"
#include "plugin_api/handle.h"

struct ip_addr_encap;

struct log_data
{
	char* logfile;
	int fd;
};


static void set_error_message(struct plugin_handle* plugin, const char* msg)
{
	plugin->error_msg = msg;
}


static struct log_data* log_open(struct plugin_handle* plugin, const char* config)
{
	struct log_data* data = (struct log_data*) hub_malloc(sizeof(struct log_data));
	data->logfile = strdup(config);
	data->fd = open(data->logfile, O_CREAT | O_APPEND | O_NOATIME | O_LARGEFILE | O_WRONLY, 0664);
	if (data->fd == -1)
	{
		set_error_message(plugin, "Unable to open log file!");
		hub_free(data->logfile);
		hub_free(data);
		return NULL;
	}
	return data;
}

static void log_close(struct log_data* data)
{
	hub_free(data->logfile);
	close(data->fd);
	hub_free(data);
}

static void log_message(struct log_data* data, const char *format, ...)
{
	static char logmsg[1024];
	struct tm *tmp;
	time_t t;
	va_list args;
	ssize_t size = 0;

	t = time(NULL);
	tmp = localtime(&t);
	strftime(logmsg, 32, "%Y-%m-%d %H:%M:%S ", tmp);

	va_start(args, format);
	size = vsnprintf(logmsg + 20, 1004, format, args);
	va_end(args);

	write(data->fd, logmsg, size + 20);
	fdatasync(data->fd);
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
	plugin->name = "Logging plugin";
	plugin->version = "1.0";
	plugin->description = "Logs users entering and leaving the hub.";
	plugin->ptr = NULL;
	plugin->plugin_api_version = PLUGIN_API_VERSION;
	plugin->plugin_funcs_size = sizeof(struct plugin_funcs);
	memset(&plugin->funcs, 0, sizeof(struct plugin_funcs));

	plugin->funcs.on_user_login = log_user_login;
	plugin->funcs.on_user_login_error = log_user_login_error;
	plugin->funcs.on_user_logout = log_user_logout;
	plugin->funcs.on_user_nick_change = log_change_nick;

	plugin->ptr = log_open(plugin, config);
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

