/**
 * This is a minimal example plugin for uhub.
 */

// #include "uhub.h"
#include "plugin_api/handle.h"

struct ip_addr_encap;

plugin_st log_connect(struct ip_addr_encap* addr)
{
	return st_default;
}

void log_user_login(struct plugin_user* user)
{
	printf("login: \"%s\"\n", user->nick);
}

void log_user_logout(struct plugin_user* user)
{
	printf("logout: \"%s\"\n", user->nick);
}

plugin_st log_change_nick(struct plugin_user* user, const char* new_nick)
{
	printf("\"%s\" -> \"%s\"\n", user->nick, new_nick);
	return st_default;
}


int plugin_register(struct uhub_plugin_handle* plugin, const char* config)
{
	plugin->name = "Logging plugin";
	plugin->version = "1.0";
	plugin->description = "Logs users entering and leaving the hub.";
	plugin->ptr = NULL;
	plugin->plugin_api_version = PLUGIN_API_VERSION;
	plugin->plugin_funcs_size = sizeof(struct plugin_funcs);
	memset(&plugin->funcs, 0, sizeof(struct plugin_funcs));
/*
	plugin->funcs.on_connect = log_connect;
	plugin->funcs.on_user_login = log_user_login;
	plugin->funcs.on_user_logout = log_user_logout;
	plugin->funcs.on_user_change_nick = log_change_nick;
*/
	puts("* plugin register");
	return 0;
}

int plugin_unregister(struct uhub_plugin_handle* plugin)
{
	/* No need to do anything! */
	puts("* plugin unregister");
	return 0;
}

