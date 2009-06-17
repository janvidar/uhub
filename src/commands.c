/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2009, Jan Vidar Krey
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

typedef int (*command_handler)(struct hub_info* hub, struct user* user, const char* message);

struct commands_handler
{
	const char* prefix;
	size_t length;
	enum user_credentials cred;
	command_handler handler;
	const char* description;
};

static struct commands_handler command_handlers[];

static void send_message(struct hub_info* hub, struct user* user, const char* message)
{
	char* buffer = adc_msg_escape(message);
	struct adc_message* command = adc_msg_construct(ADC_CMD_IMSG, strlen(buffer) + 6);
	adc_msg_add_argument(command, buffer);
	route_to_user(hub, user, command);
	adc_msg_free(command);
	hub_free(buffer);
}

static int command_access_denied(struct hub_info* hub, struct user* user, const char* command)
{
	char temp[128];
	snprintf(temp, 128, "*** Access denied: \"%s\"", command);
	send_message(hub, user, temp);
	return 0;
}

static int command_not_found(struct hub_info* hub, struct user* user, const char* command)
{
	char temp[128];
	snprintf(temp, 128, "*** Command not found: \"%s\"", command);
	send_message(hub, user, temp);
	return 0;
}

static int command_status(struct hub_info* hub, struct user* user, const char* command, const char* message)
{
	char temp[1024];
	snprintf(temp, 1024, "*** %s: %s", command, message);
	send_message(hub, user, temp);
	return 0;
}

static int command_stats(struct hub_info* hub, struct user* user, const char* message)
{
	char temp[128];
	snprintf(temp, 128, "%zu users, peak: %zu. Network (up/down): %d/%d KB/s, peak: %d/%d KB/s",
	hub->users->count,
	hub->users->count_peak,
	(int) hub->stats.net_tx / 1024,
	(int) hub->stats.net_rx / 1024,
	(int) hub->stats.net_tx_peak / 1024,
	(int) hub->stats.net_rx_peak / 1024);
	
	return command_status(hub, user, "stats", temp);
}

static int command_help(struct hub_info* hub, struct user* user, const char* message)
{
#define MAX_HELP_MSG 1024
	size_t n;
	char msg[MAX_HELP_MSG];
	msg[0] = 0;
	strcat(msg, "Available commands:\n");
	
	for (n = 0; command_handlers[n].prefix; n++)
	{
		if (command_handlers[n].cred <= user->credentials)
		{
			strcat(msg, "!");
			strcat(msg, command_handlers[n].prefix);
			strcat(msg, " - ");
			strcat(msg, command_handlers[n].description);
			strcat(msg, "\n");
		}
	}
	return command_status(hub, user, "help", msg);
}

static int command_uptime(struct hub_info* hub, struct user* user, const char* message)
{
	char tmp[128];
	size_t d;
	size_t h;
	size_t m;
	size_t D = (size_t) difftime(time(0), hub->tm_started);

	d = D / (24 * 3600);
	D = D % (24 * 3600);
	h = D / 3600;
	D = D % 3600;
	m = D / 60;

	tmp[0] = 0;
	if (d)
	{
		strcat(tmp, uhub_itoa((int) d));
		strcat(tmp, " day");
		if (d != 1) strcat(tmp, "s");
		strcat(tmp, ", ");
	}

	if (h < 10) strcat(tmp, "0");
	strcat(tmp, uhub_itoa((int) h));
	strcat(tmp, ":");
	if (m < 10) strcat(tmp, "0");
	strcat(tmp, uhub_itoa((int) m));

	return command_status(hub, user, "uptime", tmp);
}

static int command_kick(struct hub_info* hub, struct user* user, const char* message)
{
	if (strlen(message) < 7)
	{
		return command_status(hub, user, "kick", "No nickname given");
	}
	
	const char* nick = &message[7];
	struct user* target = uman_get_user_by_nick(hub, nick);
	
	if (!target)
	{
		return command_status(hub, user, "kick", "No such user");
	}
	
	if (target == user)
	{
		return command_status(hub, user, "kick", "Cannot kick yourself");
	}
	
	hub_disconnect_user(hub, target, quit_kicked);
	return command_status(hub, user, "kick", nick);
}

static int command_reload(struct hub_info* hub, struct user* user, const char* message)
{
	hub->status = hub_status_restart;
	return command_status(hub, user, "reload", "Reloading configuration...");
}

static int command_shutdown(struct hub_info* hub, struct user* user, const char* message)
{
	hub->status = hub_status_shutdown;
	return command_status(hub, user, "shutdown", "Hub shutting down...");
}

static int command_version(struct hub_info* hub, struct user* user, const char* message)
{
    return command_status(hub, user, "version", "Powered by " PRODUCT "/" VERSION);
}

static int command_myip(struct hub_info* hub, struct user* user, const char* message)
{
    char tmp[128];
    snprintf(tmp, 128, "Your IP is \"%s\"", ip_convert_to_string(&user->net.ipaddr));
    return command_status(hub, user, "myip", tmp);
}

int command_dipatcher(struct hub_info* hub, struct user* user, const char* message)
{
	size_t n = 0;
	for (n = 0; command_handlers[n].prefix; n++)
	{
		if (!strncmp(&message[1], command_handlers[n].prefix, command_handlers[n].length))
		{
			if (command_handlers[n].cred <= user->credentials)
			{
				return command_handlers[n].handler(hub, user, message);
			}
			else
			{
				return command_access_denied(hub, user, command_handlers[n].prefix);
			}
		}
	}

	command_not_found(hub, user, message);
	return 1;
}

static struct commands_handler command_handlers[] = {
	{ "help",       4, cred_guest,     command_help,     "Show this help message."      },
	{ "stats",      5, cred_super,     command_stats,    "Show hub statistics."         },
	{ "version",    7, cred_guest,     command_version,  "Show hub version info."       },
	{ "uptime",     6, cred_guest,     command_uptime,   "Display hub uptime info."     },
	{ "kick",       4, cred_operator,  command_kick,     "Kick a user"                  },
	{ "reload",     6, cred_admin,     command_reload,   "Reload configuration files."  },
	{ "shutdown",   8, cred_admin,     command_shutdown, "Shutdown hub."                },
	{ "myip",       4, cred_guest,     command_myip,     "Show your own IP."            },
	{ 0,            0, cred_none,      command_help,     ""                             }
};

