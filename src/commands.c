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

static void send_message(struct user* user, const char* message)
{
	char* buffer = adc_msg_escape(message);
	struct adc_message* command = adc_msg_construct(ADC_CMD_IMSG, strlen(buffer) + 6);
	adc_msg_add_argument(command, buffer);
	route_to_user(user, command);
	adc_msg_free(command);
	hub_free(buffer);
}

static int command_access_denied(struct user* user)
{
    send_message(user, "*** Access denied.");
    return 0;
}


static int command_stats(struct user* user, const char* message)
{
    if (user->credentials < cred_super)
	return command_access_denied(user);
	
    char temp[128];
    snprintf(temp, 128, "*** Stats: %zu users, peak: %zu. Network (up/down): %d/%d KB/s, peak: %d/%d KB/s",
	user->hub->users->count,
	user->hub->users->count_peak,
	(int) user->hub->stats.net_tx / 1024,
	(int) user->hub->stats.net_rx / 1024,
	(int) user->hub->stats.net_tx_peak / 1024,
	(int) user->hub->stats.net_rx_peak / 1024);

    send_message(user, temp);
    return 0;
}


static int command_help(struct user* user, const char* message)
{
       send_message(user, "\n"
		"*** Available commands:\n"
		"!help         - Show this help message\n"
		"!stats        - Show hub stats (super)\n"
		"!version      - Show this help message\n"
		"!uptime       - Display hub uptime\n"
		"!kick <user>  - Kick user (operator)\n"
		"!reload       - Reload configuration (admin)\n"
		"!shutdown     - Shutdown hub (admin)\n"
	);
    return 0;
}

static int command_uptime(struct user* user, const char* message)
{
	char tmp[128];
	size_t d;
	size_t h;
	size_t m;
	size_t D = (size_t) difftime(time(0), user->hub->tm_started);

	d = D / (24 * 3600);
	D = D % (24 * 3600);
	h = D / 3600;
	D = D % 3600;
	m = D / 60;

	tmp[0] = 0;
	strcat(tmp, "*** Uptime: ");

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

	send_message(user, tmp);
	return 0;
}

static int command_kick(struct user* user, const char* message)
{
	if (user->credentials < cred_operator)
		return command_access_denied(user);

	send_message(user, "*** Kick not implemented!");
	return 0;
}

static int command_reload(struct user* user, const char* message)
{
	if (user->credentials < cred_admin)
		return command_access_denied(user);

	send_message(user, "*** Reloading configuration");
	user->hub->status = hub_status_restart;
	return 0;
}

static int command_shutdown(struct user* user, const char* message)
{
	if (user->credentials < cred_admin)
		return command_access_denied(user);

	send_message(user, "*** Hub shuting down...");
	user->hub->status = hub_status_shutdown;
	return 0;
}


static int command_version(struct user* user, const char* message)
{
    send_message(user, "*** Powered by " PRODUCT "/" VERSION);
    return 0;
}

static int command_myip(struct user* user, const char* message)
{
    char tmp[128];

    tmp[0] = 0;
    strcat(tmp, "*** Your IP: ");
    strcat(tmp, ip_convert_to_string(&user->ipaddr));

    send_message(user, tmp);
    return 0;
}


int command_dipatcher(struct user* user, const char* message)
{
    if      (!strncmp(message, "!stats",   6)) command_stats(user, message);
    else if (!strncmp(message, "!help",    5)) command_help(user, message);
    else if (!strncmp(message, "!kick",    5)) command_kick(user, message);
    else if (!strncmp(message, "!version", 8)) command_version(user, message);
    else if (!strncmp(message, "!uptime",  7)) command_uptime(user, message);
    else if (!strncmp(message, "+myip",    5)) command_myip(user, message);
    else if (!strncmp(message, "!reload",  7)) command_reload(user, message);
    else if (!strncmp(message, "!shutdown",9)) command_shutdown(user, message);
    else
	return 1;
    return 0;
}

