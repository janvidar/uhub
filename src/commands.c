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

static int command_access_denied(struct user* user)
{
    struct adc_message* command;
    char* buffer = adc_msg_escape("Access denied.");
    command = adc_msg_construct(ADC_CMD_IMSG, strlen(buffer) + 6);
    adc_msg_add_argument(command, buffer);
    route_to_user(user, command);
    adc_msg_free(command);
    hub_free(buffer);
    return 0;
}


static int command_stats(struct user* user, const char* message)
{
    struct adc_message* command;
    
    if (user->credentials < cred_super)
	return command_access_denied(user);
   
    char temp[64];
    snprintf(temp, 64, "*** Stats: %u users, peak %u", (unsigned int) user->hub->users->count, (unsigned int) user->hub->users->count_peak);
    char* buffer = adc_msg_escape(temp);
    command = adc_msg_construct(ADC_CMD_IMSG, strlen(buffer) + 6);
    adc_msg_add_argument(command, buffer);
    route_to_user(user, command);
    adc_msg_free(command);
    hub_free(buffer);
    return 0;
}


static int command_help(struct user* user, const char* message)
{
    struct adc_message* command;
    char* buffer = adc_msg_escape(
	"*** Available commands:\n"
	"!help         - Show this help message\n"
	"!stats        - Show hub stats (super)\n"
	"!version      - Show this help message\n"
	"!uptime       - Display hub uptime\n"
	"!kick <user>  - Kick user (operator)\n"
	);

    command = adc_msg_construct(ADC_CMD_IMSG, strlen(buffer) + 6);
    adc_msg_add_argument(command, buffer);
    route_to_user(user, command);
    adc_msg_free(command);
    hub_free(buffer);
    return 0;
}

static int command_uptime(struct user* user, const char* message)
{
    struct adc_message* command;
    char temp[64];
    snprintf(temp, 64, "*** Uptime: %s seconds", uhub_itoa((int) difftime(time(0), user->hub->tm_started)));
    char* buffer = adc_msg_escape(temp);
    command = adc_msg_construct(ADC_CMD_IMSG, strlen(buffer) + 6);
    adc_msg_add_argument(command, buffer);
    route_to_user(user, command);
    adc_msg_free(command);
    hub_free(buffer);
    return 0;
}

static int command_kick(struct user* user, const char* message)
{
    struct adc_message* command;
    
    if (user->credentials < cred_operator)
	return command_access_denied(user);
   
    char* buffer = adc_msg_escape("*** Kick not implemented!");
    command = adc_msg_construct(ADC_CMD_IMSG, strlen(buffer) + 6);
    adc_msg_add_argument(command, buffer);
    route_to_user(user, command);
    adc_msg_free(command);
    hub_free(buffer);
    return 0;
}

static int command_version(struct user* user, const char* message)
{
    struct adc_message* command;
    char* buffer = adc_msg_escape("*** Powered by " PRODUCT "/" VERSION);
    command = adc_msg_construct(ADC_CMD_IMSG, strlen(buffer) + 6);
    adc_msg_add_argument(command, buffer);
    route_to_user(user, command);
    adc_msg_free(command);
    hub_free(buffer);
    return 0;
}

int command_dipatcher(struct user* user, const char* message)
{
    if      (!strncmp(message, "!stats",   6)) command_stats(user, message);
    else if (!strncmp(message, "!help",    5)) command_help(user, message);
    else if (!strncmp(message, "!kick",    5)) command_kick(user, message);
    else if (!strncmp(message, "!version", 8)) command_version(user, message);
    else if (!strncmp(message, "!uptime",  7)) command_uptime(user, message);
    else
	return 1;
    return 0;
}

