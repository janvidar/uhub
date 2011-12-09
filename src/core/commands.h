/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2011, Jan Vidar Krey
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

struct command_base;
struct command_handle;

struct hub_command
{
	const char* message;
	char* prefix;
	size_t prefix_len;
	struct linked_list* args;
};

typedef int (*command_handler)(struct command_base*, struct hub_user* user, struct command_handle*, struct hub_command*);

/**
 * Argument codes are used to automatically parse arguments
 * for a a hub command.
 *
 * n = nick name (must exist in hub session)
 * i = CID (must exist in hub)
 * a = (IP) address (must be a valid IPv4 or IPv6 address)
 * m = message (string)
 * p = password (string)
 * C = credentials (see auth_string_to_cred).
 * c = command (name of command)
 * N = number (integer)
 *
 * Prefix an argument with ? to make it optional.
 * NOTE; if an argument is optional then all following arguments must also be optional.
 *
 * Example:
 * "nia" means "nick cid ip"
 * "n?p" means "nick [password]" where password is optional.
 *
 */
struct command_handle
{
	const char* prefix;				/**<<< "Command prefix, for instance 'help' would be the prefix for the !help command." */
	size_t length;					/**<<< "Length of the prefix" */
	const char* args;				/**<<< "Argument codes (see above)" */
	enum auth_credentials cred;		/**<<< "Minimum access level for the command" */
	command_handler handler;		/**<<< "Function pointer for the command" */
	const char* description;		/**<<< "Description for the command" */
	const char* origin;				/**<<< "Name of module where the command is implemented." */
	void* ptr;
};



/**
 * Returns NULL on error, or handle
 */
extern struct command_base* command_initialize(struct hub_info* hub);
extern void command_shutdown(struct command_base* cbase);

/**
 * Add a new command to the command base.
 * Returns 1 on success, or 0 on error.
 */
extern int command_add(struct command_base*, struct command_handle*, void* ptr);

/**
 * Remove a command from the command base.
 * Returns 1 on success, or 0 on error.
 */
extern int command_del(struct command_base*, struct command_handle*);

/**
 * Returns 1 if a command is available to a user (user has access to run it.)
 */
extern int command_is_available(struct command_handle*, struct hub_user* user);

/**
 * Dispatch a message and forward it as a command.
 * Returns 1 if the message should be forwarded as a chat message, or 0 if
 * it is supposed to be handled internally in the dispatcher.
 *
 * This will break the message down into a struct hub_command and invoke the command handler
 * for that command if the sufficient access credentials are met.
 */
extern int command_invoke(struct command_base*, struct hub_user* user, const char* message);
