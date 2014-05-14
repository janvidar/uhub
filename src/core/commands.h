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

#ifndef HAVE_UHUB_COMMANDS_H
#define HAVE_UHUB_COMMANDS_H

struct command_base;
struct command_handle;
struct hub_command;

/**
 * Argument codes are used to automatically parse arguments
 * for a a hub command.
 *
 * u = user (must exist in hub session, or will cause error)
 * n = nick name (string)
 * i = CID (must exist in hub)
 * a = (IP) address (must be a valid IPv4 or IPv6 address)
 * r = (IP) address range (either: IP-IP or IP/mask, both IPv4 or IPv6 work)
 * m = message (string)
 * p = password (string)
 * C = credentials (see auth_string_to_cred).
 * c = command (name of command)
 * N = number (integer)
 *
 * Prefix an argument with ? to make it optional.
 * Prefix with + to make the argument greedy, which causes it to grab the rest of the line ignoring boundaries (only supported for string types).
 *
 * NOTE: if an argument is optional then all following arguments must also be optional.
 * NOTE: You can combine optional and greedy, example: "?+m" would match "", "a", "a b c", etc.
 *
 * Example:
 * "nia" means "nick cid ip"
 * "n?p" means "nick [password]" where password is optional.
 * "?N?N" means zero, one, or two integers.
 * "?NN" means zero or two integers.
 * "?+m" means an optional string which may contain spaces that would otherwise be split into separate arguments.
 */
struct command_handle
{
	const char* prefix;             /**<<< "Command prefix, for instance 'help' would be the prefix for the !help command." */
	size_t length;                  /**<<< "Length of the prefix" */
	const char* args;               /**<<< "Argument codes (see above)" */
	enum auth_credentials cred;     /**<<< "Minimum access level for the command" */
	command_handler handler;        /**<<< "Function pointer for the command" */
	const char* description;        /**<<< "Description for the command" */
	const char* origin;             /**<<< "Name of module where the command is implemented." */
	void* ptr;                      /**<<< "A pointer which will be passed along to the handler. @See hub_command::ptr" */
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
 * Dispatch a message and forward it as a command.
 * Returns 1 if the message should be forwarded as a chat message, or 0 if
 * it is supposed to be handled internally in the dispatcher.
 *
 * This will break the message down into a struct hub_command and invoke the command handler
 * for that command if the sufficient access credentials are met.
 */
extern int command_invoke(struct command_base*, struct hub_user* user, const char* message);

/**
 * Returns 1 if the command handle can be used with the given credentials, 0 otherwise.
 */
int command_is_available(struct command_handle* handle, enum auth_credentials credentials);

/**
 * Lookup a command handle based on prefix.
 * If no matching command handle is found then NULL is returned.
 */
struct command_handle* command_handler_lookup(struct command_base* cbase, const char* prefix);

extern void commands_builtin_add(struct command_base*);
extern void commands_builtin_remove(struct command_base*);

#endif /* HAVE_UHUB_COMMANDS_H */
