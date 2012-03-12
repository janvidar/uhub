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

#ifndef HAVE_UHUB_COMMANDS_H
#define HAVE_UHUB_COMMANDS_H

struct command_base;
struct command_handle;
struct hub_command;

typedef int (*command_handler)(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd);

enum command_parse_status
{
	cmd_status_ok,             /** <<< "Everything seems to OK" */
	cmd_status_not_found,      /** <<< "Command was not found" */
	cmd_status_access_error,   /** <<< "You don't have access to this command" */
	cmd_status_syntax_error,   /** <<< "Not a valid command." */
	cmd_status_missing_args,   /** <<< "Missing some or all required arguments." */
	cmd_status_arg_nick,       /** <<< "A nick argument does not match an online user. ('n')" */
	cmd_status_arg_cid,        /** <<< "A cid argument does not match an online user. ('i')." */
	cmd_status_arg_address,    /** <<< "A address range argument is not valid ('a')." */
	cmd_status_arg_number,     /** <<< "A number argument is not valid ('N')" */
	cmd_status_arg_cred,       /** <<< "A credentials argument is not valid ('C')" */
	cmd_status_arg_command,    /** <<< "A command argument is not valid ('c')" */
};

struct hub_command_arg_data
{
	enum Type {
		type_integer,
		type_string,
		type_user,
		type_address,
		type_range,
		type_credentials,
		type_command
	} type;

	union {
		int integer;
		char* string;
		struct hub_user* user;
		struct ip_addr_encap* address;
		struct ip_range* range;
		enum auth_credentials credentials;
		struct command_handle* command;
	} data;

	struct hub_command_arg_data* next;
};

void hub_command_args_free(struct hub_command* command);

/**
 * This struct contains all information needed to invoke
 * a command, which includes the whole message, the prefix,
 * the decoded arguments (according to parameter list), and
 * the user pointer (ptr) which comes from the command it was matched to.
 *
 * The message and prefix is generally always available, but args only
 * if status == cmd_status_ok.
 * Handler and ptr are NULL if status == cmd_status_not_found, or status == cmd_status_access_error.
 * Ptr might also be NULL if cmd_status_ok because the command that handles it was added with a NULL ptr.
 */
struct hub_command
{
	const char* message;                /**<<< "The complete message." */
	char* prefix;                       /**<<< "The prefix extracted from the message." */
	struct linked_list* args;           /**<<< "List of all parsed arguments from the message. Type depends on expectations." */
	enum command_parse_status status;   /**<<< "Status of the hub_command." */
	command_handler handler;            /**<<< "The function handler to call in order to invoke this command." */
	const struct hub_user* user;        /**<<< "The user who invoked this command." */
	void* ptr;                          /**<<< "A pointer of data which came from struct command_handler" */
};

/**
 * Argument codes are used to automatically parse arguments
 * for a a hub command.
 *
 * n = nick name (must exist in hub session)
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
 * NOTE; if an argument is optional then all following arguments must also be optional.
 *
 * Example:
 * "nia" means "nick cid ip"
 * "n?p" means "nick [password]" where password is optional.
 *
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
 * Parse a message as a command and return a status indicating if the command
 * is valid and that the arguments are sane.
 *
 * @param cbase Command base pointer.
 * @param user User who invoked the command.
 * @param message The message that is to be interpreted as a command (including the invokation prefix '!' or '+')
 *
 * @return a hub_command that must be freed with command_free(). @See struct hub_command.
 */
extern struct hub_command* command_parse(struct command_base* cbase, const struct hub_user* user, const char* message);

/**
 * Free a hub_command that was created in command_parse().
 */
extern void command_free(struct hub_command* command);


extern void commands_builtin_add(struct command_base*);
extern void commands_builtin_remove(struct command_base*);

#endif /* HAVE_UHUB_COMMANDS_H */
