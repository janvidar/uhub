/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2012, Jan Vidar Krey
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

#ifndef HAVE_UHUB_COMMAND_PARSER_H
#define HAVE_UHUB_COMMAND_PARSER_H

struct hub_command;
struct hub_user;
struct command_base;

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
extern struct hub_command* command_parse(struct command_base* cbase, struct hub_info* hub, const struct hub_user* user, const char* message);

/**
 * Free a hub_command that was created in command_parse().
 */
extern void command_free(struct hub_command* command);


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

enum hub_command_arg_type
{
		type_integer,
		type_string,
		type_user,
		type_address,
		type_range,
		type_credentials,
		type_command
};

struct hub_command_arg_data
{
	enum hub_command_arg_type type;
	union {
		int integer;
		char* string;
		struct hub_user* user;
		struct ip_addr_encap* address;
		struct ip_range* range;
		enum auth_credentials credentials;
		struct command_handle* command;
	} data;
};

typedef int (*command_handler)(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd);

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
	struct linked_list* args;           /**<<< "List of arguments of type struct hub_command_arg_data. Parsed from message." */
	enum command_parse_status status;   /**<<< "Status of the parsed hub_command." */
	command_handler handler;            /**<<< "The function handler to call in order to invoke this command." */
	const struct hub_user* user;        /**<<< "The user who invoked this command." */
	void* ptr;                          /**<<< "A pointer of data which came from struct command_handler" */
};

/**
 * Reset the command argument iterator and return the number of arguments
 * that can be extracted from a parsed command.
 *
 * @param cmd the command to start iterating arguments
 * @return returns the number of arguments provided for the command
 */
extern size_t hub_command_arg_reset(struct hub_command* cmd);

/**
 * Obtain the current argument and place it in data and increments the iterator.
 * If no argument exists, or the argument is of a different type than \param type, then 0 is returned.
 *
 * NOTE: when calling hub_command_arg_next the first time during a command callback it is safe to assume
 * that the first argument will be extracted. Thus you don't need to call hub_command_arg_reset().
 *
 * @param cmd the command used for iterating arguments.
 * @param type the expected type of this argument
 * @return NULL if no argument is found or if the argument found does not match the expected type.
 */
extern struct hub_command_arg_data* hub_command_arg_next(struct hub_command* cmd, enum hub_command_arg_type type);

#endif /* HAVE_UHUB_COMMAND_PARSER_H */
