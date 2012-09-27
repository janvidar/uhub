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

#include "uhub.h"

static void hub_command_args_free(struct hub_command* cmd)
{
	struct hub_command_arg_data* data = NULL;

	if (!cmd->args)
		return;

	for (data = (struct hub_command_arg_data*) list_get_first(cmd->args); data; data = (struct hub_command_arg_data*) list_get_next(cmd->args))
	{
		switch (data->type)
		{
			case type_string:
				hub_free(data->data.string);
				break;
			case type_range:
				hub_free(data->data.range);
				break;
			default:
				break;
		}
	}

	list_clear(cmd->args, hub_free);
	list_destroy(cmd->args);
	cmd->args = NULL;
}

void command_free(struct hub_command* cmd)
{
	if (!cmd) return;

	hub_free(cmd->prefix);
	hub_command_args_free(cmd);
	hub_free(cmd);
}

static enum command_parse_status command_extract_arguments(struct hub_info* hub, const struct hub_user* user, struct command_handle* command, struct linked_list* tokens, struct linked_list* args)
{
	int arg = 0;
	int opt = 0;
	int greedy = 0;
	char arg_code;
	char* token = NULL;
	char* tmp = NULL;
	size_t size = 0;
	struct hub_command_arg_data* data = NULL;
	enum command_parse_status status = cmd_status_ok;

	// Ignore the first token since it is the prefix.
	token = list_get_first(tokens);
	list_remove(tokens, token);
	hub_free(token);

	while (status == cmd_status_ok && (arg_code = command->args[arg++]))
	{
		if (greedy)
		{
			size = 1;
			for (tmp = (char*) list_get_first(tokens); tmp; tmp = (char*) list_get_next(tokens))
				size += (strlen(tmp) + 1);
			token = hub_malloc_zero(size);

			while ((tmp = list_get_first(tokens)))
			{
				if (*token)
					strcat(token, " ");
				strcat(token, tmp);
				list_remove(tokens, tmp);
				hub_free(tmp);
			}
		}
		else
		{
			token = list_get_first(tokens);
		}

		if (!token || !*token)
		{
			if (arg_code == '?' || opt == 1)
				status = cmd_status_ok;
			else
				status = cmd_status_missing_args;
			break;
		}

		switch (arg_code)
		{
			case '?':
				opt = 1;
				continue;

			case '+':
				greedy = 1;
				continue;

			case 'u':
				data = hub_malloc(sizeof(*data));
				data->type = type_user;
				data->data.user = uman_get_user_by_nick(hub->users, token);
				if (!data->data.user)
				{
					hub_free(data);
					data = NULL;
					status = cmd_status_arg_nick;
				}
				break;

			case 'i':
				data = hub_malloc(sizeof(*data));
				data->type = type_user;
				data->data.user = uman_get_user_by_cid(hub->users, token);
				if (!data->data.user)
				{
					hub_free(data);
					data = NULL;
					status = cmd_status_arg_cid;
				}
				break;

			case 'a':
				data = hub_malloc(sizeof(*data));
				data->type = type_address;
				if (ip_convert_to_binary(token, data->data.address) == -1)
				{
					hub_free(data);
					data = NULL;
					status = cmd_status_arg_address;
				}
				break;

			case 'r':
				data = hub_malloc(sizeof(*data));
				data->type = type_range;
				data->data.range = hub_malloc_zero(sizeof(struct ip_range));
				if (!ip_convert_address_to_range(token, data->data.range))
				{
					hub_free(data->data.range);
					hub_free(data);
					data = NULL;
					status = cmd_status_arg_address;
				}
				break;

			case 'n':
			case 'm':
			case 'p':
				data = hub_malloc(sizeof(*data));
				data->type = type_string;
				data->data.string = strdup(token);
				break;

			case 'c':
				data = hub_malloc(sizeof(*data));
				data->type = type_command;
				data->data.command = command_handler_lookup(hub->commands, token);
				if (!data->data.command)
				{
					hub_free(data);
					data = NULL;
					status = cmd_status_arg_command;
				}
				break;

			case 'C':
				data = hub_malloc(sizeof(*data));
				data->type = type_credentials;
				if (!auth_string_to_cred(token, &data->data.credentials))
				{
					hub_free(data);
					data = NULL;
					status = cmd_status_arg_cred;
				}
				break;

			case 'N':
				data = hub_malloc(sizeof(*data));
				data->type = type_integer;
				if (!is_number(token, &data->data.integer))
				{
					hub_free(data);
					data = NULL;
					status = cmd_status_arg_number;
				}
				break;

			case '\0':
				if (!opt)
				{
					status = cmd_status_missing_args;
				}
				else
				{
					status = cmd_status_ok;
				}
		}

		if  (data)
		{
			list_append(args, data);
			data = NULL;
		}

		list_remove(tokens, token);
		hub_free(token);
	}

	hub_free(data);
	return status;
}

static struct command_handle* command_get_handler(struct command_base* cbase, const char* prefix, const struct hub_user* user, struct hub_command* cmd)
{
	struct command_handle* handler = NULL;
	uhub_assert(cmd != NULL);

	if (prefix && prefix[0] && prefix[1])
	{
		handler = command_handler_lookup(cbase, prefix + 1);
		if (handler)
		{
			cmd->ptr = handler->ptr;
			cmd->handler = handler->handler;
			cmd->status = command_is_available(handler, user->credentials) ? cmd_status_ok : cmd_status_access_error;
		}
		else
		{
			cmd->status = cmd_status_not_found;
		}
	}
	else
	{
		cmd->status = cmd_status_syntax_error;
	}
	return handler;
}


/**
 * Parse a command and break it down into a struct hub_command.
 */
struct hub_command* command_parse(struct command_base* cbase, struct hub_info* hub, const struct hub_user* user, const char* message)
{
	struct linked_list* tokens = list_create();
	struct hub_command* cmd = NULL;
	struct command_handle* handle = NULL;

	cmd = hub_malloc_zero(sizeof(struct hub_command));
	cmd->status = cmd_status_ok;
	cmd->message = message;
	cmd->prefix = NULL;
	cmd->args = list_create();
	cmd->user = user;

	if (split_string(message, " ", tokens, 0) <= 0)
	{
		cmd->status = cmd_status_syntax_error;
		goto command_parse_cleanup;
	}

	// Setup hub command.
	cmd->prefix = strdup(((char*) list_get_first(tokens)) + 1);

	// Find a matching command handler
	handle = command_get_handler(cbase, list_get_first(tokens), user, cmd);
	if (cmd->status != cmd_status_ok)
		goto command_parse_cleanup;

	// Parse arguments
	cmd->status = command_extract_arguments(hub, user, handle, tokens, cmd->args);
	goto command_parse_cleanup;

command_parse_cleanup:
	list_clear(tokens, &hub_free);
	list_destroy(tokens);
	return cmd;
}

