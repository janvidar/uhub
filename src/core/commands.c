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

#ifdef DEBUG
// #define CRASH_DEBUG
// #define DEBUG_UNLOAD_PLUGINS
#endif

#define MAX_HELP_MSG 16384
#define MAX_HELP_LINE 512

static int send_command_access_denied(struct command_base* cbase, struct hub_user* user, const char* prefix);
static int send_command_not_found(struct command_base* cbase, struct hub_user* user, const char* prefix);
static int send_command_syntax_error(struct command_base* cbase, struct hub_user* user);
static int send_command_missing_arguments(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd);

static void null_free(void* ptr) { }

struct command_base
{
	struct hub_info* hub;
	struct linked_list* handlers;
	size_t prefix_length_max;
	struct ip_range range; // cached for parsing. Only one can be used per parameter.
};

struct command_base* command_initialize(struct hub_info* hub)
{
	struct command_base* cbase = (struct command_base*) hub_malloc(sizeof(struct command_base));
	uhub_assert(cbase != NULL);
	// uhub_assert(hub != NULL);

	cbase->hub = hub;
	cbase->handlers = (struct linked_list*) list_create();
	cbase->prefix_length_max = 0;

	uhub_assert(cbase->handlers != NULL);

	commands_builtin_add(cbase);

	return cbase;
}

void command_shutdown(struct command_base* cbase)
{
	commands_builtin_remove(cbase);
	assert(list_size(cbase->handlers) == 0);
	list_destroy(cbase->handlers);
	hub_free(cbase);
}

int command_add(struct command_base* cbase, struct command_handle* cmd, void* ptr)
{
	uhub_assert(cbase != NULL);
	uhub_assert(cmd != NULL);
	uhub_assert(cmd->length == strlen(cmd->prefix));
	uhub_assert(cmd->handler != NULL);
	uhub_assert(cmd->description && *cmd->description);
	list_append(cbase->handlers, cmd);
	cbase->prefix_length_max = MAX(cmd->length, cbase->prefix_length_max);
	cmd->ptr = ptr;
	return 1;
}

int command_del(struct command_base* cbase, struct command_handle* cmd)
{
	uhub_assert(cbase != NULL);
	uhub_assert(cmd != NULL);
	list_remove(cbase->handlers, cmd);
	return 1;
}

static int command_is_available(struct command_handle* handle, const struct hub_user* user)
{
	uhub_assert(handle != NULL);
	uhub_assert(user != NULL);
	return handle->cred <= user->credentials;
}

void command_free(struct hub_command* cmd)
{
	if (!cmd) return;

	hub_free(cmd->prefix);
	if (cmd->args)
	{
		list_clear(cmd->args, &null_free);
		list_destroy(cmd->args);
	}
	hub_free(cmd);
}

static struct command_handle* command_handler_lookup(struct command_base* cbase, const char* prefix)
{
	struct command_handle* handler = NULL;
	size_t prefix_len = strlen(prefix);

	for (handler = (struct command_handle*) list_get_first(cbase->handlers); handler; handler = (struct command_handle*) list_get_next(cbase->handlers))
	{
		if (prefix_len != handler->length)
			continue;

		if (!memcmp(prefix, handler->prefix, handler->length))
			return handler;
	}
	return NULL;
}

static enum command_parse_status command_extract_arguments(struct command_base* cbase, const struct hub_user* user, struct command_handle* command, struct linked_list* tokens, struct linked_list** args)
{
	int arg = 0;
	int opt = 0;
	char arg_code;
	char* token = NULL;
	struct hub_user* target = NULL;
	struct command_handle* target_command = NULL;
	enum auth_credentials cred;
	enum command_parse_status status = cmd_status_ok;
	int args_addr_range = 0;
	int temp_num;

	// Ignore the first token since it is the prefix.
	token = list_get_first(tokens);
	list_remove(tokens, token);
	hub_free(token);

	uhub_assert(args);
	*args = list_create();

	while ((arg_code = command->args[arg++]))
	{
		token = list_get_first(tokens);
		if (!token || !*token)
		{
			status = (arg_code == '?')  ? cmd_status_ok : cmd_status_missing_args;
			break;
		}

		switch (arg_code)
		{
			case '?':
				opt = 1;
				continue;

			case 'n':
				target = uman_get_user_by_nick(cbase->hub, token);
				if (!target)
				{
					status = cmd_status_arg_nick;
					goto parse_arguments_error;
				}
				list_append(*args, target);
				break;

			case 'i':
				target = uman_get_user_by_cid(cbase->hub, token);
				if (!target)
				{
					status = cmd_status_arg_cid;
					goto parse_arguments_error;
				}
				list_append(*args, target);
				break;

			case 'a':
				uhub_assert(args_addr_range == 0 || !"BUG: Can only be one address range argument per command!");
				if (!ip_convert_address_to_range(token, &cbase->range))
				{
					status = cmd_status_arg_address;
					goto parse_arguments_error;
				}
				list_append(*args, &cbase->range);
				args_addr_range++;
				break;

			case 'm':
			case 'p':
				list_append(*args, token);
				break;

			case 'c':
				target_command = command_handler_lookup(cbase, token);
				if (!target_command)
				{
					status = cmd_status_arg_command;
					goto parse_arguments_error;
				}
				list_append(*args, target_command);
				break;

			case 'C':
				if (!auth_string_to_cred(token, &cred))
				{
					status = cmd_status_arg_cred;
					goto parse_arguments_error;
				}
				list_append(*args, (void*) cred);
				break;

			case 'N':
				if (!is_number(token, &temp_num))
				{
					status = cmd_status_arg_number;
					goto parse_arguments_error;
				}
				list_append(*args, (void*) (int*) (intptr_t) temp_num);
				break;

			case '\0':
				if (!opt)
				{
					status = cmd_status_missing_args;
					goto parse_arguments_error;
				}
				else
				{
					status = cmd_status_ok;
					break;
				}
		}
		list_remove(tokens, token);
		hub_free(token);
	}
	return status;

parse_arguments_error:
	list_clear(*args, &null_free);
	list_destroy(*args);
	*args = NULL;
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
			cmd->status = command_is_available(handler, user) ? cmd_status_ok : cmd_status_access_error;
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
struct hub_command* command_parse(struct command_base* cbase, const struct hub_user* user, const char* message)
{
	struct linked_list* tokens = list_create();
	struct hub_command* cmd = NULL;
	struct command_handle* handle = NULL;

	cmd = hub_malloc_zero(sizeof(struct hub_command));
	cmd->status = cmd_status_ok;
	cmd->message = message;
	cmd->prefix = NULL;
	cmd->args = NULL;
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
	cmd->status = command_extract_arguments(cbase, user, handle, tokens, &cmd->args);
	goto command_parse_cleanup;

command_parse_cleanup:
	list_clear(tokens, &hub_free);
	list_destroy(tokens);
	return cmd;
}

void command_get_syntax(struct command_handle* handler, struct cbuffer* buf)
{
	size_t n = 0;
	int opt = 0;
	if (handler->args)
	{
		for (n = 0; n < strlen(handler->args); n++)
		{
			if (n > 0 && !opt) cbuf_append(buf, " ");
			switch (handler->args[n])
			{
				case '?': cbuf_append(buf, "["); opt = 1; continue;
				case 'n': cbuf_append(buf, "<nick>"); break;
				case 'i': cbuf_append(buf, "<cid>");  break;
				case 'a': cbuf_append(buf, "<addr>"); break;
				case 'm': cbuf_append(buf, "<message>"); break;
				case 'p': cbuf_append(buf, "<password>"); break;
				case 'C': cbuf_append(buf, "<credentials>"); break;
				case 'c': cbuf_append(buf, "<command>"); break;
				case 'N': cbuf_append(buf, "<number>"); break;
			}
			if (opt)
			{
				cbuf_append(buf, "]");
				opt = 0;
			}
		}
	}
}


void send_message(struct command_base* cbase, struct hub_user* user, struct cbuffer* buf)
{
	char* buffer = adc_msg_escape(cbuf_get(buf));
	struct adc_message* command = adc_msg_construct(ADC_CMD_IMSG, strlen(buffer) + 6);
	adc_msg_add_argument(command, buffer);
	route_to_user(cbase->hub, user, command);
	adc_msg_free(command);
	hub_free(buffer);
	cbuf_destroy(buf);
}

static int send_command_access_denied(struct command_base* cbase, struct hub_user* user, const char* prefix)
{
	struct cbuffer* buf = cbuf_create(128);
	cbuf_append_format(buf, "*** %s: Access denied.", prefix);
	send_message(cbase, user, buf);
	return 0;
}

static int send_command_not_found(struct command_base* cbase, struct hub_user* user, const char* prefix)
{
	struct cbuffer* buf = cbuf_create(128);
	cbuf_append_format(buf, "*** %s: Command not found.", prefix);
	send_message(cbase, user, buf);
	return 0;
}

static int send_command_syntax_error(struct command_base* cbase, struct hub_user* user)
{
	struct cbuffer* buf = cbuf_create(128);
	cbuf_append(buf, "*** Syntax error.");
	send_message(cbase, user, buf);
	return 0;
}

static int send_command_missing_arguments(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf = cbuf_create(512);
	cbuf_append_format(buf, "*** Missing argument: See !help %s\n", cmd->prefix);
	send_message(cbase, user, buf);
	return 0;
}

static size_t command_count_required_args(struct command_handle* handler)
{
	size_t n = 0;
	for (n = 0; n < strlen(handler->args); n++)
	{
		if (handler->args[n] == '?')
			break;
	}
	return n;
}

int command_check_args(struct hub_command* cmd, struct command_handle* handler)
{
	if (!handler->args)
		return 1;

	if (list_size(cmd->args) >= command_count_required_args(handler))
		return 1;

	return 0;
}

int command_invoke(struct command_base* cbase, struct hub_user* user, const char* message)
{
	int ret = 0;
	struct hub_command* cmd = command_parse(cbase, user, message);

	switch (cmd->status)
	{
		case cmd_status_ok:
			ret = cmd->handler(cbase, user, cmd);
			break;

		case cmd_status_not_found:
			ret = send_command_not_found(cbase, user, cmd->prefix);
			break;

		case cmd_status_access_error:
			ret = send_command_access_denied(cbase, user, cmd->prefix);
			break;

		case cmd_status_syntax_error:
			ret = send_command_syntax_error(cbase, user);
			break;

		case cmd_status_missing_args:
			ret = send_command_missing_arguments(cbase, user, cmd);
			break;

		case cmd_status_arg_nick:
		case cmd_status_arg_cid:
		case cmd_status_arg_address:
		case cmd_status_arg_number:
		case cmd_status_arg_cred:
		case cmd_status_arg_command:
			ret = send_command_syntax_error(cbase, user);
			break;
	}

	command_free(cmd);

	return ret;
}

static int command_status(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd, struct cbuffer* msg)
{
	struct cbuffer* buf = cbuf_create(cbuf_size(msg) + strlen(cmd->prefix) + 8);
	cbuf_append_format(buf, "*** %s: %s", cmd->prefix, cbuf_get(msg));
	send_message(cbase, user, buf);
	cbuf_destroy(msg);
	return 0;
}

static int command_help(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	size_t n;
	struct cbuffer* buf = cbuf_create(MAX_HELP_LINE);
	struct command_handle* command = list_get_first(cmd->args);

	if (!command)
	{
		cbuf_append(buf, "Available commands:\n");

		for (command = (struct command_handle*) list_get_first(cbase->handlers); command; command = (struct command_handle*) list_get_next(cbase->handlers))
		{
			if (command_is_available(command, user))
			{
				cbuf_append_format(buf, "!%s", command->prefix);
				for (n = strlen(command->prefix); n < cbase->prefix_length_max; n++)
					cbuf_append(buf, " ");
				cbuf_append_format(buf, " - %s\n", command->description);
			}
		}
	}
	else
	{
		if (command_is_available(command, user))
		{
			cbuf_append_format(buf, "Usage: !%s ", command->prefix);
			command_get_syntax(command, buf);
			cbuf_append_format(buf, "\n%s\n", command->description);
		}
		else
		{
			cbuf_append(buf, "This command is not available to you.\n");
		}
	}
	return command_status(cbase, user, cmd, buf);
}

static int command_uptime(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	size_t d;
	size_t h;
	size_t m;
	size_t D = (size_t) difftime(time(0), cbase->hub->tm_started);

	d = D / (24 * 3600);
	D = D % (24 * 3600);
	h = D / 3600;
	D = D % 3600;
	m = D / 60;

	if (d)
		cbuf_append_format(buf, "%d day%s, ", (int) d, d != 1 ? "s" : "");
	cbuf_append_format(buf, "%02d:%02d", (int) h, (int) m);
	return command_status(cbase, user, cmd, buf);
}

static int command_kick(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf;
	struct hub_user* target = list_get_first(cmd->args);

	buf = cbuf_create(128);
	if (target == user)
	{
		cbuf_append(buf, "Cannot kick yourself.");
	}
	else
	{
		cbuf_append_format(buf, "Kicking user \"%s\".", target->id.nick);
		hub_disconnect_user(cbase->hub, target, quit_kicked);
	}
	return command_status(cbase, user, cmd, buf);
}

static int command_ban(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct hub_user* target = list_get_first(cmd->args);

	if (target == user)
	{
		cbuf_append(buf, "Cannot kick/ban yourself");
	}
	else
	{
		cbuf_append_format(buf, "Banning user \"%s\"", target->id.nick);

		hub_disconnect_user(cbase->hub, target, quit_kicked);
		acl_user_ban_nick(cbase->hub->acl, target->id.nick);
		acl_user_ban_cid(cbase->hub->acl, target->id.cid);
	}
	return command_status(cbase, user, cmd, buf);
}

static int command_unban(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	return command_status(cbase, user, cmd, cbuf_create_const("Not implemented"));
}

static int command_mute(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct hub_user* target = list_get_first(cmd->args);
	struct cbuffer* buf = cbuf_create(128);

	if (strlen(cmd->prefix) == 4)
	{
		cbuf_append_format(buf, "Muted \"%s\"", target->id.nick);
		user_flag_set(target, flag_muted);
	}
	else
	{
		cbuf_append_format(buf, "Unmuted \"%s\"", target->id.nick);
		user_flag_unset(target, flag_muted);
	}
	return command_status(cbase, user, cmd, buf);
}

static int command_reload(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	cbase->hub->status = hub_status_restart;
	return command_status(cbase, user, cmd, cbuf_create_const("Reloading configuration..."));
}

#ifdef DEBUG_UNLOAD_PLUGINS
int hub_plugins_load(struct hub_info* hub);
int hub_plugins_unload(struct hub_info* hub);

static int command_load(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	hub_plugins_load(cbase->hub);
	return command_status(cbase, user, cmd, cbuf_create_const("Loading plugins..."));
}

static int command_unload(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	hub_plugins_unload(cbase->hub);
	return command_status(cbase, user, cmd, cbuf_create_const("Unloading plugins..."));
}
#endif /* DEBUG_UNLOAD_PLUGINS */

static int command_shutdown_hub(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	cbase->hub->status = hub_status_shutdown;
	return command_status(cbase, user, cmd, cbuf_create_const("Hub shutting down..."));
}

static int command_version(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf;
	if (cbase->hub->config->show_banner_sys_info)
		buf = cbuf_create_const("Powered by " PRODUCT_STRING " on " OPSYS "/" CPUINFO);
	else
		buf = cbuf_create_const("Powered by " PRODUCT_STRING);
	return command_status(cbase, user, cmd, buf);
}

static int command_myip(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	cbuf_append_format(buf, "Your address is \"%s\"", user_get_address(user));
	return command_status(cbase, user, cmd, buf);
}

static int command_getip(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct hub_user* target = list_get_first(cmd->args);
	cbuf_append_format(buf, "\"%s\" has address \"%s\"", target->id.nick, user_get_address(target));
	return command_status(cbase, user, cmd, buf);
}

static int command_whoip(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf;
	struct ip_range* range = list_get_first(cmd->args);
	struct linked_list* users = (struct linked_list*) list_create();
	struct hub_user* u;
	int ret = 0;

	ret = uman_get_user_by_addr(cbase->hub, users, range);
	if (!ret)
	{
		list_clear(users, &null_free);
		list_destroy(users);
		return command_status(cbase, user, cmd, cbuf_create_const("No users found."));
	}

	buf = cbuf_create(128 + ((MAX_NICK_LEN + INET6_ADDRSTRLEN + 5) * ret));
	cbuf_append_format(buf, "*** %s: Found %d match%s:\n", cmd->prefix, ret, ((ret != 1) ? "es" : ""));

	u = (struct hub_user*) list_get_first(users);
	while (u)
	{
		cbuf_append_format(buf, "%s (%s)\n", u->id.nick, user_get_address(u));
		u = (struct hub_user*) list_get_next(users);
	}
	cbuf_append(buf, "\n");

	send_message(cbase, user, buf);
	list_clear(users, &null_free);
	list_destroy(users);
	return 0;
}


static int command_broadcast(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	size_t offset = 11;
	size_t message_len = strlen(cmd->message + offset);
	char* message = adc_msg_escape(cmd->message + offset);
	char pm_flag[7] = "PM";
	char from_sid[5];
	size_t recipients = 0;
	struct hub_user* target;
	struct cbuffer* buf = cbuf_create(128);
	struct adc_message* command = NULL;

	memcpy(from_sid, sid_to_string(user->id.sid), sizeof(from_sid));
	memcpy(pm_flag + 2, from_sid, sizeof(from_sid));

	target = (struct hub_user*) list_get_first(cbase->hub->users->list);
	while (target)
	{
		if (target != user)
		{
			recipients++;
			command = adc_msg_construct(ADC_CMD_DMSG, message_len + 23);
			if (!command)
				break;

			adc_msg_add_argument(command, from_sid);
			adc_msg_add_argument(command, sid_to_string(target->id.sid));
			adc_msg_add_argument(command, message);
			adc_msg_add_argument(command, pm_flag);

			route_to_user(cbase->hub, target, command);
			adc_msg_free(command);
		}
		target = (struct hub_user*) list_get_next(cbase->hub->users->list);
	}

	cbuf_append_format(buf, "*** %s: Delivered to " PRINTF_SIZE_T " user%s", cmd->prefix, recipients, (recipients != 1 ? "s" : ""));
	send_message(cbase, user, buf);
	hub_free(message);
	return 0;
}

static int command_log(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf;
	struct linked_list* messages = cbase->hub->logout_info;
	struct hub_logout_info* log;
	char* search = 0;
	size_t search_len = 0;
	size_t search_hits = 0;

	if (!list_size(messages))
	{
		return command_status(cbase, user, cmd, cbuf_create_const("No entries logged."));
	}

	buf = cbuf_create(128);
	search = list_get_first(cmd->args);
	if (search)
	{
		search_len = strlen(search);
	}

	if (search_len)
	{
		cbuf_append_format(buf, "Logged entries: " PRINTF_SIZE_T ", searching for \"%s\"", list_size(messages), search);
	}
	else
	{
		cbuf_append_format(buf, "Logged entries: " PRINTF_SIZE_T, list_size(messages));
	}
	command_status(cbase, user, cmd, buf);

	buf = cbuf_create(MAX_HELP_LINE);
	log = (struct hub_logout_info*) list_get_first(messages);
	while (log)
	{
		const char* address = ip_convert_to_string(&log->addr);
		int show = 0;

		if (search_len)
		{
			if (memmem(log->cid, MAX_CID_LEN, search, search_len) || memmem(log->nick, MAX_NICK_LEN, search, search_len) || memmem(address, strlen(address), search, search_len))
			{
				search_hits++;
				show = 1;
			}
		}
		else
		{
			show = 1;
		}

		if (show)
		{
			cbuf_append_format(buf, "* %s %s, %s [%s] - %s", get_timestamp(log->time), log->cid, log->nick, ip_convert_to_string(&log->addr), user_get_quit_reason_string(log->reason));
			send_message(cbase, user, buf);
			buf = cbuf_create(MAX_HELP_LINE);
		}
		log = (struct hub_logout_info*) list_get_next(messages);
	}

	if (search_len)
	{
		cbuf_append_format(buf, PRINTF_SIZE_T " entries shown.", search_hits);
		command_status(cbase, user, cmd, buf);
		buf = NULL;
	}

	if (buf)
		cbuf_destroy(buf);
	return 0;
}

static int command_register(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct auth_info data;
	char* password = list_get_first(cmd->args);

	strncpy(data.nickname, user->id.nick, MAX_NICK_LEN);
	strncpy(data.password, password, MAX_PASS_LEN);
	data.nickname[MAX_NICK_LEN] = '\0';
	data.password[MAX_PASS_LEN] = '\0';
	data.credentials = auth_cred_user;

	if (acl_register_user(cbase->hub, &data))
	{
		cbuf_append_format(buf, "User \"%s\" registered.", user->id.nick);
	}
	else
	{
		cbuf_append_format(buf, "Unable to register user \"%s\".", user->id.nick);
	}
	return command_status(cbase, user, cmd, buf);
}

static int command_password(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct auth_info data;
	char* password = list_get_first(cmd->args);

	strncpy(data.nickname, user->id.nick, MAX_NICK_LEN);
	strncpy(data.password, password, MAX_PASS_LEN);
	data.nickname[MAX_NICK_LEN] = '\0';
	data.password[MAX_PASS_LEN] = '\0';
	data.credentials = user->credentials;

	if (acl_update_user(cbase->hub, &data))
	{
		cbuf_append(buf, "Password changed.");
	}
	else
	{
		cbuf_append_format(buf, "Unable to change password for user \"%s\".", user->id.nick);
	}
	return command_status(cbase, user, cmd, buf);
}

static int command_useradd(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct auth_info data;
	char* nick = list_get_first(cmd->args);
	char* pass = list_get_next(cmd->args);
	char* cred = list_get_next(cmd->args);
	enum auth_credentials credentials;

	if (!(cred && auth_string_to_cred(cred, &credentials)))
		credentials = auth_cred_user;

	strncpy(data.nickname, nick, MAX_NICK_LEN);
	strncpy(data.password, pass, MAX_PASS_LEN);
	data.nickname[MAX_NICK_LEN] = '\0';
	data.password[MAX_PASS_LEN] = '\0';
	data.credentials = credentials;

	if (acl_register_user(cbase->hub, &data))
		cbuf_append_format(buf, "User \"%s\" registered.", nick);
	else
		cbuf_append_format(buf, "Unable to register user \"%s\".", nick);
	return command_status(cbase, user, cmd, buf);
}

static int command_userdel(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	char* nick = list_get_first(cmd->args);

	if (acl_delete_user(cbase->hub, nick))
		cbuf_append_format(buf, "User \"%s\" is deleted.", nick);
	else
		cbuf_append_format(buf, "Unable to delete user \"%s\".", nick);
	return command_status(cbase, user, cmd, buf);
}

static int command_usermod(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	return command_status(cbase, user, cmd, cbuf_create_const("Not implemented!"));
}

static int command_userinfo(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	return command_status(cbase, user, cmd, cbuf_create_const("Not implemented!"));
}

static int command_userpass(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	return command_status(cbase, user, cmd, cbuf_create_const("Not implemented!"));
}

#ifdef CRASH_DEBUG
static int command_crash(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	void (*crash)(void) = NULL;
	crash();
	return 0;
}
#endif

static int command_stats(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct hub_info* hub = cbase->hub;

	cbuf_append_format(buf, PRINTF_SIZE_T " users, peak: " PRINTF_SIZE_T ". Network (up/down): %d/%d KB/s, peak: %d/%d KB/s",
		hub->users->count,
		hub->users->count_peak,
		(int) hub->stats.net_tx / 1024,
		(int) hub->stats.net_rx / 1024,
		(int) hub->stats.net_tx_peak / 1024,
		(int) hub->stats.net_rx_peak / 1024);
	return command_status(cbase, user, cmd, buf);
}

static struct command_handle* add_builtin(struct command_base* cbase, const char* prefix, const char* args, enum auth_credentials cred, command_handler handler, const char* description)
{
	struct command_handle* handle = (struct command_handle*) hub_malloc_zero(sizeof(struct command_handle));
	handle->prefix = prefix;
	handle->length = strlen(prefix);
	handle->args = args;
	handle->cred = cred;
	handle->handler = handler;
	handle->description = description;
	handle->origin = "built-in";
	handle->ptr = cbase;
	return handle;
}

#define ADD_COMMAND(PREFIX, LENGTH, ARGS, CREDENTIALS, FUNCTION, DESCRIPTION) \
	command_add(cbase, add_builtin(cbase, PREFIX, ARGS, CREDENTIALS, FUNCTION, DESCRIPTION), NULL)

void commands_builtin_add(struct command_base* cbase)
{
	ADD_COMMAND("ban",        3, "n", auth_cred_operator,  command_ban,      "Ban a user"                   );
	ADD_COMMAND("broadcast",  9, "m", auth_cred_operator,  command_broadcast,"Send a message to all users"  );
#ifdef CRASH_DEBUG
	ADD_COMMAND("crash",      5, "",  auth_cred_admin,     command_crash,    "Crash the hub (DEBUG)."       );
#endif
	ADD_COMMAND("getip",      5, "n", auth_cred_operator,  command_getip,    "Show IP address for a user"   );
	ADD_COMMAND("help",       4, "?c",auth_cred_guest,     command_help,     "Show this help message."      );
	ADD_COMMAND("kick",       4, "n", auth_cred_operator,  command_kick,     "Kick a user"                  );
	ADD_COMMAND("log",        3, "",  auth_cred_operator,  command_log,      "Display log"                  );
	ADD_COMMAND("mute",       4, "n", auth_cred_operator,  command_mute,     "Mute user"                    );
	ADD_COMMAND("myip",       4, "",  auth_cred_guest,     command_myip,     "Show your own IP."            );
	ADD_COMMAND("register",   8, "p", auth_cred_guest,     command_register, "Register your username."      );
	ADD_COMMAND("reload",     6, "",  auth_cred_admin,     command_reload,   "Reload configuration files."  );
	ADD_COMMAND("password",   8, "p", auth_cred_user,      command_password, "Change your own password."    );
	ADD_COMMAND("shutdown",   8, "",  auth_cred_admin,     command_shutdown_hub, "Shutdown hub."            );
	ADD_COMMAND("stats",      5, "",  auth_cred_super,     command_stats,    "Show hub statistics."         );
	ADD_COMMAND("unban",      5, "n", auth_cred_operator,  command_unban,    "Lift ban on a user"           );
	ADD_COMMAND("unmute",     6, "n", auth_cred_operator,  command_mute,     "Unmute user"                  );
	ADD_COMMAND("uptime",     6, "",  auth_cred_guest,     command_uptime,   "Display hub uptime info."     );
	ADD_COMMAND("useradd",    7, "np",auth_cred_operator,  command_useradd,  "Register a new user."         );
	ADD_COMMAND("userdel",    7, "n", auth_cred_operator,  command_userdel,  "Delete a registered user."    );
	ADD_COMMAND("userinfo",   8, "n", auth_cred_operator,  command_userinfo, "Show registered user info."   );
	ADD_COMMAND("usermod",    7, "nC",auth_cred_admin,     command_usermod,  "Modify user credentials."     );
	ADD_COMMAND("userpass",   8, "np",auth_cred_operator,  command_userpass, "Change password for a user."  );
	ADD_COMMAND("version",    7, "",  auth_cred_guest,     command_version,  "Show hub version info."       );
	ADD_COMMAND("whoip",      5, "a", auth_cred_operator,  command_whoip,    "Show users matching IP range" );

#ifdef DEBUG_UNLOAD_PLUGINS
	ADD_COMMAND("load",       4, "",  auth_cred_admin,     command_load,     "Load plugins."                );
	ADD_COMMAND("unload",     6, "",  auth_cred_admin,     command_unload,   "Unload plugins."              );
#endif /* DEBUG_UNLOAD_PLUGINS */
}

void commands_builtin_remove(struct command_base* cbase)
{
	struct command_handle* command;
	while ((command = list_get_first(cbase->handlers)))
	{
		command_del(cbase, command);
		hub_free(command);
	}
}
