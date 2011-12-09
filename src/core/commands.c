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

#ifdef DEBUG
#define CRASH_DEBUG
#endif

#define MAX_HELP_MSG 1024

static int command_access_denied(struct command_base* cbase, struct hub_user* user, const char* prefix);
static int command_not_found(struct command_base* cbase, struct hub_user* user, const char* prefix);
static int command_syntax_error(struct command_base* cbase, struct hub_user* user);

static size_t str_append(char* dst, const char* buf, size_t size)
{
	size_t dst_len = strlen(dst);
	size_t buf_len = strlen(buf);

	if (dst_len + buf_len >= size)
		return dst_len + buf_len;

	memcpy(dst + dst_len, buf, buf_len);
	dst[dst_len + buf_len] = '\0';
	return dst_len + buf_len;
}

struct command_base
{
	struct hub_info* hub;
	struct linked_list* handlers;
	size_t prefix_length_max;
};

struct command_base* command_initialize(struct hub_info* hub)
{
	struct command_base* cbase = (struct command_base*) hub_malloc(sizeof(struct command_base));
	uhub_assert(cbase != NULL);
	uhub_assert(hub != NULL);

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

/**
 * Destroy / free a command created by command_create().
 */
static void command_destroy(struct hub_command* cmd)
{
	if (!cmd) return;
	hub_free(cmd->prefix);

	if (cmd->args)
	{
		list_clear(cmd->args, &hub_free);
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

		if (!strncmp(prefix, handler->prefix, handler->length))
		{
			return handler;
		}
	}
	return NULL;
}

static struct linked_list* command_extract_arguments(struct command_base* cbase, struct command_handle* command, struct linked_list* tokens)
{
	int arg = 0;
	int opt = 0;
	char* token = NULL;
	struct hub_user* target = NULL;
	struct command_handle* target_command = NULL;
	enum auth_credentials cred;
	struct linked_list* args = list_create();


	if (!args)
		return NULL;

	while ((token = list_get_first(tokens)))
	{
		switch (command->args[arg++])
		{
			case '?':
				uhub_assert(opt == 0);
				opt = 1;
				continue;

			case 'n':
				target = uman_get_user_by_nick(cbase->hub, token);
				if (!target)
				{
					list_destroy(args);
					return NULL;
				}
				list_append(args, target);
				break;

			case 'i':
				uman_get_user_by_cid(cbase->hub, token);
				if (!target)
				{
					list_destroy(args);
					return NULL;
				}
				list_append(args, target);
				break;

			case 'a':
				if (!(ip_is_valid_ipv4(token) || ip_is_valid_ipv6(token)))
				{
					list_destroy(args);
					return NULL;
				}
				list_append(args, token);
				break;

			case 'm':
			case 'p':
				list_append(args, token);
				break;

			case 'c':
				target_command = command_handler_lookup(cbase, token);
				if (!target_command)
				{
					list_destroy(args);
					return NULL;
				}
				list_append(args, target_command);
				break;

			case 'C':
				if (!auth_string_to_cred(token, &cred))
				{
					list_destroy(args);
					return NULL;
				}
				list_append(args, (void*) cred);
				break;

			case 'N':
				list_append(args, (void*) (int*) (intptr_t) uhub_atoi(token));
				break;

			case '\0':
				if (!opt)
				{
					list_destroy(args);
					return NULL;
				}
				return args;
		}
		list_remove(tokens, token);
	}

	return args;
}

/**
 * Parse a command and break it down into a struct hub_command.
 */
static int command_parse(struct command_base* cbase, struct hub_user* user, const char* message)
{
	char* prefix;
	int n;
	int ret;
	struct hub_command* cmd = hub_malloc_zero(sizeof(struct hub_command));
	struct command_handle* handler = NULL;
	struct linked_list* tokens = NULL;

	if (!cmd) return 0;

	cmd->message = message;
	cmd->args = NULL;
	tokens = list_create();

	n = split_string(message, "\\s", tokens, 0);
	if (n <= 0)
	{
		ret = 0; // FIXME
		goto command_parse_cleanup;
	}

	// Find a matching command handler
	prefix = list_get_first(tokens);
	if (prefix && prefix[0] && prefix[1])
	{
		cmd->prefix = hub_strdup(&prefix[1]);
		cmd->prefix_len = strlen(cmd->prefix);
		handler = command_handler_lookup(cbase, cmd->prefix);
		if (!handler)
		{
			ret = command_not_found(cbase, user, prefix);
			goto command_parse_cleanup;
		}
	}
	else
	{
		ret = command_syntax_error(cbase, user);
		goto command_parse_cleanup;
	}

	// Remove the first token.
	list_remove(tokens, prefix);
	hub_free(prefix);

	// Parse arguments
	cmd->args = command_extract_arguments(cbase, handler, tokens);

	if (!cmd->args)
	{
		ret = 0;
		goto command_parse_cleanup;
	}

	if (command_is_available(handler, user))
	{
		handler->handler(cbase, user, handler, cmd);
		ret = 0;
		goto command_parse_cleanup;
	}
	else
	{
		ret = command_access_denied(cbase, user, prefix);
		goto command_parse_cleanup;
	}

command_parse_cleanup:
	command_destroy(cmd);
	list_clear(tokens, &hub_free);
	list_destroy(tokens);
	return ret;
}

const char* command_get_syntax(struct command_handle* handler)
{
	static char args[128];
	size_t n = 0;
	int opt = 0;
	args[0] = 0;
	if (handler->args)
	{
		for (n = 0; n < strlen(handler->args); n++)
		{
			if (n > 0 && !opt) str_append(args, " ", sizeof(args));
			switch (handler->args[n])
			{
				case '?': str_append(args, "[", sizeof(args)); opt = 1; continue;
				case 'n': str_append(args, "<nick>", sizeof(args)); break;
				case 'i': str_append(args, "<cid>", sizeof(args));  break;
				case 'a': str_append(args, "<addr>", sizeof(args)); break;
				case 'm': str_append(args, "<message>", sizeof(args)); break;
				case 'p': str_append(args, "<password>", sizeof(args)); break;
				case 'C': str_append(args, "<credentials>", sizeof(args)); break;
				case 'c': str_append(args, "<command>", sizeof(args)); break;
				case 'N': str_append(args, "<number>", sizeof(args)); break;
			}
			if (opt)
			{
				str_append(args, "]", sizeof(args));
				opt = 0;
			}
		}
	}
	return args;
}


void send_message(struct command_base* cbase, struct hub_user* user, const char* message)
{
	char* buffer = adc_msg_escape(message);
	struct adc_message* command = adc_msg_construct(ADC_CMD_IMSG, strlen(buffer) + 6);
	adc_msg_add_argument(command, buffer);
	route_to_user(cbase->hub, user, command);
	adc_msg_free(command);
	hub_free(buffer);
}

static int command_access_denied(struct command_base* cbase, struct hub_user* user, const char* prefix)
{
	char temp[128];
	snprintf(temp, 128, "*** %s: Access denied.", prefix);
	send_message(cbase, user, temp);
	return 0;
}

static int command_not_found(struct command_base* cbase, struct hub_user* user, const char* prefix)
{
	char temp[128];
	snprintf(temp, 128, "*** %s: Command not found", prefix);
	send_message(cbase, user, temp);
	return 0;
}


static int command_syntax_error(struct command_base* cbase, struct hub_user* user)
{
	send_message(cbase, user, "*** Syntax error");
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
	return command_parse(cbase, user, message);
}

int command_is_available(struct command_handle* handle, struct hub_user* user)
{
	uhub_assert(handle != NULL);
	uhub_assert(user != NULL);
	return handle->cred <= user->credentials;
}


static int command_status(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd, const char* message)
{
	char temp[1024];
	snprintf(temp, 1024, "*** %s: %s", cmd->prefix, message);
	send_message(cbase, user, temp);
	return 0;
}

static int command_status_user_not_found(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd, const char* nick)
{
	char temp[128];
	snprintf(temp, 128, "*** %s: No user \"%s\"", cmd->prefix, nick);
	send_message(cbase, user, temp);
	return 0;
}

static int command_help(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	char msg[MAX_HELP_MSG];
	struct command_handle* command = list_get_first(cmd->args);
	size_t n = 0;
	msg[0] = 0;

	if (!command)
	{
		n += snprintf(msg, sizeof(msg), "Available commands:\n");

		for (command = (struct command_handle*) list_get_first(cbase->handlers); command; command = (struct command_handle*) list_get_next(cbase->handlers))
		{
			if (command_is_available(command, user))
			{
				n += snprintf(msg + n, sizeof(msg) - n, "!%s%20s- %s\n", command->prefix, " ", command->description);
			}
		}
	}
	else
	{
		if (command_is_available(command, user))
		{
			snprintf(msg, sizeof(msg), "Usage: !%s %s\n%s\n", command->prefix, command_get_syntax(command), command->description);
		}
		else
		{
			snprintf(msg, sizeof(msg), "This command is not available to you.\n");
		}
	}
	return command_status(cbase, user, cmd, msg);
}

static int command_uptime(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	char tmp[128];
	size_t d;
	size_t h;
	size_t m;
	size_t D = (size_t) difftime(time(0), cbase->hub->tm_started);
	size_t offset = 0;

	d = D / (24 * 3600);
	D = D % (24 * 3600);
	h = D / 3600;
	D = D % 3600;
	m = D / 60;

	tmp[0] = 0;
	if (d)
		offset += snprintf(tmp, sizeof(tmp), "%d day%s, ", (int) d, d != 1 ? "s" : "");
	snprintf(tmp + offset, sizeof(tmp) - offset, "%02d:%02d", (int) h, (int) m);
	return command_status(cbase, user, cmd, tmp);
}

static int command_kick(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	char* nick = list_get_first(cmd->args);
	struct hub_user* target;
	if (!nick)
		return -1; // FIXME: bad syntax.

	target = uman_get_user_by_nick(cbase->hub, nick);
	
	if (!target)
		return command_status_user_not_found(cbase, user, cmd, nick);
	
	if (target == user)
		return command_status(cbase, user, cmd, "Cannot kick yourself");
	
	hub_disconnect_user(cbase->hub, target, quit_kicked);
	return command_status(cbase, user, cmd, nick);
}

static int command_ban(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	char* nick = list_get_first(cmd->args);
	struct hub_user* target;
	if (!nick)
		return -1; // FIXME: bad syntax.

	target = uman_get_user_by_nick(cbase->hub, nick);

	if (!target)
		return command_status_user_not_found(cbase, user, cmd, nick);

	if (target == user)
		return command_status(cbase, user, cmd, "Cannot kick/ban yourself");

	hub_disconnect_user(cbase->hub, target, quit_kicked);
	acl_user_ban_nick(cbase->hub->acl, target->id.nick);
	acl_user_ban_cid(cbase->hub->acl, target->id.cid);

	return command_status(cbase, user, cmd, nick);
}

static int command_unban(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	return command_status(cbase, user, cmd, "Not implemented");
}

static int command_mute(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	char* nick = list_get_first(cmd->args);
	struct hub_user* target;
	if (!nick)
		return -1; // FIXME: bad syntax.

	target = uman_get_user_by_nick(cbase->hub, nick);

	if (!target)
		return command_status_user_not_found(cbase, user, cmd, nick);

	if (strlen(cmd->prefix) == 4)
	{
		user_flag_set(target, flag_muted);
	}
	else
	{
		user_flag_unset(target, flag_muted);
	}
	return command_status(cbase, user, cmd, nick);
}

static int command_reload(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	cbase->hub->status = hub_status_restart;
	return command_status(cbase, user, cmd, "Reloading configuration...");
}

static int command_shutdown_hub(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	cbase->hub->status = hub_status_shutdown;
	return command_status(cbase, user, cmd, "Hub shutting down...");
}

static int command_version(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	const char* tmp;
	if (cbase->hub->config->show_banner_sys_info)
		tmp = "Powered by " PRODUCT_STRING " on " OPSYS "/" CPUINFO;
	else
		tmp = "Powered by " PRODUCT_STRING;
	return command_status(cbase, user, cmd, tmp);
}

static int command_myip(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	char tmp[128];
	snprintf(tmp, 128, "Your address is \"%s\"", user_get_address(user));
	return command_status(cbase, user, cmd, tmp);
}

static int command_getip(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	char tmp[128];
	char* nick = list_get_first(cmd->args);
	struct hub_user* target;

	if (!nick)
		return -1; // FIXME: bad syntax/OOM

	target = uman_get_user_by_nick(cbase->hub, nick);

	if (!target)
		return command_status_user_not_found(cbase, user, cmd, nick);

	snprintf(tmp, 128, "%s has address \"%s\"", nick, user_get_address(target));
	return command_status(cbase, user, cmd, tmp);
}

static int command_whoip(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	char* address = list_get_first(cmd->args);
	struct ip_range range;
	struct linked_list* users;
	struct hub_user* u;
	int ret = 0;
	char tmp[128];
	char* buffer;
	size_t length;

	if (!address)
		return -1; // FIXME: bad syntax.

	ret = ip_convert_address_to_range(address, &range);
	if (!ret)
		return command_status(cbase, user, cmd, "Invalid IP address/range/mask");

	users = (struct linked_list*) list_create();
	if (!users)
		return -1; // FIXME: OOM

	ret = uman_get_user_by_addr(cbase->hub, users, &range);

	if (!ret)
	{
		list_destroy(users);
		return command_status(cbase, user, cmd, "No users found.");
	}

	snprintf(tmp, 128, "*** %s: Found %d match%s:", cmd->prefix, ret, ((ret != 1) ? "es" : ""));

	length = ((MAX_NICK_LEN + INET6_ADDRSTRLEN + 5) * ret) + strlen(tmp) + 3;
	buffer = hub_malloc(length);
	if (!buffer)
	{
		list_destroy(users);
		return -1; // FIXME: OOM
	}

	buffer[0] = 0;
	str_append(buffer, tmp, length);
	str_append(buffer, "\n", length);

	u = (struct hub_user*) list_get_first(users);
	while (u)
	{
		str_append(buffer, u->id.nick, length);
		str_append(buffer, " (", length);
		str_append(buffer, user_get_address(u), length);
		str_append(buffer, ")\n", length);
		u = (struct hub_user*) list_get_next(users);
	}
	str_append(buffer, "\n", length);

	send_message(cbase, user, buffer);
	hub_free(buffer);
	list_destroy(users);
	return 0;
}

static int command_broadcast(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	size_t offset = 12;
#if USE_OLD_BROADCAST_STYLE
	struct adc_message* command = adc_msg_construct(ADC_CMD_IMSG, strlen((cmd->message + offset)) + 6);
	adc_msg_add_argument(command, (cmd->message + offset));
	route_to_all(hub, command);
	adc_msg_free(command);
	return 0;
#else
	size_t message_len = strlen(cmd->message + offset);
	struct adc_message* command = 0;
	char pm_flag[7] = "PM";
	char from_sid[5];
	char buffer[128];
	size_t recipients = 0;
	struct hub_user* target;

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
			adc_msg_add_argument(command, (cmd->message + offset));
			adc_msg_add_argument(command, pm_flag);

			route_to_user(cbase->hub, target, command);
			adc_msg_free(command);
		}
		target = (struct hub_user*) list_get_next(cbase->hub->users->list);
	}

	snprintf(buffer, sizeof(buffer), "*** %s: Delivered to " PRINTF_SIZE_T " user%s", cmd->prefix, recipients, (recipients != 1 ? "s" : ""));
	send_message(cbase, user, buffer);
	return 0;
#endif
}

static int command_history(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	char* buffer;
	struct linked_list* messages = cbase->hub->chat_history;
	char* message = 0;
	int ret = (int) list_size(messages);
	size_t bufsize;
	char tmp[128];
	char* maxlines_str = list_get_first(cmd->args);
	int maxlines = 0;
	int lines = 0;

	if (!ret)
	{
		return command_status(cbase, user, cmd, "No messages.");
	}

	if (maxlines_str)
		maxlines = uhub_atoi(maxlines_str);

	if (maxlines <= 0 || maxlines > ret)
		maxlines = ret;

	if (maxlines != ret)
	{
		lines = ret - maxlines;
		snprintf(tmp, 128, "*** %s: Displaying %d of %d message%s:", cmd->prefix, maxlines, ret, ((ret != 1) ? "s" : ""));
	}
	else
	{
		snprintf(tmp, 128, "*** %s: Found %d message%s:", cmd->prefix, ret, ((ret != 1) ? "s" : ""));
	}

	bufsize = strlen(tmp);
	message = (char*) list_get_first(messages);
	while (message)
	{
		bufsize += strlen(message);
		message = (char*) list_get_next(messages);
	}

	bufsize += 4;
	buffer = hub_malloc(bufsize);
	if (!buffer)
	{
		return command_status(cbase, user, cmd, "Not enough memory.");
	}

	buffer[0] = 0;
	str_append(buffer, tmp, bufsize);
	str_append(buffer, "\n", bufsize);

	message = (char*) list_get_first(messages);
	while (message)
	{
		if (--lines < 0)
			str_append(buffer, message, bufsize);
		message = (char*) list_get_next(messages);
	}
	str_append(buffer, "\n", bufsize);

	send_message(cbase, user, buffer);
	hub_free(buffer);
	return 0;
}

static int command_log(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	struct linked_list* messages = cbase->hub->logout_info;
	struct hub_logout_info* log;
	char tmp[1024];
	char* search = 0;
	size_t search_len = 0;
	size_t search_hits = 0;

	if (!list_size(messages))
	{
		return command_status(cbase, user, cmd, "No entries logged.");
	}

	search = list_get_first(cmd->args);
	if (search)
	{
		search_len = strlen(search);
	}

	if (search_len)
	{
		snprintf(tmp, sizeof(tmp), "Logged entries: " PRINTF_SIZE_T ", searching for \"%s\"", list_size(messages), search);
	}
	else
	{
		snprintf(tmp, sizeof(tmp), "Logged entries: " PRINTF_SIZE_T, list_size(messages));
	}
	command_status(cbase, user, cmd, tmp);

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
			snprintf(tmp, sizeof(tmp), "* %s %s, %s [%s] - %s", get_timestamp(log->time), log->cid, log->nick, ip_convert_to_string(&log->addr), user_get_quit_reason_string(log->reason));
			send_message(cbase, user, tmp);
		}
		log = (struct hub_logout_info*) list_get_next(messages);
	}

	if (search_len)
	{
		snprintf(tmp, sizeof(tmp), PRINTF_SIZE_T " entries shown.", search_hits);
		command_status(cbase, user, cmd, tmp);
	}

	return 0;
}

static int command_register(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	struct auth_info data;
	char tmp[1024];
	char* password = list_get_first(cmd->args);

	strncpy(data.nickname, user->id.nick, MAX_NICK_LEN);
	strncpy(data.password, password, MAX_PASS_LEN);
	data.nickname[MAX_NICK_LEN] = '\0';
	data.password[MAX_PASS_LEN] = '\0';
	data.credentials = auth_cred_user;

	if (acl_register_user(cbase->hub, &data))
	{
		snprintf(tmp, sizeof(tmp), "User \"%s\" registered.", user->id.nick);
		return command_status(cbase, user, cmd, tmp);
	}
	else
	{
		snprintf(tmp, sizeof(tmp), "Unable to register user \"%s\".", user->id.nick);
		return command_status(cbase, user, cmd, tmp);
	}
}

static int command_password(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	struct auth_info data;
	char tmp[1024];
	char* password = list_get_first(cmd->args);

	strncpy(data.nickname, user->id.nick, MAX_NICK_LEN);
	strncpy(data.password, password, MAX_PASS_LEN);
	data.nickname[MAX_NICK_LEN] = '\0';
	data.password[MAX_PASS_LEN] = '\0';
	data.credentials = user->credentials;

	if (acl_update_user(cbase->hub, &data))
	{
		return command_status(cbase, user, cmd, "Password changed.");
	}
	else
	{
		snprintf(tmp, sizeof(tmp), "Unable to change password for user \"%s\".", user->id.nick);
		return command_status(cbase, user, cmd, tmp);
	}
}

static int command_useradd(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	struct auth_info data;
	char tmp[1024];
	char* nick = list_get_first(cmd->args);
	char* pass = list_get_next(cmd->args);
	char* cred = list_get_next(cmd->args);
	enum auth_credentials credentials;

	if (!(cred && auth_string_to_cred(cred, &credentials)))
	{
		credentials = auth_cred_user;
	}

	strncpy(data.nickname, nick, MAX_NICK_LEN);
	strncpy(data.password, pass, MAX_PASS_LEN);
	data.nickname[MAX_NICK_LEN] = '\0';
	data.password[MAX_PASS_LEN] = '\0';
	data.credentials = credentials;

	if (acl_register_user(cbase->hub, &data))
	{
		snprintf(tmp, sizeof(tmp), "User \"%s\" registered.", nick);
		return command_status(cbase, user, cmd, tmp);
	}
	else
	{
		snprintf(tmp, sizeof(tmp), "Unable to register user \"%s\".", nick);
		return command_status(cbase, user, cmd, tmp);
	}
}

static int command_userdel(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	char tmp[1024];
	char* nick = list_get_first(cmd->args);

	if (acl_delete_user(cbase->hub, nick))
	{
		snprintf(tmp, sizeof(tmp), "User \"%s\" is deleted.", nick);
		return command_status(cbase, user, cmd, tmp);
	}
	else
	{
		snprintf(tmp, sizeof(tmp), "Unable to delete user \"%s\".", nick);
		return command_status(cbase, user, cmd, tmp);
	}
}

static int command_usermod(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	return command_status(cbase, user, cmd, "Not implemented!");
}

static int command_userinfo(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	return command_status(cbase, user, cmd, "Not implemented!");
}

static int command_userpass(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	return command_status(cbase, user, cmd, "Not implemented!");
}

static int command_rules(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	if (!hub_send_rules(cbase->hub, user))
		return command_status(cbase, user, cmd, "no rules defined.");
	return 0;
}

static int command_motd(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	if (!hub_send_motd(cbase->hub, user))
		return command_status(cbase, user, cmd, "no motd defined.");
	return 0;
}

#ifdef CRASH_DEBUG
static int command_crash(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	void (*crash)(void) = NULL;
	crash();
	return 0;
}
#endif

static int command_stats(struct command_base* cbase, struct hub_user* user, struct command_handle* handle, struct hub_command* cmd)
{
	char temp[128];
	struct hub_info* hub = cbase->hub;

	snprintf(temp, 128, PRINTF_SIZE_T " users, peak: " PRINTF_SIZE_T ". Network (up/down): %d/%d KB/s, peak: %d/%d KB/s",
	hub->users->count,
	hub->users->count_peak,
	(int) hub->stats.net_tx / 1024,
	(int) hub->stats.net_rx / 1024,
	(int) hub->stats.net_tx_peak / 1024,
	(int) hub->stats.net_rx_peak / 1024);
	return command_status(cbase, user, cmd, temp);
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
	ADD_COMMAND("crash",      5, 0,   auth_cred_admin,     command_crash,    "Crash the hub (DEBUG)."       );
#endif
	ADD_COMMAND("getip",      5, "n", auth_cred_operator,  command_getip,    "Show IP address for a user"   );
	ADD_COMMAND("help",       4, "?c",auth_cred_guest,     command_help,     "Show this help message."      );
	ADD_COMMAND("history",    7, "?N",auth_cred_guest,     command_history,  "Show the last chat messages." );
	ADD_COMMAND("kick",       4, "n", auth_cred_operator,  command_kick,     "Kick a user"                  );
	ADD_COMMAND("log",        3, 0,   auth_cred_operator,  command_log,      "Display log"                  );
	ADD_COMMAND("motd",       4, 0,   auth_cred_guest,     command_motd,     "Show the message of the day"  );
	ADD_COMMAND("mute",       4, "n", auth_cred_operator,  command_mute,     "Mute user"                    );
	ADD_COMMAND("myip",       4, 0,   auth_cred_guest,     command_myip,     "Show your own IP."            );
	ADD_COMMAND("register",   8, "p", auth_cred_guest,     command_register, "Register your username."      );
	ADD_COMMAND("reload",     6, 0,   auth_cred_admin,     command_reload,   "Reload configuration files."  );
	ADD_COMMAND("rules",      5, 0,   auth_cred_guest,     command_rules,    "Show the hub rules"           );
	ADD_COMMAND("password",   8, "p", auth_cred_user,      command_password, "Change your own password."    );
	ADD_COMMAND("shutdown",   8, 0,   auth_cred_admin,     command_shutdown_hub, "Shutdown hub."                );
	ADD_COMMAND("stats",      5, 0,   auth_cred_super,     command_stats,    "Show hub statistics."         );
	ADD_COMMAND("unban",      5, "n", auth_cred_operator,  command_unban,    "Lift ban on a user"           );
	ADD_COMMAND("unmute",     6, "n", auth_cred_operator,  command_mute,     "Unmute user"                  );
	ADD_COMMAND("uptime",     6, 0,   auth_cred_guest,     command_uptime,   "Display hub uptime info."     );
	ADD_COMMAND("useradd",    7, "np",auth_cred_operator,  command_useradd,  "Register a new user."         );
	ADD_COMMAND("userdel",    7, "n", auth_cred_operator,  command_userdel,  "Delete a registered user."    );
	ADD_COMMAND("userinfo",   8, "n", auth_cred_operator,  command_userinfo, "Show registered user info."   );
	ADD_COMMAND("usermod",    7, "nC",auth_cred_admin,     command_usermod,  "Modify user credentials."     );
	ADD_COMMAND("userpass",   8, "np",auth_cred_operator,  command_userpass, "Change password for a user."  );
	ADD_COMMAND("version",    7, 0,   auth_cred_guest,     command_version,  "Show hub version info."       );
	ADD_COMMAND("whoip",      5, "a", auth_cred_operator,  command_whoip,    "Show users matching IP range" );
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
