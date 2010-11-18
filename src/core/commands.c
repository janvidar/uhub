/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2010, Jan Vidar Krey
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
static int command_status_user_not_found(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd, const char* nick);
static int command_arg_mismatch(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd, struct command_handle* handler);

struct command_base
{
	struct hub_info* hub;
	struct linked_list* handlers;
};

struct command_base* command_initialize(struct hub_info* hub)
{
	struct command_base* cbase = (struct command_base*) hub_malloc(sizeof(struct command_base));
	uhub_assert(cbase != NULL);
	uhub_assert(hub != NULL);

	cbase->hub = hub;
	cbase->handlers = (struct linked_list*) list_create();

	uhub_assert(cbase->handlers != NULL);
	return cbase;
}

void command_shutdown(struct command_base* cbase)
{
	assert(list_size(cbase->handlers) == 0);
	hub_free(cbase);
}

int command_add(struct command_base* cbase, struct command_handle* cmd)
{
	uhub_assert(cbase != NULL);
	uhub_assert(cmd != NULL);
	uhub_assert(cmd->length == strlen(cmd->prefix));
	uhub_assert(cmd->handler != NULL);
	uhub_assert(cmd->description && *cmd->description);
	list_append(cbase->handlers, cmd);
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

static struct command_handle* command_find_handler(struct command_base* cbase, struct hub_user* user, const char* prefix)
{
	struct command_handle* handler = NULL;
	size_t prefix_len = strlen(prefix);

	for (handler = (struct command_handle*) list_get_first(cbase->handlers); handler; handler = (struct command_handle*) list_get_next(cbase->handlers))
	{
		if (prefix_len != handler->length)
			continue;

		if (!strncmp(prefix, handler->prefix, handler->length))
		{
			if (handler->cred <= user->credentials)
			{
				return handler;
			}
			else
			{
				command_access_denied(cbase, user, prefix);
				return NULL;
			}
		}
	}

	command_not_found(cbase, user, prefix);
	return NULL;
}

static struct linked_list* command_extract_arguments(struct command_base* cbase, struct hub_user* user, struct command_handle* command, struct linked_list* tokens)
{
	int arg = 0;
	int opt = 0;
	char* token = NULL;
	char* temp = NULL;
	struct hub_user* target = NULL;
	enum auth_credentials cred;
	struct linked_list* args = list_create();


	if (!args)
		return NULL;

	while ((token = list_get_first(tokens)))
	{
		user = NULL;
		temp = NULL;

		switch (command->args[arg++])
		{
			case '?':
				uhub_assert(opt == 0);
				opt = 1;
				break;

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
			case 'c':
				list_append(args, token);
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
static void command_parse(struct command_base* cbase, struct hub_user* user, const char* message)
{
	char* prefix;
	int n;
	struct hub_command* cmd = hub_malloc_zero(sizeof(struct hub_command));
	struct command_handle* handler = NULL;
	struct linked_list* tokens = NULL;

	if (!cmd) return;

	cmd->message = message;
	cmd->args = NULL;
	tokens = list_create();

	n = split_string(message, "\\s", tokens, 0);
	if (n <= 0)
	{
		command_destroy(cmd);
		return;
	}

	// Find a matching command handler
	prefix = list_get_first(tokens);
	if (prefix && prefix[0] && prefix[1])
	{
		cmd->prefix = hub_strdup(&prefix[1]);
		cmd->prefix_len = strlen(cmd->prefix);
		handler = command_find_handler(cbase, user, cmd->prefix);
	}
	else
	{
		command_destroy(cmd);
		return;
	}

	// Remove the first token.
	list_remove(tokens, prefix);
	hub_free(prefix);

	// Parse arguments
	cmd->args = command_extract_arguments(cbase, user, handler, tokens);
	list_clear(tokens, &hub_free);
	list_destroy(tokens);

	if (!cmd->args)
	{
		command_destroy(cmd);
		return;
	}

	handler->handler(cbase, user, cmd);
	command_destroy(cmd);
	return;
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
			if (n > 0 && !opt) strcat(args, " ");
			switch (handler->args[n])
			{
				case '?': strcat(args, "["); opt = 1; continue;
				case 'n': strcat(args, "<nick>"); break;
				case 'i': strcat(args, "<cid>");  break;
				case 'a': strcat(args, "<addr>"); break;
				case 'm': strcat(args, "<message>"); break;
				case 'p': strcat(args, "<password>"); break;
				case 'C': strcat(args, "<credentials>"); break;
				case 'c': strcat(args, "<command>"); break;
				case 'N': strcat(args, "<number>"); break;
			}
			if (opt)
			{
				strcat(args, "]");
				opt = 0;
			}
		}
	}
	return args;
}


static void send_message(struct command_base* cbase, struct hub_user* user, const char* message)
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

static int command_status_user_not_found(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd, const char* nick)
{
	char temp[128];
	snprintf(temp, 128, "*** %s: No user \"%s\"", cmd->prefix, nick);
	send_message(cbase, user, temp);
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

static int command_arg_mismatch(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd, struct command_handle* handler)
{
	char temp[256];
	const char* args = command_get_syntax(handler);
	if (args) snprintf(temp, 256, "*** %s: Use: !%s %s", cmd->prefix, cmd->prefix, args);
	else      snprintf(temp, 256, "*** %s: Use: !%s", cmd->prefix, cmd->prefix);
	send_message(cbase, user, temp);
	return 0;
}

static int command_status(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd, const char* message)
{
	char temp[1024];
	snprintf(temp, 1024, "*** %s: %s", cmd->prefix, message);
	send_message(cbase, user, temp);
	return 0;
}

int command_invoke(struct command_base* cbase, struct hub_user* user, const char* message)
{
	command_parse(cbase, user, message);
	return 0;
}




static int command_stats(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
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

static int command_help(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
#if 0
	size_t n;
	char msg[MAX_HELP_MSG];
	char* command = list_get_first(cmd->args);
	msg[0] = 0;

	if (!command)
	{
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
	}
	else
	{
		int found = 0;
		for (n = 0; command_handlers[n].prefix; n++)
		{
			if (strcmp(command, command_handlers[n].prefix) == 0)
			{
				found = 1;
				if (command_handlers[n].cred <= user->credentials)
				{
					strcat(msg, "Usage: !");
					strcat(msg, command_handlers[n].prefix);
					strcat(msg, " ");
					strcat(msg, command_get_syntax(&command_handlers[n]));
					strcat(msg, "\n");

					strcat(msg, command_handlers[n].description);
					strcat(msg, "\n");
				}
				else
				{
					strcat(msg, "This command is not available to you.\n");
				}
			}
		}

		if (!found)
		{
			sprintf(msg, "Command \"%s\" not found.\n", command);
		}
	}
	return command_status(cbase, user, cmd, msg);
#endif
	return 0;
}

static int command_uptime(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	char tmp[128];
	size_t d;
	size_t h;
	size_t m;
	size_t D = (size_t) difftime(time(0), cbase->hub->tm_started);

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

	return command_status(cbase, user, cmd, tmp);
}

static int command_kick(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
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

static int command_ban(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
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

static int command_unban(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	return command_status(cbase, user, cmd, "Not implemented");
}

static int command_mute(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
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

static int command_reload(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	cbase->hub->status = hub_status_restart;
	return command_status(cbase, user, cmd, "Reloading configuration...");
}

static int command_shutdown_hub(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	cbase->hub->status = hub_status_shutdown;
	return command_status(cbase, user, cmd, "Hub shutting down...");
}

static int command_version(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	const char* tmp;
	if (cbase->hub->config->show_banner_sys_info)
		tmp = "Powered by " PRODUCT_STRING " on " OPSYS "/" CPUINFO;
	else
		tmp = "Powered by " PRODUCT_STRING;
	return command_status(cbase, user, cmd, tmp);
}

static int command_myip(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	char tmp[128];
	snprintf(tmp, 128, "Your address is \"%s\"", user_get_address(user));
	return command_status(cbase, user, cmd, tmp);
}

static int command_getip(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
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

static int command_whoip(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	char* address = list_get_first(cmd->args);
	struct ip_range range;
	struct linked_list* users;
	struct hub_user* u;
	int ret = 0;
	char tmp[128];
	char* buffer;

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

	buffer = hub_malloc(((MAX_NICK_LEN + INET6_ADDRSTRLEN + 5) * ret) + strlen(tmp) + 3);
	if (!buffer)
	{
		list_destroy(users);
		return -1; // FIXME: OOM
	}

	buffer[0] = 0;
	strcat(buffer, tmp);
	strcat(buffer, "\n");

	u = (struct hub_user*) list_get_first(users);
	while (u)
	{
		strcat(buffer, u->id.nick);
		strcat(buffer, " (");
		strcat(buffer, user_get_address(u));
		strcat(buffer, ")\n");
		u = (struct hub_user*) list_get_next(users);
	}
	strcat(buffer, "\n");

	send_message(cbase, user, buffer);
	hub_free(buffer);
	list_destroy(users);
	return 0;
}

static int command_broadcast(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
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

static int command_history(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
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

	buffer = hub_malloc(bufsize+4);
	if (!buffer)
	{
		return command_status(cbase, user, cmd, "Not enough memory.");
	}

	buffer[0] = 0;
	strcat(buffer, tmp);
	strcat(buffer, "\n");

	message = (char*) list_get_first(messages);
	while (message)
	{
		if (--lines < 0)
			strcat(buffer, message);
		message = (char*) list_get_next(messages);
	}
	strcat(buffer, "\n");

	send_message(cbase, user, buffer);
	hub_free(buffer);
	return 0;
}

static int command_log(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
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
		sprintf(tmp, "Logged entries: " PRINTF_SIZE_T ", searching for \"%s\"", list_size(messages), search);
	}
	else
	{
		sprintf(tmp, "Logged entries: " PRINTF_SIZE_T, list_size(messages));
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
			sprintf(tmp, "* %s %s, %s [%s] - %s", get_timestamp(log->time), log->cid, log->nick, ip_convert_to_string(&log->addr), user_get_quit_reason_string(log->reason));
			send_message(cbase, user, tmp);
		}
		log = (struct hub_logout_info*) list_get_next(messages);
	}

	if (search_len)
	{
		sprintf(tmp, PRINTF_SIZE_T " entries shown.", search_hits);
		command_status(cbase, user, cmd, tmp);
	}

	return 0;
}

static int command_register(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
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
		sprintf(tmp, "User \"%s\" registered.", user->id.nick);
		return command_status(cbase, user, cmd, tmp);
	}
	else
	{
		sprintf(tmp, "Unable to register user \"%s\".", user->id.nick);
		return command_status(cbase, user, cmd, tmp);
	}
}

static int command_password(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
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
		sprintf(tmp, "Unable to change password for user \"%s\".", user->id.nick);
		return command_status(cbase, user, cmd, tmp);
	}
}

static int command_useradd(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
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
		sprintf(tmp, "User \"%s\" registered.", nick);
		return command_status(cbase, user, cmd, tmp);
	}
	else
	{
		sprintf(tmp, "Unable to register user \"%s\".", nick);
		return command_status(cbase, user, cmd, tmp);
	}
}

static int command_userdel(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	char tmp[1024];
	char* nick = list_get_first(cmd->args);

	if (acl_delete_user(cbase->hub, nick))
	{
		sprintf(tmp, "User \"%s\" is deleted.", nick);
		return command_status(cbase, user, cmd, tmp);
	}
	else
	{
		sprintf(tmp, "Unable to delete user \"%s\".", nick);
		return command_status(cbase, user, cmd, tmp);
	}
}

static int command_usermod(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	return command_status(cbase, user, cmd, "Not implemented!");
}

static int command_userinfo(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	return command_status(cbase, user, cmd, "Not implemented!");
}

static int command_userpass(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	return command_status(cbase, user, cmd, "Not implemented!");
}

static int command_rules(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	if (!hub_send_rules(cbase->hub, user))
		return command_status(cbase, user, cmd, "no rules defined.");
	return 0;
}

static int command_motd(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	if (!hub_send_motd(cbase->hub, user))
		return command_status(cbase, user, cmd, "no motd defined.");
	return 0;
}

#ifdef CRASH_DEBUG
static int command_crash(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	void (*crash)(void) = NULL;
	crash();
	return 0;
}
#endif

#if 0
int command_dipatcher(struct hub_info* hub, struct hub_user* user, const char* message)
{
	size_t n = 0;
	int rc;

	/* Parse and validate the command */
	struct hub_command* cmd = command_create(message);
	if (!cmd) return 0;

	for (n = 0; command_handlers[n].prefix; n++)
	{
		struct commands_handler* handler = &command_handlers[n];
		if (cmd->prefix_len != handler->length)
			continue;

		if (!strncmp(cmd->prefix, handler->prefix, handler->length))
		{
			if (handler->cred <= user->credentials)
			{
				if (command_check_args(cmd, handler))
				{
					rc = handler->handler(hub, user, cmd);
				}
				else
				{
					rc = command_arg_mismatch(hub, user, cmd, handler);
				}
				command_destroy(cmd);
				return rc;
			}
			else
			{
				rc = command_access_denied(hub, user, cmd);
				command_destroy(cmd);
				return rc;
			}
		}
	}

	command_not_found(hub, user, cmd);
	command_destroy(cmd);
	return 0;
}
#endif
