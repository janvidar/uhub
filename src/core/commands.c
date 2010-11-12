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

struct hub_command
{
	const char* message;
	char* prefix;
	size_t prefix_len;
	struct linked_list* args;
};

typedef int (*command_handler)(struct hub_info* hub, struct hub_user* user, struct hub_command*);

struct commands_handler
{
	const char* prefix;
	size_t length;
	const char* args;
	enum auth_credentials cred;
	command_handler handler;
	const char* description;
};

static struct commands_handler command_handlers[];

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

static struct hub_command* command_create(const char* message)
{
	char* prefix;
	int n;
	struct hub_command* cmd = hub_malloc_zero(sizeof(struct hub_command));

	if (!cmd) return 0;

	cmd->message = message;
	cmd->args = list_create();

	n = split_string(message, "\\s", cmd->args, 0);
	if (n <= 0)
	{
		command_destroy(cmd);
		return 0;
	}

	prefix = list_get_first(cmd->args);
	if (prefix && prefix[0] && prefix[1])
	{
		cmd->prefix = hub_strdup(&prefix[1]);
		cmd->prefix_len = strlen(cmd->prefix);
	}
	else
	{
		command_destroy(cmd);
		return 0;
	}
	list_remove(cmd->args, prefix);
	hub_free(prefix);
	return cmd;
}

static void send_message(struct hub_info* hub, struct hub_user* user, const char* message)
{
	char* buffer = adc_msg_escape(message);
	struct adc_message* command = adc_msg_construct(ADC_CMD_IMSG, strlen(buffer) + 6);
	adc_msg_add_argument(command, buffer);
	route_to_user(hub, user, command);
	adc_msg_free(command);
	hub_free(buffer);
}

static int command_access_denied(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	char temp[128];
	snprintf(temp, 128, "*** %s: Access denied.", cmd->prefix);
	send_message(hub, user, temp);
	return 0;
}

static int command_not_found(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	char temp[128];
	snprintf(temp, 128, "*** %s: Command not found", cmd->prefix);
	send_message(hub, user, temp);
	return 0;
}

static int command_status_user_not_found(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd, const char* nick)
{
	char temp[128];
	snprintf(temp, 128, "*** %s: No user \"%s\"", cmd->prefix, nick);
	send_message(hub, user, temp);
	return 0;
}

const char* command_get_syntax(struct commands_handler* handler)
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

static size_t command_count_required_args(struct commands_handler* handler)
{
	size_t n = 0;
	for (n = 0; n < strlen(handler->args); n++)
	{
		if (handler->args[n] == '?')
			break;
	}
	return n;
}

int command_check_args(struct hub_command* cmd, struct commands_handler* handler)
{
	if (!handler->args)
		return 1;

	if (list_size(cmd->args) >= command_count_required_args(handler))
		return 1;

	return 0;
}

static int command_arg_mismatch(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd, struct commands_handler* handler)
{
	char temp[256];
	const char* args = command_get_syntax(handler);
	if (args) snprintf(temp, 256, "*** %s: Use: !%s %s", cmd->prefix, cmd->prefix, args);
	else      snprintf(temp, 256, "*** %s: Use: !%s", cmd->prefix, cmd->prefix);
	send_message(hub, user, temp);
	return 0;
}

static int command_status(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd, const char* message)
{
	char temp[1024];
	snprintf(temp, 1024, "*** %s: %s", cmd->prefix, message);
	send_message(hub, user, temp);
	return 0;
}

static int command_stats(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	char temp[128];
	snprintf(temp, 128, PRINTF_SIZE_T " users, peak: " PRINTF_SIZE_T ". Network (up/down): %d/%d KB/s, peak: %d/%d KB/s",
	hub->users->count,
	hub->users->count_peak,
	(int) hub->stats.net_tx / 1024,
	(int) hub->stats.net_rx / 1024,
	(int) hub->stats.net_tx_peak / 1024,
	(int) hub->stats.net_rx_peak / 1024);
	return command_status(hub, user, cmd, temp);
}

static int command_help(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	size_t n;
	char msg[MAX_HELP_MSG];
	msg[0] = 0;
	char* command = list_get_first(cmd->args);

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
	return command_status(hub, user, cmd, msg);
}

static int command_uptime(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	char tmp[128];
	size_t d;
	size_t h;
	size_t m;
	size_t D = (size_t) difftime(time(0), hub->tm_started);

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

	return command_status(hub, user, cmd, tmp);
}

static int command_kick(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	char* nick = list_get_first(cmd->args);
	struct hub_user* target;
	if (!nick)
		return -1; // FIXME: bad syntax.

	target = uman_get_user_by_nick(hub, nick);
	
	if (!target)
		return command_status_user_not_found(hub, user, cmd, nick);
	
	if (target == user)
		return command_status(hub, user, cmd, "Cannot kick yourself");
	
	hub_disconnect_user(hub, target, quit_kicked);
	return command_status(hub, user, cmd, nick);
}

static int command_ban(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	char* nick = list_get_first(cmd->args);
	struct hub_user* target;
	if (!nick)
		return -1; // FIXME: bad syntax.

	target = uman_get_user_by_nick(hub, nick);

	if (!target)
		return command_status_user_not_found(hub, user, cmd, nick);

	if (target == user)
		return command_status(hub, user, cmd, "Cannot kick/ban yourself");

	hub_disconnect_user(hub, target, quit_kicked);
	acl_user_ban_nick(hub->acl, target->id.nick);
	acl_user_ban_cid(hub->acl, target->id.cid);

	return command_status(hub, user, cmd, nick);
}

static int command_unban(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	return command_status(hub, user, cmd, "Not implemented");
}

static int command_mute(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	char* nick = list_get_first(cmd->args);
	struct hub_user* target;
	if (!nick)
		return -1; // FIXME: bad syntax.

	target = uman_get_user_by_nick(hub, nick);

	if (!target)
		return command_status_user_not_found(hub, user, cmd, nick);

	if (strlen(cmd->prefix) == 4)
	{
		user_flag_set(target, flag_muted);
	}
	else
	{
		user_flag_unset(target, flag_muted);
	}
	return command_status(hub, user, cmd, nick);
}

static int command_reload(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	hub->status = hub_status_restart;
	return command_status(hub, user, cmd, "Reloading configuration...");
}

static int command_shutdown(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	hub->status = hub_status_shutdown;
	return command_status(hub, user, cmd, "Hub shutting down...");
}

static int command_version(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	const char* tmp;
	if (hub->config->show_banner_sys_info)
		tmp = "Powered by " PRODUCT_STRING " on " OPSYS "/" CPUINFO;
	else
		tmp = "Powered by " PRODUCT_STRING;
	return command_status(hub, user, cmd, tmp);
}

static int command_myip(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	char tmp[128];
	snprintf(tmp, 128, "Your address is \"%s\"", user_get_address(user));
	return command_status(hub, user, cmd, tmp);
}

static int command_getip(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	char tmp[128];
	char* nick = list_get_first(cmd->args);
	struct hub_user* target;

	if (!nick)
		return -1; // FIXME: bad syntax/OOM

	target = uman_get_user_by_nick(hub, nick);

	if (!target)
		return command_status_user_not_found(hub, user, cmd, nick);

	snprintf(tmp, 128, "%s has address \"%s\"", nick, user_get_address(target));
	return command_status(hub, user, cmd, tmp);
}

static int command_whoip(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
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
		return command_status(hub, user, cmd, "Invalid IP address/range/mask");

	users = (struct linked_list*) list_create();
	if (!users)
		return -1; // FIXME: OOM

	ret = uman_get_user_by_addr(hub, users, &range);

	if (!ret)
	{
		list_destroy(users);
		return command_status(hub, user, cmd, "No users found.");
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

	send_message(hub, user, buffer);
	hub_free(buffer);
	list_destroy(users);
	return 0;
}

static int command_broadcast(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
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

	memcpy(from_sid, sid_to_string(user->id.sid), sizeof(from_sid));
	memcpy(pm_flag + 2, from_sid, sizeof(from_sid));

	struct hub_user* target = (struct hub_user*) list_get_first(hub->users->list);
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

			route_to_user(hub, target, command);
			adc_msg_free(command);
		}
		target = (struct hub_user*) list_get_next(hub->users->list);
	}

	snprintf(buffer, sizeof(buffer), "*** %s: Delivered to " PRINTF_SIZE_T " user%s", cmd->prefix, recipients, (recipients != 1 ? "s" : ""));
	send_message(hub, user, buffer);
	return 0;
#endif
}

static int command_history(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	char* buffer;
	struct linked_list* messages = hub->chat_history;
	char* message = 0;
	int ret = (int) list_size(messages);
	size_t bufsize;
	char tmp[128];
	char* maxlines_str = list_get_first(cmd->args);
	int maxlines = 0;
	int lines = 0;

	if (!ret)
	{
		return command_status(hub, user, cmd, "No messages.");
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
		return command_status(hub, user, cmd, "Not enough memory.");
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

	send_message(hub, user, buffer);
	hub_free(buffer);
	return 0;
}

static int command_log(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	struct linked_list* messages = hub->logout_info;
	struct hub_logout_info* log;
	char tmp[1024];
	char* search = 0;
	size_t search_len = 0;
	size_t search_hits = 0;

	if (!list_size(messages))
	{
		return command_status(hub, user, cmd, "No entries logged.");
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
	command_status(hub, user, cmd, tmp);

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
			send_message(hub, user, tmp);
		}
		log = (struct hub_logout_info*) list_get_next(messages);
	}

	if (search_len)
	{
		sprintf(tmp, PRINTF_SIZE_T " entries shown.", search_hits);
		command_status(hub, user, cmd, tmp);
	}

	return 0;
}

static int command_register(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	struct auth_info data;
	char tmp[1024];
	char* password = list_get_first(cmd->args);

	strncpy(data.nickname, user->id.nick, MAX_NICK_LEN);
	strncpy(data.password, password, MAX_PASS_LEN);
	data.nickname[MAX_NICK_LEN] = '\0';
	data.password[MAX_PASS_LEN] = '\0';
	data.credentials = auth_cred_user;

	if (acl_register_user(hub, &data))
	{
		sprintf(tmp, "User \"%s\" registered.", user->id.nick);
		return command_status(hub, user, cmd, tmp);
	}
	else
	{
		sprintf(tmp, "Unable to register user \"%s\".", user->id.nick);
		return command_status(hub, user, cmd, tmp);
	}
}

static int command_password(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	struct auth_info data;
	char tmp[1024];
	char* password = list_get_first(cmd->args);

	strncpy(data.nickname, user->id.nick, MAX_NICK_LEN);
	strncpy(data.password, password, MAX_PASS_LEN);
	data.nickname[MAX_NICK_LEN] = '\0';
	data.password[MAX_PASS_LEN] = '\0';
	data.credentials = user->credentials;

	if (acl_update_user(hub, &data))
	{
		return command_status(hub, user, cmd, "Password changed.");
	}
	else
	{
		sprintf(tmp, "Unable to change password for user \"%s\".", user->id.nick);
		return command_status(hub, user, cmd, tmp);
	}
}

static int command_useradd(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
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

	if (acl_register_user(hub, &data))
	{
		sprintf(tmp, "User \"%s\" registered.", nick);
		return command_status(hub, user, cmd, tmp);
	}
	else
	{
		sprintf(tmp, "Unable to register user \"%s\".", nick);
		return command_status(hub, user, cmd, tmp);
	}
}

static int command_userdel(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	char tmp[1024];
	char* nick = list_get_first(cmd->args);

	if (acl_delete_user(hub, nick))
	{
		sprintf(tmp, "User \"%s\" is deleted.", nick);
		return command_status(hub, user, cmd, tmp);
	}
	else
	{
		sprintf(tmp, "Unable to delete user \"%s\".", nick);
		return command_status(hub, user, cmd, tmp);
	}
}

static int command_usermod(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	return command_status(hub, user, cmd, "Not implemented!");
}

static int command_userinfo(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	return command_status(hub, user, cmd, "Not implemented!");
}

static int command_userpass(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	return command_status(hub, user, cmd, "Not implemented!");
}

static int command_rules(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	if (!hub_send_rules(hub, user))
		return command_status(hub, user, cmd, "no rules defined.");
	return 0;
}

static int command_motd(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	if (!hub_send_motd(hub, user))
		return command_status(hub, user, cmd, "no motd defined.");
	return 0;
}

#ifdef CRASH_DEBUG
static int command_crash(struct hub_info* hub, struct hub_user* user, struct hub_command* cmd)
{
	void (*crash)(void) = NULL;
	crash();
	return 0;
}
#endif

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

static struct commands_handler command_handlers[] = {
	{ "ban",        3, "n", auth_cred_operator,  command_ban,      "Ban a user"                   },
	{ "broadcast",  9, "m", auth_cred_operator,  command_broadcast,"Send a message to all users"  },
#ifdef CRASH_DEBUG
	{ "crash",      5, 0,   auth_cred_admin,     command_crash,    "Crash the hub (DEBUG)."       },
#endif
	{ "getip",      5, "n", auth_cred_operator,  command_getip,    "Show IP address for a user"   },
	{ "help",       4, "?c",auth_cred_guest,     command_help,     "Show this help message."      },
	{ "history",    7, "?N",auth_cred_guest,     command_history,  "Show the last chat messages." },
	{ "kick",       4, "n", auth_cred_operator,  command_kick,     "Kick a user"                  },
	{ "log",        3, 0,   auth_cred_operator,  command_log,      "Display log"                  },
	{ "motd",       4, 0,   auth_cred_guest,     command_motd,     "Show the message of the day"  },
	{ "mute",       4, "n", auth_cred_operator,  command_mute,     "Mute user"                    },
	{ "myip",       4, 0,   auth_cred_guest,     command_myip,     "Show your own IP."            },
	{ "register",   8, "p", auth_cred_guest,     command_register, "Register your username."      },
	{ "reload",     6, 0,   auth_cred_admin,     command_reload,   "Reload configuration files."  },
	{ "rules",      5, 0,   auth_cred_guest,     command_rules,    "Show the hub rules"           },
	{ "password",   8, "p", auth_cred_user,      command_password, "Change your own password."    },
	{ "shutdown",   8, 0,   auth_cred_admin,     command_shutdown, "Shutdown hub."                },
	{ "stats",      5, 0,   auth_cred_super,     command_stats,    "Show hub statistics."         },
	{ "unban",      5, "n", auth_cred_operator,  command_unban,    "Lift ban on a user"           },
	{ "unmute",     6, "n", auth_cred_operator,  command_mute,     "Unmute user"                  },
	{ "uptime",     6, 0,   auth_cred_guest,     command_uptime,   "Display hub uptime info."     },
	{ "useradd",    7, "np",auth_cred_operator,  command_useradd,  "Register a new user."         },
	{ "userdel",    7, "n", auth_cred_operator,  command_userdel,  "Delete a registered user."    },
	{ "userinfo",   8, "n", auth_cred_operator,  command_userinfo, "Show registered user info."   },
	{ "usermod",    7, "nC",auth_cred_admin,     command_usermod,  "Modify user credentials."     },
	{ "userpass",   8, "np",auth_cred_operator,  command_userpass, "Change password for a user."  },
	{ "version",    7, 0,   auth_cred_guest,     command_version,  "Show hub version info."       },
	{ "whoip",      5, "a", auth_cred_operator,  command_whoip,    "Show users matching IP range" },
	{ 0,            0, 0,   auth_cred_none,      command_help,     ""                             }
};

