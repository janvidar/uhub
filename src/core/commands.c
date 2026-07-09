/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include "util/cbuffer.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "core/commands.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/route.h"
#include "core/usermanager.h"

#ifdef DEBUG
// #define DEBUG_UNLOAD_PLUGINS
#endif

#define MAX_HELP_MSG 16384
#define MAX_HELP_LINE 512

static int send_command_access_denied(struct command_base* cbase, struct hub_user* user, const char* prefix);
static int send_command_not_found(struct command_base* cbase, struct hub_user* user, const char* prefix);
static int send_command_syntax_error(struct command_base* cbase, struct hub_user* user);
static int send_command_missing_arguments(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd);

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
	uhub_assert(list_size(cbase->handlers) == 0);
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

int command_is_available(struct command_handle* handle, enum auth_credentials credentials)
{
	uhub_assert(handle != NULL);
	return handle->cred <= credentials;
}


struct command_handle* command_handler_lookup(struct command_base* cbase, const char* prefix)
{
	struct command_handle* handler = NULL;
	size_t prefix_len = strlen(prefix);

	LIST_FOREACH(struct command_handle*, handler, cbase->handlers,
	{
		if (prefix_len != handler->length)
			continue;

		if (!memcmp(prefix, handler->prefix, handler->length))
			return handler;
	});
	return NULL;
}


void command_foreach(struct command_base* cbase, enum auth_credentials credentials, command_handle_enum handler, void* ptr)
{
	struct command_handle* command = NULL;
	LIST_FOREACH(struct command_handle*, command, cbase->handlers,
	{
		if (command_is_available(command, credentials))
			handler(command, ptr);
	});
}


void command_get_syntax(struct command_handle* handler, struct cbuffer* buf)
{
	size_t n, arg_count;
	int opt = 0;
	char arg_code, last_arg = -1;

	cbuf_append_format(buf, "!%s", handler->prefix);
	if (handler->args)
	{
		arg_count = strlen(handler->args);
		for (n = 0; n < arg_count; n++)
		{
			if (!strchr("?+", last_arg))
				cbuf_append(buf, " ");
			arg_code = handler->args[n];
			switch (arg_code)
			{
				case '?': cbuf_append(buf, "["); opt++;      break;
				case '+': /* ignore */                       break;
				case 'n': cbuf_append(buf, "<nick>");        break;
				case 'u': cbuf_append(buf, "<user>");        break;
				case 'i': cbuf_append(buf, "<cid>");         break;
				case 'a': cbuf_append(buf, "<addr>");        break;
				case 'A': cbuf_append(buf, "<address>");     break;
				case 'r': cbuf_append(buf, "<addr range>");  break;
				case 'm': cbuf_append(buf, "<message>");     break;
				case 'p': cbuf_append(buf, "<password>");    break;
				case 'C': cbuf_append(buf, "<credentials>"); break;
				case 'c': cbuf_append(buf, "<command>");     break;
				case 'N': cbuf_append(buf, "<number>");      break;
				default: LOG_ERROR("unknown argument code '%c'", arg_code);
			}
			last_arg = arg_code;
		}
		while (opt--)
			cbuf_append(buf, "]");
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
	struct hub_command* cmd = command_parse(cbase, cbase->hub, user, message);

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

		case cmd_status_missing_args:
			ret = send_command_missing_arguments(cbase, user, cmd);
			break;

		case cmd_status_syntax_error:
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

size_t hub_command_arg_reset(struct hub_command* cmd)
{
	cmd->args->iterator = NULL;
	return list_size(cmd->args);
}

struct hub_command_arg_data* hub_command_arg_next(struct hub_command* cmd, enum hub_command_arg_type type)
{
	struct hub_command_arg_data* ptr = (struct hub_command_arg_data*) list_get_next(cmd->args);
	if (!ptr)
		return NULL;

	uhub_assert(ptr->type == type);
	if (ptr->type != type)
		return NULL;

	return ptr;
}

static int command_status(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd, struct cbuffer* msg)
{
	struct cbuffer* buf = cbuf_create(cbuf_size(msg) + strlen(cmd->prefix) + 7);
	cbuf_append_format(buf, "*** %s: %s", cmd->prefix, cbuf_get(msg));
	send_message(cbase, user, buf);
	cbuf_destroy(msg);
	return 0;
}

static int command_help(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	size_t n;
	struct cbuffer* buf = cbuf_create(MAX_HELP_LINE);
	struct hub_command_arg_data* data = hub_command_arg_next(cmd, type_command);
	struct command_handle* command;

	if (!data)
	{
		cbuf_append(buf, "Available commands:\n");

		LIST_FOREACH(struct command_handle*, command, cbase->handlers,
		{
			if (command_is_available(command, user->credentials))
			{
				cbuf_append_format(buf, "!%s", command->prefix);
				for (n = strlen(command->prefix); n < cbase->prefix_length_max; n++)
					cbuf_append(buf, " ");
				cbuf_append_format(buf, " - %s\n", command->description);
			}
		});
	}
	else
	{
		command = data->data.command;
		if (command_is_available(command, user->credentials))
		{
			cbuf_append_format(buf, "Usage: ");
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
	struct hub_command_arg_data* arg = hub_command_arg_next(cmd, type_user);
	struct hub_user* target = arg->data.user;

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

/* Accept only adc://host:port, adcs://host:port or dchub://host:port, with a
 * non-empty host (hostname / IPv4 / bracketed IPv6) and a numeric port in
 * 1..65535. Restricting the character set keeps the value safe to place in an
 * ADC RD flag without further escaping. */
int command_redirect_valid_address(const char* addr)
{
	static const char* const schemes[] = { "adc://", "adcs://", "dchub://", NULL };
	const char* host = NULL;
	const char* colon;
	const char* p;
	size_t i;
	long port;

	if (!addr || !*addr || strlen(addr) > 255)
		return 0;

	for (i = 0; schemes[i]; i++)
	{
		size_t len = strlen(schemes[i]);
		if (!strncmp(addr, schemes[i], len))
		{
			host = addr + len;
			break;
		}
	}
	if (!host)
		return 0;

	/* Rightmost ':' splits host from port, so bracketed IPv6 ([::1]:411) works. */
	colon = strrchr(host, ':');
	if (!colon || colon == host)
		return 0;

	for (p = host; p < colon; p++)
	{
		char c = *p;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '-' ||
		      c == ':' || c == '[' || c == ']'))
			return 0;
	}

	for (p = colon + 1; *p; p++)
		if (*p < '0' || *p > '9')
			return 0;

	port = strtol(colon + 1, NULL, 10);
	if (port < 1 || port > 65535)
		return 0;

	return 1;
}

static int command_redirect(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf = cbuf_create(256);
	struct hub_command_arg_data* arg_user = hub_command_arg_next(cmd, type_user);
	struct hub_command_arg_data* arg_addr = hub_command_arg_next(cmd, type_string);
	struct hub_user* target = arg_user->data.user;
	const char* address = arg_addr->data.string;

	if (target == user)
	{
		cbuf_append(buf, "Cannot redirect yourself.");
	}
	else if (!command_redirect_valid_address(address))
	{
		cbuf_append_format(buf, "Invalid redirect address \"%s\". Expected adc://host:port, adcs://host:port or dchub://host:port.", address);
	}
	else
	{
		cbuf_append_format(buf, "Redirecting user \"%s\" to %s.", target->id.nick, address);
		hub_redirect_user(cbase->hub, target, address);
	}
	return command_status(cbase, user, cmd, buf);
}

static int command_ban(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf;
	struct hub_command_arg_data* arg = hub_command_arg_next(cmd, type_user);
	struct hub_user* target = arg->data.user;
	struct hub_command_arg_data* darg = hub_command_arg_next(cmd, type_string);
	int seconds = 0;
	time_t expiry = 0;

	buf = cbuf_create(128);

	/* Optional duration argument, e.g. "1h", "30m", "7d" or bare seconds. */
	if (darg && parse_duration_seconds(darg->data.string, &seconds) == -1)
	{
		cbuf_append_format(buf, "Invalid duration \"%s\"; use e.g. 30m, 12h, 7d.", darg->data.string);
		return command_status(cbase, user, cmd, buf);
	}
	if (seconds > 0)
		expiry = time(NULL) + seconds;

	if (target == user)
	{
		cbuf_append(buf, "Cannot ban yourself.");
	}
	else
	{
		if (expiry)
			cbuf_append_format(buf, "Banning user \"%s\" for %d seconds.", target->id.nick, seconds);
		else
			cbuf_append_format(buf, "Banning user \"%s\".", target->id.nick);
		/* Ban by CID and nick, disconnect, and propagate to linked hubs so the
		   ban applies across the whole logical hub. */
		hub_apply_ban(cbase->hub, target->id.cid, target->id.nick, expiry, 1);
	}
	return command_status(cbase, user, cmd, buf);
}

static int command_unban(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf;
	struct hub_command_arg_data* arg = hub_command_arg_next(cmd, type_string);
	const char* target = arg->data.string;
	int removed;

	buf = cbuf_create(128);
	/* Lift the ban from this node and propagate cluster-wide. target may be a
	   nick, CID or IP/range; a user banned via !ban has both a nick and a CID
	   ban, so lifting both may take two !unban calls (one per identifier). */
	removed = hub_apply_unban(cbase->hub, target, 1);
	if (removed)
		cbuf_append_format(buf, "Removed ban matching \"%s\".", target);
	else
		cbuf_append_format(buf, "No ban found matching \"%s\".", target);
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
	struct hub_command_arg_data* arg = hub_command_arg_next(cmd, type_user);
	cbuf_append_format(buf, "\"%s\" has address \"%s\"", arg->data.user->id.nick, user_get_address(arg->data.user));
	return command_status(cbase, user, cmd, buf);
}

static int command_whoip(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf;
	struct hub_command_arg_data* arg = hub_command_arg_next(cmd, type_range);
	struct linked_list* users = (struct linked_list*) list_create();
	struct hub_user* u;
	int ret = 0;

	ret = uman_get_user_by_addr(cbase->hub->users, users, arg->data.range);
	if (!ret)
	{
		list_clear(users, NULL);
		list_destroy(users);
		return command_status(cbase, user, cmd, cbuf_create_const("No users found."));
	}

	buf = cbuf_create(128 + ((MAX_NICK_LEN + INET6_ADDRSTRLEN + 5) * ret));
	cbuf_append_format(buf, "*** %s: Found %d match%s:\n", cmd->prefix, ret, ((ret != 1) ? "es" : ""));

	LIST_FOREACH(struct hub_user*, u, users,
	{
		cbuf_append_format(buf, "%s (%s)\n", u->id.nick, user_get_address(u));
	});
	cbuf_append(buf, "\n");

	send_message(cbase, user, buf);
	list_clear(users, NULL);
	list_destroy(users);
	return 0;
}


static int command_broadcast(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct hub_command_arg_data* arg = hub_command_arg_next(cmd, type_string);
	char* message = adc_msg_escape(arg->data.string);
	size_t message_len = strlen(message);
	char pm_flag[7] = "PM";
	char from_sid[5];
	size_t recipients = 0;
	struct hub_user* target;
	struct cbuffer* buf = cbuf_create(128);
	struct adc_message* command = NULL;

	/* Deliver as a private message from the hub itself (the reserved SID
	 * "AAAA" == 0), not from the sending operator. Otherwise away/auto-reply
	 * messages from every recipient flood the sender. See issue #83. */
	memcpy(from_sid, sid_to_string(0), sizeof(from_sid));
	memcpy(pm_flag + 2, from_sid, sizeof(from_sid));

	LIST_FOREACH(struct hub_user*, target, cbase->hub->users->list,
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
	});

	hub_free(message);
	cbuf_append_format(buf, "*** %s: Delivered to " PRINTF_SIZE_T " user%s", cmd->prefix, recipients, (recipients != 1 ? "s" : ""));
	send_message(cbase, user, buf);
	return 0;
}

static int command_log(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf;
	struct hub_command_arg_data* arg = hub_command_arg_next(cmd, type_string);
	struct linked_list* messages = cbase->hub->logout_info;
	struct hub_logout_info* log;
	char* search = arg ? arg->data.string : "";
	size_t search_len = strlen(search);
	size_t search_hits = 0;

	if (!list_size(messages))
	{
		return command_status(cbase, user, cmd, cbuf_create_const("No entries logged."));
	}

	buf = cbuf_create(128);
	cbuf_append_format(buf, "Logged entries: " PRINTF_SIZE_T, list_size(messages));

	if (search_len)
	{
		cbuf_append_format(buf, ", searching for \"%s\"", search);
	}
	command_status(cbase, user, cmd, buf);

	buf = cbuf_create(MAX_HELP_LINE);
	LIST_FOREACH(struct hub_logout_info*, log, messages,
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
	});

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

static int command_stats(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	struct cbuffer* buf = cbuf_create(128);
	struct hub_info* hub = cbase->hub;
	static char rxbuf[64] = { "0 B" };
	static char txbuf[64] = { "0 B" };

	cbuf_append(buf, "Hub statistics: ");
	cbuf_append_format(buf, PRINTF_SIZE_T "/" PRINTF_SIZE_T " users (peak %d). ", hub->users->count, hub->config->max_users, hub->users->count_peak);

	format_size(hub->stats.net_rx, rxbuf, sizeof(rxbuf));
	format_size(hub->stats.net_tx, txbuf, sizeof(txbuf));

	cbuf_append_format(buf, "Network: tx=%s/s, rx=%s/s", txbuf, rxbuf);

#ifdef SHOW_PEAK_NET_STATS /* currently disabled */
	format_size(hub->stats.net_rx_peak, rxbuf, sizeof(rxbuf));
	format_size(hub->stats.net_tx_peak, txbuf, sizeof(txbuf));
	cbuf_append_format(buf, ", peak_tx=%s/s, peak_rx=%s/s", txbuf, rxbuf);
#endif

	format_size(hub->stats.net_rx_total, rxbuf, sizeof(rxbuf));
	format_size(hub->stats.net_tx_total, txbuf, sizeof(txbuf));
	cbuf_append_format(buf, ", total_tx=%s", txbuf);
	cbuf_append_format(buf, ", total_rx=%s", rxbuf);

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
	ADD_COMMAND("broadcast",  9, "+m",auth_cred_operator,  command_broadcast,"Send a message to all users"  );
	ADD_COMMAND("getip",      5, "u", auth_cred_operator,  command_getip,    "Show IP address for a user"   );
	ADD_COMMAND("help",       4, "?c",auth_cred_guest,     command_help,     "Show this help message."      );
	ADD_COMMAND("ban",        3, "u?n",auth_cred_operator, command_ban,      "Ban a user (cluster-wide); optional duration e.g. 30m/12h/7d");
	ADD_COMMAND("unban",      5, "+n",auth_cred_operator,  command_unban,    "Remove a ban by nick/CID/IP"  );
	ADD_COMMAND("kick",       4, "u", auth_cred_operator,  command_kick,     "Kick a user"                  );
	ADD_COMMAND("redirect",   8, "uA",auth_cred_operator,  command_redirect, "Redirect a user to another hub");
	ADD_COMMAND("log",        3, "?m",auth_cred_operator,  command_log,      "Display log"                  ); // fail
	ADD_COMMAND("myip",       4, "",  auth_cred_guest,     command_myip,     "Show your own IP."            );
	ADD_COMMAND("reload",     6, "",  auth_cred_admin,     command_reload,   "Reload configuration files."  );
	ADD_COMMAND("shutdown",   8, "",  auth_cred_admin,     command_shutdown_hub, "Shutdown hub."            );
	ADD_COMMAND("stats",      5, "",  auth_cred_super,     command_stats,    "Show hub statistics."         );
	ADD_COMMAND("uptime",     6, "",  auth_cred_guest,     command_uptime,   "Display hub uptime info."     );
	ADD_COMMAND("version",    7, "",  auth_cred_guest,     command_version,  "Show hub version info."       );
	ADD_COMMAND("whoip",      5, "r", auth_cred_operator,  command_whoip,    "Show users matching IP range" );

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
