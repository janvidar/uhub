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

#include "uhub_limits.h"
#include <openssl/rand.h>
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "util/tiger.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "network/connection.h"
#include "network/dnsresolver.h"
#include "network/network.h"
#include "core/auth.h"
#include "core/commands.h"
#include "core/config.h"
#include "core/eventid.h"
#include "core/eventqueue.h"
#include "core/hbri.h"
#include "core/hub.h"
#include "core/hubevent.h"
#include "core/inf.h"
#include "core/ipcount.h"
#include "core/ioqueue.h"
#include "core/link.h"
#include "core/netevent.h"
#include "core/plugininvoke.h"
#include "core/pluginloader.h"
#include "core/regserver.h"
#include "core/route.h"
#include "core/usermanager.h"

struct hub_info* g_hub = 0;

/* The hub detects floods against the configured flood_ctl_* thresholds; the
 * action is delegated to plugins via the on_flood_detected event. A plugin may
 * return st_allow to let the offending message through, st_deny to drop it
 * quietly (the plugin handled it - e.g. disconnected or warned itself), or
 * st_default (also the no-plugin case) to get the hub's built-in response:
 * drop the message and send the configured msg_user_flood_* warning. */
#define CHECK_FLOOD(TYPE, WARN) \
	if (flood_control_check(&u->flood_ ## TYPE , hub->config->flood_ctl_  ## TYPE, hub->config->flood_ctl_interval, net_get_time()) &&  !auth_cred_is_unrestricted(u->credentials)) \
	{ \
		plugin_st flood_action = plugin_flood_detected(hub, u, flood_type_ ## TYPE); \
		if (flood_action != st_allow) \
		{ \
			if (flood_action == st_default && (WARN)) \
			{ \
				hub_send_flood_warning(hub, u, hub->config->msg_user_flood_ ## TYPE); \
			} \
			break; \
		} \
	}

#define ROUTE_MSG \
	if (user_is_logged_in(u)) \
	{ \
		ret = route_message(hub, u, cmd); \
	} \
	else \
	{ \
		ret = -1; \
	} \
	break;

/**
 * Returns 1 if a search request must be rejected because its longest substring
 * include term ("AN") is shorter than the configured limit_min_search.
 *
 * Substring searches on very short terms (such as a single letter) match a huge
 * number of files and generate a lot of traffic, so the hub can require search
 * terms to be a few characters long. Exact content (TTH) searches are cheap and
 * are never restricted, and searches without any include term (e.g. by size or
 * extension only) are left alone.
 */
static int hub_search_is_too_short(struct hub_info* hub, struct adc_message* cmd)
{
	int min = hub->config->limit_min_search;
	int offset = 0;
	char* arg;
	int has_include = 0;
	size_t longest = 0;

	if (min <= 0)
		return 0;

	/* Exact content (TTH) searches resolve to a single file; never reject them. */
	if (adc_msg_has_named_argument(cmd, ADC_SCH_FLAG_TTH))
		return 0;

	while ((arg = adc_msg_get_argument(cmd, offset++)) != NULL)
	{
		if (strncmp(arg, ADC_SCH_FLAG_INCLUDE, 2) == 0)
		{
			size_t len = strlen(arg) - 2;
			has_include = 1;
			if (len > longest)
				longest = len;
		}
		hub_free(arg);
	}

	return (has_include && longest < (size_t) min);
}

int hub_handle_message(struct hub_info* hub, struct hub_user* u, const char* line, size_t length)
{
	int ret = 0;
	struct adc_message* cmd = 0;

	LOG_PROTO("recv %s: %s", sid_to_string(u->id.sid), line);

	if (user_is_disconnecting(u))
		return -1;

	cmd = adc_msg_parse_verify(u, line, length);
	if (cmd)
	{
		switch (cmd->cmd)
		{
			case ADC_CMD_HTCP:
				/* HBRI secondary-protocol validation reply. This arrives on a
				   fresh connection as its very first command (no HSUP), so it
				   is handled before the normal handshake. The validation
				   connection is always closed afterwards. */
				ret = hbri_handle_validation(hub, u, cmd);
				break;

			case ADC_CMD_HSUP:
				CHECK_FLOOD(extras, 0);
				ret = hub_handle_support(hub, u, cmd);
				break;

			case ADC_CMD_HPAS:
				CHECK_FLOOD(extras, 0);
				ret = hub_handle_password(hub, u, cmd);
				break;

			case ADC_CMD_BINF:
				CHECK_FLOOD(update, 1);
				ret = hub_handle_info(hub, u, cmd);
				break;

			case ADC_CMD_DINF:
			case ADC_CMD_EINF:
			case ADC_CMD_FINF:
			case ADC_CMD_BQUI:
			case ADC_CMD_DQUI:
			case ADC_CMD_EQUI:
			case ADC_CMD_FQUI:
				/* these must never be allowed for security reasons, so we ignore them. */
				CHECK_FLOOD(extras, 1);
				break;

			case ADC_CMD_EMSG:
			case ADC_CMD_DMSG:
			case ADC_CMD_BMSG:
			case ADC_CMD_FMSG:
				CHECK_FLOOD(chat, 1);
				ret = hub_handle_chat_message(hub, u, cmd);
				break;

			case ADC_CMD_BSCH:
			case ADC_CMD_DSCH:
			case ADC_CMD_ESCH:
			case ADC_CMD_FSCH:
				cmd->priority = -1;
				if (plugin_handle_search(hub, u, cmd->cache) == st_deny)
					break;
				if (hub_search_is_too_short(hub, cmd) && !auth_cred_is_unrestricted(u->credentials))
				{
					hub_send_status(hub, u, status_msg_search_too_short, status_level_error);
					break;
				}
				CHECK_FLOOD(search, 1);
				hub->metrics.searches++;
				ROUTE_MSG;

			case ADC_CMD_FRES: // spam
			case ADC_CMD_BRES: // spam
			case ADC_CMD_ERES: // pointless.
				CHECK_FLOOD(extras, 1);
				break;

			case ADC_CMD_DRES:
				cmd->priority = -1;
				if (plugin_handle_search_result(hub, u, uman_get_user_by_sid(hub->users, cmd->target), cmd->cache) == st_deny)
					break;
				/* CHECK_FLOOD(search, 0); */
				hub->metrics.search_results++;
				ROUTE_MSG;

			case ADC_CMD_DRCM:
				cmd->priority = -1;
				if (plugin_handle_revconnect(hub, u, uman_get_user_by_sid(hub->users, cmd->target)) == st_deny)
					break;
				CHECK_FLOOD(connect, 1);
				hub->metrics.rev_connect_requests++;
				ROUTE_MSG;

			case ADC_CMD_DCTM:
				cmd->priority = -1;
				if (plugin_handle_connect(hub, u, uman_get_user_by_sid(hub->users, cmd->target)) == st_deny)
					break;
				CHECK_FLOOD(connect, 1);
				hub->metrics.connect_requests++;
				ROUTE_MSG;

			case ADC_CMD_DNAT:
			case ADC_CMD_DRNT:
				/* NATT (NAT traversal): relayed verbatim between the two peers,
				   like DCTM/DRCM. The hub only passes these through; the hole-
				   punching is entirely client-driven. */
				cmd->priority = -1;
				CHECK_FLOOD(connect, 1);
				ROUTE_MSG;

			case ADC_CMD_BCMD:
			case ADC_CMD_DCMD:
			case ADC_CMD_ECMD:
			case ADC_CMD_FCMD:
			case ADC_CMD_HCMD:
				CHECK_FLOOD(extras, 1);
				break;

			default:
				CHECK_FLOOD(extras, 1);
				ROUTE_MSG;
		}
		adc_msg_free(cmd);
	}
	else
	{
		if (!user_is_logged_in(u))
		{
			ret = -1;
		}
	}

	return ret;
}


int hub_handle_support(struct hub_info* hub, struct hub_user* u, struct adc_message* cmd)
{
	int ret = 0;
	int index = 0;
	int ok = 1;
	char* arg = adc_msg_get_argument(cmd, index);

	if (hub->status == hub_status_disabled && u->state == state_protocol)
	{
		on_login_failure(hub, u, status_msg_hub_disabled);
		hub_free(arg);
		return -1;
	}

	while (arg)
	{
		if (strlen(arg) == 6)
		{
			fourcc_t fourcc = FOURCC(arg[2], arg[3], arg[4], arg[5]);
			if (strncmp(arg, ADC_SUP_FLAG_ADD, 2) == 0)
			{
				user_support_add(u, fourcc);
			}
			else if (strncmp(arg, ADC_SUP_FLAG_REMOVE, 2) == 0)
			{
				user_support_remove(u, fourcc);
			}
			else
			{
				ok = 0;
			}
		}
		else
		{
			ok = 0;
		}

		index++;
		hub_free(arg);
		arg = adc_msg_get_argument(cmd, index);
	}

	if (u->state == state_protocol)
	{
		if (index == 0) ok = 0; /* Need to support *SOMETHING*, at least BASE */
		if (!ok)
		{
			/* disconnect user. Do not send crap during initial handshake! */
			hub_disconnect_user(hub, u, quit_logon_error);
			return -1;
		}

		if (user_flag_get(u, feature_base))
		{
			/* User supports ADC/1.0 and a hash we know */
			if (user_flag_get(u, feature_tiger))
			{
				hub_send_handshake(hub, u);
				net_con_set_timeout(u->connection, TIMEOUT_HANDSHAKE);
			}
			else
			{
				// no common hash algorithm.
				hub_send_status(hub, u, status_msg_proto_no_common_hash, status_level_fatal);
				hub_disconnect_user(hub, u, quit_protocol_error);
			}
		}
		else if (user_flag_get(u, feature_bas0))
		{
			if (hub->config->obsolete_clients)
			{
				hub_send_handshake(hub, u);
				net_con_set_timeout(u->connection, TIMEOUT_HANDSHAKE);
			}
			else
			{
				/* disconnect user for using an obsolete client. */
				char* tmp = adc_msg_escape(hub->config->msg_proto_obsolete_adc0);
				struct adc_message* message = adc_msg_construct(ADC_CMD_IMSG, 6 + (tmp ? strlen(tmp) : 0));
				if (message)
				{
					adc_msg_add_argument(message, tmp);
					route_to_user(hub, u, message);
					adc_msg_free(message);
				}
				hub_free(tmp);
				hub_disconnect_user(hub, u, quit_protocol_error);
			}
		}
		else
		{
			/* Not speaking a compatible protocol - just disconnect. */
			hub_disconnect_user(hub, u, quit_logon_error);
		}
	}

	return ret;
}


static int check_duplicate_logins_ok(struct hub_info* hub, struct hub_user* user);

int hub_handle_password(struct hub_info* hub, struct hub_user* u, struct adc_message* cmd)
{
	char* password = adc_msg_get_argument(cmd, 0);
	int ret = 0;

	if (u->state == state_verify)
	{
		if (hub->config->auth_proxy)
		{
			/* Slave: forward the challenge-response to the master to verify
			   (the master holds the password). The login completes in
			   hub_auth_proxy_verified() when the master replies (LVRS). */
			if (password && link_auth_proxy_verify(hub, u, acl_password_generate_challenge(hub, u), password))
			{
				hub_free(password);
				return 0; /* paused until LVRS */
			}
			/* No master link reachable -- cannot verify. */
			on_login_failure(hub, u, status_msg_auth_invalid_password);
			hub_free(password);
			return -1;
		}

		if (acl_password_verify(hub, u, password))
		{
			/* Another login may have claimed this CID/nick while we were
			   waiting for the password response. */
			int status = check_duplicate_logins_ok(hub, u);
			if (!status)
			{
				on_login_success(hub, u);
			}
			else
			{
				on_login_failure(hub, u, (enum status_message) status);
				ret = -1;
			}
		}
		else
		{
			on_login_failure(hub, u, status_msg_auth_invalid_password);
			ret = -1;
		}
	}

	hub_free(password);
	return ret;
}

/*
 * Master-slave auth (slave side): the master verified (or rejected) a proxied
 * login (LVRS). Complete the login that paused in hub_handle_password().
 */
void hub_auth_proxy_verified(struct hub_info* hub, struct hub_user* user, int ok)
{
	if (user->state != state_verify)
		return; /* stale (user disconnected or already resolved) */

	if (ok)
	{
		int status = check_duplicate_logins_ok(hub, user);
		if (!status)
			on_login_success(hub, user);
		else
			on_login_failure(hub, user, (enum status_message) status);
	}
	else
	{
		on_login_failure(hub, user, status_msg_auth_invalid_password);
	}
}


int hub_handle_chat_message(struct hub_info* hub, struct hub_user* u, struct adc_message* cmd)
{
	char* message = adc_msg_get_argument(cmd, 0);
	char* message_decoded = NULL;
	int ret = 0;
	int relay = 1;
	int broadcast;
	int private_msg;
	int command;
	int offset;

	if (!message)
		return 0;

	message_decoded = adc_msg_unescape(message);
	if (!message_decoded)
	{
		hub_free(message);
		return 0;
	}

	if (!user_is_logged_in(u))
	{
		hub_free(message_decoded);
		hub_free(message);
		return 0;
	}

	broadcast = (cmd->cache[0] == 'B');
	private_msg = (cmd->cache[0] == 'D' || cmd->cache[0] == 'E');
	command = (message[0] == '!' || message[0] == '+');

	if (broadcast && command)
	{
		/*
		 * A message such as "++message" is handled as "+message", by removing the first character.
		 * The first character is removed by memmoving the string one byte to the left.
		 */
		if (message[1] == message[0])
		{
			relay = 1;
			offset = adc_msg_get_arg_offset(cmd);
			memmove(cmd->cache+offset+1, cmd->cache+offset+2, cmd->length - offset);
			cmd->length--;
		}
		else
		{
			relay = command_invoke(hub->commands, u, message_decoded);
		}
	}

	/* FIXME: Plugin should do this! */
	if (relay && broadcast)
	{
		if (hub->config->chat_is_privileged && !user_is_protected(u))
		{
			relay = 0;
			hub_send_chat_denied(hub, u, hub->config->msg_chat_is_privileged);
		}
		else if (user_flag_get(u, flag_muted))
		{
			relay = 0;
		}
	}

	if (relay)
	{
		plugin_st status = st_default;
		if (broadcast)
		{
			status = plugin_handle_chat_message(hub, u, message_decoded, 0);
		}
		else if (private_msg)
		{
			struct hub_user* target = uman_get_user_by_sid(hub->users, cmd->target);
			if (target)
				status = plugin_handle_private_message(hub, u, target, message_decoded, 0);
			else
				relay = 0;
		}

		if (status == st_deny)
			relay = 0;
	}

	if (relay)
	{
		/* adc_msg_remove_named_argument(cmd, "PM"); */
		if (broadcast)
		{
			plugin_log_chat_message(hub, u, message_decoded, 0);
			hub->metrics.chat_messages++;
		}
		else if (private_msg)
		{
			hub->metrics.private_messages++;
		}
		ret = route_message(hub, u, cmd);
	}
	hub_free(message);
	hub_free(message_decoded);
	return ret;
}

void hub_send_support(struct hub_info* hub, struct hub_user* u)
{
	if (user_is_connecting(u) || user_is_logged_in(u))
	{
		route_to_user(hub, u, hub->command_support);
	}
}


void hub_send_sid(struct hub_info* hub, struct hub_user* u)
{
	sid_t sid;
	struct adc_message* command;
	if (user_is_connecting(u))
	{
		command = adc_msg_construct(ADC_CMD_ISID, 10);
		if (!command)
			return; /* OOM */
		sid = uman_get_free_sid(hub->users, u);
		adc_msg_add_argument(command, (const char*) sid_to_string(sid));
		route_to_user(hub, u, command);
		adc_msg_free(command);
	}
}


void hub_send_ping(struct hub_info* hub, struct hub_user* user)
{
	/* This will just send a newline, despite appearing to do more below. */
	struct adc_message* ping = adc_msg_construct(0, 0);
	if (!ping)
		return; /* OOM */
	ping->cache[0]     = '\n';
	ping->cache[1]     = 0;
	ping->length       = 1;
	ping->priority     = 1;
	route_to_user(hub, user, ping);
	adc_msg_free(ping);
}


void hub_send_hubinfo(struct hub_info* hub, struct hub_user* u)
{
	struct adc_message* info = adc_msg_copy(hub->command_info);
	int value = 0;
	uint64_t size = 0;

	if (!info)
		return; /* OOM */

	if (user_flag_get(u, feature_ping))
	{
/*
		FIXME: These are missing:
		HH - Hub Host address ( DNS or IP )
		WS - Hub Website
		NE - Hub Network
		OW - Hub Owner name
*/
		adc_msg_add_named_argument(info, "UC", uhub_itoa(hub_get_user_count(hub)));
		adc_msg_add_named_argument(info, "MC", uhub_itoa(hub_get_max_user_count(hub)));
		adc_msg_add_named_argument(info, "SS", uhub_ulltoa(hub_get_shared_size(hub)));
		adc_msg_add_named_argument(info, "SF", uhub_ulltoa(hub_get_shared_files(hub)));

		/* Maximum/minimum share size */
		size = hub_get_max_share(hub);
		if (size) adc_msg_add_named_argument(info, "XS", uhub_ulltoa(size));
		size = hub_get_min_share(hub);
		if (size) adc_msg_add_named_argument(info, "MS", uhub_ulltoa(size));

		/* Maximum/minimum upload slots allowed per user */
		value = hub_get_max_slots(hub);
		if (value) adc_msg_add_named_argument(info, "XL", uhub_itoa(value));
		value = hub_get_min_slots(hub);
		if (value) adc_msg_add_named_argument(info, "ML", uhub_itoa(value));

		/* guest users must be on min/max hubs */
		value = hub_get_max_hubs_user(hub);
		if (value) adc_msg_add_named_argument(info, "XU", uhub_itoa(value));
		value = hub_get_min_hubs_user(hub);
		if (value) adc_msg_add_named_argument(info, "MU", uhub_itoa(value));

		/* registered users must be on min/max hubs */
		value = hub_get_max_hubs_reg(hub);
		if (value) adc_msg_add_named_argument(info, "XR", uhub_itoa(value));
		value = hub_get_min_hubs_reg(hub);
		if (value) adc_msg_add_named_argument(info, "MR", uhub_itoa(value));

		/* operators must be on min/max hubs */
		value = hub_get_max_hubs_op(hub);
		if (value) adc_msg_add_named_argument(info, "XO", uhub_itoa(value));
		value = hub_get_min_hubs_op(hub);
		if (value) adc_msg_add_named_argument(info, "MO", uhub_itoa(value));

		/* uptime in seconds */
		adc_msg_add_named_argument(info, "UP", uhub_itoa((int) difftime(time(0), hub->tm_started)));

		/* Optional descriptive fields (escaped; omitted when not configured) */
		{
			/* Normalize the advertised hub address to a complete adc:// or
			 * adcs:// URL with a port (same form as the registration announce),
			 * filling in a missing scheme/port from tls_enable/server_port. */
			char hh[256 + 80];
			if (regserver_hub_url(hub->config->hub_address, hub->config->tls_enable,
					hub->config->server_port, hub->tls_keyprint, hh, sizeof(hh)))
				adc_msg_add_named_argument_string(info, "HH", hh);
		}
		if (*hub->config->hub_website)
			adc_msg_add_named_argument_string(info, "WS", hub->config->hub_website);
		if (*hub->config->hub_network)
			adc_msg_add_named_argument_string(info, "NE", hub->config->hub_network);
		if (*hub->config->hub_owner)
			adc_msg_add_named_argument_string(info, "OW", hub->config->hub_owner);
	}

	if (user_is_connecting(u) || user_is_logged_in(u))
	{
		route_to_user(hub, u, info);
	}
	adc_msg_free(info);

	/* Only send banner when connecting */
	if (hub->config->show_banner && user_is_connecting(u))
	{
		route_to_user(hub, u, hub->command_banner);
	}
}

void hub_send_handshake(struct hub_info* hub, struct hub_user* u)
{
	user_flag_set(u, flag_pipeline);
	hub_send_support(hub, u);
	hub_send_sid(hub, u);
	hub_send_hubinfo(hub, u);
	route_flush_pipeline(hub, u);

	if (!user_is_disconnecting(u))
	{
		user_set_state(u, state_identify);
	}
}

void hub_send_password_challenge(struct hub_info* hub, struct hub_user* u)
{
	struct adc_message* igpa;
	igpa = adc_msg_construct(ADC_CMD_IGPA, 38);
	if (!igpa)
		return; /* OOM */
	adc_msg_add_argument(igpa, acl_password_generate_challenge(hub, u));
	user_set_state(u, state_verify);
	route_to_user(hub, u, igpa);
	adc_msg_free(igpa);
}

/* Format an ADC status code as "<severity><2-digit error>" into a 4-byte
 * buffer, e.g. (status_level_error, ADC_STATUS_HUB_GENERIC) -> "110". */
static void set_status_code(enum msg_status_level level, int code, char buffer[4])
{
	buffer[0] = ('0' + (int) level);
	buffer[1] = ('0' + (code / 10));
	buffer[2] = ('0' + (code % 10));
	buffer[3] = 0;
}

void hub_send_flood_warning(struct hub_info* hub, struct hub_user* u, const char* message)
{
	struct adc_message* msg;
	char* tmp;
	char code[4];

	if (user_flag_get(u, flag_flood))
		return;

	msg = adc_msg_construct(ADC_CMD_ISTA, 128);
	if (msg)
	{
		tmp = adc_msg_escape(message);
		set_status_code(status_level_error, ADC_STATUS_HUB_GENERIC, code);
		adc_msg_add_argument(msg, code);
		adc_msg_add_argument(msg, tmp);
		hub_free(tmp);

		route_to_user(hub, u, msg);
		user_flag_set(u, flag_flood);
		adc_msg_free(msg);
	}
}

void hub_send_chat_denied(struct hub_info* hub, struct hub_user* u, const char* message)
{
	struct adc_message* msg;
	char* tmp;
	char code[4];

	msg = adc_msg_construct(ADC_CMD_ISTA, 128);
	if (msg)
	{
		tmp = adc_msg_escape(message);
		/* recoverable error, registered/privileged users only */
		set_status_code(status_level_error, ADC_STATUS_REGISTERED_ONLY, code);
		adc_msg_add_argument(msg, code);
		adc_msg_add_argument(msg, tmp);
		hub_free(tmp);

		route_to_user(hub, u, msg);
		adc_msg_free(msg);
	}
}

static int check_duplicate_logins_ok(struct hub_info* hub, struct hub_user* user)
{
	struct hub_user* lookup1;
	struct hub_user* lookup2;

	lookup1 = uman_get_user_by_nick(hub->users, user->id.nick);
	if (lookup1)
		return status_msg_inf_error_nick_taken;

	lookup2 = uman_get_user_by_cid(hub->users, user->id.cid);
	if (lookup2)
		return status_msg_inf_error_cid_taken;

	return 0;
}

static void hub_event_dispatcher(void* callback_data, struct event_data* message)
{
	int status;
	struct hub_info* hub = (struct hub_info*) callback_data;
	struct hub_user* user = (struct hub_user*) message->ptr;
	uhub_assert(hub != NULL);

	switch (message->id)
	{
		case UHUB_EVENT_USER_JOIN:
		{
			if (user_is_disconnecting(user))
				break;

			if (message->flags)
			{
				hub_send_password_challenge(hub, user);
			}
			else
			{
				/* Race condition, we could have two messages for two logins queued up.
				   So make sure we don't let the second client in. */
				status = check_duplicate_logins_ok(hub, user);
				if (!status)
				{
					on_login_success(hub, user);
				}
				else
				{
					on_login_failure(hub, user, (enum status_message) status);
				}
			}
			break;
		}

		case UHUB_EVENT_USER_QUIT:
		{
			uman_remove(hub->users, user);
			uman_send_quit_message(hub, hub->users, user);
			/* Propagate the local user's departure to linked hubs. */
			link_broadcast_local_quit(hub, user);
			on_logout_user(hub, user);
			hub_schedule_destroy_user(hub, user);
			break;
		}

		case UHUB_EVENT_USER_DESTROY:
		{
			route_clear_dirty(hub, user);
			user_destroy(user);
			break;
		}

		case UHUB_EVENT_HUB_SHUTDOWN:
		{
			struct hub_user* u = (struct hub_user*) list_get_first(hub->users->list);
			while (u)
			{
				uman_remove(hub->users, u);
				user_destroy(u);
				u = (struct hub_user*) list_get_first(hub->users->list);
			}
			break;
		}


		default:
			/* No handler for this event type; nothing to do. */
			break;
	}
}


static void hub_update_stats(struct hub_info* hub)
{
	const int factor = TIMEOUT_STATS;
	struct net_statistics* total;
	struct net_statistics* intermediate;
	net_stats_get(&intermediate, &total);

	hub->stats.net_tx = (intermediate->tx / factor);
	hub->stats.net_rx = (intermediate->rx / factor);
	hub->stats.net_tx_peak = MAX(hub->stats.net_tx, hub->stats.net_tx_peak);
	hub->stats.net_rx_peak = MAX(hub->stats.net_rx, hub->stats.net_rx_peak);
	hub->stats.net_tx_total = total->tx;
	hub->stats.net_rx_total = total->rx;

	net_stats_reset();
}

static void hub_timer_statistics(struct timeout_evt* t)
{
	struct hub_info* hub = (struct hub_info*) t->ptr;
	hub_update_stats(hub);
	timeout_queue_reschedule(net_backend_get_timeout_queue(), hub->stats.timeout, TIMEOUT_STATS);
}

static struct net_connection* start_listening_socket(const char* bind_addr, uint16_t port, int backlog, int reuseport, struct hub_info* hub)
{
	struct net_connection* server;
	struct sockaddr_storage addr;
	socklen_t sockaddr_size;
	int sd, ret;

	if (ip_convert_address(bind_addr, port, (struct sockaddr*) &addr, &sockaddr_size) == -1)
	{
		return 0;
	}

	sd = net_socket_create(addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (sd == -1)
	{
		return 0;
	}

	if ((net_set_reuseaddress(sd, 1) == -1) || (net_set_nonblocking(sd, 1) == -1))
	{
		net_close(sd);
		return 0;
	}

	/* When several worker processes share the client-facing port, set
	   SO_REUSEPORT so the kernel load-balances connections across them. */
	if (reuseport && net_set_reuseport(sd, 1) == -1)
	{
		LOG_ERROR("start_listening_socket(): server_reuseport is set but SO_REUSEPORT is unavailable");
		net_close(sd);
		return 0;
	}

	ret = net_bind(sd, (struct sockaddr*) &addr, sockaddr_size);
	if (ret == -1)
	{
		LOG_ERROR("hub_start_service(): Unable to bind to TCP local address. errno=%d, str=%s", net_error(), net_error_string(net_error()));
		net_close(sd);
		return 0;
	}

	ret = net_listen(sd, backlog);
	if (ret == -1)
	{
		LOG_ERROR("hub_start_service(): Unable to listen to socket");
		net_close(sd);
		return 0;
	}

	server = net_con_create();
	net_con_initialize(server, sd, net_on_accept, hub, NET_EVENT_READ);

	return server;
}

struct server_alt_port_data
{
	struct hub_info* hub;
	struct hub_config* config;
};

static int server_alt_port_start_one(char* line, int count, void* ptr)
{
	(void) count;
	struct server_alt_port_data* data = (struct server_alt_port_data*) ptr;

	int port = uhub_atoi(line);
	struct net_connection* con = start_listening_socket(data->config->server_bind_addr, port, data->config->server_listen_backlog, data->config->server_reuseport, data->hub);
	if (con)
	{
		list_append(data->hub->server_alt_ports, con);
		LOG_INFO("Listening on alternate port %d...", port);
		return 0;
	}
	return -1;
}

static void server_alt_port_start(struct hub_info* hub, struct hub_config* config)
{
	struct server_alt_port_data data;

	if (!config->server_alt_ports || !*config->server_alt_ports)
		return;

	hub->server_alt_ports = (struct linked_list*) list_create();

	data.hub = hub;
	data.config = config;

	string_split(config->server_alt_ports, ",", &data, server_alt_port_start_one);
}

static void server_alt_port_clear(void* ptr)
{
	struct net_connection* con = (struct net_connection*) ptr;
	if (con)
	{
		net_con_close(con);
		hub_free(con);
	}
}

static void server_alt_port_stop(struct hub_info* hub)
{
	if (hub->server_alt_ports)
	{
		list_clear(hub->server_alt_ports, &server_alt_port_clear);
		list_destroy(hub->server_alt_ports);
	}
}

static int load_ssl_certificates(struct hub_info* hub, struct hub_config* config)
{
	if (config->tls_enable)
	{
		hub->ctx = net_ssl_context_create(config->tls_version, config->tls_ciphersuite, config->tls_ciphersuites);

		if (!hub->ctx)
		  return 0;

		if (ssl_load_certificate(hub->ctx, config->tls_certificate) &&
			ssl_load_private_key(hub->ctx, config->tls_private_key) &&
			ssl_check_private_key(hub->ctx))
		{
			char keyprint[80];
			LOG_INFO("Enabling TLS (%s), using certificate: %s, private key: %s", net_ssl_get_provider(), config->tls_certificate, config->tls_private_key);

			/* Cache the certificate's KEYP keyprint so it can be advertised in
			 * adcs:// URLs (HH field / registration) without re-hashing per use. */
			if (net_ssl_get_keyprint(hub->ctx, keyprint, sizeof(keyprint)))
				hub->tls_keyprint = hub_strdup(keyprint);
			else
				LOG_WARN("Unable to compute TLS certificate keyprint; adcs:// URLs will omit ?kp=.");
			return 1;
		}
		return 0;
	}
	return 1;
}

static void unload_ssl_certificates(struct hub_info* hub)
{
	if (hub->ctx)
		net_ssl_context_destroy(hub->ctx);
	hub_free(hub->tls_keyprint);
	hub->tls_keyprint = NULL;
}

static void hub_init_secret(struct hub_info* hub) {
    /* A random secret unknown to clients; falls back to startup entropy if the
	   CSPRNG is somehow unavailable. */
	if (RAND_bytes(hub->hub_secret, (int) sizeof(hub->hub_secret)) != 1)
	{
		uint64_t seed[3];
		char buf[64];
		int n = snprintf(buf, sizeof(buf), "%p|%ld|%d", (void*) hub, (long) time(NULL), (int) getpid());
		tiger((uint64_t*) buf, (uint64_t) n, seed);
		memcpy(hub->hub_secret, seed, sizeof(hub->hub_secret));
	}
}

struct hub_info* hub_start_service(struct hub_config* config)
{
	struct hub_info* hub = 0;
	int ipv6_supported;

	hub = hub_malloc_zero(sizeof(struct hub_info));
	if (!hub)
	{
		LOG_FATAL("Unable to allocate memory for hub");
		return 0;
	}

	hub->tm_started = time(0);

	/* Size the DNS worker pool before any outbound lookup spawns it. */
	net_dns_set_pool_size((size_t) config->dns_thread_pool_size);

	ipv6_supported = net_is_ipv6_supported();
	if (ipv6_supported)
		LOG_DEBUG("IPv6 supported.");
	else
		LOG_DEBUG("IPv6 not supported.");

	hub->server = start_listening_socket(config->server_bind_addr, config->server_port, config->server_listen_backlog, config->server_reuseport, hub);
	if (!hub->server)
	{
		hub_free(hub);
		LOG_FATAL("Unable to start hub service");
		return 0;
	}
	LOG_INFO("Starting " PRODUCT "/" VERSION ", listening on %s:%d...", net_get_local_address(hub->server->sd), config->server_port);

	if (!load_ssl_certificates(hub, config))
	{
		hub_free(hub);
		return 0;
	}

	/* Log the address clients should connect to: adcs://host:port with the
	 * certificate keyprint (?kp=) when TLS is on, else adc://host:port. Prefer
	 * the configured hub_address; fall back to the bound local address. */
	{
		char url[256 + 80];
		const char* addr = (config->hub_address && *config->hub_address)
			? config->hub_address : net_get_local_address(hub->server->sd);
		if (regserver_hub_url(addr, config->tls_enable, config->server_port, hub->tls_keyprint, url, sizeof(url)))
			LOG_INFO("Connect address: %s", url);
	}

	/* The metrics endpoint checks its bearer token over whatever transport the
	 * request arrives on. With TLS off, a scrape (token included) crosses the
	 * network in cleartext -- warn so it is only scraped over loopback/TLS. */
	if (config->metrics_enable && *config->metrics_token && !config->tls_enable)
		LOG_WARN("Metrics endpoint is enabled without TLS: the bearer token is sent in cleartext. Scrape only over loopback or a TLS-enabled port.");

	hub->config = config;
	hub->users = NULL;

	hub->users = uman_init(config->node_id, config->node_count);
	if (!hub->users)
	{
		net_con_close(hub->server);
		hub_free(hub);
		return 0;
	}

	if (event_queue_initialize(&hub->queue, hub_event_dispatcher, (void*) hub) == -1)
	{
		net_con_close(hub->server);
		uman_shutdown(hub->users);
		hub_free(hub);
		return 0;
	}

	hub->recvbuf = hub_malloc(MAX_RECV_BUF);
	hub->sendbuf = hub_malloc(MAX_SEND_BUF);
	if (!hub->recvbuf || !hub->sendbuf)
	{
		net_con_close(hub->server);
		hub_free(hub->recvbuf);
		hub_free(hub->sendbuf);
		uman_shutdown(hub->users);
		hub_free(hub);
		return 0;
	}

	hub->logout_info  = (struct linked_list*) list_create();
	hub->write_queue  = (struct linked_list*) list_create();

	hub->ipcount = ipcount_create();
	if (!hub->ipcount)
		LOG_WARN("hub_start_service(): unable to allocate per-IP connection tracker; max_connections_per_ip will not be enforced.");

	hub_init_secret(hub);

	server_alt_port_start(hub, config);

	hub->status = hub_status_running;

	/* Start hub-to-hub linking (outbound). Incoming links are detected on the
	   normal hub port by probe.c. Done after the hub is running so the reactor
	   is ready to drive the outbound connect. */
	link_start(hub);

	g_hub = hub;

	if (net_backend_get_timeout_queue())
	{
		hub->stats.timeout = hub_malloc_zero(sizeof(struct timeout_evt));
		timeout_evt_initialize(hub->stats.timeout, hub_timer_statistics, hub);
		timeout_queue_insert(net_backend_get_timeout_queue(), hub->stats.timeout, TIMEOUT_STATS);
	}

	// Start the hub command sub-system
	hub->commands = command_initialize(hub);

	return hub;
}


void hub_shutdown_service(struct hub_info* hub)
{
	LOG_DEBUG("hub_shutdown_service()");

	link_stop(hub);

	regserver_cleanup(hub);

	if (net_backend_get_timeout_queue())
	{
		timeout_queue_remove(net_backend_get_timeout_queue(), hub->stats.timeout);
		hub_free(hub->stats.timeout);
	}

	unload_ssl_certificates(hub);

	event_queue_shutdown(hub->queue);
	net_con_close(hub->server);
	server_alt_port_stop(hub);
	uman_shutdown(hub->users);
	ipcount_destroy(hub->ipcount);
	hub->status = hub_status_stopped;
	hub_free(hub->sendbuf);
	hub_free(hub->recvbuf);
	list_clear(hub->logout_info, hub_free_handle);
	list_destroy(hub->logout_info);
	list_clear(hub->write_queue, NULL);
	list_destroy(hub->write_queue);
	command_shutdown(hub->commands);
	hub_free(hub);
	hub = 0;
	g_hub = 0;
}

int hub_plugins_load(struct hub_info* hub)
{
	if (!hub->config->file_plugins || !*hub->config->file_plugins)
		return 0;

	hub->plugins = hub_malloc_zero(sizeof(struct uhub_plugins));
	if (!hub->plugins)
		return -1;

	if (plugin_initialize(hub->config, hub) < 0)
	{
		hub_free(hub->plugins);
		hub->plugins = 0;
		return -1;
	}
	return 0;
}

void hub_plugins_unload(struct hub_info* hub)
{
	if (hub->plugins)
	{
		plugin_shutdown(hub->plugins);
		hub_free(hub->plugins);
		hub->plugins = 0;
	}
}

void hub_update_description(struct hub_info* hub, const char* escaped_desc, int propagate)
{
	struct adc_message* command;

	if (!hub->command_info || !escaped_desc)
		return;

	/* Update the hub's own IINF and announce the change to local clients. */
	adc_msg_replace_named_argument(hub->command_info, ADC_INF_FLAG_DESCRIPTION, escaped_desc);
	command = adc_msg_construct(ADC_CMD_IINF, (int) (strlen(escaped_desc) + 8));
	if (command)
	{
		adc_msg_add_named_argument(command, ADC_INF_FLAG_DESCRIPTION, escaped_desc);
		route_to_all(hub, command);
		adc_msg_free(command);
	}

	/* Propagate to linked hubs so a topic set on one node (or worker) shows on
	   all of them. A description applied from a link is not re-propagated, which
	   keeps a full mesh loop-free. */
	if (propagate)
		link_broadcast_description(hub, escaped_desc);
}

void hub_apply_ban(struct hub_info* hub, const char* cid, const char* nick, int propagate)
{
	struct hub_user* u;

	/* Add to this node's runtime ACL so the user cannot reconnect here
	   (check_acl consults acl_is_*_banned at login). */
	if (cid && *cid)
		acl_user_ban_cid(hub->acl, cid);
	if (nick && *nick)
		acl_user_ban_nick(hub->acl, nick);

	/* Persist the ban through a storage plugin (write-through), so it survives a
	   reload/restart -- the runtime ACL above is rebuilt from config on reload.
	   No-op when no storage plugin is loaded, in which case the ban lives only in
	   the in-memory ACL and is lost on restart. Done regardless of propagate, so
	   each node persists its own copy of a cluster-wide ban. */
	{
		struct ban_info ban;
		memset(&ban, 0, sizeof(ban));
		if (cid && *cid)
		{
			ban.flags |= ban_cid;
			strncpy(ban.cid, cid, MAX_CID_LEN);
			ban.cid[MAX_CID_LEN] = '\0';
		}
		if (nick && *nick)
		{
			ban.flags |= ban_nickname;
			strncpy(ban.nickname, nick, MAX_NICK_LEN);
			ban.nickname[MAX_NICK_LEN] = '\0';
		}
		if (ban.flags)
			plugin_ban_add(hub, &ban);
	}

	/* Disconnect a matching locally-connected user. The session lives on exactly
	   one node; that node drops it here, while remote-user records on other nodes
	   are cleaned up by the owning node's LQUI. */
	if (cid && *cid)
	{
		u = uman_get_user_by_cid(hub->users, cid);
		if (u && !user_is_remote(u))
			hub_disconnect_user(hub, u, quit_banned);
	}
	if (nick && *nick)
	{
		u = uman_get_user_by_nick(hub->users, nick);
		if (u && !user_is_remote(u))
			hub_disconnect_user(hub, u, quit_banned);
	}

	/* Propagate cluster-wide so the ban applies on every node. A ban received
	   over a link is applied with propagate = 0 (loop-free on a full mesh). */
	if (propagate)
		link_broadcast_ban(hub, cid, nick);
}

int hub_apply_unban(struct hub_info* hub, const char* target, int propagate)
{
	int removed = 0;

	if (!target || !*target)
		return 0;

	/* The same string may be present as a banned nick, a banned CID, or a
	   banned IP/range (a !ban records both a nick and a CID); lift it from each
	   list it appears in. */
	if (acl_user_unban_nick(hub->acl, target) == 0)
		removed++;
	if (acl_user_unban_cid(hub->acl, target) == 0)
		removed++;
	if (acl_user_unban_ip(hub->acl, target) == 0)
		removed++;

	/* Remove any persisted record through the storage plugin. target may be a
	   nick or a CID, so offer it as both and let the plugin match either. */
	{
		struct ban_info ban;
		memset(&ban, 0, sizeof(ban));
		ban.flags = ban_nickname | ban_cid;
		strncpy(ban.nickname, target, MAX_NICK_LEN);
		ban.nickname[MAX_NICK_LEN] = '\0';
		strncpy(ban.cid, target, MAX_CID_LEN);
		ban.cid[MAX_CID_LEN] = '\0';
		if (plugin_ban_del(hub, &ban) == st_allow)
			removed++;
	}

	/* Propagate cluster-wide, mirroring hub_apply_ban. An unban received over a
	   link is applied with propagate = 0 (loop-free on a full mesh). */
	if (removed && propagate)
		link_broadcast_unban(hub, target);

	return removed;
}

void hub_set_variables(struct hub_info* hub, struct acl_handle* acl)
{
	char* tmp;
	char* server = adc_msg_escape(PRODUCT_STRING); /* may be NULL on OOM; only used as a size hint below */

	hub->acl = acl;
	hub->command_info = adc_msg_construct(ADC_CMD_IINF, 15);
	if (hub->command_info)
	{
		adc_msg_add_named_argument(hub->command_info, ADC_INF_FLAG_CLIENT_TYPE, ADC_CLIENT_TYPE_HUB);
		adc_msg_add_named_argument(hub->command_info, ADC_INF_FLAG_USER_AGENT_PRODUCT, PRODUCT);
		adc_msg_add_named_argument(hub->command_info, ADC_INF_FLAG_USER_AGENT_VERSION, GIT_VERSION);

		tmp = adc_msg_escape(hub->config->hub_name);
		adc_msg_add_named_argument(hub->command_info, ADC_INF_FLAG_NICK, tmp);
		hub_free(tmp);

		tmp = adc_msg_escape(hub->config->hub_description);
		adc_msg_add_named_argument(hub->command_info, ADC_INF_FLAG_DESCRIPTION, tmp);
		hub_free(tmp);
	}

	hub->command_support = adc_msg_construct(ADC_CMD_ISUP, 6 + strlen(ADC_PROTO_SUPPORT) + 7);
	if (hub->command_support)
	{
		adc_msg_add_argument(hub->command_support, ADC_PROTO_SUPPORT);
		if (hbri_is_enabled(hub))
			adc_msg_add_argument(hub->command_support, "ADHBRI");
	}

	hub->command_banner = adc_msg_construct(ADC_CMD_ISTA, 100 + (server ? strlen(server) : 0));
	if (hub->command_banner)
	{
		char code[4];
		if (hub->config->show_banner_sys_info)
			tmp = adc_msg_escape("Powered by " PRODUCT_STRING " on " OPSYS "/" CPUINFO);
		else
			tmp = adc_msg_escape("Powered by " PRODUCT_STRING);
		set_status_code(status_level_info, ADC_STATUS_GENERIC, code);
		adc_msg_add_argument(hub->command_banner, code);
		adc_msg_add_argument(hub->command_banner, tmp);
		hub_free(tmp);
	}

	if (hub_plugins_load(hub) < 0)
	{
		LOG_FATAL("Unable to load plugins.");
		hub->status = hub_status_shutdown;
	}
	else

	hub->status = (hub->config->hub_enabled ? hub_status_running : hub_status_disabled);
	hub_free(server);
}


void hub_free_variables(struct hub_info* hub)
{
	hub_plugins_unload(hub);

	adc_msg_free(hub->command_info);
	adc_msg_free(hub->command_banner);
	adc_msg_free(hub->command_support);
}


/**
 * @param hub The hub instance this message is sent from.
 * @param user The user this message is sent to.
 * @param msg See enum status_message
 * @param level See enum status_level
 */
void hub_send_status(struct hub_info* hub, struct hub_user* user, enum status_message msg, enum msg_status_level level)
{
	struct hub_config* cfg = hub->config;
	struct adc_message* cmd = adc_msg_construct(ADC_CMD_ISTA, 6);
	struct adc_message* qui = adc_msg_construct(ADC_CMD_IQUI, 512);
	char code[4];
	char buf[256];
	const char* text = 0;
	const char* flag = 0;
	char* escaped_text = 0;
	int reconnect_time = 0;
	int redirect = 0;

	if (!cmd || !qui)
	{
		adc_msg_free(cmd);
		adc_msg_free(qui);
		return;
	}

/* Stringize, with one level of macro expansion, so RECONNECT_TIME_TEMP_BAN
 * (e.g. 600) yields the string "600" for the "TL" flag below. */
#define HUB_STR_(x) #x
#define HUB_STR(x) HUB_STR_(x)
#define STATUS(CODE, MSG, FLAG, RCONTIME, REDIRECT) case status_ ## MSG : set_status_code(level, CODE, code); text = cfg->MSG; flag = FLAG; reconnect_time = RCONTIME; redirect = REDIRECT; break
	switch (msg)
	{
		STATUS(ADC_STATUS_HUB_FULL, msg_hub_full, 0, RECONNECT_TIME_HUB_FULL, 1);
		STATUS(ADC_STATUS_HUB_DISABLED, msg_hub_disabled, 0, -1, 1);
		STATUS(ADC_STATUS_REGISTERED_ONLY, msg_hub_registered_users_only, 0, 0, 1);
		STATUS(ADC_STATUS_INF_FIELD_BAD, msg_inf_error_nick_missing, 0, 0, 0);
		STATUS(ADC_STATUS_INF_FIELD_BAD, msg_inf_error_nick_multiple, 0, 0, 0);
		STATUS(ADC_STATUS_NICK_INVALID, msg_inf_error_nick_invalid, 0, 0, 0);
		STATUS(ADC_STATUS_NICK_INVALID, msg_inf_error_nick_long, 0, 0, 0);
		STATUS(ADC_STATUS_NICK_INVALID, msg_inf_error_nick_short, 0, 0, 0);
		STATUS(ADC_STATUS_NICK_INVALID, msg_inf_error_nick_spaces, 0, 0, 0);
		STATUS(ADC_STATUS_NICK_INVALID, msg_inf_error_nick_bad_chars, 0, 0, 0);
		STATUS(ADC_STATUS_NICK_INVALID, msg_inf_error_nick_not_utf8, 0, 0, 0);
		STATUS(ADC_STATUS_NICK_TAKEN, msg_inf_error_nick_taken, 0, 0, 0);
		STATUS(ADC_STATUS_NICK_INVALID, msg_inf_error_nick_restricted, 0, 0, 0);
		STATUS(ADC_STATUS_INF_FIELD_BAD, msg_inf_error_cid_invalid, "FBID", 0, 0);
		STATUS(ADC_STATUS_INF_FIELD_BAD, msg_inf_error_cid_missing, "FMID", 0, 0);
		STATUS(ADC_STATUS_CID_TAKEN, msg_inf_error_cid_taken, 0, 0, 0);
		STATUS(ADC_STATUS_INF_FIELD_BAD, msg_inf_error_pid_missing, "FMPD", 0, 0);
		STATUS(ADC_STATUS_INVALID_PID, msg_inf_error_pid_invalid, "FBPD", 0, 0);
		STATUS(ADC_STATUS_BANNED_PERMANENTLY, msg_ban_permanently, 0, 0, 0);
		STATUS(ADC_STATUS_BANNED_TEMPORARILY, msg_ban_temporarily, "TL" HUB_STR(RECONNECT_TIME_TEMP_BAN), RECONNECT_TIME_TEMP_BAN, 0);
		STATUS(ADC_STATUS_INVALID_PASSWORD, msg_auth_invalid_password, 0, 0, 0);
		STATUS(ADC_STATUS_LOGIN_GENERIC, msg_auth_user_not_found, 0, 0, 0);
		STATUS(ADC_STATUS_DISCONNECT_GENERIC, msg_error_no_memory, 0, 0, 0);
		STATUS(ADC_STATUS_INF_FIELD_BAD, msg_user_share_size_low,   "FB" ADC_INF_FLAG_SHARED_SIZE, 0, 1);
		STATUS(ADC_STATUS_INF_FIELD_BAD, msg_user_share_size_high,  "FB" ADC_INF_FLAG_SHARED_SIZE, 0, 1);
		STATUS(ADC_STATUS_INF_FIELD_BAD, msg_user_slots_low,        "FB" ADC_INF_FLAG_UPLOAD_SLOTS, 0, 1);
		STATUS(ADC_STATUS_INF_FIELD_BAD, msg_user_slots_high,       "FB" ADC_INF_FLAG_UPLOAD_SLOTS, 0, 1);
		STATUS(ADC_STATUS_INF_FIELD_BAD, msg_user_hub_limit_low, 0, 0, 1);
		STATUS(ADC_STATUS_INF_FIELD_BAD, msg_user_hub_limit_high, 0, 0, 1);
		STATUS(ADC_STATUS_GENERIC, msg_search_too_short, 0, 0, 0);
		STATUS(ADC_STATUS_NO_COMMON_HASH, msg_proto_no_common_hash, 0, -1, 1);
		STATUS(ADC_STATUS_PROTOCOL_GENERIC, msg_proto_obsolete_adc0, 0, -1, 1);
	}
#undef STATUS
#undef HUB_STR
#undef HUB_STR_

	escaped_text = adc_msg_escape(text);
	if (!escaped_text)
	{
		adc_msg_free(cmd);
		adc_msg_free(qui);
		return;
	}

	adc_msg_add_argument(cmd, code);
	adc_msg_add_argument(cmd, escaped_text);

	if (flag)
	{
		adc_msg_add_argument(cmd, flag);
	}

	route_to_user(hub, user, cmd);

	if (level >= status_level_fatal)
	{
		adc_msg_add_argument(qui, sid_to_string(user->id.sid));

		snprintf(buf, 230, "MS%s", escaped_text);
		adc_msg_add_argument(qui, buf);

		if (reconnect_time != 0)
		{
			snprintf(buf, 10, "TL%d", reconnect_time);
			adc_msg_add_argument(qui, buf);
		}

		if (redirect && *hub->config->redirect_addr)
		{
			snprintf(buf, 255, "RD%s", hub->config->redirect_addr);
			adc_msg_add_argument(qui, buf);
		}
		route_to_user(hub, user, qui);
	}

	hub_free(escaped_text);
	adc_msg_free(cmd);
	adc_msg_free(qui);
}

void hub_redirect_user(struct hub_info* hub, struct hub_user* user, const char* address)
{
	struct adc_message* qui = adc_msg_construct(ADC_CMD_IQUI, 512);
	char buf[300];

	if (!qui)
		return;

	/* Tell the client to reconnect elsewhere: an IQUI carrying the user's own
	 * SID plus an RD (redirect) flag, mirroring the redirect path in
	 * hub_send_status(). The caller has validated the address, so it needs no
	 * escaping. The message is routed before the disconnect, whose pre-close
	 * flush pushes it to the socket. */
	adc_msg_add_argument(qui, sid_to_string(user->id.sid));
	snprintf(buf, sizeof(buf), "RD%s", address);
	adc_msg_add_argument(qui, buf);
	route_to_user(hub, user, qui);
	adc_msg_free(qui);

	hub_disconnect_user(hub, user, quit_disconnected);
}

const char* hub_get_status_message(struct hub_info* hub, enum status_message msg)
{
#define STATUS(MSG) case status_ ## MSG : return cfg->MSG; break
	struct hub_config* cfg = hub->config;
	switch (msg)
	{
		STATUS(msg_hub_full);
		STATUS(msg_hub_disabled);
		STATUS(msg_hub_registered_users_only);
		STATUS(msg_inf_error_nick_missing);
		STATUS(msg_inf_error_nick_multiple);
		STATUS(msg_inf_error_nick_invalid);
		STATUS(msg_inf_error_nick_long);
		STATUS(msg_inf_error_nick_short);
		STATUS(msg_inf_error_nick_spaces);
		STATUS(msg_inf_error_nick_bad_chars);
		STATUS(msg_inf_error_nick_not_utf8);
		STATUS(msg_inf_error_nick_taken);
		STATUS(msg_inf_error_nick_restricted);
		STATUS(msg_inf_error_cid_invalid);
		STATUS(msg_inf_error_cid_missing);
		STATUS(msg_inf_error_cid_taken);
		STATUS(msg_inf_error_pid_missing);
		STATUS(msg_inf_error_pid_invalid);
		STATUS(msg_ban_permanently);
		STATUS(msg_ban_temporarily);
		STATUS(msg_auth_invalid_password);
		STATUS(msg_auth_user_not_found);
		STATUS(msg_error_no_memory);
		STATUS(msg_user_share_size_low);
		STATUS(msg_user_share_size_high);
		STATUS(msg_user_slots_low);
		STATUS(msg_user_slots_high);
		STATUS(msg_user_hub_limit_low);
		STATUS(msg_user_hub_limit_high);
		STATUS(msg_search_too_short);
		STATUS(msg_proto_no_common_hash);
		STATUS(msg_proto_obsolete_adc0);
	}
#undef STATUS
	return "Unknown";
}

const char* hub_get_status_message_log(struct hub_info* hub, enum status_message msg)
{
	(void) hub;
#define STATUS(MSG) case status_ ## MSG : return #MSG; break
	switch (msg)
	{
		STATUS(msg_hub_full);
		STATUS(msg_hub_disabled);
		STATUS(msg_hub_registered_users_only);
		STATUS(msg_inf_error_nick_missing);
		STATUS(msg_inf_error_nick_multiple);
		STATUS(msg_inf_error_nick_invalid);
		STATUS(msg_inf_error_nick_long);
		STATUS(msg_inf_error_nick_short);
		STATUS(msg_inf_error_nick_spaces);
		STATUS(msg_inf_error_nick_bad_chars);
		STATUS(msg_inf_error_nick_not_utf8);
		STATUS(msg_inf_error_nick_taken);
		STATUS(msg_inf_error_nick_restricted);
		STATUS(msg_inf_error_cid_invalid);
		STATUS(msg_inf_error_cid_missing);
		STATUS(msg_inf_error_cid_taken);
		STATUS(msg_inf_error_pid_missing);
		STATUS(msg_inf_error_pid_invalid);
		STATUS(msg_ban_permanently);
		STATUS(msg_ban_temporarily);
		STATUS(msg_auth_invalid_password);
		STATUS(msg_auth_user_not_found);
		STATUS(msg_error_no_memory);
		STATUS(msg_user_share_size_low);
		STATUS(msg_user_share_size_high);
		STATUS(msg_user_slots_low);
		STATUS(msg_user_slots_high);
		STATUS(msg_user_hub_limit_low);
		STATUS(msg_user_hub_limit_high);
		STATUS(msg_search_too_short);
		STATUS(msg_proto_no_common_hash);
		STATUS(msg_proto_obsolete_adc0);
	}
#undef STATUS
	return "unknown";
}


size_t hub_get_user_count(struct hub_info* hub)
{
	return hub->users->count;
}

size_t hub_get_max_user_count(struct hub_info* hub)
{
	return hub->config->max_users;
}

uint64_t hub_get_shared_size(struct hub_info* hub)
{
	return hub->users->shared_size;
}

uint64_t hub_get_shared_files(struct hub_info* hub)
{
	return hub->users->shared_files;
}

uint64_t hub_get_min_share(struct hub_info* hub)
{
	uint64_t size = hub->config->limit_min_share;
	size *= (1024 * 1024);
	return size;
}

uint64_t hub_get_max_share(struct hub_info* hub)
{
        uint64_t size = hub->config->limit_max_share;
        size *= (1024 * 1024);
        return size;
}

size_t hub_get_min_slots(struct hub_info* hub)
{
	return hub->config->limit_min_slots;
}

size_t hub_get_max_slots(struct hub_info* hub)
{
	return hub->config->limit_max_slots;
}

size_t hub_get_max_hubs_total(struct hub_info* hub)
{
	return hub->config->limit_max_hubs;
}

size_t hub_get_max_hubs_user(struct hub_info* hub)
{
	return hub->config->limit_max_hubs_user;
}

size_t hub_get_min_hubs_user(struct hub_info* hub)
{
	return hub->config->limit_min_hubs_user;
}

size_t hub_get_max_hubs_reg(struct hub_info* hub)
{
	return hub->config->limit_max_hubs_reg;
}

size_t hub_get_min_hubs_reg(struct hub_info* hub)
{
	return hub->config->limit_min_hubs_reg;
}

size_t hub_get_max_hubs_op(struct hub_info* hub)
{
	return hub->config->limit_max_hubs_op;
}

size_t hub_get_min_hubs_op(struct hub_info* hub)
{
	return hub->config->limit_min_hubs_op;
}

void hub_schedule_destroy_user(struct hub_info* hub, struct hub_user* user)
{
	struct event_data post;
	memset(&post, 0, sizeof(post));
	post.id = UHUB_EVENT_USER_DESTROY;
	post.ptr = user;
	event_queue_post(hub->queue, &post);

	if (user->id.sid)
	{
		sid_free(hub->users->sids, user->id.sid);
	}
}

void hub_disconnect_all(struct hub_info* hub)
{
	struct event_data post;
	memset(&post, 0, sizeof(post));
	post.id = UHUB_EVENT_HUB_SHUTDOWN;
	post.ptr = 0;
	event_queue_post(hub->queue, &post);
}

void hub_event_loop(struct hub_info* hub)
{
	do
	{
		net_backend_process();
		event_queue_process(hub->queue);
		/* Flush deferred writes last, so output queued while handling events
		   (notably the user-list dump and presence sent on login) is sent in
		   this iteration instead of waiting for the next reactor wakeup -- which
		   on an idle hub is a timer, delaying logins by seconds. */
		route_flush_dirty(hub);
	}
	while (hub->status == hub_status_running || hub->status == hub_status_disabled);


	if (hub->status == hub_status_shutdown)
	{
		LOG_DEBUG("Removing all users...");
		event_queue_process(hub->queue);
		event_queue_process(hub->queue);
		hub_disconnect_all(hub);
		event_queue_process(hub->queue);
		hub->status = hub_status_stopped;
	}
}


void hub_disconnect_user(struct hub_info* hub, struct hub_user* user, int reason)
{
	struct event_data post;
	int need_notify = 0;

	/* is user already being disconnected ? */
	if (user_is_disconnecting(user))
	{
		return;
	}

	/* Drop the user from the master-auth pending registry (if proxying) before
	   it is freed, so a late LACR/LVRS never dereferences it. */
	link_auth_pending_forget(user);

	/* Best-effort flush of queued output before closing. Writes are normally
	   deferred to route_flush_dirty() at end of the event-loop iteration, but a
	   status message routed immediately before a disconnect (e.g. a fatal login
	   error) must still be pushed to the socket before it is closed. */
	if (user->connection && !ioq_send_is_empty(user->send_queue))
		handle_net_write(user);

	/* stop reading from user */
	net_shutdown_r(net_con_get_sd(user->connection));
	net_con_close(user->connection);
	user->connection = 0;

	LOG_TRACE("hub_disconnect_user(), user=%p, reason=%d, state=%d", user, reason, user->state);

	need_notify = user_is_logged_in(user) && hub->status == hub_status_running;
	user->quit_reason = reason;
	user_set_state(user, state_cleanup);

	if (need_notify)
	{
		memset(&post, 0, sizeof(post));
		post.id     = UHUB_EVENT_USER_QUIT;
		post.ptr    = user;
		event_queue_post(hub->queue, &post);
	}
	else
	{
		hub_schedule_destroy_user(hub, user);
	}
}

void hub_logout_log(struct hub_info* hub, struct hub_user* user)
{
	struct hub_logout_info* loginfo = hub_malloc_zero(sizeof(struct hub_logout_info));
	if (!loginfo) return;
	loginfo->time = time(NULL);
	memcpy(loginfo->cid, user->id.cid, sizeof(loginfo->cid));
	memcpy(loginfo->nick, user->id.nick, sizeof(loginfo->nick));
	memcpy(&loginfo->addr, &user->id.addr, sizeof(struct ip_addr_encap));
	loginfo->reason = user->quit_reason;

	list_append(hub->logout_info, loginfo);
	while (list_size(hub->logout_info) > (size_t) hub->config->max_logout_log)
	{
		list_remove_first(hub->logout_info, hub_free_handle);
	}
}
