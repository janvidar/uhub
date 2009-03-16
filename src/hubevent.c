/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2009, Jan Vidar Krey
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

/* Send MOTD, do logging etc */
void on_login_success(struct user* u)
{
	/* Logging - FIXME: Move this to a plugin */
	const char* addr = ip_convert_to_string(&u->ipaddr);
	const char* credentials_string[] = { "!none!", "link", "guest", "user", "operator", "super", "admin" };
	struct timeval timeout = { TIMEOUT_IDLE, 0 };
	
	/* Send user list of all existing users */
	if (!send_user_list(u))
		return;

	/* Mark as being in the normal state, and add user to the user list */
	user_set_state(u, state_normal);
	user_manager_add(u);

	/* Print log message */
	hub_log(log_user, "Login OK    %s/%s \"%s\" [%s] (%s) \"%s\"", sid_to_string(u->id.sid), u->id.cid, u->id.nick, addr, credentials_string[u->credentials], u->user_agent);

	/* Announce new user to all connected users */
	if (user_is_logged_in(u))
		route_info_message(u);
	
	/* Send message of the day (if any) */
	if (user_is_logged_in(u)) /* Previous send() can fail! */
		hub_send_motd(u);
		
	/* reset to idle timeout */
	if (u->ev_read)
		event_add(u->ev_read, &timeout);
}


void on_login_failure(struct user* u, enum status_message msg)
{
	const char* addr = ip_convert_to_string(&u->ipaddr);
	const char* message = hub_get_status_message(u->hub, msg);
	hub_log(log_user, "Login FAIL  %s/%s \"%s\" [%s] (%s) \"%s\"", sid_to_string(u->id.sid), u->id.cid, u->id.nick, addr, message, u->user_agent);
	
	hub_send_status(u, msg, status_level_fatal);
	user_disconnect(u, quit_logon_error);
}


void on_nick_change(struct user* u, const char* nick)
{
	if (user_is_logged_in(u))
	{
		hub_log(log_user, "Nick change %s/%s \"%s\" -> \"%s\"", sid_to_string(u->id.sid), u->id.cid, u->id.nick, nick);
	}
}


void on_logout_user(struct user* user)
{
	const char* reason = "";
	const char* addr;
	
	/* These are used for logging purposes */
	switch (user->quit_reason)
	{
		case quit_disconnected:     reason = "disconnected";    break;
		case quit_kicked:           reason = "kicked";         break;
		case quit_banned:           reason = "banned";         break;
		case quit_timeout:          reason = "timeout";        break;
		case quit_send_queue:       reason = "send queue";     break;
		case quit_memory_error:     reason = "out of memory";  break;
		case quit_socket_error:     reason = "socket error";   break;
		case quit_protocol_error:   reason = "protocol error"; break;
		case quit_logon_error:      reason = "login error";    break;
		case quit_hub_disabled:     reason = "hub disabled";   break;
		default:
			if (user->hub->status == hub_status_shutdown)
				reason = "hub shutdown";
			else
				reason = "unknown error";
			break;
	}
	
	addr = ip_convert_to_string(&user->ipaddr);
	hub_log(log_user, "Logout      %s/%s \"%s\" [%s] (%s)", sid_to_string(user->id.sid), user->id.cid, user->id.nick, addr, reason);

	
	user->quit_reason = 0;
}

