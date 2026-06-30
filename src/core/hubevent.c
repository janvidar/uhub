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

#include "adc/message.h"
#include "network/connection.h"
#include "core/hbri.h"
#include "core/hub.h"
#include "core/hubevent.h"
#include "core/link.h"
#include "core/netevent.h"
#include "core/plugininvoke.h"
#include "core/route.h"
#include "core/usermanager.h"
#include "plugin_api/handle.h"

/* Notify plugins, etc */
void on_login_success(struct hub_info* hub, struct hub_user* u)
{
	/* Send user list of all existing users */
	if (!uman_send_user_list(hub, hub->users, u))
		return;

	/*
	 * Flush the freshly-queued user list to the socket now. The list is sent
	 * with the send-queue limit bypassed (flag_user_list) and, since writes are
	 * deferred to route_flush_dirty() at the end of the iteration, it would
	 * otherwise sit in the send queue. On a populated hub that backlog exceeds
	 * max_send_buffer, so the very next route to this user -- route_info_message()
	 * below -- would trip the hard send-queue limit and disconnect the user
	 * mid-login (nulling u->connection and crashing the code after this point).
	 * Draining it here keeps the deferred-write fast path for steady-state
	 * traffic while restoring correct login behaviour.
	 */
	if (u->connection && handle_net_write(u))
	{
		hub_disconnect_user(hub, u, quit_send_queue);
		return;
	}

	/* Mark as being in the normal state, and add user to the user list */
	user_set_state(u, state_normal);
	uman_add(hub->users, u);

	/*
	 * HBRI: the user logs in immediately over its primary protocol. If it also
	 * advertised an address in the other protocol family, strip that (still
	 * unverified) address before the INF is broadcast and ask the client to
	 * prove it. On success the address is added back via an INF update; if it
	 * never validates the user simply stays primary-only. This must run before
	 * route_info_message() so the unverified address is never advertised.
	 */
	hbri_on_login(hub, u);

	/* Announce new user to all connected users */
	if (user_is_logged_in(u))
	{
		route_info_message(hub, u);
		/* Propagate the new local user to linked hubs (live join). */
		link_broadcast_local_inf(hub, u);
	}

	plugin_log_user_login_success(hub, u);
	hub->metrics.logins++;

	/* reset timeout -- guard against a disconnect triggered while routing above
	   (e.g. a send-queue overflow), which clears u->connection. */
	if (u->connection)
		net_con_clear_timeout(u->connection);
}

void on_login_failure(struct hub_info* hub, struct hub_user* u, enum status_message msg)
{
	plugin_log_user_login_error(hub, u, hub_get_status_message_log(hub, msg));
	hub->metrics.login_failures++;
	hub_send_status(hub, u, msg, status_level_fatal);
	hub_disconnect_user(hub, u, quit_logon_error);
}

void on_update_failure(struct hub_info* hub, struct hub_user* u, enum status_message msg)
{
	plugin_log_user_update_error(hub, u, hub_get_status_message_log(hub, msg));
	hub_send_status(hub, u, msg, status_level_fatal);
	hub_disconnect_user(hub, u, quit_update_error);
}

void on_nick_change(struct hub_info* hub, struct hub_user* u, const char* nick)
{
	if (user_is_logged_in(u))
	{
		plugin_log_user_nick_change(hub, u, nick);
	}
}

void on_logout_user(struct hub_info* hub, struct hub_user* user)
{
	const char* reason = user_get_quit_reason_string(user->quit_reason);

	plugin_log_user_logout(hub, user, reason);
	hub_logout_log(hub, user);

	/* Only count teardown of users that actually completed login, so the count
	   pairs with metrics.logins (connecting users that never logged in quit here
	   too, but were counted as login_failures instead). */
	if (user_is_logged_in(user))
		hub->metrics.logouts++;
}

