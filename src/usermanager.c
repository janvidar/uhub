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

/*
 * This callback function is used to clear user objects from the userlist.
 * Should only be used in uman_shutdown().
 */
static void clear_user_list_callback(void* ptr)
{
	if (ptr)
	{
		struct user* u = (struct user*) ptr;
		
		/* Mark the user as already being disconnected.
		 * This prevents the hub from trying to send
		 * quit messages to other users.
		 */
		u->credentials = cred_none;
		user_destroy(u);
	}
}


void uman_update_stats(struct hub_info* hub)
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


void uman_print_stats(struct hub_info* hub)
{
	hub_log(log_info, "Statistics  users=%zu (peak_users=%zu), net_tx=%d KB/s, net_rx=%d KB/s (peak_tx=%d KB/s, peak_rx=%d KB/s)",
		hub->users->count,
		hub->users->count_peak,
		(int) hub->stats.net_tx / 1024,
		(int) hub->stats.net_rx / 1024,
		(int) hub->stats.net_tx_peak / 1024,
		(int) hub->stats.net_rx_peak / 1024);
}

#ifdef USERMANAGER_TIMER
static void timer_statistics(int fd, short ev, void *arg)
{
	struct hub_info* hub = (struct hub_info*) arg;
	struct timeval timeout = { TIMEOUT_STATS, 0 };
	uman_update_stats(hub);
	evtimer_set(&hub->ev_timer, timer_statistics, hub);
	event_base_set(hub->evbase, &hub->ev_timer);
	evtimer_add(&hub->ev_timer, &timeout);
}
#endif


int uman_init(struct hub_info* hub)
{
	struct user_manager* users = NULL;
#ifdef USERMANAGER_TIMER
	struct timeval timeout = { TIMEOUT_STATS, 0 };
#endif
	if (!hub)
		return -1;

	users = (struct user_manager*) hub_malloc_zero(sizeof(struct user_manager));
	if (!users)
		return -1;

	users->list = list_create();
	users->free_sid = 1;
	
	if (!users->list)
	{
		list_destroy(users->list);
		return -1;
	}
	
	hub->users = users;

#ifdef USERMANAGER_TIMER
	evtimer_set(&hub->ev_timer, timer_statistics, hub);
	event_base_set(hub->evbase, &hub->ev_timer);
	evtimer_add(&hub->ev_timer, &timeout);
#endif // 0
	return 0;
}


int uman_shutdown(struct hub_info* hub)
{
	if (!hub || !hub->users)
		return -1;

#ifdef USERMANAGER_TIMER
	event_del(&hub->ev_timer);
#endif

	if (hub->users->list)
	{
		list_clear(hub->users->list, &clear_user_list_callback);
		list_destroy(hub->users->list);
	}
	hub_free(hub->users);
	hub->users = 0;

	return 0;
}


int uman_add(struct hub_info* hub, struct user* user)
{
	if (!hub || !user)
		return -1;

	if (user->hub)
		return -1;

	list_append(hub->users->list, user);
	hub->users->count++;
	hub->users->count_peak = MAX(hub->users->count, hub->users->count_peak);

	hub->users->shared_size  += user->limits.shared_size;
	hub->users->shared_files += user->limits.shared_files;

	user->hub = hub;
	return 0;
}

int uman_remove(struct hub_info* hub, struct user* user)
{
	if (!hub || !user)
		return -1;

	list_remove(hub->users->list, user);
	
	if (hub->users->count > 0)
	{
		hub->users->count--;
	}
	else
	{
		assert(!"negative count!");
	}
	
	hub->users->shared_size  -= user->limits.shared_size;
	hub->users->shared_files -= user->limits.shared_files;

	user->hub = 0;
	
	return 0;
}


struct user* uman_get_user_by_sid(struct hub_info* hub, sid_t sid)
{
	struct user* user = (struct user*) list_get_first(hub->users->list); /* iterate users */
	while (user)
	{
		if (user->id.sid == sid)
			return user;
		user = (struct user*) list_get_next(hub->users->list);
	}
	return NULL;
}


struct user* uman_get_user_by_cid(struct hub_info* hub, const char* cid)
{
	struct user* user = (struct user*) list_get_first(hub->users->list); /* iterate users - only on incoming INF msg */
	while (user)
	{
		if (strcmp(user->id.cid, cid) == 0)
			return user;
		user = (struct user*) list_get_next(hub->users->list);
	}
	return NULL;
}


struct user* uman_get_user_by_nick(struct hub_info* hub, const char* nick)
{
	struct user* user = (struct user*) list_get_first(hub->users->list); /* iterate users - only on incoming INF msg */
	while (user)
	{
		if (strcmp(user->id.nick, nick) == 0)
			return user;
		user = (struct user*) list_get_next(hub->users->list);
	}
	return NULL;
}


int uman_send_user_list(struct hub_info* hub, struct user* target)
{
	int ret = 1;
	user_flag_set(target, flag_user_list);
	struct user* user = (struct user*) list_get_first(hub->users->list); /* iterate users - only on INF or PAS msg */
	while (user)
	{
		if (user_is_logged_in(user))
		{
			ret = route_to_user(hub, target, user->info);
			if (!ret)
				break;
		}
		user = (struct user*) list_get_next(hub->users->list);
	}
	
	if (!target->send_queue_size)
	{
	    user_flag_unset(target, flag_user_list);
	}
	return ret;
}


void uman_send_quit_message(struct hub_info* hub, struct user* leaving)
{
	struct adc_message* command = adc_msg_construct(ADC_CMD_IQUI, 6);
	adc_msg_add_argument(command, (const char*) sid_to_string(leaving->id.sid));
	
	if (leaving->quit_reason == quit_banned || leaving->quit_reason == quit_kicked)
	{
		adc_msg_add_argument(command, ADC_QUI_FLAG_DISCONNECT);
	}
	
	route_to_all(hub, command);
	adc_msg_free(command);
}


sid_t uman_get_free_sid(struct hub_info* hub)
{
#if 0
	struct user* user;
	user = (struct user*) list_get_first(hub->users->list); /* iterate normal users */
	while (user)
	{
		if (user->sid == hub->users->free_sid)
		{
			hub->users->free_sid++;
			if (hub->users->free_sid >= SID_MAX) hub->users->free_sid = 1;
			break;
		}
		user = (struct user*) list_get_next(hub->users->list);
	}
#endif
	return hub->users->free_sid++;
}

