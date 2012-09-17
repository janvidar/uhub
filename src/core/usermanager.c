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
		struct hub_user* u = (struct hub_user*) ptr;
		
		/* Mark the user as already being disconnected.
		 * This prevents the hub from trying to send
		 * quit messages to other users.
		 */
		u->credentials = auth_cred_none;
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
	LOG_INFO("Statistics  users=" PRINTF_SIZE_T " (peak_users=" PRINTF_SIZE_T "), net_tx=%d KB/s, net_rx=%d KB/s (peak_tx=%d KB/s, peak_rx=%d KB/s)",
		hub->users->count,
		hub->users->count_peak,
		(int) hub->stats.net_tx / 1024,
		(int) hub->stats.net_rx / 1024,
		(int) hub->stats.net_tx_peak / 1024,
		(int) hub->stats.net_rx_peak / 1024);
}

static void timer_statistics(struct timeout_evt* t)
{
	struct hub_info* hub = (struct hub_info*) t->ptr;
	uman_update_stats(hub);
	timeout_queue_reschedule(net_backend_get_timeout_queue(), hub->users->timeout, TIMEOUT_STATS);
}

int add_reserved_sid(char* nick, int splitcount, void* data)
{
	struct hub_user_manager* users = (struct hub_user_manager*)data;

	/* Safety check: make sure the nickname can fit. */
	size_t nicklen = strlen(nick);
	if(nicklen > MAX_NICK_LEN)
	{
		LOG_ERROR("Nickname %s for reserved SID is too long (length %d, max %d)", nick, nicklen, MAX_NICK_LEN);
		return -1;
	}

	/* Try to create a structure for the new reserved SID. */
	struct reserved_sid* newresv = (struct reserved_sid*)hub_malloc(sizeof(struct reserved_sid));
	if(newresv == NULL)
	{
		LOG_ERROR("Could not allocate memory for reserved SID for %s", nick);
		return -1;
	}

	/* Try to create a dummy user for the reserved SID. */
	newresv->dummy_user = (struct hub_user*)hub_malloc(sizeof(struct hub_user));
	if(newresv->dummy_user == NULL)
	{
		LOG_ERROR("Could not allocate memory for reserved SID for %s", nick);
		hub_free(newresv);
		return -1;
	}
	strncpy(newresv->dummy_user->id.nick, nick, nicklen+1);

	/* No users logged in at this point. */
	newresv->real_user = NULL;

	/* Allocate the SID. */
	newresv->pool = users->sids;
	newresv->sid = sid_alloc(users->sids, newresv->dummy_user);

	/* Add to the list and keep track of how many we've allocated. */
	list_append(users->reserved, newresv);
	users->reserved_end = newresv->sid;

	/* Done. */
	LOG_INFO("Reserved SID %s for %s", sid_to_string(newresv->sid), newresv->dummy_user->id.nick);
	return 1;
}

void remove_reserved_sid(void *node)
{
	struct reserved_sid* resv = (struct reserved_sid*)node;
	LOG_INFO("Removing reserved SID %s for %s", sid_to_string(resv->sid), resv->dummy_user->id.nick);
	sid_free(resv->pool, resv->sid);
	hub_free(resv->dummy_user);
	hub_free(resv);
}

int uman_init(struct hub_info* hub)
{
	struct hub_user_manager* users = NULL;
	if (!hub)
		return -1;

	users = (struct hub_user_manager*) hub_malloc_zero(sizeof(struct hub_user_manager));
	if (!users)
		return -1;

	users->list = list_create();
	users->sids = sid_pool_create(net_get_max_sockets());

	if (!users->list)
	{
		list_destroy(users->list);
		hub_free(users);
		return -1;
	}

	if (net_backend_get_timeout_queue())
	{
		users->timeout = hub_malloc_zero(sizeof(struct timeout_evt));
		timeout_evt_initialize(users->timeout, timer_statistics, hub);
		timeout_queue_insert(net_backend_get_timeout_queue(), users->timeout, TIMEOUT_STATS);
	}

	/* Process any reserved SIDs. */
	users->reserved = list_create();
	users->reserved_end = 0;
	string_split(hub->config->reserved_sids, " ", (void*)users, &add_reserved_sid);

	hub->users = users;
	return 0;
}


int uman_shutdown(struct hub_info* hub)
{
	if (!hub || !hub->users)
		return -1;

	if (net_backend_get_timeout_queue())
	{
		timeout_queue_remove(net_backend_get_timeout_queue(), hub->users->timeout);
		hub_free(hub->users->timeout);
	}

	if (hub->users->reserved)
	{
		list_clear(hub->users->reserved, &remove_reserved_sid);
		list_destroy(hub->users->reserved);
	}

	if (hub->users->list)
	{
		list_clear(hub->users->list, &clear_user_list_callback);
		list_destroy(hub->users->list);
	}
	sid_pool_destroy(hub->users->sids);
	hub_free(hub->users);
	hub->users = 0;


	return 0;
}


int uman_add(struct hub_info* hub, struct hub_user* user)
{
	if (!hub || !user)
		return -1;

	if (user->hub)
		return -1;

	/* Check if a SID has been reserved for this user. NB. user must be
	 * registered for reserved SIDs to be used. */
	if(hub->users->reserved_end && user->credentials >= auth_cred_user)
	{
		struct reserved_sid* resv = (struct reserved_sid*)list_get_first(hub->users->reserved);
		while(resv)
		{
			if(strcmp(resv->dummy_user->id.nick, user->id.nick) == 0)
			{
				resv->real_user = user;
				LOG_INFO("Reserved user %s logged in.", user->id.nick);
				break;
			}
			resv = (struct reserved_sid*)list_get_next(hub->users->reserved);
		}
	}

	list_append(hub->users->list, user);
	hub->users->count++;
	hub->users->count_peak = MAX(hub->users->count, hub->users->count_peak);

	hub->users->shared_size  += user->limits.shared_size;
	hub->users->shared_files += user->limits.shared_files;

	user->hub = hub;
	return 0;
}

int uman_remove(struct hub_info* hub, struct hub_user* user)
{
	if (!hub || !user)
		return -1;

	/* Check if a SID has been reserved for this user. */
	if(hub->users->reserved_end)
	{
		struct reserved_sid* resv = (struct reserved_sid*)list_get_first(hub->users->reserved);
		while(resv)
		{
			if(resv->real_user == user)
			{
				resv->real_user = NULL;
				LOG_INFO("Reserved user %s has left the building.", user->id.nick);
				break;
			}
			resv = (struct reserved_sid*)list_get_next(hub->users->reserved);
		}
	}

	list_remove(hub->users->list, user);

	if (hub->users->count > 0)
	{
		hub->users->count--;
	}
	else
	{
		uhub_assert(!"negative count!");
	}

	hub->users->shared_size  -= user->limits.shared_size;
	hub->users->shared_files -= user->limits.shared_files;

	user->hub = 0;

	return 0;
}


struct hub_user* uman_get_user_by_sid(struct hub_info* hub, sid_t sid)
{
	/* This is a reserved SID. */
	if(sid && sid <= hub->users->reserved_end)
	{
		struct reserved_sid* resv = (struct reserved_sid*)list_get_index(hub->users->reserved, sid-1);

		/* See if the real user is currently logged on and return accordingly. */
		if(resv->real_user != NULL) return resv->real_user;
		return 0;
	}

	/* Use the SID lookup code. */
	return sid_lookup(hub->users->sids, sid);
}


struct hub_user* uman_get_user_by_cid(struct hub_info* hub, const char* cid)
{
	struct hub_user* user = (struct hub_user*) list_get_first(hub->users->list); /* iterate users - only on incoming INF msg */
	while (user)
	{
		if (strcmp(user->id.cid, cid) == 0)
			return user;
		user = (struct hub_user*) list_get_next(hub->users->list);
	}
	return NULL;
}


struct hub_user* uman_get_user_by_nick(struct hub_info* hub, const char* nick)
{
	struct hub_user* user = (struct hub_user*) list_get_first(hub->users->list); /* iterate users - only on incoming INF msg */
	while (user)
	{
		if (strcmp(user->id.nick, nick) == 0)
			return user;
		user = (struct hub_user*) list_get_next(hub->users->list);
	}
	return NULL;
}

size_t uman_get_user_by_addr(struct hub_info* hub, struct linked_list* users, struct ip_range* range)
{
	size_t num = 0;
	struct hub_user* user = (struct hub_user*) list_get_first(hub->users->list); /* iterate users - only on incoming INF msg */
	while (user)
	{
		if (ip_in_range(&user->id.addr, range))
		{
			list_append(users, user);
			num++;
		}
		user = (struct hub_user*) list_get_next(hub->users->list);
	}
	return num;
}

int uman_send_user_list(struct hub_info* hub, struct hub_user* target)
{
	int ret = 1;
	struct hub_user* user;
	user_flag_set(target, flag_user_list);
	user = (struct hub_user*) list_get_first(hub->users->list); /* iterate users - only on INF or PAS msg */
	while (user)
	{
		if (user_is_logged_in(user))
		{
			ret = route_to_user(hub, target, user->info);
			if (!ret)
				break;
		}
		user = (struct hub_user*) list_get_next(hub->users->list);
	}

#if 0
	FIXME: FIXME FIXME handle send queue excess
	if (!target->send_queue_size)
	{
	    user_flag_unset(target, flag_user_list);
	}
#endif
	return ret;
}

void uman_send_quit_message(struct hub_info* hub, struct hub_user* leaving)
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

sid_t uman_get_free_sid(struct hub_info* hub, struct hub_user* user)
{
	sid_t sid = sid_alloc(hub->users->sids, user);
	user->id.sid = sid;
	return sid;
}

