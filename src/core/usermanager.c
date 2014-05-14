/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2014, Jan Vidar Krey
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

static int uman_map_compare(const void* a, const void* b)
{
	return strcmp((const char*) a, (const char*) b);
}


struct hub_user_manager* uman_init()
{
	struct hub_user_manager* users = (struct hub_user_manager*) hub_malloc_zero(sizeof(struct hub_user_manager));
	if (!users)
		return NULL;

	users->list = list_create();
	users->nickmap = rb_tree_create(uman_map_compare, NULL, NULL);
	users->cidmap = rb_tree_create(uman_map_compare, NULL, NULL);
	users->sids = sid_pool_create(net_get_max_sockets());

	return users;
}


int uman_shutdown(struct hub_user_manager* users)
{
	if (!users)
		return -1;

	if (users->nickmap)
		rb_tree_destroy(users->nickmap);

	if (users->cidmap)
		rb_tree_destroy(users->cidmap);

	if (users->list)
	{
		list_clear(users->list, &clear_user_list_callback);
		list_destroy(users->list);
	}

	sid_pool_destroy(users->sids);

	hub_free(users);
	return 0;
}


int uman_add(struct hub_user_manager* users, struct hub_user* user)
{
	if (!users || !user)
		return -1;

	rb_tree_insert(users->nickmap, user->id.nick, user);
	rb_tree_insert(users->cidmap, user->id.cid, user);

	list_append(users->list, user);
	users->count++;
	users->count_peak = MAX(users->count, users->count_peak);

	users->shared_size  += user->limits.shared_size;
	users->shared_files += user->limits.shared_files;
	return 0;
}

int uman_remove(struct hub_user_manager* users, struct hub_user* user)
{
	if (!users || !user)
		return -1;

	list_remove(users->list, user);
	rb_tree_remove(users->nickmap, user->id.nick);
	rb_tree_remove(users->cidmap, user->id.cid);

	if (users->count > 0)
	{
		users->count--;
	}
	else
	{
		uhub_assert(!"negative count!");
	}

	users->shared_size  -= user->limits.shared_size;
	users->shared_files -= user->limits.shared_files;
	return 0;
}


struct hub_user* uman_get_user_by_sid(struct hub_user_manager* users, sid_t sid)
{
	return sid_lookup(users->sids, sid);
}


struct hub_user* uman_get_user_by_cid(struct hub_user_manager* users, const char* cid)
{
	struct hub_user* user = (struct hub_user*) rb_tree_get(users->cidmap, (const void*) cid);
	return user;
}


struct hub_user* uman_get_user_by_nick(struct hub_user_manager* users, const char* nick)
{
	struct hub_user* user = (struct hub_user*) rb_tree_get(users->nickmap, nick);
	return user;
}

size_t uman_get_user_by_addr(struct hub_user_manager* users, struct linked_list* target, struct ip_range* range)
{
	size_t num = 0;
	struct hub_user* user;
	LIST_FOREACH(struct hub_user*, user, users->list,
	{
		if (ip_in_range(&user->id.addr, range))
		{
			list_append(target, user);
			num++;
		}
	});
	return num;
}

int uman_send_user_list(struct hub_info* hub, struct hub_user_manager* users, struct hub_user* target)
{
	int ret = 1;
	struct hub_user* user;
	user_flag_set(target, flag_user_list);

	LIST_FOREACH(struct hub_user*, user, users->list,
	{
		if (user_is_logged_in(user))
		{
			ret = route_to_user(hub, target, user->info);
			if (!ret)
				break;
		}
	});

#if 0
	FIXME: FIXME FIXME handle send queue excess
	if (!target->send_queue_size)
	{
	    user_flag_unset(target, flag_user_list);
	}
#endif
	return ret;
}

void uman_send_quit_message(struct hub_info* hub, struct hub_user_manager* users, struct hub_user* leaving)
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

sid_t uman_get_free_sid(struct hub_user_manager* users, struct hub_user* user)
{
	sid_t sid = sid_alloc(users->sids, user);
	user->id.sid = sid;
	return sid;
}

