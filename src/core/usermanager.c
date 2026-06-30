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

#include "util/log.h"
#include "util/memory.h"
#include "util/rbtree.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "network/network.h"
#include "core/route.h"
#include "core/user.h"
#include "core/usermanager.h"

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


struct hub_user_manager* uman_init(int node_id, int node_count)
{
	struct hub_user_manager* users = (struct hub_user_manager*) hub_malloc_zero(sizeof(struct hub_user_manager));
	if (!users)
		return NULL;

	users->list = list_create();
	users->nickmap = rb_tree_create(uman_map_compare, NULL, NULL);
	users->cidmap = rb_tree_create(uman_map_compare, NULL, NULL);

	if (node_count > 1)
	{
		/* Federated cluster: split the shared ~1M SID space into node_count
		   disjoint windows and allocate local SIDs only from this node's
		   window, so SIDs stay globally unique without coordination. The map
		   spans the whole space so remote users (other nodes' windows) resolve
		   through the same table. */
		sid_t window;
		sid_t base;
		sid_t min;
		sid_t max;

		if (node_id < 0 || node_id >= node_count)
		{
			LOG_ERROR("node_id %d out of range for node_count %d; using node 0", node_id, node_count);
			node_id = 0;
		}

		window = SID_MAX / (sid_t) node_count;
		base   = (sid_t) node_id * window;
		min    = base ? base : 1;          /* SID 0 is reserved for the hub */
		max    = base + window - 1;
		users->sids = sid_pool_create_range(SID_MAX, min, max);
		LOG_INFO("SID partitioning: node %d/%d owns SID window [%u, %u]",
			node_id, node_count, (unsigned) min, (unsigned) max);
	}
	else
	{
		users->sids = sid_pool_create(net_get_max_sockets());
	}

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

	if (!rb_tree_insert(users->nickmap, user->id.nick, user))
		return -1;

	if (!rb_tree_insert(users->cidmap, user->id.cid, user))
	{
		rb_tree_remove(users->nickmap, user->id.nick);
		return -1;
	}

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


int uman_add_remote(struct hub_user_manager* users, struct hub_user* user)
{
	if (!users || !user)
		return -1;

	/* A remote user arrives with a SID already assigned from the peer node's
	   window, so insert it (not allocate). Roll back the SID slot if the
	   nick/CID maps reject it (a cluster-wide collision -- handled by B5). */
	if (!sid_pool_insert(users->sids, user->id.sid, user))
		return -1;

	if (uman_add(users, user) != 0)
	{
		sid_free(users->sids, user->id.sid);
		return -1;
	}
	return 0;
}

int uman_remove_remote(struct hub_user_manager* users, struct hub_user* user)
{
	if (!users || !user)
		return -1;

	/* Mirror of uman_add_remote: drop the maps/list/count (uman_remove) and
	   release the SID slot. Freeing the user struct is the caller's job, as
	   with local users. */
	uman_remove(users, user);
	sid_free(users->sids, user->id.sid);
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

	/* The userlist is fully queued. */
	user_flag_unset(target, flag_user_list);
	return ret;
}

void uman_send_quit_message(struct hub_info* hub, struct hub_user_manager* users, struct hub_user* leaving)
{
	struct adc_message* command = adc_msg_construct(ADC_CMD_IQUI, 6);
	adc_msg_add_argument(command, (const char*) sid_to_string(leaving->id.sid));

	if (leaving->quit_reason == quit_banned || leaving->quit_reason == quit_kicked)
	{
		adc_msg_add_named_argument(command, ADC_QUI_FLAG_DISCONNECT, "1");
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

