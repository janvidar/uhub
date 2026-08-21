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

#include "fuse/roster.h"
#include "fuse/nodes.h"
#include "adc/adcconst.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "util/memory.h"
#include "util/rbtree.h"

static int cmp_cid(const void* a, const void* b)
{
	return strcmp((const char*) a, (const char*) b);
}

/* SIDs are 20 bits, so the difference cannot overflow an int. */
static int cmp_sid(const void* a, const void* b)
{
	return (int) ((intptr_t) a - (intptr_t) b);
}

static const void* sid_key(sid_t sid)
{
	return (const void*) (intptr_t) sid;
}

struct fs_roster* fs_roster_create(void)
{
	struct fs_roster* roster = (struct fs_roster*) hub_malloc_zero(sizeof(struct fs_roster));
	if (!roster)
		return NULL;

	roster->by_sid = rb_tree_create(cmp_sid, NULL, NULL);
	roster->by_cid = rb_tree_create(cmp_cid, NULL, NULL);

	if (!roster->by_sid || !roster->by_cid)
	{
		fs_roster_destroy(roster);
		return NULL;
	}

	return roster;
}

static void user_free(struct fs_roster_user* user)
{
	if (!user)
		return;

	adc_msg_free(user->inf);
	hub_free(user);
}

void fs_roster_clear(struct fs_roster* roster)
{
	struct rb_node* node;

	if (!roster)
		return;

	/* The CID key is inside the user struct, so the user must come out of both
	   trees before it is freed. */
	while ((node = rb_tree_first(roster->by_sid)) != NULL)
	{
		struct fs_roster_user* user = (struct fs_roster_user*) node->value;

		rb_tree_remove(roster->by_sid, node->key);
		if (user)
		{
			rb_tree_remove(roster->by_cid, user->cid);
			user_free(user);
		}
	}

	/*
	 * Reset the CID tree's iterator, which the loop above never touched: it
	 * only ever removed from that tree. A walk left in progress by anybody --
	 * a lookup that stopped at its match, a listing that returned early --
	 * leaves a stack behind, and rb_tree_destroy() aborts on one. On an empty
	 * tree this clears it and returns NULL, which is the only way to say
	 * "abandon any walk" through that API.
	 */
	rb_tree_first(roster->by_cid);
}

void fs_roster_destroy(struct fs_roster* roster)
{
	if (!roster)
		return;

	if (roster->by_sid && roster->by_cid)
		fs_roster_clear(roster);

	if (roster->by_sid)
		rb_tree_destroy(roster->by_sid);

	if (roster->by_cid)
		rb_tree_destroy(roster->by_cid);

	hub_free(roster);
}

/**
 * Merge @p update into @p user's stored INF.
 *
 * Field by field, so a partial update keeps everything it did not mention.
 * On OOM the previous INF is kept and the update is dropped -- stale is better
 * than half-applied.
 */
static int merge_inf(struct fs_roster_user* user, struct adc_message* update)
{
	struct adc_message* merged = adc_msg_copy(user->inf);
	char* argument;
	size_t n = 0;

	if (!merged)
		return 0;

	argument = adc_msg_get_argument(update, n++);
	while (argument)
	{
		if (strlen(argument) >= 2)
		{
			char prefix[2] = { argument[0], argument[1] };
			adc_msg_replace_named_argument(merged, prefix, argument + 2);
		}

		hub_free(argument);
		argument = adc_msg_get_argument(update, n++);
	}

	adc_msg_free(user->inf);
	user->inf = merged;
	return 1;
}

enum fs_roster_result fs_roster_update(struct fs_roster* roster, struct adc_message* binf, time_t now)
{
	struct fs_roster_user* user;
	char* cid;

	if (!roster || !binf || !binf->source)
		return FS_ROSTER_REJECTED;

	user = fs_roster_by_sid(roster, binf->source);
	if (user)
		return merge_inf(user, binf) ? FS_ROSTER_UPDATED : FS_ROSTER_REJECTED;

	/* A first INF without an ID is either a hub that does not relay one or a
	   user the mount cannot name. Either way there is no path to put them at. */
	cid = adc_msg_get_named_argument(binf, ADC_INF_FLAG_CLIENT_ID);
	if (!cid)
		return FS_ROSTER_REJECTED;

	if (!fs_is_base32_hash(cid))
	{
		hub_free(cid);
		return FS_ROSTER_REJECTED;
	}

	user = (struct fs_roster_user*) hub_malloc_zero(sizeof(struct fs_roster_user));
	if (!user)
	{
		hub_free(cid);
		return FS_ROSTER_REJECTED;
	}

	user->sid = binf->source;
	user->since = now;
	memcpy(user->cid, cid, MAX_CID_LEN + 1);
	hub_free(cid);

	user->inf = adc_msg_copy(binf);
	if (!user->inf)
	{
		user_free(user);
		return FS_ROSTER_REJECTED;
	}

	/* Two SIDs claiming one CID is a hub that let a ghost linger. The newcomer
	   is the one whose SID is live, so it wins the CID and the old entry goes. */
	{
		struct fs_roster_user* incumbent = fs_roster_by_cid(roster, user->cid);
		if (incumbent)
			fs_roster_remove(roster, incumbent->sid);
	}

	if (!rb_tree_insert(roster->by_sid, sid_key(user->sid), user))
	{
		user_free(user);
		return FS_ROSTER_REJECTED;
	}

	if (!rb_tree_insert(roster->by_cid, user->cid, user))
	{
		rb_tree_remove(roster->by_sid, sid_key(user->sid));
		user_free(user);
		return FS_ROSTER_REJECTED;
	}

	return FS_ROSTER_ADDED;
}

int fs_roster_remove(struct fs_roster* roster, sid_t sid)
{
	struct fs_roster_user* user = fs_roster_by_sid(roster, sid);

	if (!user)
		return 0;

	rb_tree_remove(roster->by_cid, user->cid);
	rb_tree_remove(roster->by_sid, sid_key(sid));
	user_free(user);
	return 1;
}

struct fs_roster_user* fs_roster_by_sid(struct fs_roster* roster, sid_t sid)
{
	if (!roster || !sid)
		return NULL;

	return (struct fs_roster_user*) rb_tree_get(roster->by_sid, sid_key(sid));
}

struct fs_roster_user* fs_roster_by_cid(struct fs_roster* roster, const char* cid)
{
	if (!roster || !cid)
		return NULL;

	return (struct fs_roster_user*) rb_tree_get(roster->by_cid, cid);
}

size_t fs_roster_size(struct fs_roster* roster)
{
	return roster ? rb_tree_size(roster->by_cid) : 0;
}

struct fs_roster_user* fs_roster_first(struct fs_roster* roster)
{
	struct rb_node* node;

	if (!roster)
		return NULL;

	node = rb_tree_first(roster->by_cid);
	return node ? (struct fs_roster_user*) node->value : NULL;
}

struct fs_roster_user* fs_roster_next(struct fs_roster* roster)
{
	struct rb_node* node;

	if (!roster)
		return NULL;

	node = rb_tree_next(roster->by_cid);
	return node ? (struct fs_roster_user*) node->value : NULL;
}

size_t fs_roster_nick(const struct fs_roster_user* user, char* buf, size_t size)
{
	char* escaped;
	char* nick;
	size_t len;

	if (!buf || !size)
		return 0;

	buf[0] = '\0';

	if (!user || !user->inf)
		return 0;

	escaped = adc_msg_get_named_argument(user->inf, ADC_INF_FLAG_NICK);
	if (!escaped)
		return 0;

	nick = adc_msg_unescape(escaped);
	hub_free(escaped);

	if (!nick)
		return 0;

	len = strlen(nick);
	if (len >= size)
		len = size - 1;

	memcpy(buf, nick, len);
	buf[len] = '\0';
	hub_free(nick);

	return len;
}

struct name_entry
{
	char name[FS_DISPLAY_NAME_MAX];
};

/**
 * Finish a walk that stopped early.
 *
 * The tree keeps its iteration state inside itself, on a stack it pushes to on
 * the way down. A walk abandoned part-way leaves that stack loaded, and
 * rb_tree_destroy() asserts that it is empty -- so a lookup that stops at the
 * first match takes the mount down at unmount time, long after the walk, and
 * only when no later walk happened to run to the end and reset it.
 */
static void roster_finish_walk(struct fs_roster* roster)
{
	while (rb_tree_next(roster->by_cid))
		; /* nothing: the walking is the point */
}

int fs_roster_walk_names(struct fs_roster* roster, fs_name_cb cb, void* ptr)
{
	struct fs_roster_user* user;
	struct name_entry* seen;
	size_t count;
	size_t used = 0;
	int stopped = 0;

	if (!roster || !cb)
		return 0;

	/* The names handed out so far, to spot a collision. A hub where this array
	   is large is a hub where the walk itself is the expensive part; readdir is
	   not a hot path, and losing the allocation only costs the "~<sid>" that
	   would have told two identical names apart. */
	count = fs_roster_size(roster);
	seen = count ? (struct name_entry*) hub_malloc(count * sizeof(struct name_entry)) : NULL;

	for (user = fs_roster_first(roster); user; user = fs_roster_next(roster))
	{
		char nick[MAX_NICK_LEN + 1];
		char name[FS_DISPLAY_NAME_MAX];

		fs_roster_nick(user, nick, sizeof(nick));
		fs_sanitize_nick(nick, name, MAX_NICK_LEN + 1);

		if (seen && used < count)
		{
			size_t n;

			for (n = 0; n < used; n++)
			{
				if (strcmp(seen[n].name, name) == 0)
				{
					size_t len = strlen(name);
					snprintf(&name[len], sizeof(name) - len, "~%s", sid_to_string(user->sid));
					break;
				}
			}

			memcpy(seen[used].name, name, sizeof(name));
			used++;
		}

		if (cb(ptr, name, user))
		{
			stopped = 1;
			roster_finish_walk(roster);
			break;
		}
	}

	hub_free(seen);
	return stopped;
}

struct fs_roster_user* fs_roster_by_nick(struct fs_roster* roster, const char* nick)
{
	struct fs_roster_user* user;
	char current[MAX_NICK_LEN + 1];

	if (!roster || !nick)
		return NULL;

	for (user = fs_roster_first(roster); user; user = fs_roster_next(roster))
	{
		if (fs_roster_nick(user, current, sizeof(current)) && strcmp(current, nick) == 0)
		{
			roster_finish_walk(roster);
			return user;
		}
	}

	return NULL;
}
