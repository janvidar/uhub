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

#ifndef HAVE_UHUB_FUSE_ROSTER_H
#define HAVE_UHUB_FUSE_ROSTER_H

#include "system.h"
#include "adc/adctypes.h"

struct adc_message;
struct rb_tree;

/**
 * Who is on the hub, as the mount sees them.
 *
 * The roster keeps each user's INF and nothing else. It does not decompose it
 * into typed fields, for the same reason the hub does not (see struct hub_user
 * in src/core/user.h): a client may advertise anything the grammar allows, the
 * set grows with every extension, and a mount that modelled the fields it knew
 * about would quietly drop the ones it did not. Rendering reads the arguments
 * it wants at open() time, and users/<cid>/inf hands over the line itself.
 *
 * An INF update carries only the fields that changed, so an update is merged
 * into the stored line rather than replacing it -- the same merge the hub does
 * in user_update_info() (src/core/user.c:140).
 *
 * Keyed by SID, which is what the hub puts on the wire, and by CID, which is
 * what the mount puts in a path. A user with no CID is not admitted: the mount
 * has no name for one.
 *
 * This lives on the ADC thread and is not locked. Nothing else may touch it.
 */

struct fs_roster_user
{
	sid_t sid;
	char cid[MAX_CID_LEN + 1];

	/** The merged INF. Never NULL for a user in the roster. */
	struct adc_message* inf;

	/** When this user was first seen, for users/<cid>/connected. */
	time_t since;
};

struct fs_roster
{
	struct rb_tree* by_sid;
	struct rb_tree* by_cid;
};

/** @return a new empty roster, or NULL on OOM. */
extern struct fs_roster* fs_roster_create(void);

/** Empty the roster. Used when the hub connection drops. */
extern void fs_roster_clear(struct fs_roster* roster);

extern void fs_roster_destroy(struct fs_roster* roster);

enum fs_roster_result
{
	FS_ROSTER_REJECTED = 0,  /** No SID, no CID on a first INF, or OOM. */
	FS_ROSTER_ADDED    = 1,
	FS_ROSTER_UPDATED  = 2,
};

/**
 * Add @p binf, or merge it into what is already stored for its SID.
 *
 * @p binf is not retained: the roster keeps a copy.
 * @param now the time to stamp a newly added user with.
 */
extern enum fs_roster_result fs_roster_update(struct fs_roster* roster,
                                              struct adc_message* binf, time_t now);

/** @return 1 if a user was removed. */
extern int fs_roster_remove(struct fs_roster* roster, sid_t sid);

extern struct fs_roster_user* fs_roster_by_sid(struct fs_roster* roster, sid_t sid);
extern struct fs_roster_user* fs_roster_by_cid(struct fs_roster* roster, const char* cid);

extern size_t fs_roster_size(struct fs_roster* roster);

/**
 * Iterate, in CID order -- which is the order users/ lists them in.
 *
 * The iterator lives in the tree, so exactly one walk may be in progress at a
 * time, and nothing may be added or removed during it.
 */
extern struct fs_roster_user* fs_roster_first(struct fs_roster* roster);
extern struct fs_roster_user* fs_roster_next(struct fs_roster* roster);

/**
 * Find the user advertising @p nick, for by-nick/.
 *
 * Nicks are unique on a hub, but only at any one moment: this is a linear walk
 * and it compares the unescaped NI, so a nick containing a space matches the
 * name a shell would type. @return NULL if nobody is using it.
 */
extern struct fs_roster_user* fs_roster_by_nick(struct fs_roster* roster, const char* nick);

/** Room for a by-nick name: a nick, and the "~SID" a collision adds. */
#define FS_DISPLAY_NAME_MAX (MAX_NICK_LEN + 8)

/**
 * Called once per user by fs_roster_walk_names().
 * @return non-zero to stop the walk.
 */
typedef int (*fs_name_cb)(void* ptr, const char* name, struct fs_roster_user* user);

/**
 * Walk the roster, handing each user the name it goes by in by-nick/.
 *
 * The name is the user's nick with the bytes a filename cannot hold replaced
 * (see fs_sanitize_nick). Nicks are unique on a hub but their sanitised forms
 * need not be -- "a/b" and "a_b" collapse onto one name -- so a name already
 * taken by an earlier user gets "~<sid>" appended, which is unique by
 * construction.
 *
 * Listing the directory and resolving one name in it are the same walk, so
 * both go through here: a lookup that generated names by a different rule
 * would answer for names the listing never showed.
 *
 * @return 1 if @p cb stopped the walk.
 */
extern int fs_roster_walk_names(struct fs_roster* roster, fs_name_cb cb, void* ptr);

/**
 * The unescaped NI of @p user, copied into @p buf.
 * @return the number of bytes written, excluding the NUL, or 0.
 */
extern size_t fs_roster_nick(const struct fs_roster_user* user, char* buf, size_t size);

#endif /* HAVE_UHUB_FUSE_ROSTER_H */
