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

#ifndef HAVE_UHUB_FUSE_NODES_H
#define HAVE_UHUB_FUSE_NODES_H

#include "system.h"
#include "adc/adctypes.h"

/**
 * The shape of the mount, and nothing else.
 *
 * This module answers one question -- "what kind of thing could this path be?"
 * -- and answers it without consulting the hub. A path naming a user resolves
 * whether or not that user is online: the CID is checked for the syntax of a
 * CID and no more. Existence is the roster's business and is decided on the
 * ADC thread, where the roster lives; deciding it here would mean taking the
 * hub lock inside every path parse.
 *
 * Everything in here is therefore pure: no allocation, no I/O, no globals.
 *
 * The tree:
 *
 *   /                        FS_NODE_ROOT
 *   /hub/                    FS_NODE_HUB_DIR       fields: fs_hub_fields
 *   /me/                     FS_NODE_ME_DIR        fields: fs_me_fields
 *   /chat/main               FS_NODE_CHAT_MAIN     read: log, write: send
 *   /chat/private            FS_NODE_CHAT_PRIVATE  private messages, read only
 *   /users/<cid>/            FS_NODE_USER_DIR      fields: fs_user_fields
 *   /users/<cid>/files/...   FS_NODE_USER_FILES_*  (not yet served)
 *   /by-nick/<nick>          FS_NODE_BY_NICK_LINK  symlink to ../users/<cid>
 *   /by-tth/<tth>            FS_NODE_BY_TTH_FILE   (not yet served)
 */

enum fs_node_type
{
	FS_NODE_NONE = 0,          /** No such path. Nothing else in the node is set. */
	FS_NODE_ROOT,
	FS_NODE_HUB_DIR,
	FS_NODE_HUB_FILE,
	FS_NODE_ME_DIR,
	FS_NODE_ME_FILE,
	FS_NODE_CHAT_DIR,
	FS_NODE_CHAT_MAIN,
	FS_NODE_CHAT_PRIVATE,
	FS_NODE_USERS_DIR,
	FS_NODE_USER_DIR,
	FS_NODE_USER_FILE,
	FS_NODE_USER_MSG,
	FS_NODE_USER_FILES_DIR,    /** /users/<cid>/files */
	FS_NODE_USER_FILES_ENTRY,  /** something below it; @c tail is the remainder */
	FS_NODE_BY_NICK_DIR,
	FS_NODE_BY_NICK_LINK,
	FS_NODE_BY_TTH_DIR,
	FS_NODE_BY_TTH_FILE,
};

/** Properties of one metadata file. */
enum fs_field_flags
{
	FS_FIELD_READ    = 0x01,  /** Contents can be read. */
	FS_FIELD_WRITE   = 0x02,  /** Writing to it does something. */
	FS_FIELD_RAW_INF = 0x04,  /** The whole stored INF line, not one argument. */
	FS_FIELD_NUMERIC = 0x08,  /** Absent means zero, not absent. */
};

/**
 * One file inside hub/, me/ or a user directory.
 *
 * @c inf names the two-letter ADC INF argument the contents come from, or is
 * NULL for a file the renderer synthesises (the SID, the connect time, the raw
 * line). The value in an INF is escaped, so a reader of @c inf must unescape
 * it -- see fs_render_field(), which is the only intended reader.
 */
struct fs_field
{
	const char* name;
	const char* inf;
	unsigned int flags;
};

/**
 * The three field tables, each terminated by an entry with a NULL name.
 * They are the readdir listing for their directory as well as its lookup
 * table, so the order here is the order the files appear in.
 */
extern const struct fs_field fs_hub_fields[];
extern const struct fs_field fs_me_fields[];
extern const struct fs_field fs_user_fields[];

/** Look @p name up in a table. @return the field, or NULL. */
extern const struct fs_field* fs_field_lookup(const struct fs_field* table, const char* name);

/** A resolved path. Which members are set depends on @c type. */
struct fs_node
{
	enum fs_node_type type;

	/** FS_NODE_USER_*: the CID out of the path. */
	char cid[MAX_CID_LEN + 1];

	/** FS_NODE_BY_NICK_LINK: the link name. FS_NODE_BY_TTH_FILE: the hash. */
	char name[MAX_NICK_LEN + 1];

	/** FS_NODE_{HUB,ME,USER}_FILE: which file. */
	const struct fs_field* field;

	/**
	 * FS_NODE_USER_FILES_ENTRY: the path below files/, without a leading
	 * slash. It points into the caller's @p path and lives exactly as long.
	 */
	const char* tail;
};

/**
 * Resolve an absolute mount-relative path.
 *
 * Pure. A path that cannot be a node in this tree -- an unknown top level, a
 * CID that is not 39 base32 characters, a metadata file that is not in the
 * table -- yields FS_NODE_NONE, which is the caller's ENOENT.
 *
 * @param path a NUL-terminated path beginning with '/'. Trailing slashes are
 *             ignored; empty components ("//") are not, and are refused.
 * @param out  filled in on success, zeroed on failure. Never NULL.
 * @return 1 when @p out->type is not FS_NODE_NONE.
 */
extern int fs_node_resolve(const char* path, struct fs_node* out);

/**
 * Is @p name a syntactically valid CID or TTH -- 39 base32 characters?
 *
 * Both are a 24-byte tiger hash in base32, so this is one test for both, and
 * it is what makes a CID safe to use as a directory name: the alphabet has no
 * '/', no NUL and no '.', so "." and ".." cannot be spelled.
 */
extern int fs_is_base32_hash(const char* name);

/**
 * Turn a nick into a name usable in by-nick/.
 *
 * A nick is user text and arrives with none of a filename's restrictions: it
 * may contain a slash, may be "." or "..", and may collide with another user's.
 * Offending bytes become '_', and a name that would still be unusable falls
 * back to "user". Collisions are not resolved here -- the caller appends the
 * SID, which is unique per session, when it finds one.
 *
 * @return the number of bytes written, excluding the NUL, or 0 if @p size is 0.
 */
extern size_t fs_sanitize_nick(const char* nick, char* buf, size_t size);

#endif /* HAVE_UHUB_FUSE_NODES_H */
