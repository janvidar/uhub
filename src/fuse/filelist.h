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

#ifndef HAVE_UHUB_FUSE_FILELIST_H
#define HAVE_UHUB_FUSE_FILELIST_H

#include "system.h"
#include "adc/adctypes.h"

/**
 * What a peer says it is sharing.
 *
 * ADC has no directory listing of its own: a client that wants to see somebody
 * else's share downloads their *file list*, which is an XML document,
 * bzip2-compressed, named "files.xml.bz2". It is the same document every
 * Direct Connect client has produced since DC++ defined it:
 *
 *   <FileListing Version="1" CID="..." Base="/" Generator="DC++ 0.868">
 *     <Directory Name="Music">
 *       <File Name="song.flac" Size="41234567" TTH="ZP2X...Q"/>
 *     </Directory>
 *   </FileListing>
 *
 * The interesting part of each File is its TTH: a name in a listing is only a
 * label, and the hash is what a download actually asks for. So a parsed list is
 * how a path under users/<cid>/files/ becomes something by-tth could have
 * fetched.
 *
 * EVERY BYTE HERE IS UNTRUSTED. It arrives over a connection anybody can open,
 * from a peer with no obligation to be truthful or even well-formed, and the
 * names in it become path components in a mounted filesystem. The parser is
 * therefore bounded in every direction -- depth, node count, name length,
 * decompressed size -- and refuses rather than repairs. See fs_filelist_parse().
 */

/** Largest decompressed file list accepted, in bytes. */
#define FS_FILELIST_MAX (64 * 1024 * 1024)

/** Deepest nesting accepted. Beyond this a list is refused, not truncated. */
#define FS_FILELIST_MAX_DEPTH 64

/** Most entries accepted in one list. */
#define FS_FILELIST_MAX_NODES 500000

/** Longest single name accepted, in bytes. */
#define FS_FILELIST_NAME_MAX 255

struct fs_filelist;

/** One entry: a directory with children, or a file with a hash. */
struct fs_filelist_node
{
	char* name;
	int is_dir;
	uint64_t size;                     /** Files only. */
	char tth[MAX_CID_LEN + 1];         /** Files only; "" when the peer sent none. */

	struct fs_filelist_node* children; /** Directories only. */
	struct fs_filelist_node* next;     /** Next entry in the same directory. */
	struct fs_filelist_node* parent;
};

/**
 * Parse a decompressed file list.
 *
 * @param data the XML. Need not be NUL terminated.
 * @param len  its length.
 * @return the parsed list, or NULL if it is not one. Free with
 *         fs_filelist_destroy().
 */
extern struct fs_filelist* fs_filelist_parse(const char* data, size_t len);

/**
 * Decompress a bzip2'd file list and parse it.
 *
 * @return the parsed list, or NULL if it does not decompress, is larger than
 *         FS_FILELIST_MAX, or does not parse.
 */
extern struct fs_filelist* fs_filelist_load(const void* bz2, size_t len);

extern void fs_filelist_destroy(struct fs_filelist* list);

/** The root directory's first child. */
extern struct fs_filelist_node* fs_filelist_root(struct fs_filelist* list);

/** How many entries the list holds, directories included. */
extern size_t fs_filelist_count(struct fs_filelist* list);

/**
 * Find the entry at @p path, which is relative and uses '/' separators.
 *
 * An empty path is the root, which has no node of its own -- use
 * fs_filelist_root() to list it. @return NULL if there is no such entry.
 */
extern struct fs_filelist_node* fs_filelist_lookup(struct fs_filelist* list, const char* path);

/**
 * Decompress a bzip2 stream into a newly allocated buffer.
 *
 * Exposed for the tests. @param out_len receives the length.
 * @return the buffer, to be released with hub_free(), or NULL.
 */
extern char* fs_filelist_decompress(const void* data, size_t len, size_t* out_len);

/**
 * Make one name from a file list safe to use as a path component.
 *
 * A name in a list is whatever the peer put there: it may hold a slash, be
 * empty, be "." or "..", or be a control character away from being unprintable.
 * Any of those would either escape the directory it is in or be unusable, so
 * they are replaced or refused here -- never passed through.
 *
 * @return 1 if @p name yielded a usable component in @p buf.
 */
extern int fs_filelist_safe_name(const char* name, char* buf, size_t size);

#endif /* HAVE_UHUB_FUSE_FILELIST_H */
