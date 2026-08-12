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

#ifndef HAVE_UHUB_BBS_INDEX_H
#define HAVE_UHUB_BBS_INDEX_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "adc/adctypes.h"

/**
 * The BBS0 post index.
 *
 * For each board the hub keeps an ordered list of index entries, and that is
 * all it keeps: an entry points at a post document by its Tiger tree hash, and
 * the bytes of the document are never stored here, nor served by the hub. What
 * makes the index a board is that it is per hub, ordered, and where permission
 * and moderation live.
 *
 * Nothing ever enters the index in the past. A post takes the time of its
 * arrival, never the time its author claims, which is what lets a client resume
 * from a timestamp cursor without a generation counter to guard it.
 */

/** A Tiger tree hash root: 39 base32 characters, as the TIGR feature uses. */
#define BBS_TTH_LEN 39

/**
 * Longest subject the hub will index. The subject in an entry is a copy of the
 * document's, offered so a client can build a threaded view before fetching
 * anything; a document may carry a longer one, and the client prefers the
 * document once it has it.
 */
#define BBS_MAX_SUBJECT 255

struct bbs_index;

enum bbs_index_result
{
	bbs_index_ok = 0,
	bbs_index_error = -1,       /**<< The database refused the operation. */
	bbs_index_duplicate = -2,   /**<< This post is already indexed on this board. */
	bbs_index_no_parent = -3,   /**<< The post named by "PA" is not on this board. */
	bbs_index_not_found = -4    /**<< No entry for the requested post. */
};

/**
 * One index entry, as carried in IBBL.
 *
 * Fixed-size buffers throughout, so an entry can be a stack local while a
 * replay walks a board. Absent optional fields are the empty string.
 */
struct bbs_entry
{
	char tth[BBS_TTH_LEN + 1];    /**<< "TR": the post's identity. */
	char parent[BBS_TTH_LEN + 1]; /**<< "PA": empty in a post that starts a thread. */
	char thread[BBS_TTH_LEN + 1]; /**<< "TH": the thread root, derived by the hub. */
	char cid[MAX_CID_LEN + 1];    /**<< "ID": the CID the hub accepted the post from. */
	char nick[MAX_NICK_LEN + 1];  /**<< "NI": the nick that session held at the time. */
	char subject[BBS_MAX_SUBJECT + 1]; /**<< "SJ": copied from the document. */
	uint64_t size;                /**<< "SI": the document size the author declared. */
	time_t ts;                    /**<< "TS": when the hub accepted the post. */
	int removed;                  /**<< "RM": non-zero once the post is withdrawn. */
};

/** Called once per entry during a replay, in non-decreasing order of ts. */
typedef void (*bbs_index_callback)(const struct bbs_entry* entry, void* ptr);

/**
 * Open (creating if necessary) the index database.
 *
 * @param filename path to the SQLite database, or ":memory:".
 * @return the index, or NULL on failure.
 */
extern struct bbs_index* bbs_index_open(const char* filename);

/** Close an index. Tolerates NULL. */
extern void bbs_index_close(struct bbs_index* index);

/**
 * @return 1 if @p tth is a syntactically valid Tiger tree hash root.
 */
extern int bbs_tth_is_valid(const char* tth);

/**
 * Board statistics for the board descriptor.
 *
 * @param newest receives the newest timestamp on the board, or 0 if it has none.
 * @param oldest receives the oldest retained timestamp, or 0 if the board is empty.
 * @param count receives the number of posts indexed, excluding tombstones.
 * @return 0 on success, -1 on failure. Any out parameter may be NULL.
 */
extern int bbs_index_stats(struct bbs_index* index, const char* board,
                           time_t* newest, time_t* oldest, size_t* count);

/**
 * Look up a single entry, withdrawn or not.
 *
 * @return bbs_index_ok and fills @p out, or bbs_index_not_found.
 */
extern enum bbs_index_result bbs_index_lookup(struct bbs_index* index, const char* board,
                                              const char* tth, struct bbs_entry* out);

/**
 * Add a post to a board.
 *
 * The caller fills in tth, parent, cid, nick, subject and size; this assigns
 * @p entry->ts and derives @p entry->thread, so that on success the entry is
 * exactly what should go out to subscribers.
 *
 * @param now the current time. The assigned timestamp is never lower than the
 *        highest already on the board, so a clock that moves backwards cannot
 *        place an entry behind a cursor that has already passed it.
 * @param max_entries retain at most this many entries on the board, dropping
 *        the oldest; 0 retains everything.
 */
extern enum bbs_index_result bbs_index_append(struct bbs_index* index, const char* board,
                                              struct bbs_entry* entry, time_t now,
                                              size_t max_entries);

/**
 * Withdraw a post.
 *
 * The entry keeps its hash and takes a *new* timestamp -- the time of the
 * withdrawal -- which is what places the tombstone at the head of the stream,
 * where it reaches a subscriber at once and an absent client as soon as it
 * resumes. The original timestamp would leave it behind every cursor that had
 * already moved past it.
 *
 * @param out receives the tombstone to send to subscribers. May be NULL.
 */
extern enum bbs_index_result bbs_index_withdraw(struct bbs_index* index, const char* board,
                                                const char* tth, time_t now,
                                                struct bbs_entry* out);

/**
 * Replay a board from a timestamp.
 *
 * Every entry whose ts is greater than or equal to @p from, tombstones
 * included, in non-decreasing order of ts.
 *
 * @return the number of entries passed to @p callback, or -1 on failure.
 */
extern int bbs_index_replay(struct bbs_index* index, const char* board, time_t from,
                            bbs_index_callback callback, void* ptr);

#endif /* HAVE_UHUB_BBS_INDEX_H */
