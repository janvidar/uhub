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

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#include "core/bbs_index.h"
#include "util/log.h"
#include "util/memory.h"

struct bbs_index
{
	sqlite3* db;
};

/* Every value that reaches the database comes from a remote user, so every
   statement here is prepared and bound -- none is built by string formatting. */
static const char* bbs_index_schema =
	"CREATE TABLE IF NOT EXISTS bbs_post ("
	"  board   TEXT    NOT NULL,"
	"  tth     TEXT    NOT NULL,"
	"  size    INTEGER NOT NULL,"
	"  cid     TEXT    NOT NULL,"
	"  nick    TEXT    NOT NULL DEFAULT '',"
	"  parent  TEXT    NOT NULL DEFAULT '',"
	"  thread  TEXT    NOT NULL,"
	"  subject TEXT    NOT NULL DEFAULT '',"
	"  ts      INTEGER NOT NULL,"
	"  removed INTEGER NOT NULL DEFAULT 0,"
	"  PRIMARY KEY (board, tth));"
	"CREATE INDEX IF NOT EXISTS bbs_post_stream ON bbs_post (board, ts);";

int bbs_tth_is_valid(const char* tth)
{
	size_t n;

	if (!tth)
		return 0;

	for (n = 0; n < BBS_TTH_LEN; n++)
	{
		char c = tth[n];
		/* RFC 4648 base32, never padded. */
		if (!((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')))
			return 0;
	}
	return tth[BBS_TTH_LEN] == '\0';
}

struct bbs_index* bbs_index_open(const char* filename)
{
	struct bbs_index* index;
	char* error = NULL;

	index = (struct bbs_index*) hub_malloc_zero(sizeof(struct bbs_index));
	if (!index)
	{
		LOG_FATAL("bbs_index_open: out of memory");
		return NULL;
	}

	if (sqlite3_open(filename, &index->db) != SQLITE_OK)
	{
		LOG_ERROR("Unable to open the bulletin board index '%s': %s",
		          filename, index->db ? sqlite3_errmsg(index->db) : "unknown error");
		bbs_index_close(index);
		return NULL;
	}

	if (sqlite3_exec(index->db, bbs_index_schema, NULL, NULL, &error) != SQLITE_OK)
	{
		LOG_ERROR("Unable to create the bulletin board index schema: %s",
		          error ? error : "unknown error");
		sqlite3_free(error);
		bbs_index_close(index);
		return NULL;
	}

	return index;
}

void bbs_index_close(struct bbs_index* index)
{
	if (!index)
		return;

	if (index->db)
		sqlite3_close(index->db);
	hub_free(index);
}

/* Copy a TEXT column into a fixed-size field, tolerating a NULL column. */
static void bbs_copy_text(char* dst, size_t size, sqlite3_stmt* stmt, int column)
{
	const unsigned char* text = sqlite3_column_text(stmt, column);
	if (!text)
	{
		dst[0] = '\0';
		return;
	}
	strncpy(dst, (const char*) text, size - 1);
	dst[size - 1] = '\0';
}

static void bbs_entry_read(struct bbs_entry* entry, sqlite3_stmt* stmt)
{
	memset(entry, 0, sizeof(struct bbs_entry));
	bbs_copy_text(entry->tth, sizeof(entry->tth), stmt, 0);
	entry->size = (uint64_t) sqlite3_column_int64(stmt, 1);
	bbs_copy_text(entry->cid, sizeof(entry->cid), stmt, 2);
	bbs_copy_text(entry->nick, sizeof(entry->nick), stmt, 3);
	bbs_copy_text(entry->parent, sizeof(entry->parent), stmt, 4);
	bbs_copy_text(entry->thread, sizeof(entry->thread), stmt, 5);
	bbs_copy_text(entry->subject, sizeof(entry->subject), stmt, 6);
	entry->ts = (time_t) sqlite3_column_int64(stmt, 7);
	entry->removed = sqlite3_column_int(stmt, 8) != 0;
}

#define BBS_SELECT_COLUMNS "tth, size, cid, nick, parent, thread, subject, ts, removed"

int bbs_index_stats(struct bbs_index* index, const char* board,
                    time_t* newest, time_t* oldest, size_t* count)
{
	sqlite3_stmt* stmt = NULL;
	int ret = -1;

	if (newest) *newest = 0;
	if (oldest) *oldest = 0;
	if (count)  *count = 0;

	if (!index || !board)
		return -1;

	/* MIN/MAX over every entry (a tombstone still occupies a place in the
	   stream and must be replayable), but the post count excludes them. */
	if (sqlite3_prepare_v2(index->db,
			"SELECT MAX(ts), MIN(ts), SUM(removed = 0) FROM bbs_post WHERE board = ?;",
			-1, &stmt, NULL) != SQLITE_OK)
	{
		LOG_ERROR("bbs_index_stats: %s", sqlite3_errmsg(index->db));
		return -1;
	}

	sqlite3_bind_text(stmt, 1, board, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW)
	{
		if (newest) *newest = (time_t) sqlite3_column_int64(stmt, 0);
		if (oldest) *oldest = (time_t) sqlite3_column_int64(stmt, 1);
		if (count)  *count  = (size_t) sqlite3_column_int64(stmt, 2);
		ret = 0;
	}

	sqlite3_finalize(stmt);
	return ret;
}

enum bbs_index_result bbs_index_lookup(struct bbs_index* index, const char* board,
                                       const char* tth, struct bbs_entry* out)
{
	sqlite3_stmt* stmt = NULL;
	enum bbs_index_result result = bbs_index_not_found;

	if (!index || !board || !tth)
		return bbs_index_error;

	if (sqlite3_prepare_v2(index->db,
			"SELECT " BBS_SELECT_COLUMNS " FROM bbs_post WHERE board = ? AND tth = ?;",
			-1, &stmt, NULL) != SQLITE_OK)
	{
		LOG_ERROR("bbs_index_lookup: %s", sqlite3_errmsg(index->db));
		return bbs_index_error;
	}

	sqlite3_bind_text(stmt, 1, board, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, tth, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW)
	{
		if (out)
			bbs_entry_read(out, stmt);
		result = bbs_index_ok;
	}

	sqlite3_finalize(stmt);
	return result;
}

/**
 * The timestamp to give the next entry on a board.
 *
 * A hub must assign each entry a timestamp no lower than the highest already on
 * the board; where its clock has moved backwards it reuses the highest rather
 * than a lower one. A client that has caught up to a given second never asks
 * for anything earlier, so an entry stamped before that would reach nobody.
 */
static time_t bbs_index_next_ts(struct bbs_index* index, const char* board, time_t now)
{
	time_t newest = 0;

	if (bbs_index_stats(index, board, &newest, NULL, NULL) < 0)
		return now;

	return (now > newest) ? now : newest;
}

/* Drop the oldest entries beyond the retention limit. The board's oldest
   remaining timestamp becomes its "OT", so what the hub will replay and what it
   still holds never disagree. */
static void bbs_index_prune(struct bbs_index* index, const char* board, size_t max_entries)
{
	sqlite3_stmt* stmt = NULL;

	if (!max_entries)
		return;

	if (sqlite3_prepare_v2(index->db,
			"DELETE FROM bbs_post WHERE rowid IN ("
			"  SELECT rowid FROM bbs_post WHERE board = ?"
			"  ORDER BY ts ASC, rowid ASC"
			"  LIMIT MAX(0, (SELECT COUNT(*) FROM bbs_post WHERE board = ?) - ?));",
			-1, &stmt, NULL) != SQLITE_OK)
	{
		LOG_ERROR("bbs_index_prune: %s", sqlite3_errmsg(index->db));
		return;
	}

	sqlite3_bind_text(stmt, 1, board, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, board, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, (sqlite3_int64) max_entries);

	if (sqlite3_step(stmt) != SQLITE_DONE)
		LOG_ERROR("bbs_index_prune: %s", sqlite3_errmsg(index->db));
	else if (sqlite3_changes(index->db) > 0)
		LOG_DEBUG("bbs: pruned %d entries from board '%s'", sqlite3_changes(index->db), board);

	sqlite3_finalize(stmt);
}

enum bbs_index_result bbs_index_append(struct bbs_index* index, const char* board,
                                       struct bbs_entry* entry, time_t now,
                                       size_t max_entries)
{
	sqlite3_stmt* stmt = NULL;
	enum bbs_index_result result;

	if (!index || !board || !entry)
		return bbs_index_error;

	if (bbs_index_lookup(index, board, entry->tth, NULL) == bbs_index_ok)
		return bbs_index_duplicate;

	if (*entry->parent)
	{
		/* The thread root is not the client's to compute: the hub knows the
		   thread of the post named by PA. */
		struct bbs_entry parent;
		result = bbs_index_lookup(index, board, entry->parent, &parent);
		if (result != bbs_index_ok)
			return bbs_index_no_parent;
		/* Same-sized, NUL-terminated fields: copy the whole buffer. */
		memcpy(entry->thread, parent.thread, sizeof(entry->thread));
	}
	else
	{
		/* A post without a parent starts a thread whose root is its own hash. */
		memcpy(entry->thread, entry->tth, sizeof(entry->thread));
	}

	entry->ts = bbs_index_next_ts(index, board, now);
	entry->removed = 0;

	if (sqlite3_prepare_v2(index->db,
			"INSERT INTO bbs_post (board, tth, size, cid, nick, parent, thread, subject, ts, removed)"
			" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0);",
			-1, &stmt, NULL) != SQLITE_OK)
	{
		LOG_ERROR("bbs_index_append: %s", sqlite3_errmsg(index->db));
		return bbs_index_error;
	}

	sqlite3_bind_text(stmt, 1, board, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, entry->tth, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, (sqlite3_int64) entry->size);
	sqlite3_bind_text(stmt, 4, entry->cid, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 5, entry->nick, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 6, entry->parent, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 7, entry->thread, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 8, entry->subject, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 9, (sqlite3_int64) entry->ts);

	if (sqlite3_step(stmt) != SQLITE_DONE)
	{
		LOG_ERROR("bbs_index_append: %s", sqlite3_errmsg(index->db));
		sqlite3_finalize(stmt);
		return bbs_index_error;
	}

	sqlite3_finalize(stmt);

	bbs_index_prune(index, board, max_entries);
	return bbs_index_ok;
}

enum bbs_index_result bbs_index_withdraw(struct bbs_index* index, const char* board,
                                         const char* tth, time_t now,
                                         struct bbs_entry* out)
{
	sqlite3_stmt* stmt = NULL;
	struct bbs_entry entry;
	time_t ts;

	if (!index || !board || !tth)
		return bbs_index_error;

	if (bbs_index_lookup(index, board, tth, &entry) != bbs_index_ok)
		return bbs_index_not_found;

	ts = bbs_index_next_ts(index, board, now);

	if (sqlite3_prepare_v2(index->db,
			"UPDATE bbs_post SET removed = 1, ts = ? WHERE board = ? AND tth = ?;",
			-1, &stmt, NULL) != SQLITE_OK)
	{
		LOG_ERROR("bbs_index_withdraw: %s", sqlite3_errmsg(index->db));
		return bbs_index_error;
	}

	sqlite3_bind_int64(stmt, 1, (sqlite3_int64) ts);
	sqlite3_bind_text(stmt, 2, board, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, tth, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) != SQLITE_DONE)
	{
		LOG_ERROR("bbs_index_withdraw: %s", sqlite3_errmsg(index->db));
		sqlite3_finalize(stmt);
		return bbs_index_error;
	}

	sqlite3_finalize(stmt);

	if (out)
	{
		/* A tombstone carries the hash, the board, the new timestamp and RM1,
		   and nothing else: the subject and author of a withdrawn post are
		   usually the reason it was withdrawn. */
		memset(out, 0, sizeof(struct bbs_entry));
		memcpy(out->tth, entry.tth, sizeof(out->tth));
		out->ts = ts;
		out->removed = 1;
	}

	return bbs_index_ok;
}

int bbs_index_replay(struct bbs_index* index, const char* board, time_t from,
                     bbs_index_callback callback, void* ptr)
{
	sqlite3_stmt* stmt = NULL;
	struct bbs_entry entry;
	int count = 0;

	if (!index || !board || !callback)
		return -1;

	/* Greater than *or equal to*: a client resumes from the highest timestamp
	   it has seen rather than one second later, because timestamps are not
	   unique and a post accepted in the same second would otherwise be skipped.
	   The cost is that the final second arrives twice, which the client
	   discards by hash. */
	if (sqlite3_prepare_v2(index->db,
			"SELECT " BBS_SELECT_COLUMNS " FROM bbs_post"
			" WHERE board = ? AND ts >= ? ORDER BY ts ASC, rowid ASC;",
			-1, &stmt, NULL) != SQLITE_OK)
	{
		LOG_ERROR("bbs_index_replay: %s", sqlite3_errmsg(index->db));
		return -1;
	}

	sqlite3_bind_text(stmt, 1, board, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 2, (sqlite3_int64) from);

	while (sqlite3_step(stmt) == SQLITE_ROW)
	{
		bbs_entry_read(&entry, stmt);
		callback(&entry, ptr);
		count++;
	}

	sqlite3_finalize(stmt);
	return count;
}
