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

#include "system.h"

#include <dirent.h>
#include <sqlite3.h>
#include <sys/stat.h>

#include "seeder/cache.h"
#include "seeder/sniff.h"
#include "util/list.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "util/rbtree.h"
#include "util/tth.h"

#define SEED_DB_NAME "seedcache.db"

/*
 * The configured cache directory is bounded well below PATH_MAX so that every
 * path derived from it provably fits in SEED_PATH_MAX. Without that the
 * compiler is right to warn: a directory of PATH_MAX characters plus a suffix
 * cannot fit in another PATH_MAX buffer.
 *
 * Longest derived path: <dir> "/data/" XX "/" YY "/" <39 base32> ".bin"
 */
#define SEED_DIR_MAX  256
#define SEED_PATH_MAX 512

/* Names longer than this cannot be ours, so they are never built into a path. */
#define SEED_ENTRY_NAME_MAX 128

/*
 * Intermediate directory paths. Deliberately much smaller than SEED_PATH_MAX:
 * a path built by appending a name to another SEED_PATH_MAX buffer cannot be
 * shown to fit, so every path here is derived from cache->dir plus a suffix of
 * known length instead of by chaining.
 */
#define SEED_SUBDIR_MAX (SEED_DIR_MAX + 32)

/*
 * The bounds above are what let the compiler prove no snprintf() here can
 * truncate. Assert them rather than trusting the arithmetic: GCC reports a
 * truncation it can prove, but only on the platform being built.
 */
_Static_assert(SEED_TTH_STR_LEN == TTH_BASE32_LEN,
	"the cache names files by TTH, so the two lengths are the same thing");
_Static_assert(SEED_DIR_MAX + 6 + 2 + 1 + 2 + 1 <= SEED_SUBDIR_MAX,
	"SEED_SUBDIR_MAX must fit <dir>/data/XX/YY");
_Static_assert(SEED_DIR_MAX + 1 + sizeof(SEED_DB_NAME) <= SEED_SUBDIR_MAX,
	"SEED_SUBDIR_MAX must fit <dir>/seedcache.db");
_Static_assert(SEED_DIR_MAX + 6 + 2 + 1 + 2 + 1 + SEED_TTH_STR_LEN + 4 + 1 <= SEED_PATH_MAX,
	"SEED_PATH_MAX must fit <dir>/data/XX/YY/<tth>.bin");
_Static_assert(SEED_SUBDIR_MAX + 1 + SEED_ENTRY_NAME_MAX + 1 <= SEED_PATH_MAX,
	"SEED_PATH_MAX must fit a subdirectory plus a directory entry name");
_Static_assert(SEED_DIR_MAX + 5 + 20 + 1 + 20 + 5 + 1 <= SEED_PATH_MAX,
	"SEED_PATH_MAX must fit <dir>/tmp/<pid>-<serial>.part");

#define SEED_MAX_EVICT_PER_SWEEP 64
#define SEED_DEFAULT_MAX_FILE_SIZE  (16ull * 1024 * 1024)
#define SEED_DEFAULT_MAX_INGEST     8
#define SEED_DEFAULT_TYPES "image/png,image/jpeg,image/gif,image/webp"

/*
 * Access times are seconds, but eviction orders by them, and a busy second
 * would otherwise leave the order among its entries up to the query planner.
 * Stamps are therefore forced to increase, and clamped so they can never run
 * more than this far ahead of the wall clock -- which bounds how late a TTL can
 * fire under sustained load.
 */
#define SEED_STAMP_MAX_SKEW 60

/* -- runtime state -------------------------------------------------------- */

/**
 * A pin. Runtime only: never persisted, never reloaded. Its existence is what
 * keeps a file on disk after its record has gone.
 */
struct seed_pin
{
	char     tth[SEED_TTH_STR_LEN + 1];
	unsigned refs;
	int      unlink_pending;
};

/** An access not yet written to the database. Flushed by the sweep. */
struct seed_touch
{
	char     tth[SEED_TTH_STR_LEN + 1];
	time_t   last_access;
	uint32_t hits;
};

/** A candidate for removal, collected before any row is deleted. */
struct seed_victim
{
	char     tth[SEED_TTH_STR_LEN + 1];
	uint64_t size;
};

struct seed_ingest
{
	struct seed_cache* cache;
	struct tth_context hash;
	char     expect_tth[SEED_TTH_STR_LEN + 1];
	int      have_expect;
	int      fd;
	char     tmp_path[SEED_PATH_MAX];
	uint64_t received;
	uint64_t limit;        /* hard ceiling for this job */
	uint64_t reserved;     /* charged against the cache size while in flight */
	uint8_t  sniff[SEED_SNIFF_BYTES];
	size_t   sniff_len;
	int      media_decided;
	int      media_allowed;
	char     media_type[SEED_MIME_MAX];
	char     name[SEED_NAME_MAX];
	char     origin_cid[64];
	char     origin_nick[64];
	char     origin_addr[64];
};

struct seed_cache
{
	char     dir[SEED_DIR_MAX];
	char*    allowed_types;

	sqlite3* db;
	sqlite3_stmt* st_lookup;
	sqlite3_stmt* st_insert;
	sqlite3_stmt* st_touch;
	sqlite3_stmt* st_delete;
	sqlite3_stmt* st_blocked;
	sqlite3_stmt* st_iter;

	struct rb_tree* pins;   /* tth -> struct seed_pin*   */
	struct rb_tree* dirty;  /* tth -> struct seed_touch* */

	uint64_t bytes_used;
	uint64_t bytes_reserved;
	uint64_t bytes_max;
	uint64_t max_file_size;
	size_t   entries;
	size_t   entries_max;
	size_t   blocked;
	size_t   active_ingests;
	size_t   max_concurrent_ingest;
	int      entry_ttl;
	size_t   serial;
	time_t   stamp;
	int      degraded;
};

/* Columns, in the order every entry-shaped SELECT below uses them. */
#define SEED_COLUMNS \
	"tth, size, media_type, name, first_seen, last_access, hits, " \
	"origin_cid, origin_nick, origin_addr"

const char* seed_error_string(enum seed_error error)
{
	switch (error)
	{
		case SEED_OK:              return "ok";
		case SEED_ERR_DISABLED:    return "disabled";
		case SEED_ERR_DEGRADED:    return "degraded";
		case SEED_ERR_ADMISSION:   return "admission";
		case SEED_ERR_QUOTA:       return "quota";
		case SEED_ERR_FULL:        return "full";
		case SEED_ERR_TOO_LARGE:   return "too_large";
		case SEED_ERR_TTH_MISMATCH:return "tth_mismatch";
		case SEED_ERR_MEDIA_TYPE:  return "media_type";
		case SEED_ERR_BLOCKED:     return "blocked";
		case SEED_ERR_TRUNCATED:   return "truncated";
		case SEED_ERR_IO:          return "io";
	}
	return "unknown";
}

/* -- paths ---------------------------------------------------------------- */

/*
 * Every path is built from a base32 TTH, which is 39 characters drawn from
 * [A-Z2-7] and validated before it ever reaches here. That is what makes path
 * traversal impossible by construction rather than by sanitizing.
 */
static int seed_valid_tth(const char* str)
{
	size_t i;

	if (!str)
		return 0;
	for (i = 0; i < SEED_TTH_STR_LEN; i++)
		if (!is_valid_base32_char(str[i]))
			return 0;
	return str[SEED_TTH_STR_LEN] == '\0';
}

static void seed_data_path(struct seed_cache* cache, const char* tth, char* out, size_t outlen)
{
	snprintf(out, outlen, "%s/data/%c%c/%c%c/%s.bin", cache->dir,
		tth[0], tth[1], tth[2], tth[3], tth);
}

static void seed_fanout_path(struct seed_cache* cache, const char* tth, char* out, size_t outlen, int level)
{
	if (level == 1)
		snprintf(out, outlen, "%s/data/%c%c", cache->dir, tth[0], tth[1]);
	else
		snprintf(out, outlen, "%s/data/%c%c/%c%c", cache->dir, tth[0], tth[1], tth[2], tth[3]);
}

/*
 * Copy a directory entry name into a bounded buffer. The caller has already
 * rejected anything longer; going through a fixed-size local is what lets the
 * compiler bound the paths built from it.
 */
static void seed_copy_name(char dest[SEED_ENTRY_NAME_MAX + 1], const char* name)
{
	size_t len = strlen(name);
	if (len > SEED_ENTRY_NAME_MAX)
		len = SEED_ENTRY_NAME_MAX;
	memcpy(dest, name, len);
	dest[len] = '\0';
}

static int seed_mkdir(const char* path)
{
	if (mkdir(path, 0700) == 0)
		return 1;
	return errno == EEXIST;
}

static void seed_unlink_file(struct seed_cache* cache, const char* tth)
{
	char path[SEED_PATH_MAX];

	seed_data_path(cache, tth, path, sizeof(path));
	if (unlink(path) != 0 && errno != ENOENT)
		LOG_WARN("seed: unable to remove %s: %s", path, strerror(errno));
}

/* -- sqlite plumbing ------------------------------------------------------- */

static int seed_exec(struct seed_cache* cache, const char* sql)
{
	char* message = NULL;
	int rc = sqlite3_exec(cache->db, sql, NULL, NULL, &message);

	if (rc != SQLITE_OK)
	{
		LOG_ERROR("seed: \"%s\" failed: %s", sql, message ? message : sqlite3_errmsg(cache->db));
		sqlite3_free(message);
		return 0;
	}
	sqlite3_free(message);
	return 1;
}

static sqlite3_stmt* seed_prepare(struct seed_cache* cache, const char* sql)
{
	sqlite3_stmt* stmt = NULL;

	if (sqlite3_prepare_v2(cache->db, sql, -1, &stmt, NULL) != SQLITE_OK)
	{
		LOG_ERROR("seed: unable to prepare \"%s\": %s", sql, sqlite3_errmsg(cache->db));
		return NULL;
	}
	return stmt;
}

/**
 * A metadata write failed. The bytes on disk are still fine, but the cache can
 * no longer be trusted to remember what it holds, so ingest stops and the
 * operator is told once.
 */
static void seed_degrade(struct seed_cache* cache, const char* what)
{
	if (!cache->degraded)
		LOG_ERROR("seed: %s failed: %s -- cache degraded, ingest suspended",
			what, sqlite3_errmsg(cache->db));
	cache->degraded = 1;
}

/** Run a statement that returns no rows, then reset it. @return 1 on success. */
static int seed_step_done(struct seed_cache* cache, sqlite3_stmt* stmt, const char* what)
{
	int rc = sqlite3_step(stmt);

	sqlite3_reset(stmt);
	sqlite3_clear_bindings(stmt);

	if (rc != SQLITE_DONE)
	{
		seed_degrade(cache, what);
		return 0;
	}
	return 1;
}

static void seed_bind_tth(sqlite3_stmt* stmt, int index, const char* tth)
{
	sqlite3_bind_text(stmt, index, tth, SEED_TTH_STR_LEN, SQLITE_TRANSIENT);
}

/** Bind a string, or SQL NULL when it is absent or empty. */
static void seed_bind_opt(sqlite3_stmt* stmt, int index, const char* text)
{
	if (text && *text)
		sqlite3_bind_text(stmt, index, text, -1, SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(stmt, index);
}

static void seed_copy_text(char* dest, size_t destlen, const unsigned char* src)
{
	dest[0] = '\0';
	if (!src)
		return;
	strncpy(dest, (const char*) src, destlen - 1);
	dest[destlen - 1] = '\0';
}

/* -- pins ----------------------------------------------------------------- */

static int seed_strcmp(const void* a, const void* b)
{
	return strcmp((const char*) a, (const char*) b);
}

static struct seed_pin* seed_pin_find(struct seed_cache* cache, const char* tth)
{
	return (struct seed_pin*) rb_tree_get(cache->pins, tth);
}

int seed_cache_pin(struct seed_cache* cache, const char* tth)
{
	struct seed_pin* pin;

	if (!cache || !seed_valid_tth(tth))
		return 0;

	pin = seed_pin_find(cache, tth);
	if (pin)
	{
		pin->refs++;
		return 1;
	}

	/* Only something the cache actually holds can be pinned. */
	if (!seed_cache_lookup(cache, tth, NULL))
		return 0;

	pin = (struct seed_pin*) hub_malloc_zero(sizeof(*pin));
	if (!pin)
		return 0;

	memcpy(pin->tth, tth, SEED_TTH_STR_LEN + 1);
	pin->refs = 1;

	if (!rb_tree_insert(cache->pins, pin->tth, pin))
	{
		hub_free(pin);
		return 0;
	}
	return 1;
}

void seed_cache_unpin(struct seed_cache* cache, const char* tth)
{
	struct seed_pin* pin;

	if (!cache || !seed_valid_tth(tth))
		return;

	pin = seed_pin_find(cache, tth);
	if (!pin || pin->refs == 0)
		return;

	pin->refs--;
	if (pin->refs > 0)
		return;

	/* Last reader gone: whatever was deferred can happen now. */
	if (pin->unlink_pending)
		seed_unlink_file(cache, pin->tth);

	rb_tree_remove(cache->pins, pin->tth);
	hub_free(pin);
}

/* -- access times --------------------------------------------------------- */

/**
 * Stamp an access. Forced to increase so that entries touched within the same
 * second still evict in the order they were used, and clamped so the stamp can
 * never run far ahead of the wall clock.
 */
static time_t seed_stamp(struct seed_cache* cache, time_t now)
{
	time_t stamp = now;

	if (stamp <= cache->stamp)
		stamp = cache->stamp + 1;
	if (stamp > now + SEED_STAMP_MAX_SKEW)
		stamp = now + SEED_STAMP_MAX_SKEW;

	cache->stamp = stamp;
	return stamp;
}

static void seed_touch(struct seed_cache* cache, const char* tth)
{
	struct seed_touch* touch = (struct seed_touch*) rb_tree_get(cache->dirty, tth);

	if (!touch)
	{
		touch = (struct seed_touch*) hub_malloc_zero(sizeof(*touch));
		if (!touch)
			return;
		memcpy(touch->tth, tth, SEED_TTH_STR_LEN + 1);
		if (!rb_tree_insert(cache->dirty, touch->tth, touch))
		{
			hub_free(touch);
			return;
		}
	}

	touch->last_access = seed_stamp(cache, time(NULL));
	touch->hits++;
}

static void seed_touch_drop(struct seed_cache* cache, const char* tth)
{
	struct seed_touch* touch = (struct seed_touch*) rb_tree_get(cache->dirty, tth);

	if (!touch)
		return;
	rb_tree_remove(cache->dirty, touch->tth);
	hub_free(touch);
}

/**
 * Write out every access batched since the last flush.
 *
 * This is the whole point of batching: serving a file touches memory only, and
 * one transaction here pays for all of it. Eviction calls this first, because
 * ORDER BY last_access is only meaningful once the accesses have landed.
 */
static void seed_flush_touches(struct seed_cache* cache)
{
	struct rb_node* node;

	if (!cache->db || rb_tree_size(cache->dirty) == 0)
		return;

	seed_exec(cache, "BEGIN;");
	for (node = rb_tree_first(cache->dirty); node; node = rb_tree_next(cache->dirty))
	{
		struct seed_touch* touch = (struct seed_touch*) node->value;

		sqlite3_bind_int64(cache->st_touch, 1, (sqlite3_int64) touch->last_access);
		sqlite3_bind_int64(cache->st_touch, 2, (sqlite3_int64) touch->hits);
		seed_bind_tth(cache->st_touch, 3, touch->tth);
		seed_step_done(cache, cache->st_touch, "access time update");
	}
	seed_exec(cache, "COMMIT;");

	/* Remove before freeing: the node key points into the value. */
	while ((node = rb_tree_first(cache->dirty)) != NULL)
	{
		void* value = (void*) node->value;
		rb_tree_remove(cache->dirty, node->key);
		hub_free(value);
	}
}

/* -- rows ----------------------------------------------------------------- */

static void seed_row_to_entry(struct seed_cache* cache, sqlite3_stmt* stmt, struct seed_entry* out)
{
	struct seed_touch* touch;

	memset(out, 0, sizeof(*out));
	seed_copy_text(out->tth, sizeof(out->tth), sqlite3_column_text(stmt, 0));
	out->size = (uint64_t) sqlite3_column_int64(stmt, 1);
	seed_copy_text(out->media_type, sizeof(out->media_type), sqlite3_column_text(stmt, 2));
	seed_copy_text(out->name, sizeof(out->name), sqlite3_column_text(stmt, 3));
	out->first_seen = (time_t) sqlite3_column_int64(stmt, 4);
	out->last_access = (time_t) sqlite3_column_int64(stmt, 5);
	out->hits = (uint32_t) sqlite3_column_int64(stmt, 6);
	seed_copy_text(out->origin_cid, sizeof(out->origin_cid), sqlite3_column_text(stmt, 7));
	seed_copy_text(out->origin_nick, sizeof(out->origin_nick), sqlite3_column_text(stmt, 8));
	seed_copy_text(out->origin_addr, sizeof(out->origin_addr), sqlite3_column_text(stmt, 9));

	/* Overlay accesses that have not reached the database yet, so a caller
	   never sees a hit count go backwards across a sweep. */
	touch = (struct seed_touch*) rb_tree_get(cache->dirty, out->tth);
	if (touch)
	{
		out->last_access = touch->last_access;
		out->hits += touch->hits;
	}
}

/** Fetch a row without counting it as an access. @return 1 if found. */
static int seed_row_get(struct seed_cache* cache, const char* tth, struct seed_entry* out)
{
	int found = 0;

	seed_bind_tth(cache->st_lookup, 1, tth);
	if (sqlite3_step(cache->st_lookup) == SQLITE_ROW)
	{
		found = 1;
		if (out)
			seed_row_to_entry(cache, cache->st_lookup, out);
	}
	sqlite3_reset(cache->st_lookup);
	sqlite3_clear_bindings(cache->st_lookup);
	return found;
}

int seed_cache_peek(struct seed_cache* cache, const char* tth, struct seed_entry* out)
{
	if (!cache || !seed_valid_tth(tth))
		return 0;

	return seed_row_get(cache, tth, out);
}

int seed_cache_lookup(struct seed_cache* cache, const char* tth, struct seed_entry* out)
{
	if (!cache || !seed_valid_tth(tth))
		return 0;

	if (!seed_row_get(cache, tth, out))
		return 0;

	seed_touch(cache, tth);

	/* The access just recorded is the caller's own; show it the result rather
	   than the row as it stood a moment ago. */
	if (out)
	{
		out->last_access = cache->stamp;
		out->hits++;
	}
	return 1;
}

int seed_cache_open_file(struct seed_cache* cache, const char* tth)
{
	char path[SEED_PATH_MAX];
	int fd;

	if (!cache || !seed_valid_tth(tth))
		return -1;

	seed_data_path(cache, tth, path, sizeof(path));
	fd = open(path, O_RDONLY);
	if (fd < 0)
		LOG_WARN("seed: unable to open %s: %s", path, strerror(errno));
	return fd;
}

ssize_t seed_cache_read(struct seed_cache* cache, int fd, uint64_t size, uint64_t offset, void* buf, size_t len)
{
	ssize_t ret;

	if (!cache || fd < 0 || !buf)
		return -1;

	if (offset >= size)
		return 0;

	if ((uint64_t) len > (size - offset))
		len = (size_t) (size - offset);

	do
	{
		ret = pread(fd, buf, len, (off_t) offset);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

/* -- removal -------------------------------------------------------------- */

/**
 * Drop the record so nothing can look the entry up or take a fresh pin, then
 * drop the file. A pinned entry keeps its bytes on disk until the last transfer
 * finishes -- callers already holding a descriptor keep reading, and
 * seed_cache_unpin() finishes the job.
 */
static void seed_retire(struct seed_cache* cache, const char* tth, uint64_t size, const char* reason)
{
	struct seed_pin* pin;

	(void) reason; /* only read by LOG_DEBUG, which is compiled out in release builds */

	seed_bind_tth(cache->st_delete, 1, tth);
	if (!seed_step_done(cache, cache->st_delete, "entry removal"))
		return;

	seed_touch_drop(cache, tth);

	if (cache->entries)
		cache->entries--;
	cache->bytes_used = (cache->bytes_used > size) ? (cache->bytes_used - size) : 0;

	pin = seed_pin_find(cache, tth);
	if (pin && pin->refs > 0)
	{
		pin->unlink_pending = 1;
		LOG_DEBUG("seed: retired TTH=%s reason=%s (%u pins outstanding)",
			tth, reason ? reason : "-", pin->refs);
		return;
	}

	seed_unlink_file(cache, tth);
}

int seed_cache_remove(struct seed_cache* cache, const char* tth, const char* reason)
{
	struct seed_entry entry;

	if (!cache || !seed_valid_tth(tth))
		return 0;

	if (!seed_row_get(cache, tth, &entry))
		return 0;

	LOG_INFO("seed: removed TTH=%s size=%" PRIu64 " reason=%s",
		tth, entry.size, reason ? reason : "-");

	seed_retire(cache, tth, entry.size, reason);
	return 1;
}

/**
 * Collect victims before deleting any of them. Stepping a SELECT while removing
 * the rows it is walking is not something to rely on.
 */
static struct linked_list* seed_collect(sqlite3_stmt* stmt)
{
	struct linked_list* found = list_create();

	if (!found)
		return NULL;

	while (sqlite3_step(stmt) == SQLITE_ROW)
	{
		struct seed_victim* victim;
		const unsigned char* text = sqlite3_column_text(stmt, 0);

		if (!text || strlen((const char*) text) != SEED_TTH_STR_LEN)
			continue;

		victim = (struct seed_victim*) hub_malloc_zero(sizeof(*victim));
		if (!victim)
			break;
		memcpy(victim->tth, text, SEED_TTH_STR_LEN + 1);
		victim->size = (uint64_t) sqlite3_column_int64(stmt, 1);
		list_append(found, victim);
	}
	sqlite3_reset(stmt);
	return found;
}

size_t seed_cache_remove_by_cid(struct seed_cache* cache, const char* cid)
{
	sqlite3_stmt* stmt;
	struct linked_list* victims;
	struct seed_victim* victim;
	struct node* cursor;
	size_t removed = 0;

	if (!cache || !cid || !*cid)
		return 0;

	stmt = seed_prepare(cache, "SELECT tth, size FROM seed WHERE origin_cid = ?;");
	if (!stmt)
		return 0;

	sqlite3_bind_text(stmt, 1, cid, -1, SQLITE_TRANSIENT);
	victims = seed_collect(stmt);
	sqlite3_finalize(stmt);
	if (!victims)
		return 0;

	LIST_FOREACH_SAFE(struct seed_victim*, victim, victims, cursor,
	{
		seed_retire(cache, victim->tth, victim->size, "purge");
		removed++;
	});

	list_clear(victims, hub_free_handle);
	list_destroy(victims);
	return removed;
}

/* -- blocklist ------------------------------------------------------------ */

int seed_cache_is_blocked(struct seed_cache* cache, const char* tth)
{
	int blocked;

	if (!cache || !seed_valid_tth(tth))
		return 0;

	seed_bind_tth(cache->st_blocked, 1, tth);
	blocked = (sqlite3_step(cache->st_blocked) == SQLITE_ROW);
	sqlite3_reset(cache->st_blocked);
	sqlite3_clear_bindings(cache->st_blocked);
	return blocked;
}

int seed_cache_block(struct seed_cache* cache, const char* tth, const char* who, const char* reason)
{
	sqlite3_stmt* stmt;
	int ok;

	if (!cache || !seed_valid_tth(tth))
		return 0;

	if (seed_cache_is_blocked(cache, tth))
		return 0;

	stmt = seed_prepare(cache, "INSERT OR IGNORE INTO blocked (tth, who, reason, ts) VALUES (?,?,?,?);");
	if (!stmt)
		return 0;

	seed_bind_tth(stmt, 1, tth);
	seed_bind_opt(stmt, 2, who);
	seed_bind_opt(stmt, 3, reason);
	sqlite3_bind_int64(stmt, 4, (sqlite3_int64) time(NULL));
	ok = (sqlite3_step(stmt) == SQLITE_DONE);
	sqlite3_finalize(stmt);

	if (!ok)
	{
		seed_degrade(cache, "blocklist insert");
		return 0;
	}

	cache->blocked++;
	LOG_USER("seed: blocked TTH=%s by %s reason=%s",
		tth, who ? who : "-", reason ? reason : "-");

	/* Blocking without deleting the copy already held would be pointless. */
	seed_cache_remove(cache, tth, "blocked");
	return 1;
}

int seed_cache_unblock(struct seed_cache* cache, const char* tth)
{
	sqlite3_stmt* stmt;
	int changed;

	if (!cache || !seed_valid_tth(tth))
		return 0;

	stmt = seed_prepare(cache, "DELETE FROM blocked WHERE tth = ?;");
	if (!stmt)
		return 0;

	seed_bind_tth(stmt, 1, tth);
	if (sqlite3_step(stmt) != SQLITE_DONE)
	{
		sqlite3_finalize(stmt);
		seed_degrade(cache, "blocklist delete");
		return 0;
	}
	changed = sqlite3_changes(cache->db);
	sqlite3_finalize(stmt);

	if (changed > 0 && cache->blocked)
		cache->blocked--;
	return changed > 0;
}

/* -- eviction ------------------------------------------------------------- */

static int seed_over_limit(struct seed_cache* cache)
{
	if (cache->bytes_max && (cache->bytes_used + cache->bytes_reserved) > cache->bytes_max)
		return 1;
	if (cache->entries_max && cache->entries > cache->entries_max)
		return 1;
	return 0;
}

/**
 * Evict least recently used entries until the cache fits again. Entries with a
 * transfer in flight are skipped, so a busy cache can legitimately stay over
 * its limit for a moment rather than cutting a download short.
 */
static size_t seed_evict(struct seed_cache* cache, size_t budget)
{
	sqlite3_stmt* stmt;
	struct linked_list* victims;
	struct seed_victim* victim;
	struct node* cursor;
	size_t evicted = 0;
	sqlite3_int64 limit;

	if (!cache->db || !seed_over_limit(cache))
		return 0;

	/* ORDER BY last_access only means anything once the accesses are written. */
	seed_flush_touches(cache);

	stmt = seed_prepare(cache, "SELECT tth, size FROM seed ORDER BY last_access LIMIT ?;");
	if (!stmt)
		return 0;

	/* Ask for enough rows that skipping the pinned ones still leaves a full
	   budget of candidates. -1 is "no limit" to SQLite. */
	if (budget == (size_t) -1 || budget > (size_t) INT32_MAX)
		limit = -1;
	else
		limit = (sqlite3_int64) (budget + rb_tree_size(cache->pins));

	sqlite3_bind_int64(stmt, 1, limit);
	victims = seed_collect(stmt);
	sqlite3_finalize(stmt);
	if (!victims)
		return 0;

	LIST_FOREACH_SAFE(struct seed_victim*, victim, victims, cursor,
	{
		struct seed_pin* pin;

		if (evicted >= budget || !seed_over_limit(cache))
			break;

		pin = seed_pin_find(cache, victim->tth);
		if (pin && pin->refs > 0)
			continue;

		LOG_DEBUG("seed: evicted TTH=%s size=%" PRIu64, victim->tth, victim->size);
		seed_retire(cache, victim->tth, victim->size, "evict");
		evicted++;
	});

	list_clear(victims, hub_free_handle);
	list_destroy(victims);

	if (seed_over_limit(cache) && evicted == 0)
		LOG_WARN("seed: cache is over its limit but nothing is evictable (%zu pinned)",
			rb_tree_size(cache->pins));

	return evicted;
}

static void seed_expire(struct seed_cache* cache, time_t now)
{
	sqlite3_stmt* stmt;
	struct linked_list* victims;
	struct seed_victim* victim;
	struct node* cursor;

	if (cache->entry_ttl <= 0 || !cache->db)
		return;

	seed_flush_touches(cache);

	stmt = seed_prepare(cache, "SELECT tth, size FROM seed WHERE last_access <= ? ORDER BY last_access;");
	if (!stmt)
		return;

	sqlite3_bind_int64(stmt, 1, (sqlite3_int64) now - (sqlite3_int64) cache->entry_ttl);
	victims = seed_collect(stmt);
	sqlite3_finalize(stmt);
	if (!victims)
		return;

	LIST_FOREACH_SAFE(struct seed_victim*, victim, victims, cursor,
	{
		struct seed_pin* pin = seed_pin_find(cache, victim->tth);
		if (pin && pin->refs > 0)
			continue;
		seed_retire(cache, victim->tth, victim->size, "expired");
	});

	list_clear(victims, hub_free_handle);
	list_destroy(victims);
}

void seed_cache_sweep(struct seed_cache* cache, time_t now)
{
	if (!cache)
		return;

	seed_expire(cache, now);
	seed_evict(cache, SEED_MAX_EVICT_PER_SWEEP);
	seed_flush_touches(cache);
}

/* -- ingest --------------------------------------------------------------- */

static void seed_ingest_cleanup(struct seed_ingest* job)
{
	if (job->fd >= 0)
	{
		close(job->fd);
		job->fd = -1;
	}
	if (job->tmp_path[0])
	{
		unlink(job->tmp_path);
		job->tmp_path[0] = '\0';
	}
	job->cache->bytes_reserved -= job->reserved;
	job->cache->active_ingests--;
	hub_free(job);
}

struct seed_ingest* seed_ingest_begin(struct seed_cache* cache, const struct seed_ingest_request* req, enum seed_error* error)
{
	struct seed_ingest* job;
	enum seed_error err = SEED_OK;
	uint64_t reserve;

	if (error)
		*error = SEED_OK;

	if (!cache || !req)
		err = SEED_ERR_DISABLED;
	else if (cache->degraded)
		err = SEED_ERR_DEGRADED;
	else if (cache->active_ingests >= cache->max_concurrent_ingest)
		err = SEED_ERR_ADMISSION;
	else if (req->expect_tth && !seed_valid_tth(req->expect_tth))
		err = SEED_ERR_TTH_MISMATCH;
	else if (req->expect_tth && seed_cache_is_blocked(cache, req->expect_tth))
		err = SEED_ERR_BLOCKED;
	else if (req->announced_size && req->announced_size > cache->max_file_size)
		err = SEED_ERR_TOO_LARGE;

	if (err != SEED_OK)
	{
		if (error)
			*error = err;
		return NULL;
	}

	/*
	 * Reserve the worst case up front. Checking after the fact cannot stop N
	 * concurrent ingests from collectively blowing past the cache size.
	 */
	reserve = req->announced_size ? req->announced_size : cache->max_file_size;
	if (reserve > cache->max_file_size)
		reserve = cache->max_file_size;

	if (cache->bytes_max && (cache->bytes_used + cache->bytes_reserved + reserve) > cache->bytes_max)
	{
		cache->bytes_reserved += reserve;
		seed_evict(cache, SEED_MAX_EVICT_PER_SWEEP);
		cache->bytes_reserved -= reserve;

		if ((cache->bytes_used + cache->bytes_reserved + reserve) > cache->bytes_max)
		{
			if (error)
				*error = SEED_ERR_FULL;
			return NULL;
		}
	}

	job = (struct seed_ingest*) hub_malloc_zero(sizeof(*job));
	if (!job)
	{
		if (error)
			*error = SEED_ERR_IO;
		return NULL;
	}

	job->cache = cache;
	job->fd = -1;
	job->reserved = reserve;

	/* The announced size may lower the ceiling, never raise it, and is never
	   used as an allocation size anywhere. */
	job->limit = req->announced_size ? req->announced_size : cache->max_file_size;
	if (job->limit > cache->max_file_size)
		job->limit = cache->max_file_size;

	if (req->expect_tth)
	{
		memcpy(job->expect_tth, req->expect_tth, SEED_TTH_STR_LEN + 1);
		job->have_expect = 1;
	}

	if (req->name)
		strncpy(job->name, req->name, sizeof(job->name) - 1);
	if (req->origin_cid)
		strncpy(job->origin_cid, req->origin_cid, sizeof(job->origin_cid) - 1);
	if (req->origin_nick)
		strncpy(job->origin_nick, req->origin_nick, sizeof(job->origin_nick) - 1);
	if (req->origin_addr)
		strncpy(job->origin_addr, req->origin_addr, sizeof(job->origin_addr) - 1);

	snprintf(job->tmp_path, sizeof(job->tmp_path), "%s/tmp/%ld-%zu.part",
		cache->dir, (long) getpid(), cache->serial++);

	job->fd = open(job->tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (job->fd < 0)
	{
		LOG_ERROR("seed: unable to create %s: %s", job->tmp_path, strerror(errno));
		cache->degraded = 1;
		job->tmp_path[0] = '\0';
		hub_free(job);
		if (error)
			*error = SEED_ERR_IO;
		return NULL;
	}

	tth_init(&job->hash);
	cache->bytes_reserved += reserve;
	cache->active_ingests++;
	return job;
}

/**
 * Decide the media type from the buffered head. Called as soon as the head is
 * complete, so a disallowed type is refused near byte SEED_SNIFF_BYTES rather
 * than after a full download, and again at finish for a file shorter than that.
 */
static int seed_ingest_decide_media(struct seed_ingest* job)
{
	const char* type;

	if (job->media_decided)
		return job->media_allowed;

	type = seed_sniff_media_type(job->sniff, job->sniff_len);
	strncpy(job->media_type, type, sizeof(job->media_type) - 1);
	job->media_type[sizeof(job->media_type) - 1] = '\0';

	job->media_allowed = seed_sniff_type_allowed(job->media_type, job->cache->allowed_types);
	job->media_decided = 1;
	return job->media_allowed;
}

int seed_ingest_write(struct seed_ingest* job, const void* data, size_t len)
{
	const uint8_t* ptr = (const uint8_t*) data;
	size_t written = 0;

	if (!job || !data)
		return -SEED_ERR_IO;

	/*
	 * The limit is enforced against bytes actually received, never against the
	 * size the sender announced -- that is what stops a short Content-Length
	 * followed by a huge body, and a lying peer, with the same check.
	 */
	if ((job->received + (uint64_t) len) > job->limit)
		return -SEED_ERR_TOO_LARGE;

	/* Buffer the head so the media type can be decided before the whole
	   transfer is paid for. */
	if (!job->media_decided && job->sniff_len < SEED_SNIFF_BYTES)
	{
		size_t take = SEED_SNIFF_BYTES - job->sniff_len;
		if (take > len)
			take = len;
		memcpy(job->sniff + job->sniff_len, ptr, take);
		job->sniff_len += take;

		if (job->sniff_len == SEED_SNIFF_BYTES && !seed_ingest_decide_media(job))
		{
			LOG_USER("seed: rejected (media_type) type=%s cid=%s name=%s",
				job->media_type, job->origin_cid[0] ? job->origin_cid : "-", job->name);
			return -SEED_ERR_MEDIA_TYPE;
		}
	}

	while (written < len)
	{
		ssize_t ret = write(job->fd, ptr + written, len - written);
		if (ret < 0)
		{
			if (errno == EINTR)
				continue;
			LOG_ERROR("seed: write failed: %s", strerror(errno));
			if (errno == ENOSPC || errno == EIO || errno == EDQUOT)
				job->cache->degraded = 1;
			return -SEED_ERR_IO;
		}
		written += (size_t) ret;
	}

	tth_update(&job->hash, data, len);
	job->received += (uint64_t) len;
	return 0;
}

static int seed_ingest_publish(struct seed_ingest* job, const char* tth)
{
	struct seed_cache* cache = job->cache;
	char dir[SEED_SUBDIR_MAX];
	char path[SEED_PATH_MAX];
	time_t now = time(NULL);

	if (fsync(job->fd) != 0)
		LOG_WARN("seed: fsync failed: %s", strerror(errno));
	close(job->fd);
	job->fd = -1;

	seed_fanout_path(cache, tth, dir, sizeof(dir), 1);
	if (!seed_mkdir(dir))
	{
		LOG_ERROR("seed: unable to create %s: %s", dir, strerror(errno));
		cache->degraded = 1;
		return 0;
	}
	seed_fanout_path(cache, tth, dir, sizeof(dir), 2);
	if (!seed_mkdir(dir))
	{
		LOG_ERROR("seed: unable to create %s: %s", dir, strerror(errno));
		cache->degraded = 1;
		return 0;
	}

	seed_data_path(cache, tth, path, sizeof(path));

	/*
	 * Publish atomically. Until this rename the bytes live only under tmp/,
	 * which is why a crash can never leave a partial file where a reader would
	 * find it.
	 */
	if (rename(job->tmp_path, path) != 0)
	{
		LOG_ERROR("seed: unable to publish %s: %s", path, strerror(errno));
		cache->degraded = 1;
		return 0;
	}
	job->tmp_path[0] = '\0';

	seed_bind_tth(cache->st_insert, 1, tth);
	sqlite3_bind_int64(cache->st_insert, 2, (sqlite3_int64) job->received);
	sqlite3_bind_text(cache->st_insert, 3, job->media_type, -1, SQLITE_TRANSIENT);
	seed_bind_opt(cache->st_insert, 4, job->name);
	sqlite3_bind_int64(cache->st_insert, 5, (sqlite3_int64) now);
	sqlite3_bind_int64(cache->st_insert, 6, (sqlite3_int64) seed_stamp(cache, now));
	seed_bind_opt(cache->st_insert, 7, job->origin_cid);
	seed_bind_opt(cache->st_insert, 8, job->origin_nick);
	seed_bind_opt(cache->st_insert, 9, job->origin_addr);

	if (!seed_step_done(cache, cache->st_insert, "entry insert"))
	{
		/* The record is what makes the file reachable; without it the bytes are
		   an orphan that startup would adopt with no provenance. Take them back
		   out rather than leaving that behind. */
		unlink(path);
		return 0;
	}

	cache->entries++;
	cache->bytes_used += job->received;
	return 1;
}

int seed_ingest_finish(struct seed_ingest* job, struct seed_entry* out, enum seed_error* error)
{
	struct seed_cache* cache;
	uint8_t root[TTH_SIZE];
	char tth[SEED_TTH_STR_LEN + 1];
	enum seed_error err = SEED_OK;

	if (error)
		*error = SEED_OK;

	if (!job)
		return 0;

	cache = job->cache;

	tth_finalize(&job->hash, root);
	tth_to_string(root, tth);

	if (job->have_expect && strcmp(tth, job->expect_tth) != 0)
	{
		LOG_USER("seed: rejected (tth_mismatch) announced=%s computed=%s cid=%s",
			job->expect_tth, tth, job->origin_cid[0] ? job->origin_cid : "-");
		err = SEED_ERR_TTH_MISMATCH;
	}
	else if (seed_cache_is_blocked(cache, tth))
	{
		err = SEED_ERR_BLOCKED;
	}
	else if (!seed_ingest_decide_media(job))
	{
		LOG_USER("seed: rejected (media_type) type=%s cid=%s name=%s",
			job->media_type, job->origin_cid[0] ? job->origin_cid : "-", job->name);
		err = SEED_ERR_MEDIA_TYPE;
	}

	if (err != SEED_OK)
	{
		seed_ingest_cleanup(job);
		if (error)
			*error = err;
		return 0;
	}

	/* Deduplicate: a different URL may well have produced bytes we hold. */
	if (seed_row_get(cache, tth, out))
	{
		seed_touch(cache, tth);
		seed_ingest_cleanup(job);
		return 1;
	}

	if (!seed_ingest_publish(job, tth))
	{
		seed_ingest_cleanup(job);
		if (error)
			*error = SEED_ERR_IO;
		return 0;
	}

	LOG_USER("seed: accepted TTH=%s size=%" PRIu64 " type=%s cid=%s name=%s",
		tth, job->received, job->media_type,
		job->origin_cid[0] ? job->origin_cid : "-", job->name);

	seed_ingest_cleanup(job);
	seed_evict(cache, SEED_MAX_EVICT_PER_SWEEP);

	if (out)
		seed_row_get(cache, tth, out);
	return 1;
}

void seed_ingest_abort(struct seed_ingest* job, enum seed_error reason)
{
	if (!job)
		return;

	LOG_DEBUG("seed: ingest aborted (%s)", seed_error_string(reason));
	(void) reason; /* only read by LOG_DEBUG, which is compiled out in release builds */

	seed_ingest_cleanup(job);
}

/* -- startup recovery ----------------------------------------------------- */

static void seed_clear_tmp(struct seed_cache* cache)
{
	char path[SEED_SUBDIR_MAX];
	DIR* dir;
	struct dirent* ent;

	snprintf(path, sizeof(path), "%s/tmp", cache->dir);
	dir = opendir(path);
	if (!dir)
		return;

	/* Anything here is by definition an unverified partial transfer. */
	while ((ent = readdir(dir)) != NULL)
	{
		char file[SEED_PATH_MAX];
		char safe[SEED_ENTRY_NAME_MAX + 1];

		if (ent->d_name[0] == '.')
			continue;
		if (strlen(ent->d_name) > SEED_ENTRY_NAME_MAX)
		{
			/* Far longer than anything this code writes, so it is not ours and
			   is left alone rather than built into a path that would truncate. */
			LOG_WARN("seed: ignoring unexpected name in %s", path);
			continue;
		}
		seed_copy_name(safe, ent->d_name);
		snprintf(file, sizeof(file), "%s/%s", path, safe);
		unlink(file);
	}
	closedir(dir);
}

/** Sniff a file already on disk, for an orphan that has no recorded type. */
static void seed_sniff_file(const char* path, char* out, size_t outlen)
{
	uint8_t head[SEED_SNIFF_BYTES];
	size_t have = 0;
	int fd = open(path, O_RDONLY);

	if (fd >= 0)
	{
		while (have < sizeof(head))
		{
			ssize_t got = read(fd, head + have, sizeof(head) - have);
			if (got < 0 && errno == EINTR)
				continue;
			if (got <= 0)
				break;
			have += (size_t) got;
		}
		close(fd);
	}

	strncpy(out, seed_sniff_media_type(head, have), outlen - 1);
	out[outlen - 1] = '\0';
}

static void seed_adopt(struct seed_cache* cache, const char* tth, const char* path, const struct stat* st)
{
	char media_type[SEED_MIME_MAX];

	seed_sniff_file(path, media_type, sizeof(media_type));

	seed_bind_tth(cache->st_insert, 1, tth);
	sqlite3_bind_int64(cache->st_insert, 2, (sqlite3_int64) st->st_size);
	sqlite3_bind_text(cache->st_insert, 3, media_type, -1, SQLITE_TRANSIENT);
	sqlite3_bind_null(cache->st_insert, 4);
	sqlite3_bind_int64(cache->st_insert, 5, (sqlite3_int64) st->st_mtime);
	sqlite3_bind_int64(cache->st_insert, 6, (sqlite3_int64) st->st_mtime);
	sqlite3_bind_null(cache->st_insert, 7);
	sqlite3_bind_null(cache->st_insert, 8);
	sqlite3_bind_null(cache->st_insert, 9);

	if (seed_step_done(cache, cache->st_insert, "orphan adoption"))
		LOG_INFO("seed: adopted TTH=%s size=%lld type=%s",
			tth, (long long) st->st_size, media_type);
}

/**
 * Reconcile the database against what is actually on disk.
 *
 * The file name is the content hash, so the directory is the authority for what
 * exists and the database only for what is known about it: a record without a
 * file is dropped, and a file without a record is adopted -- its bytes are not
 * re-hashed here, which is why a lazy verification option exists.
 */
static void seed_reconcile(struct seed_cache* cache)
{
	char root[SEED_SUBDIR_MAX];
	sqlite3_stmt* present;
	DIR* d1;
	struct dirent* e1;

	snprintf(root, sizeof(root), "%s/data", cache->dir);
	d1 = opendir(root);
	if (!d1)
	{
		/*
		 * The directory is the authority, so not being able to read it is not a
		 * licence to declare everything gone. Leave the records alone.
		 */
		LOG_ERROR("seed: unable to read %s: %s -- keeping the index as it stands",
			root, strerror(errno));
		return;
	}

	if (!seed_exec(cache, "CREATE TEMP TABLE IF NOT EXISTS present (tth TEXT PRIMARY KEY, size INTEGER NOT NULL);") ||
	    !seed_exec(cache, "DELETE FROM present;"))
	{
		closedir(d1);
		return;
	}

	present = seed_prepare(cache, "INSERT OR IGNORE INTO present (tth, size) VALUES (?, ?);");
	if (!present)
	{
		closedir(d1);
		return;
	}

	seed_exec(cache, "BEGIN;");

	while ((e1 = readdir(d1)) != NULL)
	{
		char l1[SEED_SUBDIR_MAX];
		DIR* d2;
		struct dirent* e2;

		/* Our fanout directories are exactly two characters. Anything else is
		   not ours, and refusing it here is what keeps every path below inside
		   SEED_PATH_MAX. */
		if (e1->d_name[0] == '.' || strlen(e1->d_name) != 2)
			continue;
		snprintf(l1, sizeof(l1), "%s/data/%c%c", cache->dir, e1->d_name[0], e1->d_name[1]);
		d2 = opendir(l1);
		if (!d2)
			continue;

		while ((e2 = readdir(d2)) != NULL)
		{
			char l2[SEED_SUBDIR_MAX];
			DIR* d3;
			struct dirent* e3;

			if (e2->d_name[0] == '.' || strlen(e2->d_name) != 2)
				continue;
			snprintf(l2, sizeof(l2), "%s/data/%c%c/%c%c", cache->dir,
				e1->d_name[0], e1->d_name[1], e2->d_name[0], e2->d_name[1]);
			d3 = opendir(l2);
			if (!d3)
				continue;

			while ((e3 = readdir(d3)) != NULL)
			{
				char file[SEED_PATH_MAX];
				char safe[SEED_ENTRY_NAME_MAX + 1];
				char tth[SEED_TTH_STR_LEN + 1];
				struct stat st;
				size_t len = strlen(e3->d_name);

				if (e3->d_name[0] == '.')
					continue;

				/*
				 * Only "<39 base32>.bin" is ours. The length is checked before
				 * the path is built, so nothing longer is ever formatted into
				 * it -- which is what keeps this inside SEED_PATH_MAX.
				 */
				if (len > SEED_ENTRY_NAME_MAX)
				{
					LOG_WARN("seed: ignoring unexpected name in %s", l2);
					continue;
				}

				seed_copy_name(safe, e3->d_name);
				snprintf(file, sizeof(file), "%s/%s", l2, safe);

				if (len != (SEED_TTH_STR_LEN + 4) || strcmp(e3->d_name + SEED_TTH_STR_LEN, ".bin") != 0)
				{
					LOG_WARN("seed: removing unexpected file %s", file);
					unlink(file);
					continue;
				}

				memcpy(tth, e3->d_name, SEED_TTH_STR_LEN);
				tth[SEED_TTH_STR_LEN] = '\0';

				if (!seed_valid_tth(tth) || stat(file, &st) != 0 || !S_ISREG(st.st_mode))
				{
					LOG_WARN("seed: removing unexpected file %s", file);
					unlink(file);
					continue;
				}

				seed_bind_tth(present, 1, tth);
				sqlite3_bind_int64(present, 2, (sqlite3_int64) st.st_size);
				seed_step_done(cache, present, "reconciliation");

				if (!seed_row_get(cache, tth, NULL))
					seed_adopt(cache, tth, file, &st);
			}
			closedir(d3);
		}
		closedir(d2);
	}
	closedir(d1);

	/* Records with no file left behind: drop them. */
	seed_exec(cache, "DELETE FROM seed WHERE tth NOT IN (SELECT tth FROM present);");

	/* The file is the authority for its own size as well, not just for whether
	   it exists -- a truncated file must not be served at its recorded length. */
	seed_exec(cache,
		"UPDATE seed SET size = (SELECT p.size FROM present p WHERE p.tth = seed.tth) "
		"WHERE tth IN (SELECT tth FROM present);");

	seed_exec(cache, "COMMIT;");
	sqlite3_finalize(present);
	seed_exec(cache, "DROP TABLE IF EXISTS present;");
}

/**
 * A blocked TTH must not come back after a restart, however its file got there
 * -- a pin outliving a block, or a copy dropped into data/ by hand.
 */
static void seed_purge_blocked(struct seed_cache* cache)
{
	sqlite3_stmt* stmt = seed_prepare(cache,
		"SELECT tth, size FROM seed WHERE tth IN (SELECT tth FROM blocked);");
	struct linked_list* victims;
	struct seed_victim* victim;
	struct node* cursor;

	if (!stmt)
		return;

	victims = seed_collect(stmt);
	sqlite3_finalize(stmt);
	if (!victims)
		return;

	LIST_FOREACH_SAFE(struct seed_victim*, victim, victims, cursor,
	{
		LOG_WARN("seed: removing blocked TTH=%s found on disk", victim->tth);
		seed_retire(cache, victim->tth, victim->size, "blocked");
	});

	list_clear(victims, hub_free_handle);
	list_destroy(victims);
}

static void seed_load_counters(struct seed_cache* cache)
{
	sqlite3_stmt* stmt;

	cache->entries = 0;
	cache->bytes_used = 0;
	cache->blocked = 0;

	stmt = seed_prepare(cache, "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM seed;");
	if (stmt)
	{
		if (sqlite3_step(stmt) == SQLITE_ROW)
		{
			cache->entries = (size_t) sqlite3_column_int64(stmt, 0);
			cache->bytes_used = (uint64_t) sqlite3_column_int64(stmt, 1);
		}
		sqlite3_finalize(stmt);
	}

	stmt = seed_prepare(cache, "SELECT COUNT(*) FROM blocked;");
	if (stmt)
	{
		if (sqlite3_step(stmt) == SQLITE_ROW)
			cache->blocked = (size_t) sqlite3_column_int64(stmt, 0);
		sqlite3_finalize(stmt);
	}
}

/* -- lifecycle ------------------------------------------------------------ */

static const char* seed_schema =
	"CREATE TABLE IF NOT EXISTS seed ("
		"tth TEXT PRIMARY KEY, size INTEGER NOT NULL, media_type TEXT NOT NULL, name TEXT,"
		"first_seen INTEGER NOT NULL, last_access INTEGER NOT NULL, hits INTEGER NOT NULL DEFAULT 0,"
		"origin_cid TEXT, origin_nick TEXT, origin_addr TEXT);"
	"CREATE INDEX IF NOT EXISTS seed_lru ON seed(last_access);"
	"CREATE INDEX IF NOT EXISTS seed_origin ON seed(origin_cid);"
	"CREATE TABLE IF NOT EXISTS blocked ("
		"tth TEXT PRIMARY KEY, who TEXT, reason TEXT, ts INTEGER);";

static int seed_open_db(struct seed_cache* cache)
{
	char path[SEED_SUBDIR_MAX];

	snprintf(path, sizeof(path), "%s/%s", cache->dir, SEED_DB_NAME);

	if (sqlite3_open_v2(path, &cache->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK)
	{
		LOG_ERROR("seed: unable to open %s: %s", path,
			cache->db ? sqlite3_errmsg(cache->db) : "out of memory");
		return 0;
	}

	sqlite3_busy_timeout(cache->db, 250);

	/*
	 * The first statement is where a corrupt or unreadable file shows up --
	 * sqlite3_open_v2() only records the name. Failing here is not fatal: the
	 * caller is told the cache is unavailable and carries on without one.
	 */
	if (!seed_exec(cache, "PRAGMA journal_mode = WAL;") ||
	    !seed_exec(cache, "PRAGMA synchronous = NORMAL;") ||
	    !seed_exec(cache, seed_schema))
	{
		LOG_ERROR("seed: %s is not usable -- cache disabled", path);
		return 0;
	}

	cache->st_lookup = seed_prepare(cache, "SELECT " SEED_COLUMNS " FROM seed WHERE tth = ?;");
	cache->st_insert = seed_prepare(cache,
		"INSERT INTO seed (" SEED_COLUMNS ") VALUES (?,?,?,?,?,?,0,?,?,?);");
	cache->st_touch = seed_prepare(cache, "UPDATE seed SET last_access = ?, hits = hits + ? WHERE tth = ?;");
	cache->st_delete = seed_prepare(cache, "DELETE FROM seed WHERE tth = ?;");
	cache->st_blocked = seed_prepare(cache, "SELECT 1 FROM blocked WHERE tth = ?;");

	return cache->st_lookup && cache->st_insert && cache->st_touch &&
	       cache->st_delete && cache->st_blocked;
}

struct seed_cache* seed_cache_open(const struct seed_cache_config* cfg)
{
	struct seed_cache* cache;
	char path[SEED_SUBDIR_MAX];

	if (!cfg || !cfg->dir || !*cfg->dir)
		return NULL;

	cache = (struct seed_cache*) hub_malloc_zero(sizeof(*cache));
	if (!cache)
		return NULL;

	/* Bounded so that every path derived from it fits in SEED_PATH_MAX. */
	if (strlen(cfg->dir) >= sizeof(cache->dir))
	{
		LOG_ERROR("seed: cache directory is longer than %d characters -- cache disabled",
			(int) sizeof(cache->dir) - 1);
		hub_free(cache);
		return NULL;
	}
	strncpy(cache->dir, cfg->dir, sizeof(cache->dir) - 1);

	cache->bytes_max = cfg->max_bytes;
	cache->max_file_size = cfg->max_file_size ? cfg->max_file_size : SEED_DEFAULT_MAX_FILE_SIZE;
	cache->entries_max = cfg->max_entries;
	cache->entry_ttl = cfg->entry_ttl;
	cache->max_concurrent_ingest = cfg->max_concurrent_ingest ? cfg->max_concurrent_ingest : SEED_DEFAULT_MAX_INGEST;
	cache->allowed_types = hub_strdup(cfg->allowed_types ? cfg->allowed_types : SEED_DEFAULT_TYPES);

	/*
	 * This may run after privileges are dropped, so the parent directory has to
	 * be writable by the daemon user. Failing here disables the cache and
	 * leaves the daemon running.
	 */
	if (!cache->allowed_types || !seed_mkdir(cache->dir))
	{
		LOG_ERROR("seed: unable to create %s: %s -- cache disabled", cache->dir, strerror(errno));
		hub_free(cache->allowed_types);
		hub_free(cache);
		return NULL;
	}

	snprintf(path, sizeof(path), "%s/tmp", cache->dir);
	if (!seed_mkdir(path))
	{
		LOG_ERROR("seed: unable to create %s: %s -- cache disabled", path, strerror(errno));
		hub_free(cache->allowed_types);
		hub_free(cache);
		return NULL;
	}

	snprintf(path, sizeof(path), "%s/data", cache->dir);
	if (!seed_mkdir(path))
	{
		LOG_ERROR("seed: unable to create %s: %s -- cache disabled", path, strerror(errno));
		hub_free(cache->allowed_types);
		hub_free(cache);
		return NULL;
	}

	cache->pins = rb_tree_create(seed_strcmp, NULL, NULL);
	cache->dirty = rb_tree_create(seed_strcmp, NULL, NULL);

	if (!cache->pins || !cache->dirty || !seed_open_db(cache))
	{
		seed_cache_close(cache);
		return NULL;
	}

	seed_clear_tmp(cache);
	seed_reconcile(cache);
	seed_purge_blocked(cache);
	seed_load_counters(cache);

	/* A cache size that shrank between runs takes effect immediately. */
	seed_evict(cache, (size_t) -1);

	LOG_INFO("seed: cache ready at %s (%zu entries, %" PRIu64 " bytes, limit %" PRIu64 " bytes)",
		cache->dir, cache->entries, cache->bytes_used, cache->bytes_max);

	return cache;
}

static void seed_free_tree(struct seed_cache* cache, struct rb_tree* tree, int unlink_pending)
{
	struct rb_node* node;

	if (!tree)
		return;

	/*
	 * rb_tree_destroy() releases the tree itself but not its nodes, so the tree
	 * has to be emptied first. Remove before freeing the value: the node key
	 * points into it.
	 */
	while ((node = rb_tree_first(tree)) != NULL)
	{
		void* value = (void*) node->value;

		if (unlink_pending)
		{
			struct seed_pin* pin = (struct seed_pin*) value;
			/* The record is already gone; leaving the file would only have it
			   adopted as an orphan on the next start. */
			if (pin->unlink_pending)
				seed_unlink_file(cache, pin->tth);
		}

		rb_tree_remove(tree, node->key);
		hub_free(value);
	}

	rb_tree_destroy(tree);
}

void seed_cache_close(struct seed_cache* cache)
{
	if (!cache)
		return;

	if (cache->active_ingests)
		LOG_WARN("seed: closing with %zu ingest(s) still in flight", cache->active_ingests);

	if (cache->db)
	{
		seed_flush_touches(cache);

		if (cache->st_iter)
			sqlite3_finalize(cache->st_iter);
		sqlite3_finalize(cache->st_lookup);
		sqlite3_finalize(cache->st_insert);
		sqlite3_finalize(cache->st_touch);
		sqlite3_finalize(cache->st_delete);
		sqlite3_finalize(cache->st_blocked);
		cache->st_iter = NULL;

		if (sqlite3_close(cache->db) != SQLITE_OK)
			LOG_WARN("seed: unable to close the database cleanly: %s", sqlite3_errmsg(cache->db));
		cache->db = NULL;
	}

	seed_free_tree(cache, cache->pins, 1);
	seed_free_tree(cache, cache->dirty, 0);

	hub_free(cache->allowed_types);
	hub_free(cache);
}

void seed_cache_get_stats(struct seed_cache* cache, struct seed_cache_stats* out)
{
	if (!out)
		return;

	memset(out, 0, sizeof(*out));
	if (!cache)
		return;

	out->bytes_used = cache->bytes_used;
	out->bytes_reserved = cache->bytes_reserved;
	out->bytes_max = cache->bytes_max;
	out->entries = cache->entries;
	out->entries_max = cache->entries_max;
	out->pinned = rb_tree_size(cache->pins);
	out->active_ingests = cache->active_ingests;
	out->blocked = cache->blocked;
	out->degraded = cache->degraded;
}

/* -- iteration ------------------------------------------------------------ */

int seed_cache_first(struct seed_cache* cache, struct seed_entry* out)
{
	if (!cache || !out)
		return 0;

	if (cache->st_iter)
	{
		sqlite3_finalize(cache->st_iter);
		cache->st_iter = NULL;
	}

	/* The listing shows the access times, so it has to see the batched ones. */
	seed_flush_touches(cache);

	cache->st_iter = seed_prepare(cache, "SELECT " SEED_COLUMNS " FROM seed ORDER BY last_access DESC;");
	if (!cache->st_iter)
		return 0;

	return seed_cache_next(cache, out);
}

int seed_cache_next(struct seed_cache* cache, struct seed_entry* out)
{
	if (!cache || !out || !cache->st_iter)
		return 0;

	if (sqlite3_step(cache->st_iter) != SQLITE_ROW)
	{
		sqlite3_finalize(cache->st_iter);
		cache->st_iter = NULL;
		return 0;
	}

	seed_row_to_entry(cache, cache->st_iter, out);
	return 1;
}
