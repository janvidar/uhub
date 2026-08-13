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

#ifndef HAVE_UHUB_SEEDER_CACHE_H
#define HAVE_UHUB_SEEDER_CACHE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/**
 * The seed cache: a content addressed store of files the seeder serves.
 *
 * Files are named by their TTH, which is verified before anything is ever
 * published, so a file name is always a 39 character base32 token from a fixed
 * alphabet and never anything a peer supplied. Partial transfers live only
 * under tmp/ and are moved into place with rename(2) once verified, so there is
 * no code path by which an unverified byte can be served.
 *
 * Metadata lives in an SQLite database in the cache directory. The database is
 * what is *known* about the cache; the data/ directory is what the cache
 * actually *is*. Startup reconciles the two in that order of authority: a
 * record with no file is dropped, a file with no record is adopted.
 *
 * Everything here is single threaded and runs on the daemon's main loop. No
 * call blocks on the network, and only seed_cache_sweep() writes metadata in
 * bulk -- serving a file costs no database write at all.
 */

#define SEED_TTH_STR_LEN 39  /** Length of a base32 TTH, excluding NUL. */
#define SEED_NAME_MAX   256  /** Display name, sanitized and NUL terminated. */
#define SEED_MIME_MAX    64  /** Detected media type. */

struct seed_cache;
struct seed_ingest;

enum seed_error
{
	SEED_OK = 0,
	SEED_ERR_DISABLED,     /** The cache is not enabled. */
	SEED_ERR_DEGRADED,     /** Disk or database error; ingest suspended. */
	SEED_ERR_ADMISSION,    /** Too many concurrent ingests. */
	SEED_ERR_QUOTA,        /** Per peer rate or byte quota exceeded. */
	SEED_ERR_FULL,         /** Would not fit within the configured cache size. */
	SEED_ERR_TOO_LARGE,    /** Exceeds the per file size limit. */
	SEED_ERR_TTH_MISMATCH, /** Content did not hash to the announced TTH. */
	SEED_ERR_MEDIA_TYPE,   /** Detected media type is not allowed. */
	SEED_ERR_BLOCKED,      /** TTH is on the operator blocklist. */
	SEED_ERR_TRUNCATED,    /** Sender stopped early. */
	SEED_ERR_IO            /** Local I/O failure. */
};

/**
 * A cached file, as reported to a caller. This is a snapshot copied out of the
 * database, not a handle: it does not stay live, and holding one is not a pin.
 */
struct seed_entry
{
	char     tth[SEED_TTH_STR_LEN + 1];
	uint64_t size;
	char     media_type[SEED_MIME_MAX];
	char     name[SEED_NAME_MAX];

	time_t   first_seen;
	time_t   last_access;
	uint32_t hits;

	/* Provenance, so a takedown request months later can be answered. */
	char     origin_cid[64];
	char     origin_nick[64];
	char     origin_addr[64];
};

/**
 * Cache configuration. Copied by seed_cache_open(); none of the pointers need
 * outlive the call.
 *
 * @c max_bytes, @c max_entries and @c entry_ttl are limits, and 0 means "no
 * limit". @c max_file_size and @c max_concurrent_ingest are not limits but
 * budgets that the admission control divides up, so 0 there selects a default
 * rather than switching the check off -- an unbounded per file size would make
 * the up front reservation meaningless.
 */
struct seed_cache_config
{
	const char* dir;            /** Cache directory. Bounded; see SEED_DIR_MAX. */
	uint64_t max_bytes;         /** Total cache size in bytes. */
	uint64_t max_file_size;     /** Per file ceiling in bytes. */
	size_t   max_entries;
	int      entry_ttl;         /** Seconds since last access, 0 = never. */
	size_t   max_concurrent_ingest;
	const char* allowed_types;  /** Comma separated media types. */
};

struct seed_cache_stats
{
	uint64_t bytes_used;
	uint64_t bytes_reserved;
	uint64_t bytes_max;
	size_t   entries;
	size_t   entries_max;
	size_t   pinned;
	size_t   active_ingests;
	size_t   blocked;
	int      degraded;
};

/**
 * Open the cache, creating the directory layout and the database if needed, and
 * reconcile the two against each other.
 *
 * Never aborts. If the directory cannot be created or written -- remember this
 * may run after privileges are dropped -- or the database is corrupt or
 * unreadable, the problem is logged and NULL is returned, and the caller simply
 * runs without a cache.
 */
extern struct seed_cache* seed_cache_open(const struct seed_cache_config* cfg);

/**
 * Flush pending access times and close. Files still held by a pin that was
 * retired are unlinked here, so a restart does not re-adopt them.
 */
extern void seed_cache_close(struct seed_cache* cache);

/**
 * Look an entry up without recording an access.
 *
 * Use this for anything that merely inspects the cache. seed_cache_lookup()
 * counts a hit and moves the entry to the head of the LRU, which is right for a
 * transfer and wrong for an operator listing what is stored: it would reorder
 * eviction, and asking about a file would be enough to keep it alive.
 *
 * @param out filled in when the entry exists. May be NULL.
 * @return 1 if found, 0 otherwise.
 */
extern int seed_cache_peek(struct seed_cache* cache, const char* tth, struct seed_entry* out);

/**
 * Look up an entry by base32 TTH and count the access.
 *
 * The access time and hit count are updated in memory only; they reach the
 * database on the next sweep. Serving a file therefore costs no write.
 *
 * @param out filled in when the entry exists. May be NULL.
 * @return 1 if found, 0 otherwise.
 */
extern int seed_cache_lookup(struct seed_cache* cache, const char* tth, struct seed_entry* out);

/**
 * Hold an entry in place for the duration of a transfer.
 *
 * A pinned entry is never evicted and its file is never unlinked, so a transfer
 * in progress always completes. Pins are runtime state: they describe transfers
 * in flight, are never written to the database, and do not survive a restart.
 * An entry that is removed while pinned is retired from lookup immediately but
 * keeps its bytes until the last unpin.
 *
 * @return 1 on success, 0 if there is no such entry.
 */
extern int seed_cache_pin(struct seed_cache* cache, const char* tth);
extern void seed_cache_unpin(struct seed_cache* cache, const char* tth);

/**
 * Open a read-only descriptor for an entry. The caller must hold a pin, and
 * owns the descriptor: close it before releasing the pin.
 * @return a descriptor, or -1 on error.
 */
extern int seed_cache_open_file(struct seed_cache* cache, const char* tth);

/**
 * Read from a descriptor at an absolute offset, clamped to @p size -- the size
 * the cache recorded for the entry, not the size of the file on disk.
 * @return bytes read, 0 at end of file, -1 on error.
 */
extern ssize_t seed_cache_read(struct seed_cache* cache, int fd, uint64_t size, uint64_t offset, void* buf, size_t len);

/** Description of a file about to be ingested. All strings are untrusted. */
struct seed_ingest_request
{
	const char* expect_tth;   /** Announced TTH in base32, or NULL when mirroring a URL. */
	uint64_t announced_size;  /** 0 when unknown. Only ever lowers the limit. */
	const char* name;         /** Display name, may be NULL. */
	const char* origin_cid;   /** May be NULL. */
	const char* origin_nick;  /** May be NULL. */
	const char* origin_addr;  /** May be NULL. */
};

/**
 * Begin an ingest, reserving cache space for it up front. Checking afterwards
 * cannot stop N concurrent ingests from collectively exceeding the cache size.
 * @return a job, or NULL with @p error set.
 */
extern struct seed_ingest* seed_ingest_begin(struct seed_cache* cache, const struct seed_ingest_request* req, enum seed_error* error);

/**
 * Feed received bytes to the job.
 *
 * The size ceiling is enforced here, against bytes actually received and never
 * against the size the sender announced, and the media type is decided as soon
 * as SEED_SNIFF_BYTES have arrived. Both refusals therefore land near the start
 * of a transfer rather than after paying for all of it.
 *
 * @return 0 on success, or a negative enum seed_error. On error the job is
 *         still live and the caller must abort it.
 */
extern int seed_ingest_write(struct seed_ingest* job, const void* data, size_t len);

/**
 * Verify and publish. The job is consumed either way.
 *
 * @param out filled in with the published -- or, on a duplicate, the already
 *            cached -- entry. May be NULL.
 * @return 1 if the content is now in the cache, 0 with @p error set otherwise.
 */
extern int seed_ingest_finish(struct seed_ingest* job, struct seed_entry* out, enum seed_error* error);

/** Discard a job and its partial file. The job is consumed. */
extern void seed_ingest_abort(struct seed_ingest* job, enum seed_error reason);

/** Operator blocklist. Blocking also deletes any cached copy. */
extern int seed_cache_is_blocked(struct seed_cache* cache, const char* tth);
extern int seed_cache_block(struct seed_cache* cache, const char* tth, const char* who, const char* reason);
extern int seed_cache_unblock(struct seed_cache* cache, const char* tth);

/** Remove one entry. The file is deferred until the last pin is released. */
extern int seed_cache_remove(struct seed_cache* cache, const char* tth, const char* reason);

/** Remove every entry contributed by a given CID. @return the number removed. */
extern size_t seed_cache_remove_by_cid(struct seed_cache* cache, const char* cid);

/**
 * Periodic maintenance: expire by TTL, evict down to the configured limits and
 * write out the access times batched since the last sweep.
 */
extern void seed_cache_sweep(struct seed_cache* cache, time_t now);

extern void seed_cache_get_stats(struct seed_cache* cache, struct seed_cache_stats* out);
extern const char* seed_error_string(enum seed_error error);

/**
 * Iteration for operator listings, most recently used first.
 *
 * One cursor per cache. Do not modify the cache while a walk is open; start a
 * fresh walk instead.
 *
 * @return 1 while @p out was filled in, 0 when the walk is over.
 */
extern int seed_cache_first(struct seed_cache* cache, struct seed_entry* out);
extern int seed_cache_next(struct seed_cache* cache, struct seed_entry* out);

#endif /* HAVE_UHUB_SEEDER_CACHE_H */
