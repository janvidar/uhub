#include "system.h"

#include <dirent.h>
#include <sqlite3.h>
#include <sys/stat.h>

#include "seeder/cache.h"
#include "util/memory.h"
#include "util/tth.h"

#define SC_DIR     "test_seedcache.tmp"
#define SC_BAD_DIR "test_seedcache_bad.tmp"

static struct seed_cache* sc_cache = NULL;
static struct seed_cache_config sc_cfg;
static uint8_t sc_data[512 * 1024];

/* Recursively remove a directory tree, so each test run starts clean. */
static void sc_rmtree(const char* path)
{
	DIR* dir = opendir(path);
	struct dirent* ent;

	if (!dir)
	{
		unlink(path);
		return;
	}

	while ((ent = readdir(dir)) != NULL)
	{
		char child[1024];
		struct stat st;

		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;

		snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
		if (stat(child, &st) == 0 && S_ISDIR(st.st_mode))
			sc_rmtree(child);
		else
			unlink(child);
	}
	closedir(dir);
	rmdir(path);
}

/* A buffer that sniffs as image/png, so it passes the default allowlist. */
static void sc_make_png(uint8_t* buf, size_t len, uint32_t seed)
{
	static const uint8_t magic[8] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
	uint32_t x = seed ? seed : 1;
	size_t i;

	memcpy(buf, magic, (len < 8) ? len : 8);
	for (i = 8; i < len; i++)
	{
		x = (x * 1103515245u) + 12345u;
		buf[i] = (uint8_t) (x >> 16);
	}
}

/* The base32 TTH of the content sc_make_png() generates for these arguments. */
static void sc_tth(size_t len, uint32_t seed, char out[SEED_TTH_STR_LEN + 1])
{
	uint8_t root[TTH_SIZE];

	sc_make_png(sc_data, len, seed);
	tth(sc_data, len, root);
	tth_to_string(root, out);
}

static void sc_data_path(const char* tth, char* out, size_t outlen)
{
	snprintf(out, outlen, "%s/data/%c%c/%c%c/%s.bin", SC_DIR,
		tth[0], tth[1], tth[2], tth[3], tth);
}

static int sc_exists(const char* path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

static void sc_config(uint64_t max_bytes, size_t max_entries)
{
	memset(&sc_cfg, 0, sizeof(sc_cfg));
	sc_cfg.dir = SC_DIR;
	sc_cfg.max_bytes = max_bytes;
	sc_cfg.max_file_size = 1024 * 1024;
	sc_cfg.max_entries = max_entries;
	sc_cfg.entry_ttl = 0;
	sc_cfg.max_concurrent_ingest = 4;
	sc_cfg.allowed_types = "image/png,image/jpeg,image/gif,image/webp";
}

/* Close, wipe the directory and open again: a cold start on an empty cache. */
static int sc_restart_clean(void)
{
	seed_cache_close(sc_cache);
	sc_rmtree(SC_DIR);
	sc_cache = seed_cache_open(&sc_cfg);
	return sc_cache != NULL;
}

/* Close and open again, keeping whatever is on disk. */
static int sc_reopen(void)
{
	seed_cache_close(sc_cache);
	sc_cache = seed_cache_open(&sc_cfg);
	return sc_cache != NULL;
}

/* Ingest `len` bytes of generated content. Returns 1 when it is in the cache. */
static int sc_ingest(size_t len, uint32_t seed, const char* cid, enum seed_error* err)
{
	struct seed_ingest_request req;
	struct seed_ingest* job;
	char expect[SEED_TTH_STR_LEN + 1];

	sc_tth(len, seed, expect);

	memset(&req, 0, sizeof(req));
	req.expect_tth = expect;
	req.announced_size = len;
	req.name = "shot.png";
	req.origin_cid = cid;
	req.origin_nick = "tester";
	req.origin_addr = "192.0.2.1";

	job = seed_ingest_begin(sc_cache, &req, err);
	if (!job)
		return 0;

	if (seed_ingest_write(job, sc_data, len) != 0)
	{
		seed_ingest_abort(job, SEED_ERR_IO);
		return 0;
	}

	return seed_ingest_finish(job, NULL, err);
}

static size_t sc_count(void)
{
	struct seed_cache_stats stats;
	seed_cache_get_stats(sc_cache, &stats);
	return stats.entries;
}

static uint64_t sc_bytes(void)
{
	struct seed_cache_stats stats;
	seed_cache_get_stats(sc_cache, &stats);
	return stats.bytes_used;
}

/* Count the entries in a directory, ignoring dot files. @return -1 if absent. */
static int sc_dir_count(const char* path)
{
	DIR* dir = opendir(path);
	struct dirent* ent;
	int found = 0;

	if (!dir)
		return -1;
	while ((ent = readdir(dir)) != NULL)
		if (ent->d_name[0] != '.')
			found++;
	closedir(dir);
	return found;
}

EXO_TEST(seedcache_setup, {
	sc_rmtree(SC_DIR);
	sc_rmtree(SC_BAD_DIR);
	sc_config(1024 * 1024, 64);
	return 1;
});

EXO_TEST(seedcache_open, {
	sc_cache = seed_cache_open(&sc_cfg);
	return sc_cache != NULL;
});

EXO_TEST(seedcache_creates_layout, {
	return sc_dir_count(SC_DIR "/tmp") == 0 &&
	       sc_dir_count(SC_DIR "/data") == 0 &&
	       sc_exists(SC_DIR "/seedcache.db");
});

EXO_TEST(seedcache_creates_schema_on_fresh_directory, {
	/*
	 * Read the schema back with an independent connection: the tables and the
	 * LRU index have to exist on disk, not just in this process.
	 */
	sqlite3* db = NULL;
	sqlite3_stmt* stmt = NULL;
	int found = 0;

	if (sqlite3_open_v2(SC_DIR "/seedcache.db", &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
		return 0;

	if (sqlite3_prepare_v2(db,
		"SELECT name FROM sqlite_master WHERE name IN ('seed','blocked','seed_lru','seed_origin');",
		-1, &stmt, NULL) == SQLITE_OK)
	{
		while (sqlite3_step(stmt) == SQLITE_ROW)
			found++;
		sqlite3_finalize(stmt);
	}
	sqlite3_close(db);

	return found == 4;
});

EXO_TEST(seedcache_open_rejects_missing_directory, {
	struct seed_cache_config cfg = sc_cfg;
	cfg.dir = NULL;
	return seed_cache_open(&cfg) == NULL && seed_cache_open(NULL) == NULL;
});

EXO_TEST(seedcache_ingest_and_lookup, {
	enum seed_error err = SEED_OK;
	struct seed_entry entry;
	char expect[SEED_TTH_STR_LEN + 1];

	if (!sc_ingest(4096, 1, "CIDAAA", &err) || err != SEED_OK)
		return 0;

	sc_tth(4096, 1, expect);
	if (!seed_cache_lookup(sc_cache, expect, &entry))
		return 0;

	if (strcmp(entry.tth, expect) != 0) return 0;
	if (entry.size != 4096) return 0;
	if (strcmp(entry.media_type, "image/png") != 0) return 0;
	if (strcmp(entry.name, "shot.png") != 0) return 0;
	if (strcmp(entry.origin_cid, "CIDAAA") != 0) return 0;
	if (strcmp(entry.origin_nick, "tester") != 0) return 0;
	return strcmp(entry.origin_addr, "192.0.2.1") == 0;
});

EXO_TEST(seedcache_lookup_rejects_a_non_tth, {
	struct seed_entry entry;

	/* Nothing that is not 39 base32 characters may ever reach a path. */
	if (seed_cache_lookup(sc_cache, "../../etc/passwd", &entry)) return 0;
	if (seed_cache_lookup(sc_cache, "", &entry)) return 0;
	if (seed_cache_lookup(sc_cache, NULL, &entry)) return 0;
	return seed_cache_open_file(sc_cache, "../../etc/passwd") < 0;
});

EXO_TEST(seedcache_read_back_is_byte_exact, {
	char expect[SEED_TTH_STR_LEN + 1];
	struct seed_entry entry;
	uint8_t buf[1024];
	int fd;
	ssize_t got;

	sc_tth(4096, 1, expect);
	if (!seed_cache_lookup(sc_cache, expect, &entry)) return 0;
	if (!seed_cache_pin(sc_cache, expect)) return 0;

	fd = seed_cache_open_file(sc_cache, expect);
	if (fd < 0) { seed_cache_unpin(sc_cache, expect); return 0; }

	got = seed_cache_read(sc_cache, fd, entry.size, 2048, buf, sizeof(buf));
	close(fd);
	seed_cache_unpin(sc_cache, expect);

	if (got != 1024) return 0;
	return memcmp(buf, sc_data + 2048, 1024) == 0;
});

EXO_TEST(seedcache_read_past_end_returns_zero, {
	char expect[SEED_TTH_STR_LEN + 1];
	struct seed_entry entry;
	uint8_t buf[64];
	int fd;
	ssize_t got;

	sc_tth(4096, 1, expect);
	if (!seed_cache_lookup(sc_cache, expect, &entry)) return 0;
	if (!seed_cache_pin(sc_cache, expect)) return 0;

	fd = seed_cache_open_file(sc_cache, expect);
	got = seed_cache_read(sc_cache, fd, entry.size, 999999, buf, sizeof(buf));
	close(fd);
	seed_cache_unpin(sc_cache, expect);
	return got == 0;
});

EXO_TEST(seedcache_pin_of_unknown_content_fails, {
	char missing[SEED_TTH_STR_LEN + 1];
	sc_tth(64, 9999, missing);
	return seed_cache_pin(sc_cache, missing) == 0;
});

EXO_TEST(seedcache_dedup_same_content, {
	enum seed_error err = SEED_OK;
	size_t before = sc_count();

	/* The same bytes from a different peer are the same cache entry. */
	if (!sc_ingest(4096, 1, "CIDBBB", &err)) return 0;
	return err == SEED_OK && sc_count() == before;
});

EXO_TEST(seedcache_tth_mismatch_is_rejected, {
	struct seed_ingest_request req;
	struct seed_ingest* job;
	enum seed_error err = SEED_OK;
	char wrong[SEED_TTH_STR_LEN + 1];
	uint8_t root[TTH_SIZE];
	size_t before = sc_count();

	tth("not the same bytes", 18, root);
	tth_to_string(root, wrong);
	sc_make_png(sc_data, 2048, 77);

	memset(&req, 0, sizeof(req));
	req.expect_tth = wrong;
	req.announced_size = 2048;
	req.origin_cid = "CIDEVIL";

	job = seed_ingest_begin(sc_cache, &req, &err);
	if (!job) return 0;
	if (seed_ingest_write(job, sc_data, 2048) != 0) return 0;

	if (seed_ingest_finish(job, NULL, &err)) return 0;
	return err == SEED_ERR_TTH_MISMATCH && sc_count() == before;
});

EXO_TEST(seedcache_no_partial_left_in_tmp, {
	/* Every rejected ingest must clean up after itself. */
	return sc_dir_count(SC_DIR "/tmp") == 0;
});

EXO_TEST(seedcache_ingest_rejects_a_non_tth_announcement, {
	struct seed_ingest_request req;
	enum seed_error err = SEED_OK;

	memset(&req, 0, sizeof(req));
	req.expect_tth = "../../../etc/passwd";
	req.announced_size = 16;

	return seed_ingest_begin(sc_cache, &req, &err) == NULL && err == SEED_ERR_TTH_MISMATCH;
});

EXO_TEST(seedcache_oversize_aborts_mid_stream, {
	/*
	 * The sender announces 1024 bytes and then sends far more. The write must
	 * fail as soon as the limit is passed, not at the end of the transfer.
	 */
	struct seed_ingest_request req;
	struct seed_ingest* job;
	enum seed_error err = SEED_OK;
	int rc;

	sc_make_png(sc_data, 8192, 5);
	memset(&req, 0, sizeof(req));
	req.announced_size = 1024;

	job = seed_ingest_begin(sc_cache, &req, &err);
	if (!job) return 0;

	if (seed_ingest_write(job, sc_data, 1024) != 0) { seed_ingest_abort(job, SEED_ERR_IO); return 0; }
	rc = seed_ingest_write(job, sc_data + 1024, 1024);
	seed_ingest_abort(job, SEED_ERR_TOO_LARGE);
	return rc == -SEED_ERR_TOO_LARGE;
});

EXO_TEST(seedcache_announced_over_file_limit_refused, {
	struct seed_ingest_request req;
	enum seed_error err = SEED_OK;
	memset(&req, 0, sizeof(req));
	req.announced_size = 64 * 1024 * 1024; /* max_file_size is 1 MiB */
	return seed_ingest_begin(sc_cache, &req, &err) == NULL && err == SEED_ERR_TOO_LARGE;
});

EXO_TEST(seedcache_disallowed_media_type_refused, {
	struct seed_ingest_request req;
	struct seed_ingest* job;
	enum seed_error err = SEED_OK;
	static const char zip[] = "PK\x03\x04 and then some other bytes entirely";

	memset(&req, 0, sizeof(req));
	req.announced_size = sizeof(zip) - 1;

	job = seed_ingest_begin(sc_cache, &req, &err);
	if (!job) return 0;

	/* Shorter than SEED_SNIFF_BYTES, so the verdict lands at finish. */
	if (seed_ingest_write(job, zip, sizeof(zip) - 1) != 0) return 0;
	if (seed_ingest_finish(job, NULL, &err)) return 0;
	return err == SEED_ERR_MEDIA_TYPE;
});

EXO_TEST(seedcache_disallowed_media_type_cut_off_early, {
	/*
	 * A long disallowed upload must be refused once the head has been seen,
	 * not after the whole thing has been paid for.
	 */
	struct seed_ingest_request req;
	struct seed_ingest* job;
	enum seed_error err = SEED_OK;
	int rc;

	memset(&req, 0, sizeof(req));
	req.announced_size = 65536;

	job = seed_ingest_begin(sc_cache, &req, &err);
	if (!job) return 0;

	memset(sc_data, 0, 65536);
	memcpy(sc_data, "PK\x03\x04", 4);

	rc = seed_ingest_write(job, sc_data, 64); /* exactly SEED_SNIFF_BYTES */
	seed_ingest_abort(job, SEED_ERR_MEDIA_TYPE);
	return rc == -SEED_ERR_MEDIA_TYPE;
});

EXO_TEST(seedcache_concurrent_ingest_limit, {
	struct seed_ingest_request req;
	struct seed_ingest* jobs[8];
	enum seed_error err = SEED_OK;
	int i;
	int refused = 0;

	memset(&req, 0, sizeof(req));
	req.announced_size = 1024;

	for (i = 0; i < 8; i++)
	{
		jobs[i] = seed_ingest_begin(sc_cache, &req, &err);
		if (!jobs[i] && err == SEED_ERR_ADMISSION)
			refused++;
	}
	for (i = 0; i < 8; i++)
		if (jobs[i])
			seed_ingest_abort(jobs[i], SEED_ERR_IO);

	/* max_concurrent_ingest is 4, so the last four must be refused. */
	return refused == 4;
});

EXO_TEST(seedcache_reservation_refuses_the_nth_ingest, {
	/*
	 * Space is reserved when a transfer starts, not checked when it ends: two
	 * jobs of 2 KiB fill a 4 KiB cache, and the third must be told so before it
	 * sends a byte.
	 */
	struct seed_ingest_request req;
	struct seed_ingest* jobs[3];
	enum seed_error err = SEED_OK;
	int i;
	int ok;

	sc_config(4096, 64);
	sc_cfg.max_file_size = 2048;
	sc_cfg.max_concurrent_ingest = 8;
	if (!sc_restart_clean()) return 0;

	memset(&req, 0, sizeof(req));
	req.announced_size = 2048;

	for (i = 0; i < 3; i++)
		jobs[i] = seed_ingest_begin(sc_cache, &req, &err);

	ok = (jobs[0] && jobs[1] && !jobs[2] && err == SEED_ERR_FULL);

	for (i = 0; i < 3; i++)
		if (jobs[i])
			seed_ingest_abort(jobs[i], SEED_ERR_IO);

	sc_config(1024 * 1024, 64);
	return ok && sc_restart_clean();
});

EXO_TEST(seedcache_pin_blocks_eviction, {
	enum seed_error err = SEED_OK;
	char tth[SEED_TTH_STR_LEN + 1];
	char path[1024];
	int fd;

	if (!sc_ingest(4096, 1, "CIDPIN", &err)) return 0;
	sc_tth(4096, 1, tth);
	sc_data_path(tth, path, sizeof(path));

	if (!seed_cache_pin(sc_cache, tth)) return 0;
	if (!seed_cache_remove(sc_cache, tth, "test")) { seed_cache_unpin(sc_cache, tth); return 0; }

	/* Retired from lookup, but the bytes survive until the pin is released. */
	if (seed_cache_lookup(sc_cache, tth, NULL)) return 0;
	if (!sc_exists(path)) return 0;

	fd = seed_cache_open_file(sc_cache, tth);
	if (fd < 0) return 0;
	close(fd);

	seed_cache_unpin(sc_cache, tth);
	return !sc_exists(path) && !seed_cache_lookup(sc_cache, tth, NULL);
});

EXO_TEST(seedcache_pins_do_not_survive_a_restart, {
	enum seed_error err = SEED_OK;
	char tth[SEED_TTH_STR_LEN + 1];
	struct seed_cache_stats stats;

	if (!sc_restart_clean()) return 0;
	if (!sc_ingest(2048, 111, "CIDPIN", &err)) return 0;
	sc_tth(2048, 111, tth);

	if (!seed_cache_pin(sc_cache, tth)) return 0;
	seed_cache_get_stats(sc_cache, &stats);
	if (stats.pinned != 1) return 0;

	/* Pins describe transfers in flight; a restart has none. */
	if (!sc_reopen()) return 0;
	seed_cache_get_stats(sc_cache, &stats);
	if (stats.pinned != 0) return 0;

	/* The entry itself is untouched by any of that. */
	return seed_cache_lookup(sc_cache, tth, NULL) == 1;
});

EXO_TEST(seedcache_evicts_by_entry_count, {
	enum seed_error err = SEED_OK;
	int i;

	sc_config(1024 * 1024, 3);
	if (!sc_restart_clean()) return 0;

	for (i = 0; i < 6; i++)
		if (!sc_ingest(2048, (uint32_t) (100 + i), "CIDLRU", &err))
			return 0;

	return sc_count() <= 3;
});

EXO_TEST(seedcache_evicts_by_size, {
	enum seed_error err = SEED_OK;
	int i;

	sc_config(8192, 0);
	if (!sc_restart_clean()) return 0;

	for (i = 0; i < 6; i++)
		if (!sc_ingest(3000, (uint32_t) (150 + i), "CIDSIZE", &err))
			return 0;

	return sc_bytes() <= 8192 && sc_count() > 0;
});

EXO_TEST(seedcache_evicts_least_recently_used_first, {
	enum seed_error err = SEED_OK;
	char keep[SEED_TTH_STR_LEN + 1];
	char lost[SEED_TTH_STR_LEN + 1];

	sc_config(1024 * 1024, 3);
	if (!sc_restart_clean()) return 0;

	if (!sc_ingest(2048, 201, "CIDA", &err)) return 0;
	if (!sc_ingest(2048, 202, "CIDA", &err)) return 0;

	sc_tth(2048, 201, keep);
	sc_tth(2048, 202, lost);

	/* Touch the first one so it is no longer the least recently used. */
	if (!seed_cache_lookup(sc_cache, keep, NULL)) return 0;

	if (!sc_ingest(2048, 203, "CIDA", &err)) return 0;
	if (!sc_ingest(2048, 204, "CIDA", &err)) return 0;

	return seed_cache_lookup(sc_cache, keep, NULL) && !seed_cache_lookup(sc_cache, lost, NULL);
});

EXO_TEST(seedcache_iteration_is_most_recently_used_first, {
	char first[SEED_TTH_STR_LEN + 1];
	struct seed_entry entry;
	size_t seen = 0;

	sc_tth(2048, 203, first);
	if (!seed_cache_lookup(sc_cache, first, NULL)) return 0;

	if (!seed_cache_first(sc_cache, &entry)) return 0;
	if (strcmp(entry.tth, first) != 0) return 0;

	do { seen++; } while (seed_cache_next(sc_cache, &entry));
	return seen == sc_count();
});

EXO_TEST(seedcache_expires_by_ttl, {
	enum seed_error err = SEED_OK;
	char pinned[SEED_TTH_STR_LEN + 1];

	sc_config(1024 * 1024, 64);
	sc_cfg.entry_ttl = 60;
	if (!sc_restart_clean()) return 0;

	if (!sc_ingest(2048, 301, "CIDTTL", &err)) return 0;
	if (!sc_ingest(2048, 302, "CIDTTL", &err)) return 0;
	sc_tth(2048, 302, pinned);
	if (!seed_cache_pin(sc_cache, pinned)) return 0;

	/* Nothing is old enough yet. */
	seed_cache_sweep(sc_cache, time(NULL));
	if (sc_count() != 2) return 0;

	/* Far enough into the future that everything unpinned has aged out. */
	seed_cache_sweep(sc_cache, time(NULL) + 3600);
	if (sc_count() != 1) return 0;
	if (!seed_cache_lookup(sc_cache, pinned, NULL)) return 0;

	seed_cache_unpin(sc_cache, pinned);
	seed_cache_sweep(sc_cache, time(NULL) + 3600);
	if (sc_count() != 0) return 0;

	sc_cfg.entry_ttl = 0;
	return sc_restart_clean();
});

EXO_TEST(seedcache_hits_are_batched_into_the_sweep, {
	enum seed_error err = SEED_OK;
	char tth[SEED_TTH_STR_LEN + 1];
	struct seed_entry entry;
	int i;

	if (!sc_ingest(2048, 401, "CIDHIT", &err)) return 0;
	sc_tth(2048, 401, tth);

	for (i = 0; i < 5; i++)
		if (!seed_cache_lookup(sc_cache, tth, &entry))
			return 0;

	/* Counted in memory while serving... */
	if (entry.hits != 5) return 0;

	/* ...and still there once the sweep has written them out. */
	seed_cache_sweep(sc_cache, time(NULL));
	if (!seed_cache_lookup(sc_cache, tth, &entry)) return 0;
	return entry.hits == 6;
});

EXO_TEST(seedcache_block_removes_and_refuses, {
	enum seed_error err = SEED_OK;
	char tth[SEED_TTH_STR_LEN + 1];
	char path[1024];
	struct seed_ingest_request req;

	if (!sc_restart_clean()) return 0;
	if (!sc_ingest(2048, 501, "CIDBLK", &err)) return 0;
	sc_tth(2048, 501, tth);
	sc_data_path(tth, path, sizeof(path));

	if (!seed_cache_block(sc_cache, tth, "operator", "takedown")) return 0;
	if (!seed_cache_is_blocked(sc_cache, tth)) return 0;
	if (seed_cache_lookup(sc_cache, tth, NULL)) return 0;
	if (sc_exists(path)) return 0;

	memset(&req, 0, sizeof(req));
	req.expect_tth = tth;
	req.announced_size = 2048;
	if (seed_ingest_begin(sc_cache, &req, &err) != NULL) return 0;
	if (err != SEED_ERR_BLOCKED) return 0;

	return seed_cache_unblock(sc_cache, tth) && !seed_cache_is_blocked(sc_cache, tth);
});

EXO_TEST(seedcache_block_refuses_unannounced_content_at_finish, {
	/*
	 * A mirror job has no announced TTH, so the blocklist can only be consulted
	 * once the content has hashed. It still must not be published.
	 */
	struct seed_ingest_request req;
	struct seed_ingest* job;
	enum seed_error err = SEED_OK;
	char tth[SEED_TTH_STR_LEN + 1];

	sc_tth(2048, 601, tth);
	if (!seed_cache_block(sc_cache, tth, "operator", "takedown")) return 0;

	memset(&req, 0, sizeof(req));
	req.announced_size = 2048;
	job = seed_ingest_begin(sc_cache, &req, &err);
	if (!job) return 0;
	if (seed_ingest_write(job, sc_data, 2048) != 0) return 0;

	if (seed_ingest_finish(job, NULL, &err)) return 0;
	return err == SEED_ERR_BLOCKED && sc_dir_count(SC_DIR "/tmp") == 0;
});

EXO_TEST(seedcache_remove_by_cid, {
	enum seed_error err = SEED_OK;

	if (!sc_restart_clean()) return 0;

	if (!sc_ingest(2048, 701, "CIDSPAM", &err)) return 0;
	if (!sc_ingest(2048, 702, "CIDSPAM", &err)) return 0;
	if (!sc_ingest(2048, 703, "CIDGOOD", &err)) return 0;

	if (seed_cache_remove_by_cid(sc_cache, "CIDSPAM") != 2) return 0;
	return sc_count() == 1;
});

EXO_TEST(seedcache_survives_restart, {
	enum seed_error err = SEED_OK;
	char tth[SEED_TTH_STR_LEN + 1];
	struct seed_entry entry;

	if (!sc_restart_clean()) return 0;
	if (!sc_ingest(3000, 801, "CIDKEEP", &err)) return 0;
	sc_tth(3000, 801, tth);

	if (!sc_reopen()) return 0;

	if (!seed_cache_lookup(sc_cache, tth, &entry)) return 0;
	if (entry.size != 3000) return 0;
	if (strcmp(entry.media_type, "image/png") != 0) return 0;
	if (strcmp(entry.origin_cid, "CIDKEEP") != 0) return 0;
	if (strcmp(entry.origin_nick, "tester") != 0) return 0;
	return strcmp(entry.name, "shot.png") == 0;
});

EXO_TEST(seedcache_reopen_preserves_entries_and_counters, {
	enum seed_error err = SEED_OK;
	char tth[SEED_TTH_STR_LEN + 1];
	struct seed_entry before;
	struct seed_entry after;
	size_t entries;
	uint64_t bytes;

	if (!sc_ingest(1500, 802, "CIDKEEP", &err)) return 0;
	sc_tth(3000, 801, tth);

	if (!seed_cache_lookup(sc_cache, tth, &before)) return 0;
	entries = sc_count();
	bytes = sc_bytes();

	if (!sc_reopen()) return 0;

	if (sc_count() != entries) return 0;
	if (sc_bytes() != bytes) return 0;
	if (!seed_cache_lookup(sc_cache, tth, &after)) return 0;

	/* The database, not a rebuilt guess, is what came back. */
	if (after.first_seen != before.first_seen) return 0;
	if (after.hits < before.hits) return 0;
	return strcmp(after.name, before.name) == 0;
});

EXO_TEST(seedcache_blocklist_survives_restart, {
	char tth[SEED_TTH_STR_LEN + 1];
	struct seed_cache_stats stats;

	sc_tth(3000, 801, tth);

	if (!seed_cache_block(sc_cache, tth, "operator", "takedown")) return 0;
	if (!sc_reopen()) return 0;

	if (!seed_cache_is_blocked(sc_cache, tth)) return 0;
	seed_cache_get_stats(sc_cache, &stats);
	if (stats.blocked != 1) return 0;

	return seed_cache_unblock(sc_cache, tth);
});

EXO_TEST(seedcache_startup_clears_partials, {
	char path[1024];
	FILE* fh;

	snprintf(path, sizeof(path), "%s/tmp/9999-1.part", SC_DIR);
	fh = fopen(path, "w");
	if (!fh) return 0;
	fwrite("half a file", 1, 11, fh);
	fclose(fh);

	if (!sc_reopen()) return 0;
	return sc_dir_count(SC_DIR "/tmp") == 0;
});

EXO_TEST(seedcache_rejects_foreign_file_names, {
	char path[1024];
	FILE* fh;

	/* A file whose name is not a TTH cannot be content addressed, so it goes. */
	snprintf(path, sizeof(path), "%s/data/AA", SC_DIR);
	mkdir(path, 0700);
	snprintf(path, sizeof(path), "%s/data/AA/BB", SC_DIR);
	mkdir(path, 0700);
	snprintf(path, sizeof(path), "%s/data/AA/BB/passwd.bin", SC_DIR);
	fh = fopen(path, "w");
	if (!fh) return 0;
	fwrite("x", 1, 1, fh);
	fclose(fh);

	if (!sc_reopen()) return 0;
	return !sc_exists(path);
});

EXO_TEST(seedcache_adopts_an_orphan_file, {
	char tth[SEED_TTH_STR_LEN + 1];
	char dir[1024];
	char path[1024];
	struct seed_entry entry;
	FILE* fh;

	/* A correctly named file with no record is the cache's, and is adopted --
	   with its media type sniffed rather than assumed. */
	sc_tth(900, 901, tth);
	snprintf(dir, sizeof(dir), "%s/data/%c%c", SC_DIR, tth[0], tth[1]);
	mkdir(dir, 0700);
	snprintf(dir, sizeof(dir), "%s/data/%c%c/%c%c", SC_DIR, tth[0], tth[1], tth[2], tth[3]);
	mkdir(dir, 0700);
	sc_data_path(tth, path, sizeof(path));

	fh = fopen(path, "wb");
	if (!fh) return 0;
	fwrite(sc_data, 1, 900, fh);
	fclose(fh);

	if (!sc_reopen()) return 0;
	if (!seed_cache_lookup(sc_cache, tth, &entry)) return 0;
	if (entry.size != 900) return 0;
	return strcmp(entry.media_type, "image/png") == 0;
});

EXO_TEST(seedcache_drops_a_record_without_a_file, {
	enum seed_error err = SEED_OK;
	char tth[SEED_TTH_STR_LEN + 1];
	char path[1024];
	size_t before;

	if (!sc_ingest(2048, 1001, "CIDGONE", &err)) return 0;
	sc_tth(2048, 1001, tth);
	sc_data_path(tth, path, sizeof(path));
	before = sc_count();

	/* Take the file away behind the cache's back: the directory is the
	   authority, so the record must not survive. */
	if (unlink(path) != 0) return 0;

	if (!sc_reopen()) return 0;
	if (seed_cache_lookup(sc_cache, tth, NULL)) return 0;
	return sc_count() == before - 1;
});

EXO_TEST(seedcache_corrupt_database_degrades, {
	/*
	 * A database that is not a database must disable the cache, not take the
	 * daemon down with it.
	 */
	struct seed_cache_config cfg;
	struct seed_cache* broken;
	FILE* fh;

	sc_rmtree(SC_BAD_DIR);
	if (mkdir(SC_BAD_DIR, 0700) != 0) return 0;

	fh = fopen(SC_BAD_DIR "/seedcache.db", "wb");
	if (!fh) return 0;
	fwrite("this is definitely not an SQLite database, not even a little bit", 1, 64, fh);
	fclose(fh);

	memset(&cfg, 0, sizeof(cfg));
	cfg.dir = SC_BAD_DIR;
	cfg.max_bytes = 1024 * 1024;
	cfg.max_file_size = 1024 * 1024;
	cfg.max_concurrent_ingest = 4;

	broken = seed_cache_open(&cfg);
	if (broken)
	{
		seed_cache_close(broken);
		sc_rmtree(SC_BAD_DIR);
		return 0;
	}

	sc_rmtree(SC_BAD_DIR);
	return 1;
});

EXO_TEST(seedcache_unreadable_directory_degrades, {
	struct seed_cache_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	/* Longer than the bound every derived path is proved against. */
	cfg.dir = "/tmp/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	cfg.max_bytes = 1024;
	return seed_cache_open(&cfg) == NULL;
});

EXO_TEST(seedcache_stats, {
	struct seed_cache_stats stats;

	seed_cache_get_stats(sc_cache, &stats);
	if (stats.bytes_max != sc_cfg.max_bytes) return 0;
	if (stats.entries_max != sc_cfg.max_entries) return 0;
	if (stats.active_ingests != 0) return 0;
	if (stats.bytes_reserved != 0) return 0;
	return stats.degraded == 0;
});

EXO_TEST(seedcache_error_strings, {
	if (strcmp(seed_error_string(SEED_OK), "ok") != 0) return 0;
	if (strcmp(seed_error_string(SEED_ERR_TTH_MISMATCH), "tth_mismatch") != 0) return 0;
	return strcmp(seed_error_string((enum seed_error) 999), "unknown") == 0;
});

EXO_TEST(seedcache_cleanup, {
	seed_cache_close(sc_cache);
	sc_cache = NULL;
	sc_rmtree(SC_DIR);
	sc_rmtree(SC_BAD_DIR);
	return 1;
});
