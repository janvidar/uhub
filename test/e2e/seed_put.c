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

/*
 * seed_put: put a local file into a seed cache, and print its TTH.
 *
 * A test fixture, not a tool. Everything that serves content -- uhub-seeder's
 * transfer port, uhub-fuse's by-tth -- serves it *out of a cache*, and until
 * now nothing could put anything *into* one without a real DC client on the
 * other end of a real transfer (see the note at the top of test/seeder/e2e.sh,
 * which says as much). That left the whole client-to-client path untestable
 * from a script.
 *
 * This does the one thing that was missing: opens a cache directory, ingests a
 * file through the same seed_ingest_* path a download uses, and prints the TTH
 * the content hashed to. From there a script can ask a hub for that hash and
 * check that what comes back is the file it started with.
 *
 *   seed_put <cache-dir> <file> [name]
 *
 * Prints the TTH on stdout. Exits 0 on success, 1 on failure.
 */

#include "system.h"
#include "seeder/cache.h"
#include "util/log.h"
#include "util/memory.h"

#define CHUNK 65536

static int put(struct seed_cache* cache, const char* path, const char* name)
{
	struct seed_ingest_request req;
	struct seed_ingest* job;
	struct seed_entry entry;
	enum seed_error err = SEED_OK;
	char buf[CHUNK];
	FILE* file;
	size_t got;

	file = fopen(path, "rb");
	if (!file)
	{
		fprintf(stderr, "seed_put: cannot open %s: %s\n", path, strerror(errno));
		return 0;
	}

	memset(&req, 0, sizeof(req));
	req.expect_tth = NULL;   /* Whatever it hashes to is the answer. */
	req.name = name;
	req.origin_nick = "seed_put";

	job = seed_ingest_begin(cache, &req, &err);
	if (!job)
	{
		fprintf(stderr, "seed_put: cannot begin: %s\n", seed_error_string(err));
		fclose(file);
		return 0;
	}

	while ((got = fread(buf, 1, sizeof(buf), file)) > 0)
	{
		int rc = seed_ingest_write(job, buf, got);
		if (rc != 0)
		{
			fprintf(stderr, "seed_put: write failed: %s\n", seed_error_string((enum seed_error) -rc));
			seed_ingest_abort(job, (enum seed_error) -rc);
			fclose(file);
			return 0;
		}
	}

	if (ferror(file))
	{
		fprintf(stderr, "seed_put: read error on %s\n", path);
		seed_ingest_abort(job, SEED_ERR_IO);
		fclose(file);
		return 0;
	}

	fclose(file);

	if (!seed_ingest_finish(job, &entry, &err))
	{
		fprintf(stderr, "seed_put: cannot finish: %s\n", seed_error_string(err));
		return 0;
	}

	printf("%s\n", entry.tth);
	return 1;
}

int main(int argc, char** argv)
{
	struct seed_cache_config cfg;
	struct seed_cache* cache;
	int ok;

	if (argc < 3)
	{
		fprintf(stderr, "Usage: %s <cache-dir> <file> [name]\n", argv[0]);
		return 1;
	}

	hub_set_log_verbosity(2);

	memset(&cfg, 0, sizeof(cfg));
	cfg.dir = argv[1];
	cfg.max_bytes = (uint64_t) 1024 * 1024 * 1024;
	cfg.max_file_size = (uint64_t) 1024 * 1024 * 1024;
	cfg.max_entries = 4096;
	cfg.entry_ttl = 0;
	cfg.max_concurrent_ingest = 1;
	cfg.allowed_types = "*";    /* A fixture is not the place to filter types. */

	cache = seed_cache_open(&cfg);
	if (!cache)
	{
		fprintf(stderr, "seed_put: cannot open the cache in %s\n", argv[1]);
		return 1;
	}

	ok = put(cache, argv[2], (argc > 3) ? argv[3] : NULL);

	seed_cache_close(cache);
	return ok ? 0 : 1;
}
