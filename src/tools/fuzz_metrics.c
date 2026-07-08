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
 * libFuzzer harness for the metrics HTTP request classifier.
 *
 * metrics_classify_request() parses an accumulated HTTP request (request line
 * + headers) and validates method, path and bearer token. It runs on
 * attacker-controlled network bytes on the metrics endpoint, doing plenty of
 * pointer arithmetic over the request buffer (path extraction, header scan,
 * token trimming). The function is pure -- no I/O -- so the fuzz input is fed
 * straight in as the request text, classified against a fixed path and token.
 *
 * Build with:  cmake -B build-fuzz -DFUZZING=ON .  (clang)
 * Run with:    ./build-fuzz/fuzz_metrics autotest/fuzz/corpus/metrics
 */

#include "system.h"
#include "core/metrics.h"
#include "util/log.h"
#include "util/memory.h"

#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
	(void) argc;
	(void) argv;
	hub_set_log_verbosity(0);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	/* The classifier takes a NUL-terminated request buffer. */
	char* req = hub_malloc(size + 1);
	if (!req)
		return 0;
	memcpy(req, data, size);
	req[size] = '\0';

	/* Fixed path/token; the fuzzer explores the request text itself. The
	   return value is intentionally ignored -- we are looking for crashes,
	   OOB reads, or UB in the parse, which ASan/UBSan will catch. */
	(void) metrics_classify_request(req, "/metrics", "s3cr3t");

	hub_free(req);
	return 0;
}
