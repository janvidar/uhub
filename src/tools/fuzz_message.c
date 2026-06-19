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
 * libFuzzer harness for the ADC wire-format parser.
 *
 * adc_msg_parse() runs against attacker-controlled bytes *before* a
 * connection is authenticated (see src/network/probe.c -> user_create ->
 * hub_handle_message -> adc_msg_parse_verify). It has a long history of
 * out-of-bounds reads and OOM-state leaks, so it is the single most
 * valuable thing to fuzz continuously.
 *
 * Build with:  cmake -B build-fuzz -DFUZZING=ON .  (clang)
 * Run with:    ./build-fuzz/fuzz_message autotest/fuzz/corpus
 *
 * This harness exercises both the parser and the accessor / mutator
 * functions that operate on a parsed message, because several of the
 * historical bugs were in the get/remove/escape helpers rather than in
 * adc_msg_parse() itself.
 */

#include "system.h"
#include "util/log.h"
#include "util/memory.h"
#include "adc/message.h"

#include <stdint.h>
#include <stddef.h>

/* Named-argument prefixes worth probing. NULL terminated. The accessor
 * API only looks at the first two characters of each. */
static const char* const fuzz_prefixes[] = {
	"NI", "I4", "I6", "U4", "U6", "SS", "SF", "CT",
	"ID", "PD", "SU", "VE", "AP", "DE", "TO", "AN", NULL
};

/* Read-only-ish exploration: every accessor here is expected to leave the
 * message in the same logical state it found it (functions that temporarily
 * unterminate the buffer must re-terminate it). */
static void exercise_accessors(struct adc_message* msg)
{
	int i;

	adc_msg_get_arg_offset(msg);
	adc_msg_is_empty(msg);

	for (i = 0; i < 6; i++)
	{
		char* arg = adc_msg_get_argument(msg, i);
		if (arg)
		{
			char* esc = adc_msg_escape(arg);
			char* un  = adc_msg_unescape(arg);
			hub_free(esc);
			hub_free(un);
			hub_free(arg);
		}
	}

	for (i = 0; fuzz_prefixes[i]; i++)
	{
		const char* p = fuzz_prefixes[i];
		adc_msg_has_named_argument(msg, p);
		char* arg = adc_msg_get_named_argument(msg, p);
		hub_free(arg);
	}
}

/* Destructive exploration on a throwaway copy. */
static void exercise_mutators(const struct adc_message* original)
{
	struct adc_message* msg = adc_msg_copy(original);
	int i;

	if (!msg)
		return; /* OOM path under -fsanitize=fuzzer is fine to bail on */

	for (i = 0; fuzz_prefixes[i]; i++)
		adc_msg_remove_named_argument(msg, fuzz_prefixes[i]);

	adc_msg_add_named_argument(msg, "XX", "fuzz");
	adc_msg_add_named_argument_int(msg, "NN", -1);
	adc_msg_replace_named_argument(msg, "NI", "fuzznick");
	adc_msg_add_argument(msg, "trailing");

	/* The buffer has now been grown/shrunk repeatedly; make sure the
	 * accessors still hold up against the mutated state. */
	exercise_accessors(msg);

	adc_msg_free(msg);
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
	(void) argc;
	(void) argv;
	/* Silence the parser's LOG_DEBUG noise (it logs on every rejected
	 * message, which is most fuzz inputs). hub_log falls back to stderr
	 * when uninitialized, and only emits below this verbosity. */
	hub_set_log_verbosity(0);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	struct adc_message* msg;

	/* Mirror the hub: each network line is parsed independently with the
	 * trailing '\n' already stripped (see handle_net_read), but feeding the
	 * raw buffer also covers the need_terminate path inside the parser. */
	msg = adc_msg_parse((const char*) data, size);
	if (!msg)
		return 0;

	exercise_accessors(msg);
	exercise_mutators(msg);

	adc_msg_free(msg);
	return 0;
}
