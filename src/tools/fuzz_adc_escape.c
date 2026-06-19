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
 * libFuzzer harness for the ADC string escape / unescape helpers.
 *
 * adc_msg_escape() / adc_msg_unescape() / adc_msg_unescape_to_target() run on
 * arbitrary strings (nicks, chat text, user-agent, etc.), independently of the
 * message parser, and have had OOM / sizing bugs in the past. The allocation
 * sizing functions (adc_msg_escape_length / adc_msg_unescape_length) are
 * exercised implicitly: a wrong size is caught by AddressSanitizer when the
 * escape/unescape routine writes its output.
 *
 * Beyond crash detection this checks a property: escaping a string and then
 * unescaping the result must reproduce the original exactly. A violation is a
 * real correctness bug, so it aborts (and fails the fuzz run).
 *
 * Build with:  cmake -B build-fuzz -DFUZZING=ON .  (clang)
 * Run with:    ./build-fuzz/fuzz_adc_escape autotest/fuzz/corpus/adc_escape
 */

#include "system.h"
#include "util/log.h"
#include "util/memory.h"
#include "adc/message.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

static void fuzz_check(int condition, const char* what)
{
	if (!condition)
	{
		fprintf(stderr, "fuzz invariant violated: %s\n", what);
		abort();
	}
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
	(void) argc;
	(void) argv;
	hub_set_log_verbosity(0);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	/* The escape helpers are C-string functions; treat the input as a
	 * NUL-terminated string (it ends at the first embedded NUL, if any). */
	char* s = hub_malloc(size + 1);
	if (!s)
		return 0;
	memcpy(s, data, size);
	s[size] = '\0';

	/* 1. Unescape arbitrary attacker bytes directly: the escape state machine
	 *    must safely handle trailing backslashes and unknown "\x" escapes. */
	char* un = adc_msg_unescape(s);
	hub_free(un);

	/* 2. escape() -> unescape() must round-trip back to the original. */
	char* esc = adc_msg_escape(s);
	if (esc)
	{
		char* round = adc_msg_unescape(esc);
		if (round)
			fuzz_check(strcmp(round, s) == 0, "escape/unescape round-trip");
		hub_free(round);
		hub_free(esc);
	}

	/* 3. Unescape into fixed-size buffers, both smaller and larger than the
	 *    input, so the bounded writer is checked for overruns by ASan. */
	{
		char small_buf[16];
		char large_buf[4096];
		adc_msg_unescape_to_target(s, small_buf, sizeof(small_buf));
		adc_msg_unescape_to_target(s, large_buf, sizeof(large_buf));
	}

	hub_free(s);
	return 0;
}
