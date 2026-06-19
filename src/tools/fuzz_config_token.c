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
 * libFuzzer harness for the config tokenizer.
 *
 * cfg_tokenize() and cfg_settings_split() parse lines of uhub.conf /
 * users.conf (quoting, escaping, key=value splitting). They run against
 * file content rather than network bytes, so the threat model is weaker
 * than the ADC parser -- but they are still string parsers full of pointer
 * arithmetic, and a malformed config should never crash the hub on startup.
 *
 * Build with:  cmake -B build-fuzz -DFUZZING=ON .  (clang)
 * Run with:    ./build-fuzz/fuzz_config_token autotest/fuzz/corpus/config_token
 */

#include "system.h"
#include "util/config_token.h"
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
	/* Both entry points take a NUL-terminated line. */
	char* line = hub_malloc(size + 1);
	if (!line)
		return 0;
	memcpy(line, data, size);
	line[size] = '\0';

	struct cfg_tokens* tokens = cfg_tokenize(line);
	if (tokens)
	{
		size_t count = cfg_token_count(tokens);
		size_t i;

		/* Forward iteration. */
		char* t = cfg_token_get_first(tokens);
		while (t)
			t = cfg_token_get_next(tokens);

		/* Random access by index, including the out-of-range index. */
		for (i = 0; i <= count; i++)
			cfg_token_get(tokens, i);

		cfg_tokens_free(tokens);
	}

	struct cfg_settings* setting = cfg_settings_split(line);
	if (setting)
	{
		cfg_settings_get_key(setting);
		cfg_settings_get_value(setting);
		cfg_settings_free(setting);
	}

	hub_free(line);
	return 0;
}
