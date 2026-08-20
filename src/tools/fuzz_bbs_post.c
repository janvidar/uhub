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
 * libFuzzer harness for the BBS0 post document parser.
 *
 * A post document arrives over a client-to-client transfer from whoever
 * answered a search, is named only by a hash, and is parsed before anything in
 * it has been believed. seed_post_parse() therefore runs on bytes chosen by a
 * stranger, and the header it reads is ADC -- the same grammar that has had
 * repeated out-of-bounds read bugs on the hub side.
 *
 * The input is used as the whole document, so the fuzzer decides where the
 * header ends, whether it ends at all, and what the body contains. Attachment
 * extraction is driven from whatever the parse produced, since that is how the
 * seeder uses it.
 *
 * Beyond crash detection this checks the properties the callers rely on:
 * offsets that stay inside the buffer, and attachment entries that are always
 * bounded, NUL terminated and shaped like a TTH.
 *
 * Build with:  cmake -B build-fuzz -DFUZZING=ON .  (clang)
 * Run with:    ./build-fuzz/fuzz_bbs_post autotest/fuzz/corpus/bbs_post
 */

#include "system.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "seeder/post.h"

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
	struct seed_post post;
	struct seed_embed attachments[SEED_POST_MAX_ATTACHMENTS];
	enum seed_post_error error = SEED_POST_OK;
	size_t count;
	size_t i;

	/* Poisoned, so a field the parser failed to write is visible as garbage to
	   the checks below rather than as a plausible zero. */
	memset(&post, 0xAA, sizeof(post));

	if (!seed_post_parse(data, size, &post, &error))
	{
		/* A refusal must always say why, and the reason must be a code this
		   build knows: a caller logs it. */
		fuzz_check(error != SEED_POST_OK, "parse failed without setting an error");
		fuzz_check(error <= SEED_POST_ERR_FIELD, "parse set an unknown error code");
		fuzz_check(seed_post_error_string(error) != NULL, "no string for the error code");
		return 0;
	}

	fuzz_check(error == SEED_POST_OK, "parse succeeded but set an error");

	/* The body is what follows the header, and it is inside the buffer. */
	fuzz_check(post.body_offset <= size, "body_offset past the end of the document");
	fuzz_check(post.body_length == size - post.body_offset, "body_length disagrees with body_offset");

	/* Every string is NUL terminated within its own field. */
	fuzz_check(memchr(post.author_cid, '\0', sizeof(post.author_cid)) != NULL,
		"author_cid is not NUL terminated");
	fuzz_check(memchr(post.parent, '\0', sizeof(post.parent)) != NULL,
		"parent is not NUL terminated");
	fuzz_check(memchr(post.subject, '\0', sizeof(post.subject)) != NULL,
		"subject is not NUL terminated");

	/* ID is required, and a parent is either absent or a whole TTH. */
	fuzz_check(post.author_cid[0] != '\0', "accepted a post with no author");
	fuzz_check(post.parent[0] == '\0' || strlen(post.parent) == SEED_TTH_STR_LEN,
		"parent is neither absent nor a full TTH");

	/* A post that starts a thread must carry a subject. */
	fuzz_check(post.parent[0] != '\0' || post.subject[0] != '\0',
		"accepted a thread root with no subject");

	/* A newline in the subject is a canonical form violation and must not have
	   survived the parse. */
	fuzz_check(strchr(post.subject, '\n') == NULL, "subject carries a newline");

	memset(attachments, 0xAA, sizeof(attachments));
	count = seed_post_attachments(data, size, &post, attachments, SEED_POST_MAX_ATTACHMENTS);

	fuzz_check(count <= SEED_POST_MAX_ATTACHMENTS, "more attachments than the caller allowed");

	/* Only a rich text body carries attachments. */
	fuzz_check(post.rich_text || count == 0, "attachments found in a plain text body");

	for (i = 0; i < count; i++)
	{
		size_t j;

		fuzz_check(memchr(attachments[i].tth, '\0', sizeof(attachments[i].tth)) != NULL,
			"attachment tth is not NUL terminated");
		fuzz_check(memchr(attachments[i].name, '\0', sizeof(attachments[i].name)) != NULL,
			"attachment name is not NUL terminated");
		fuzz_check(strlen(attachments[i].tth) == SEED_TTH_STR_LEN,
			"attachment tth is not a full TTH");

		for (j = 0; j < SEED_TTH_STR_LEN; j++)
		{
			fuzz_check(is_valid_base32_char(attachments[i].tth[j]),
				"attachment tth is not base32");
		}

		/* Duplicates are collapsed, so no hash appears twice. */
		for (j = 0; j < i; j++)
		{
			fuzz_check(strcmp(attachments[i].tth, attachments[j].tth) != 0,
				"the same attachment was returned twice");
		}
	}

	/* Asking for none must write none, whatever the body says. */
	fuzz_check(seed_post_attachments(data, size, &post, attachments, 0) == 0,
		"attachments returned when the caller had room for none");

	return 0;
}
