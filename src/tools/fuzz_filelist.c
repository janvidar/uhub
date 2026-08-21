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
 * libFuzzer harness for uhub-fuse's file list parser.
 *
 * A file list is downloaded from another user over a client-to-client
 * connection -- bytes chosen by a stranger, parsed before anything in them has
 * been believed -- and what comes out of it becomes directory entries and file
 * names in a mounted filesystem. That is the whole reason this harness exists:
 * a name that escapes its directory here is a path traversal on the machine
 * doing the mounting.
 *
 * The input is fed in twice: once as a decompressed document, so the fuzzer
 * shapes the XML directly, and once as a compressed stream, so the bzip2 path
 * and the size ceiling are exercised too.
 *
 * Beyond crash detection this checks the properties the filesystem relies on:
 *
 *   - every name is non-empty, is not "." or "..", and contains no '/' -- so a
 *     name can only ever be one path component, inside its own directory
 *   - every file carries a well-formed TTH, since a file that cannot be
 *     fetched has no business being listed
 *   - the tree is a tree: no node is its own ancestor, and the depth is bounded
 *
 * Build with:  cmake -B build-fuzz -DFUZZING=ON .  (clang)
 * Run with:    ./build-fuzz/fuzz_filelist autotest/fuzz/corpus/filelist
 */

#include "system.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "fuse/filelist.h"

#include <bzlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

/** Deeper than the parser accepts; reaching it means the bound failed. */
#define FUZZ_MAX_DEPTH (FS_FILELIST_MAX_DEPTH + 2)

static void check_name(const char* name)
{
	if (!name)
		abort();

	/* One component, and a real one. */
	if (!*name || strchr(name, '/') || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		abort();
}

static void check_tth(const char* tth)
{
	size_t n;

	if (strlen(tth) != MAX_CID_LEN)
		abort();

	for (n = 0; n < MAX_CID_LEN; n++)
		if (!is_valid_base32_char(tth[n]))
			abort();
}

static void walk(struct fs_filelist_node* node, int depth)
{
	if (depth > FUZZ_MAX_DEPTH)
		abort();

	for (; node; node = node->next)
	{
		check_name(node->name);

		if (node->is_dir)
		{
			/* A directory's children must point back at it, or a lookup could
			   walk out of the subtree it was given. */
			if (node->children && node->children->parent != node)
				abort();

			walk(node->children, depth + 1);
		}
		else
		{
			check_tth(node->tth);

			if (node->children)
				abort();   /* A file has no contents to descend into. */
		}
	}
}

static void exercise(struct fs_filelist* list)
{
	if (!list)
		return;

	walk(fs_filelist_root(list), 0);

	/* Lookups the filesystem itself performs, on paths it did not choose. */
	fs_filelist_lookup(list, "");
	fs_filelist_lookup(list, "/");
	fs_filelist_lookup(list, "..");
	fs_filelist_lookup(list, "../..");
	fs_filelist_lookup(list, "a/b/c");

	fs_filelist_destroy(list);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	static int initialized = 0;
	char* packed;
	unsigned int packed_len;

	if (!initialized)
	{
		hub_set_log_verbosity(0);
		initialized = 1;
	}

	if (!size || size > (1 << 20))
		return 0;

	/* As a document. */
	exercise(fs_filelist_parse((const char*) data, size));

	/* And as a stream: compressed here so that the decompressor sees something
	   it can actually open, which is where its own bounds get tested. */
	packed_len = (unsigned int) (size * 2 + 1024);
	packed = (char*) hub_malloc(packed_len);
	if (packed)
	{
		if (BZ2_bzBuffToBuffCompress(packed, &packed_len, (char*) (uintptr_t) data,
		                             (unsigned int) size, 1, 0, 30) == BZ_OK)
			exercise(fs_filelist_load(packed, packed_len));

		hub_free(packed);
	}

	/* And as a stream that is not one. */
	exercise(fs_filelist_load(data, size));

	return 0;
}
