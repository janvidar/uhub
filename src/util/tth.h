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

#ifndef HAVE_UHUB_HASH_TTH_H
#define HAVE_UHUB_HASH_TTH_H

#include <stdint.h>
#include <stddef.h>

/**
 * Tiger Tree Hash (THEX with Tiger, 1024 byte segments) -- the content
 * identifier used by the ADC "TR" search flag and by magnet links of the form
 * "magnet:?xt=urn:tree:tiger:<base32>".
 *
 * A flat tiger() digest is NOT a TTH: the tree is built over 1024 byte leaves,
 * so anything announced as a TR must come from here or no client will ever
 * agree with it.
 *
 * Only the root is produced. The leaf level is deliberately not retained: it
 * exists to answer "CGET tthl" for segmented, multi-source downloads, which the
 * hub does not offer -- a downloader that fetches a whole blob from a single
 * source verifies it by hashing the lot and comparing the root. Not keeping it
 * is what makes the context a fixed-size struct whose footprint does not grow
 * with the file size.
 */

#define TTH_SIZE       24  /** Size of a TTH in bytes (== TIGERSIZE). */
#define TTH_BASE32_LEN 39  /** Length of a base32 TTH, excluding NUL (== MAX_CID_LEN). */
#define TTH_BLOCK_SIZE 1024 /** Leaf segment size, as fixed by the THEX/DC convention. */

/**
 * Maximum depth of the pending-subtree stack. Each level holds at most one
 * pending node, and level N covers 2^N leaves, so 64 levels spans a file far
 * larger than any filesystem. This is what decouples the context size from the
 * size of the data being hashed.
 */
#define TTH_MAX_LEVELS 64

/**
 * Incremental TTH state. Allocate it anywhere -- caller owned, no destructor.
 *
 * @note @c block is uint64_t-typed on purpose: tiger() takes a uint64_t* and
 *       dereferences it as such, so every buffer handed to it must carry
 *       8 byte alignment. See the same note at src/core/inf.c and src/core/link.c.
 */
struct tth_context
{
	uint64_t block[(TTH_BLOCK_SIZE / 8) + 1]; /** 0x00 prefix followed by up to TTH_BLOCK_SIZE bytes. */
	size_t   block_len;                       /** Bytes of leaf data buffered in @c block. */
	uint64_t total;                           /** Total bytes consumed so far. */
	uint8_t  stack[TTH_MAX_LEVELS][TTH_SIZE]; /** One pending subtree digest per level. */
	unsigned level[TTH_MAX_LEVELS];           /** Tree level of the matching stack entry. */
	unsigned depth;                           /** Number of entries currently on the stack. */
};

/**
 * Begin a new TTH computation.
 */
extern void tth_init(struct tth_context* ctx);

/**
 * Add @p len bytes of @p data to the hash. May be called any number of times
 * with any chunk sizes; the result depends only on the concatenation.
 */
extern void tth_update(struct tth_context* ctx, const void* data, size_t len);

/**
 * Complete the hash and write the root to @p root. The context must not be
 * updated again afterwards without a further tth_init().
 */
extern void tth_finalize(struct tth_context* ctx, uint8_t root[TTH_SIZE]);

/**
 * Convenience one-shot equivalent of init/update/finalize.
 */
extern void tth(const void* data, size_t len, uint8_t root[TTH_SIZE]);

/**
 * Write @p root as an unpadded base32 string. @p out must have room for
 * TTH_BASE32_LEN + 1 bytes; the result is NUL terminated.
 */
extern void tth_to_string(const uint8_t root[TTH_SIZE], char* out);

/**
 * Parse an unpadded base32 TTH.
 *
 * Rejects anything that is not exactly TTH_BASE32_LEN characters from the
 * base32 alphabet, so the result is always safe to use as a file name
 * component -- which is precisely how the blob store uses it.
 *
 * @return 1 on success, 0 if @p str is not a valid TTH.
 */
extern int tth_from_string(const char* str, uint8_t root[TTH_SIZE]);

#endif /* HAVE_UHUB_HASH_TTH_H */
