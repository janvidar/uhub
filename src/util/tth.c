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

#include "system.h"
#include "util/misc.h"
#include "util/tiger.h"
#include "util/tth.h"

/*
 * THEX domain separation: a leaf is hashed with a 0x00 prefix byte and an
 * internal node with 0x01, which is what stops a leaf digest from being
 * substituted for an internal node.
 */
#define TTH_LEAF_PREFIX     0x00
#define TTH_INTERNAL_PREFIX 0x01

/**
 * Hash the buffered leaf block. ctx->block already holds the 0x00 prefix in
 * byte 0, so the hashed length is one more than the buffered data.
 */
static void tth_hash_leaf(struct tth_context* ctx, uint8_t out[TTH_SIZE])
{
	uint64_t res[3];
	tiger(ctx->block, (uint64_t) (ctx->block_len + 1), res);
	memcpy(out, res, TTH_SIZE);
}

/**
 * Hash an internal node: tiger(0x01 || left || right).
 */
static void tth_hash_internal(const uint8_t left[TTH_SIZE], const uint8_t right[TTH_SIZE], uint8_t out[TTH_SIZE])
{
	uint64_t buf[7]; /* 56 bytes; 1 + 24 + 24 = 49 used. uint64_t-typed for tiger(). */
	uint64_t res[3];
	uint8_t* raw = (uint8_t*) buf;

	raw[0] = TTH_INTERNAL_PREFIX;
	memcpy(raw + 1, left, TTH_SIZE);
	memcpy(raw + 1 + TTH_SIZE, right, TTH_SIZE);

	tiger(buf, (uint64_t) (1 + (2 * TTH_SIZE)), res);
	memcpy(out, res, TTH_SIZE);
}

/**
 * Push a completed subtree onto the pending stack, combining eagerly while the
 * new node and the current top sit at the same level.
 *
 * The stack levels are strictly decreasing from bottom to top, so it can never
 * hold more than TTH_MAX_LEVELS entries.
 */
static void tth_push(struct tth_context* ctx, const uint8_t node[TTH_SIZE], unsigned level)
{
	uint8_t cur[TTH_SIZE];

	memcpy(cur, node, TTH_SIZE);

	while (ctx->depth > 0 && ctx->level[ctx->depth - 1] == level)
	{
		uint8_t combined[TTH_SIZE];
		ctx->depth--;
		tth_hash_internal(ctx->stack[ctx->depth], cur, combined);
		memcpy(cur, combined, TTH_SIZE);
		level++;
	}

	if (ctx->depth >= TTH_MAX_LEVELS)
		return; /* unreachable: would need 2^64 leaves */

	memcpy(ctx->stack[ctx->depth], cur, TTH_SIZE);
	ctx->level[ctx->depth] = level;
	ctx->depth++;
}

void tth_init(struct tth_context* ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	((uint8_t*) ctx->block)[0] = TTH_LEAF_PREFIX;
}

void tth_update(struct tth_context* ctx, const void* data, size_t len)
{
	const uint8_t* ptr = (const uint8_t*) data;
	uint8_t* block = ((uint8_t*) ctx->block) + 1; /* byte 0 is the leaf prefix */

	while (len > 0)
	{
		size_t space = TTH_BLOCK_SIZE - ctx->block_len;
		size_t take = (len < space) ? len : space;

		memcpy(block + ctx->block_len, ptr, take);
		ctx->block_len += take;
		ctx->total += take;
		ptr += take;
		len -= take;

		/*
		 * Emit as soon as the block is full. A file whose size is an exact
		 * multiple of the block size must not gain a trailing empty leaf, which
		 * is why finalize only flushes when there is buffered data (or when
		 * nothing at all was hashed).
		 */
		if (ctx->block_len == TTH_BLOCK_SIZE)
		{
			uint8_t leaf[TTH_SIZE];
			tth_hash_leaf(ctx, leaf);
			tth_push(ctx, leaf, 0);
			ctx->block_len = 0;
		}
	}
}

void tth_finalize(struct tth_context* ctx, uint8_t root[TTH_SIZE])
{
	/* Zero bytes of input still has exactly one leaf, tiger(0x00). */
	if (ctx->block_len > 0 || ctx->total == 0)
	{
		uint8_t leaf[TTH_SIZE];
		tth_hash_leaf(ctx, leaf);
		tth_push(ctx, leaf, 0);
		ctx->block_len = 0;
	}

	/*
	 * Fold the remaining pending subtrees right to left. Combining the two
	 * rightmost entries repeatedly is what implements the THEX rule that an
	 * unpaired node is carried up unchanged rather than hashed with itself --
	 * get this wrong and the roots stay self consistent while every other
	 * implementation disagrees.
	 */
	while (ctx->depth > 1)
	{
		uint8_t combined[TTH_SIZE];
		tth_hash_internal(ctx->stack[ctx->depth - 2], ctx->stack[ctx->depth - 1], combined);
		ctx->depth--;
		memcpy(ctx->stack[ctx->depth - 1], combined, TTH_SIZE);
	}

	memcpy(root, ctx->stack[0], TTH_SIZE);
}

void tth(const void* data, size_t len, uint8_t root[TTH_SIZE])
{
	struct tth_context ctx;
	tth_init(&ctx);
	tth_update(&ctx, data, len);
	tth_finalize(&ctx, root);
}

void tth_to_string(const uint8_t root[TTH_SIZE], char* out)
{
	base32_encode((const unsigned char*) root, TTH_SIZE, out);
	out[TTH_BASE32_LEN] = '\0';
}

int tth_from_string(const char* str, uint8_t root[TTH_SIZE])
{
	size_t i;

	if (!str)
		return 0;

	/*
	 * Reading forwards stops at the first character that is not in the base32
	 * alphabet, and NUL is not, so a short string is rejected without ever
	 * reading past its terminator.
	 */
	for (i = 0; i < TTH_BASE32_LEN; i++)
		if (!is_valid_base32_char(str[i]))
			return 0;

	if (str[TTH_BASE32_LEN] != '\0')
		return 0;

	base32_decode(str, root, TTH_SIZE);
	return 1;
}
