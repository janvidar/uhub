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
#include "util/tth.h"
#include "seeder/embed.h"

/* The anchor the scanner keys on: the closing bracket of the link label
   immediately followed by the start of a magnet url. */
#define SEED_ANCHOR     "](magnet:?"
#define SEED_ANCHOR_LEN 10

/* The only exact topic the hub cares about; anything else is not a blob. */
#define SEED_XT_PREFIX     "xt=urn:tree:tiger:"
#define SEED_XT_PREFIX_LEN 18

_Static_assert(sizeof(((struct seed_embed*) 0)->tth) >= TTH_BASE32_LEN + 1, "seed_embed::tth too small for a base32 TTH");

/**
 * True for the characters that terminate a magnet url: the closing parenthesis
 * of the CommonMark destination, or any whitespace. End-of-string terminates it
 * too, but that is handled by the NUL check at each call site.
 */
static int seed_is_url_end(char c)
{
	return (c == ')' || c == '\n' || is_white_space(c));
}

/**
 * Walk backwards from the ']' of an anchor to the '[' that opens the link
 * label. A ']' may legitimately occur inside the label, so brackets are
 * counted rather than matched on sight: only a '[' seen at depth zero opens
 * the label we are looking at.
 *
 * @param start the first byte of the message; the scan never steps before it.
 * @param pos points at the ']' of the anchor.
 * @return the opening '[', or NULL if the label starts before a newline or
 *         before the beginning of the message, in which case there is no embed.
 */
static const char* seed_find_label_start(const char* start, const char* pos)
{
	const char* p = pos;
	size_t depth = 0;

	while (p > start)
	{
		char c = *(--p);

		if (c == '\n')
			return NULL;

		if (c == ']')
		{
			depth++;
		}
		else if (c == '[')
		{
			if (depth == 0)
				return p;
			depth--;
		}
	}
	return NULL;
}

/**
 * Copy at most @p len bytes of @p src into @p dst verbatim, truncating to fit
 * and always NUL terminating. Nothing is decoded or stripped.
 */
static void seed_copy_param(char* dst, size_t dstsize, const char* src, size_t len)
{
	if (len > dstsize - 1)
		len = dstsize - 1;
	memcpy(dst, src, len);
	dst[len] = '\0';
}

/**
 * Parse an unsigned decimal in [str, end) into @p out.
 * @return 1 on success, 0 if the field is empty, holds a non-digit, or does
 *         not fit in a uint64_t.
 */
static int seed_parse_u64(const char* str, const char* end, uint64_t* out)
{
	uint64_t value = 0;
	const char* p;

	if (str >= end)
		return 0;

	for (p = str; p < end; p++)
	{
		uint64_t digit;

		if (!is_num(*p))
			return 0;

		digit = (uint64_t) (*p - '0');
		if (value > (UINT64_MAX - digit) / 10)
			return 0;
		value = (value * 10) + digit;
	}

	*out = value;
	return 1;
}

/**
 * Check that [str, end) is exactly a base32 TTH.
 */
static int seed_is_tth(const char* str, const char* end)
{
	const char* p;

	if ((size_t) (end - str) != TTH_BASE32_LEN)
		return 0;

	for (p = str; p < end; p++)
		if (!is_valid_base32_char(*p))
			return 0;
	return 1;
}

/**
 * Parse the parameters of a magnet url, the bytes between "magnet:?" and the
 * end of the url. Parameter order is not significant, and the first well formed
 * occurrence of each parameter wins.
 *
 * @param[out] embed fully overwritten; only meaningful when this returns 1.
 * @return 1 if a valid "xt=urn:tree:tiger:<tth>" was present, 0 otherwise.
 */
static int seed_parse_magnet(const char* str, const char* end, struct seed_embed* embed)
{
	const char* p = str;
	int have_tth = 0;
	int have_size = 0;
	int have_name = 0;
	int have_mime = 0;

	memset(embed, 0, sizeof(*embed));

	while (p < end)
	{
		const char* sep = p;
		size_t len;

		while (sep < end && *sep != '&')
			sep++;
		len = (size_t) (sep - p);

		if (!have_tth && len == SEED_XT_PREFIX_LEN + TTH_BASE32_LEN &&
			memcmp(p, SEED_XT_PREFIX, SEED_XT_PREFIX_LEN) == 0 &&
			seed_is_tth(p + SEED_XT_PREFIX_LEN, sep))
		{
			seed_copy_param(embed->tth, sizeof(embed->tth), p + SEED_XT_PREFIX_LEN, TTH_BASE32_LEN);
			have_tth = 1;
		}
		else if (!have_size && len >= 3 && memcmp(p, "xl=", 3) == 0)
		{
			/* An unparsable length is treated as absent, not as a reason to
			   drop the embed: the TTH alone identifies the blob. */
			if (seed_parse_u64(p + 3, sep, &embed->size))
				have_size = 1;
			else
				embed->size = 0;
		}
		else if (!have_name && len >= 3 && memcmp(p, "dn=", 3) == 0)
		{
			seed_copy_param(embed->name, sizeof(embed->name), p + 3, len - 3);
			have_name = 1;
		}
		else if (!have_mime && len >= 3 && memcmp(p, "mt=", 3) == 0)
		{
			seed_copy_param(embed->mime, sizeof(embed->mime), p + 3, len - 3);
			have_mime = 1;
		}

		p = (sep < end) ? sep + 1 : end;
	}

	return have_tth;
}

size_t seed_scan_message(const char* text, struct seed_embed* out, size_t max)
{
	size_t count = 0;
	const char* p;

	if (!text || !out || max == 0)
		return 0;

	for (p = text; *p; p++)
	{
		const char* params;
		const char* end;
		const char* label;
		struct seed_embed embed;

		if (*p != ']' || strncmp(p, SEED_ANCHOR, SEED_ANCHOR_LEN) != 0)
			continue;

		/* The url runs from the parameters up to the first ')' or whitespace. */
		params = p + SEED_ANCHOR_LEN;
		for (end = params; *end && !seed_is_url_end(*end); end++)
			;

		label = seed_find_label_start(text, p);
		if (label && seed_parse_magnet(params, end, &embed))
		{
			embed.inline_image = (label > text && label[-1] == '!') ? 1 : 0;
			out[count++] = embed;
			if (count == max)
				break;
		}

		/* Resume after the url. An anchor cannot overlap itself, and the bytes
		   in between belong to a url that has already been considered, so this
		   also keeps the backwards label scan from being repeated needlessly.
		   `end` is always past `p`, so the loop always makes progress. */
		p = end - 1;
	}

	return count;
}
