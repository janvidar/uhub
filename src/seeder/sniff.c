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
#include "seeder/sniff.h"

/*
 * ============================================================================
 * DO NOT ADD SVG DETECTION HERE.
 * ============================================================================
 *
 * SVG must never be detected. There must be no code path in this file that
 * returns "image/svg+xml", or any other XML or SVG media type.
 *
 * SVG carries script. Serving it from the hub's own origin is a stored-XSS
 * vector against any client that renders chat in a web view: an attacker posts
 * a .svg "image", the hub caches it, and every other user's client fetches and
 * renders it as a document on the hub's origin.
 *
 * An SVG file is expected to come back from this sniffer as "text/plain" (when
 * its leading bytes are printable UTF-8) or "application/octet-stream". Neither
 * is on the default allowlist, so such a blob is refused at ingest.
 *
 * "text/plain" is likewise deliberately absent from the default allowlist --
 * do not add it there to "fix" a rejected upload.
 * ============================================================================
 */

#define SEED_TYPE_PNG     "image/png"
#define SEED_TYPE_JPEG    "image/jpeg"
#define SEED_TYPE_GIF     "image/gif"
#define SEED_TYPE_WEBP    "image/webp"
#define SEED_TYPE_BMP     "image/bmp"
#define SEED_TYPE_AVIF    "image/avif"
#define SEED_TYPE_HEIC    "image/heic"
#define SEED_TYPE_PDF     "application/pdf"
#define SEED_TYPE_TEXT    "text/plain"
#define SEED_TYPE_UNKNOWN "application/octet-stream"

/*
 * A BBS0 bulletin board post document.
 *
 * Detected from content like everything else here, and given a type of its own
 * rather than being admitted as text/plain. Two reasons. A post document is
 * refused unless its type is on the operator's allowlist, and "text/plain" must
 * stay off that list -- it is where SVG and every other markup dialect lands.
 * And a distinct type keeps the storage policy legible: an operator can see in
 * the cache listing which entries are board posts, and can decline to hold them
 * at all by removing this one type from seed_allowed_types.
 *
 * The magic is the FOURCC and the space that must follow it: BBS0 requires the
 * ID field, so a well formed header always carries at least one parameter and
 * therefore always has that space. A document that is nothing but "IBB0" is not
 * a valid post and is not claimed here.
 */
#define SEED_TYPE_BBS_POST "application/x-adc-bbs-post"

/**
 * Compare @p magic_len bytes of @p magic against @p buf at @p offset.
 * Returns 0 rather than reading out of bounds whenever the buffer is too
 * short to hold the whole magic number at that offset.
 */
static int magic_at(const uint8_t* buf, size_t len, size_t offset, const char* magic, size_t magic_len)
{
	if (offset > len || len - offset < magic_len)
		return 0;
	return memcmp(buf + offset, magic, magic_len) == 0;
}

/**
 * ISO base media file format: "ftyp" at offset 4 followed by a four character
 * major brand at offset 8.
 */
static int isobmff_brand_at(const uint8_t* buf, size_t len, const char* brand)
{
	if (!magic_at(buf, len, 4, "ftyp", 4))
		return 0;
	return magic_at(buf, len, 8, brand, 4);
}

const char* seed_sniff_media_type(const uint8_t* buf, size_t len)
{
	size_t n;

	if (!buf || len == 0)
		return SEED_TYPE_UNKNOWN;

	/* Only the leading bytes are ever examined, whatever the caller passes. */
	n = (len > SEED_SNIFF_BYTES) ? (size_t) SEED_SNIFF_BYTES : len;

	if (magic_at(buf, n, 0, "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", 8))
		return SEED_TYPE_PNG;

	if (magic_at(buf, n, 0, "\xff\xd8\xff", 3))
		return SEED_TYPE_JPEG;

	if (magic_at(buf, n, 0, "GIF87a", 6) || magic_at(buf, n, 0, "GIF89a", 6))
		return SEED_TYPE_GIF;

	if (magic_at(buf, n, 0, "RIFF", 4) && magic_at(buf, n, 8, "WEBP", 4))
		return SEED_TYPE_WEBP;

	if (isobmff_brand_at(buf, n, "avif") || isobmff_brand_at(buf, n, "avis"))
		return SEED_TYPE_AVIF;

	if (isobmff_brand_at(buf, n, "heic") || isobmff_brand_at(buf, n, "heix") ||
		isobmff_brand_at(buf, n, "hevc") || isobmff_brand_at(buf, n, "mif1"))
		return SEED_TYPE_HEIC;

	if (magic_at(buf, n, 0, "BM", 2))
		return SEED_TYPE_BMP;

	if (magic_at(buf, n, 0, "%PDF-", 5))
		return SEED_TYPE_PDF;

	/* Checked before the printable-UTF-8 fallback below, which would otherwise
	   claim a post document as text/plain. */
	if (magic_at(buf, n, 0, "IBB0 ", 5))
		return SEED_TYPE_BBS_POST;

	/* Last resort, and only when the whole prefix is printable UTF-8. This is
	   where SVG, XML, HTML and every other markup dialect lands on purpose --
	   see the notice at the top of this file. */
	if (is_printable_utf8((const char*) buf, n))
		return SEED_TYPE_TEXT;

	return SEED_TYPE_UNKNOWN;
}

int seed_sniff_type_allowed(const char* type, const char* list)
{
	size_t type_len;
	const char* pos;

	if (!type || !list)
		return 0;

	type_len = strlen(type);
	if (type_len == 0)
		return 0;

	pos = list;
	for (;;)
	{
		const char* sep = strchr(pos, ',');
		const char* start = pos;
		const char* end = sep ? sep : pos + strlen(pos);

		while (start < end && is_white_space(*start))
			start++;
		while (end > start && is_white_space(end[-1]))
			end--;

		if ((size_t) (end - start) == type_len && memcmp(start, type, type_len) == 0)
			return 1;

		if (!sep)
			break;
		pos = sep + 1;
	}

	return 0;
}
