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

#ifndef HAVE_UHUB_SEEDER_SNIFF_H
#define HAVE_UHUB_SEEDER_SNIFF_H

#include <stddef.h>
#include <stdint.h>

/**
 * Media type detection for cached blobs.
 *
 * The hub caches files posted in chat and later serves them back to other
 * users. The media type a client *claims* -- the "mt" parameter of a magnet
 * embed, a filename extension, anything else carried in the message -- is
 * attacker controlled and is ignored entirely. The hub decides the type by
 * looking at the leading bytes of the blob itself, and refuses to cache a blob
 * whose detected type is not on the operator's allowlist (the hub option
 * "blob_allowed_types", default "image/png,image/jpeg,image/gif,image/webp").
 *
 * Note that SVG is deliberately not detectable, and that "text/plain" is
 * deliberately absent from the default allowlist. See seeder/sniff.c.
 */

/** Number of leading bytes the sniffer needs. The ingest path buffers exactly
 *  this many before deciding, so a rejected upload is cut off early. */
#define SEED_SNIFF_BYTES 64

/**
 * Identify the media type of a blob from its leading bytes.
 *
 * Pure: no I/O, no allocation, no globals, and no state kept between calls.
 * The function is total -- every byte string is a legal input -- and never
 * reads past @p len, so a prefix shorter than a magic number simply fails to
 * match rather than reading beyond the buffer. The bytes need not be NUL
 * terminated, and only the first SEED_SNIFF_BYTES of them are examined.
 *
 * @param buf the leading bytes of the blob. May be NULL when @p len is 0.
 * @param len the number of bytes available in @p buf.
 * @return a static string, never NULL. "application/octet-stream" when
 *         nothing matches.
 */
extern const char* seed_sniff_media_type(const uint8_t* buf, size_t len);

/**
 * Check a media type against an operator configured allowlist.
 *
 * Matching is exact and case sensitive on whole list items; a type is never
 * matched as a prefix or a substring of an item. Space and tab around an item
 * are ignored, so "image/png, image/gif" holds two types. An empty list
 * matches nothing.
 *
 * @param type the media type to look for, as returned by seed_sniff_media_type().
 * @param list a comma separated list of media types. NULL matches nothing.
 * @return 1 if @p type appears in @p list, 0 otherwise.
 */
extern int seed_sniff_type_allowed(const char* type, const char* list);

#endif /* HAVE_UHUB_SEEDER_SNIFF_H */
