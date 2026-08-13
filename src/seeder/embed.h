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

#ifndef HAVE_UHUB_SEEDER_EMBED_H
#define HAVE_UHUB_SEEDER_EMBED_H

#include <stddef.h>
#include <stdint.h>

/**
 * Content-addressed embeds in RTF0 rich text chat.
 *
 * A rich text message (one flagged "RT1") may carry CommonMark image embeds
 * "![alt](url)" and links "[text](url)". When the url is a DC-native magnet
 * link naming a tiger tree hash, the embed refers to a blob rather than to
 * some place on the web:
 *
 *   ![shot.png](magnet:?xt=urn:tree:tiger:<39 char base32>&xl=48213&dn=shot.png&mt=image/png)
 *   [report.pdf](magnet:?xt=urn:tree:tiger:<39 char base32>&xl=1048576&dn=report.pdf)
 *
 * A leading '!' means "render inline as an image"; without it the embed is a
 * plain file attachment. The hub scans relayed messages with the scanner below
 * so that it knows which TTHs it is expected to be holding.
 */

#define SEED_EMBED_MAX_NAME 256 /** Buffer size for the "dn" parameter, including NUL. */
#define SEED_EMBED_MAX_MIME 64  /** Buffer size for the "mt" parameter, including NUL. */

/**
 * One content-addressed embed found in a message.
 */
struct seed_embed
{
	char     tth[40];                   /** Base32 tiger tree root, TTH_BASE32_LEN (39) + NUL. */
	uint64_t size;                      /** The "xl" parameter, 0 if absent or unparsable. */
	char     name[SEED_EMBED_MAX_NAME]; /** The "dn" parameter verbatim, "" if absent. */
	char     mime[SEED_EMBED_MAX_MIME]; /** The "mt" parameter verbatim, "" if absent. */
	int      inline_image;              /** 1 if the embed had a leading '!', 0 otherwise. */
};

/**
 * Scan an already-unescaped rich text message for magnet embeds.
 *
 * Pure: no I/O, no allocation, no globals, and no state kept between calls.
 * The scanner is total -- every byte string is a legal input, including
 * truncated constructs, unbalanced brackets and embedded control bytes -- and
 * it never reads past the terminating NUL. It is meant to run on unauthenticated,
 * attacker-controlled input.
 *
 * An entry is emitted only for a magnet link that carries a well formed
 * "xt=urn:tree:tiger:<tth>" parameter, where <tth> is exactly 39 characters
 * from the base32 alphabet [A-Z2-7]. Parameter order is not significant, and a
 * malformed or missing "xt" discards the whole embed rather than producing a
 * partial entry. The optional "xl", "dn" and "mt" parameters are copied on a
 * best-effort basis; "dn" and "mt" are taken verbatim, without percent-decoding,
 * and are truncated to fit their buffers.
 *
 * The same TTH appearing several times in one message yields one entry per
 * occurrence; de-duplicating is left to the caller.
 *
 * @param text the message to scan, NUL terminated. NULL is treated as empty.
 * @param[out] out array receiving the embeds; may be NULL if @p max is 0.
 * @param max the number of entries @p out has room for. Scanning stops once
 *            that many entries have been written.
 * @return the number of entries written to @p out.
 */
extern size_t seed_scan_message(const char* text, struct seed_embed* out, size_t max);

#endif /* HAVE_UHUB_SEEDER_EMBED_H */
