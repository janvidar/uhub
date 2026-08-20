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

#ifndef HAVE_UHUB_SEEDER_POST_H
#define HAVE_UHUB_SEEDER_POST_H

#include <stddef.h>
#include <stdint.h>

#include "adc/adctypes.h"
#include "seeder/cache.h"
#include "seeder/embed.h"

/**
 * The BBS0 post document.
 *
 * A post is a file, and this parses it. The document is a single line of ADC
 * followed by a body:
 *
 *   IBB0 IDIPJJWEPPPLCA3PF2ZCRRYO4F2ZX2EV2JMW2KC3I SJHub\supgrade DA1786439000 RT1
 *   The hub goes down on Saturday. See ![plan.png](magnet:?xt=urn:tree:tiger:...).
 *
 * Everything before the first LF is a whole ADC message -- an `I` message, so
 * it carries no SID -- and is read with the parser the rest of the tree already
 * uses. Everything after it is the body, raw and unescaped.
 *
 * The hash of the post covers the whole document, header included, which is the
 * point of the format: the author, the parent and the subject cannot be
 * rewritten by a hub without changing the name the reader asked for. The hub's
 * index entry repeats some of those fields, and where the two disagree the
 * document wins -- it is the half that was hashed.
 *
 * Parsing is strict on purpose. BBS0 requires a reader to reject a document
 * that violates canonical form rather than repair it, because a repaired
 * document has a different hash from the one that was requested, and a client
 * that hashes what it repaired concludes the file is corrupt.
 *
 * Everything here is pure: no I/O, no allocation, no globals, no state between
 * calls. It runs on bytes fetched from a stranger, so it is total -- every byte
 * string is a legal input, including truncated headers, embedded NULs and a
 * body of arbitrary size -- and it never reads past the length it was given.
 */

/**
 * Largest header accepted, including the LF that ends it.
 *
 * BBS0 fixes this at 8192 and requires a parser to reject a document in which
 * no LF occurs within that span: the header has to be bounded before the file
 * has been read, since a document with no LF at all is otherwise a promise to
 * buffer the whole transfer before deciding anything.
 */
#define SEED_POST_HEADER_MAX 8192

/** Buffer size for the subject, including NUL. Bounded by the header. */
#define SEED_POST_SUBJECT_MAX 512

/**
 * How much of a body is scanned for attachments.
 *
 * A body has no size limit in BBS0 -- the hub bounds a post through the board's
 * MS and the seeder bounds it through seed_max_file_size -- so the scan needs a
 * bound of its own that does not depend on either. Attachments are markdown
 * links and land in prose, so a quarter of a megabyte of leading body text is
 * far past where any real post stops carrying them.
 */
#define SEED_POST_SCAN_MAX (256 * 1024)

/**
 * Most attachments collected from one post body.
 *
 * A post is written once and read for years, so a generous bound costs nothing
 * ordinary and still stops a document that is nothing but magnet links from
 * turning one fetch into an unbounded number of them.
 */
#define SEED_POST_MAX_ATTACHMENTS 16

/** Why a document was rejected. */
enum seed_post_error
{
	SEED_POST_OK = 0,
	SEED_POST_ERR_NO_HEADER,  /** No LF within the first SEED_POST_HEADER_MAX bytes. */
	SEED_POST_ERR_FOURCC,     /** The header does not open with "IBB0". */
	SEED_POST_ERR_SYNTAX,     /** Not a parseable ADC message: bad escape, control byte, bad UTF-8. */
	SEED_POST_ERR_CANONICAL,  /** Parseable, but not in the canonical form BBS0 requires. */
	SEED_POST_ERR_MISSING,    /** A required field is absent. */
	SEED_POST_ERR_FIELD       /** A field is present and malformed. */
};

/**
 * A parsed post document. Offsets refer into the buffer that was parsed; the
 * strings are copies and are always NUL terminated.
 */
struct seed_post
{
	/**
	 * The CID the author claims (`ID`). Base32, and *not* fixed at 39
	 * characters: a CID's length follows the session hash. This is a claim and
	 * nothing verifies it -- ADC cannot prove authorship -- so it is compared
	 * against the index entry's ID and reported when the two disagree, never
	 * presented as an identity.
	 */
	char author_cid[MAX_CID_LEN + 1];

	/** TTH of the post replied to (`PA`), or "" in a post that starts a thread. */
	char parent[SEED_TTH_STR_LEN + 1];

	/** The subject (`SJ`), unescaped. "" when absent, which only a reply may be. */
	char subject[SEED_POST_SUBJECT_MAX];

	/** The author's claimed time of composition (`DA`), or 0 when absent. Unverifiable. */
	uint64_t composed;

	/** 1 when the body is RTF0 rich text (`RT1`), so it may carry attachments. */
	int rich_text;

	/** Offset of the first body byte: one past the LF that ends the header. */
	size_t body_offset;

	/** Body length, i.e. the document length less @c body_offset. */
	size_t body_length;
};

/**
 * Parse and validate a post document.
 *
 * Checks, in this order: that a header exists within the bound; that it opens
 * with the `IBB0` FOURCC; that it is a well formed ADC message; that it obeys
 * the canonical form BBS0 requires (no repeated parameter, no empty value, one
 * space between parameters, recognised parameters in the order the
 * specification lists them and unrecognised ones last, no newline in the
 * subject); and that the required fields are present and well formed.
 *
 * An unrecognised parameter is *not* an error -- BBS0 requires a reader to
 * ignore one and forbids rejecting a document on account of it -- but it must
 * still come after every parameter this reader knows, which is what canonical
 * form demands of the composer.
 *
 * Verifying that the bytes hash to the TTH that was asked for is not done here
 * and is not optional: it is the cache's job, and it happens before a document
 * ever reaches this function. Until it has passed, an index entry is a
 * stranger's description of a file that may not exist.
 *
 * @param data the whole document. NULL is treated as empty.
 * @param len its length in bytes.
 * @param[out] out filled in on success. May be NULL to validate only.
 * @param[out] error filled in on failure. May be NULL.
 * @return 1 if the document is a valid post, 0 otherwise.
 */
extern int seed_post_parse(const void* data, size_t len, struct seed_post* out,
                           enum seed_post_error* error);

/** A human readable reason, for a log line. Never NULL. */
extern const char* seed_post_error_string(enum seed_post_error error);

/**
 * Collect the content-addressed attachments a post's body refers to.
 *
 * Only a body flagged `RT1` carries them: a plain text body is displayed
 * literally, so a magnet URI in one is text the author typed and not a
 * reference the seeder should act on. A post whose @c rich_text is 0 therefore
 * yields nothing.
 *
 * The body is scanned with the same scanner used on rich text chat, over at
 * most SEED_POST_SCAN_MAX leading bytes, and stops at an embedded NUL: a
 * document is not required to be text and this must not read one as though it
 * were. Duplicates within the body are collapsed, since one attachment referred
 * to twice is one file to fetch.
 *
 * @param data the whole document, as passed to seed_post_parse().
 * @param len its length.
 * @param post the parsed header, from seed_post_parse().
 * @param[out] out array receiving the attachments; may be NULL if @p max is 0.
 * @param max entries @p out has room for.
 * @return the number of entries written to @p out.
 */
extern size_t seed_post_attachments(const void* data, size_t len, const struct seed_post* post,
                                    struct seed_embed* out, size_t max);

#endif /* HAVE_UHUB_SEEDER_POST_H */
