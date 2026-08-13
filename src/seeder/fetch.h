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
 * Mirror an image that a rich text chat message embedded by URL.
 *
 * The seeder fetches the URL once, verifies and caches the bytes, and from then
 * on every viewer loads the image from the seed cache. That is a privacy fix as
 * much as a caching one: without it each viewer's client connects to whatever
 * third party host was linked, handing that host every viewer's IP address and,
 * taken together, the hub's user base and its activity pattern.
 *
 * The destination is chosen by whoever typed the message, so this is a
 * server-side request forgery primitive by construction. The countermeasures
 * live in seeder/url.h and are applied here in a fixed order, from scratch on
 * every redirect hop:
 *
 *   parse (scheme, userinfo, port allowlist)
 *     -> host allow/deny lists
 *       -> resolve, and require *every* answer to pass the address policy
 *         -> connect to the chosen address as a literal
 *           -> re-check the actual peer address off the socket
 *
 * Resolving here rather than letting net_con_connect() do it is the point of
 * step three: handing that function a hostname would resolve the name a second
 * time, and a name that answered with a public address the first time is free
 * to answer with 127.0.0.1 the second. The peer address check that follows
 * closes the remaining gap without any change to the connection layer.
 */

#ifndef HAVE_UHUB_SEEDER_FETCH_H
#define HAVE_UHUB_SEEDER_FETCH_H

#include "seeder/cache.h"
#include "seeder/url.h"

struct seed_config;

/* ------------------------------------------------------------------ fetching */

struct seed_fetch;

/**
 * Called once, on success or failure. `entry` is NULL unless err == SEED_OK,
 * and when it is not it is a snapshot owned by the caller of the callback: it
 * is valid for the duration of the call only.
 */
typedef void (*seed_fetch_cb)(void* ptr, enum seed_error err, const struct seed_entry* entry);

/**
 * Fetch `url` into `cache`. `config` supplies the seed_url_* policy and is
 * borrowed: it, and every string in it, must outlive the fetch. `req` supplies
 * the provenance (origin cid/nick/addr and display name); its expect_tth must be
 * NULL, since the hash of a mirrored URL is not known in advance.
 *
 * The callback is never invoked before this function returns, so the handle is
 * always safe to store. It is invoked exactly once afterwards, and the handle
 * is released immediately before it runs -- so the handle must not be touched,
 * and seed_fetch_cancel() must not be called, from within the callback or at
 * any point after it.
 *
 * Two things are the caller's responsibility, deliberately, because only the
 * caller knows the context they belong in:
 *
 *   - admission. seed_max_concurrent_ingest bounds ingests, but a fetch holds a
 *     socket from the DNS lookup onwards, well before an ingest begins, so the
 *     caller must bound how many fetches it starts (and is the right place to
 *     collapse several users embedding the same URL into one fetch);
 *   - shutdown. Nothing else holds this handle, so an in-flight fetch that is
 *     not cancelled before the daemon tears down leaks its connection.
 *
 * @return a handle, or NULL if the fetch could not be started (cb is NOT called).
 */
extern struct seed_fetch* seed_fetch_start(struct seed_cache* cache,
                                           const struct seed_config* config,
                                           const char* url,
                                           const struct seed_ingest_request* req,
                                           seed_fetch_cb cb, void* ptr);

/** Cancel an in-flight fetch. The callback is not invoked. */
extern void seed_fetch_cancel(struct seed_fetch* job);

/* ------------------------------------------------- response parsing (pure) --- */

/*
 * Everything below is pure: no I/O, no globals, no allocation. It runs on bytes
 * that a remote host chose, so it is the part that has to be right, and it is
 * driven directly by autotest/test_seedfetch.tcc.
 */

/** Largest response header block accepted, in bytes. */
#define SEED_FETCH_HDR_MAX       8192
/** Largest number of header lines accepted, excluding the status line. */
#define SEED_FETCH_HDR_MAX_LINES 100
/** Largest single header line accepted, excluding the CRLF. */
#define SEED_FETCH_HDR_LINE_MAX  1024

/** Why a response was refused. */
enum seed_fetch_error
{
	SEED_FETCH_ERR_NONE = 0,
	SEED_FETCH_ERR_STATUS,      /** Malformed status line, or not HTTP/1.x. */
	SEED_FETCH_ERR_HTTP_STATUS, /** Well formed, but not a status we act on. */
	SEED_FETCH_ERR_HEADER,      /** Malformed header line. */
	SEED_FETCH_ERR_TOO_LARGE,   /** Header block over one of the caps above. */
	SEED_FETCH_ERR_LENGTH,      /** Content-Length missing, repeated, negative or overflowing. */
	SEED_FETCH_ERR_SMUGGLE,     /** Content-Length and Transfer-Encoding in the same response. */
	SEED_FETCH_ERR_CHUNKED,     /** Transfer-Encoding: chunked -- not supported, see below. */
	SEED_FETCH_ERR_LOCATION     /** Redirect with no usable Location. */
};

/** Result of feeding bytes to seed_fetch_parse_response(). */
enum seed_fetch_parse
{
	SEED_FETCH_PARSE_INCOMPLETE = 0, /** The header block has not arrived in full yet. */
	SEED_FETCH_PARSE_OK,             /** Parsed; @see struct seed_fetch_response. */
	SEED_FETCH_PARSE_ERROR           /** Refused; the reason is reported separately. */
};

/** The parts of a response header block this client acts on. */
struct seed_fetch_response
{
	int      status;                 /** HTTP status code. */
	uint64_t content_length;         /** Valid only when have_content_length. */
	int      have_content_length;
	int      have_transfer_encoding;
	int      chunked;                /** Transfer-Encoding names "chunked". */
	size_t   header_len;             /** Bytes of the header block, terminator included: where the body starts. */
	size_t   header_lines;           /** Header lines seen, status line excluded. */
	char     location[SEED_URL_MAX_LEN];  /** Redirect target, verbatim; empty when absent. */
	char     content_type[SEED_MIME_MAX]; /** Advisory only -- the store sniffs the bytes. */
};

/**
 * Parse an HTTP status line.
 *
 * Requires "HTTP/1.0" or "HTTP/1.1", one space, exactly three digits, and then
 * either the end of the line or a space before the reason phrase. Anything else
 * -- HTTP/0.9, HTTP/2, a two digit code, a leading space -- is refused.
 *
 * @param len  Length of @p buf; it need not be NUL terminated, and an embedded
 *             NUL byte anywhere in the line is refused.
 * @return 1 and the code in @p out_status on success, 0 otherwise.
 */
extern int seed_fetch_parse_status(const char* buf, size_t len, int* out_status);

/** @return 1 for the 3xx codes this client follows (301, 302, 303, 307, 308). */
extern int seed_fetch_status_is_redirect(int status);

/**
 * Parse a complete response header block.
 *
 * Strict by design, because a lenient HTTP parser in front of a cache is a
 * request smuggling engine. Lines are terminated by CRLF and nothing else; a
 * lone CR or LF is refused, as is a line without a colon, an obs-fold
 * continuation line, and whitespace between the field name and its colon.
 *
 * Refused outright:
 *   - a response carrying both Content-Length and Transfer-Encoding, which is
 *     the classic smuggling shape and has no legitimate use here;
 *   - Transfer-Encoding: chunked. A chunk size decoder is new attacker facing
 *     parsing, in a codebase whose ADC parser has had repeated out of bounds
 *     reads, for a case every image host handles with Content-Length anyway. It
 *     can be added later, behind a fuzz target -- until then this is a refusal
 *     with a log line rather than a silent truncation;
 *   - a Content-Length that is negative, non-numeric, repeated with differing
 *     values, or larger than UINT64_MAX;
 *   - a 2xx response with no Content-Length at all, since without it the body
 *     length is only known by connection close, which is exactly the signal an
 *     attacker controls.
 *
 * A redirect needs no Content-Length, and its Location is captured verbatim for
 * the caller to resolve and re-validate.
 *
 * @param out  Zeroed on entry, filled in on SEED_FETCH_PARSE_OK.
 * @param err  Set to the reason on SEED_FETCH_PARSE_ERROR, SEED_FETCH_ERR_NONE
 *             otherwise. May be NULL.
 * @return INCOMPLETE while the terminating CRLFCRLF is still missing and the
 *         caps allow more bytes; OK once the block is parsed; ERROR otherwise.
 */
extern enum seed_fetch_parse seed_fetch_parse_response(const char* buf, size_t len,
                                                       struct seed_fetch_response* out,
                                                       enum seed_fetch_error* err);

/**
 * Resolve a Location value against the URL it was returned from.
 *
 * Handles the three forms that occur in practice: an absolute URL, a scheme
 * relative "//host/path", and a path relative to @p base (absolute "/p" or
 * relative "p"). The result is only a string -- the caller must still run it
 * through seed_url_parse() and the address checks, which is where a Location of
 * "file:///etc/passwd" or "http://127.0.0.1/" is stopped.
 *
 * @return 1 on success, 0 if the value is empty or the result would not fit.
 */
extern int seed_fetch_resolve_location(const struct seed_url* base, const char* location,
                                       char* out, size_t out_size);

/** Human readable name for a response error, for logging. */
extern const char* seed_fetch_error_string(enum seed_fetch_error err);

#endif /* HAVE_UHUB_SEEDER_FETCH_H */
