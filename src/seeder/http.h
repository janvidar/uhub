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

#ifndef HAVE_UHUB_SEEDER_HTTP_H
#define HAVE_UHUB_SEEDER_HTTP_H

#include <stdint.h>
#include <stddef.h>

#include "util/tth.h"

#include "seeder/cache.h"

struct net_connection;
struct ip_addr_encap;

/**
 * Serve cached files over plain HTTP: "GET /seed/<tth>".
 *
 * This is the path that works with today's unmodified clients -- a rich text
 * chat message that embeds an image by URL is fetched over HTTP, so pointing
 * that URL at the seeder needs no client change at all.
 *
 * The seeder is a separate process from the hub, so this listens on its own
 * socket (seed_http_port) and shares a port with nothing: a request that is not
 * addressed under /seed/ has nowhere to be handed on to and is answered with a
 * 404. It is also plaintext only -- there is no probe in front of it unwrapping
 * TLS -- which is why seed_http_enable defaults to off.
 *
 * URLs here are content addressed: the path *is* the hash of the bytes returned,
 * so a response can be cached forever and never revalidated.
 */

/** Largest request line + header block the parser will look at. */
#define SEED_HTTP_REQ_MAX 4096

/**
 * Sentinel used for the end of a requested byte range, meaning "to the last
 * byte of the entity". Combined with a start of 0 it means "no usable range was
 * requested", which is the same thing as asking for the whole entity.
 */
#define SEED_HTTP_RANGE_NONE ((uint64_t) -1)

/** Outcome of classifying a complete HTTP request. */
enum seed_http_result
{
	SEED_HTTP_NOT_MINE = 0, /* not addressed under /seed/; nothing else serves this port (-> 404) */
	SEED_HTTP_OK,           /* GET or HEAD of a syntactically valid /seed/<tth> */
	SEED_HTTP_NOT_FOUND,    /* under /seed/, but not a well formed request for a TTH (-> 404) */
	SEED_HTTP_BAD_METHOD    /* under /seed/, but the method is neither GET nor HEAD (-> 405) */
};

/** Everything the connection handler needs from a parsed request. */
struct seed_http_request
{
	char     tth[TTH_BASE32_LEN + 1]; /** Requested content hash, NUL terminated. */
	int      head_only;               /** HEAD: send the headers but no body. */
	uint64_t range_start;             /** First byte requested. */
	uint64_t range_end;               /** Last byte requested, or SEED_HTTP_RANGE_NONE. */
	int      if_none_match;           /** If-None-Match matched the entity tag. */
};

/**
 * Recognise "GET /seed/<tth>" and pull the request apart. Pure: no I/O, no
 * global state, so it is driven directly by the unit tests.
 *
 * The request is read length bounded and is never required to be NUL
 * terminated; a request containing a NUL byte is rejected outright, as is
 * anything longer than SEED_HTTP_REQ_MAX.
 *
 * Accepts only GET and HEAD, only the exact path prefix "/seed/", and only a
 * path of exactly TTH_BASE32_LEN characters from the base32 alphabet after it
 * (validated with tth_from_string()). A query string is permitted and ignored,
 * as it cannot change which blob is addressed. The request line must carry an
 * HTTP/1.x version and be terminated by CRLF.
 *
 * A single "Range: bytes=N-M" or "bytes=N-" is honoured. Suffix ranges
 * ("bytes=-N"), multi ranges and syntactically invalid ranges are ignored --
 * RFC 9110 allows a server to ignore Range entirely -- and come back as
 * range_start 0 / range_end SEED_HTTP_RANGE_NONE, i.e. the whole entity.
 *
 * @return SEED_HTTP_OK and a filled @p out on a match. @p out is always
 *         initialized, whatever the result.
 */
extern enum seed_http_result seed_http_classify_request(const char* request, size_t len, struct seed_http_request* out);

/**
 * Recognise "GET /seed/<tth>" and extract the TTH.
 * Pure: no I/O. Returns 1 and fills out_tth on a match.
 *
 * Thin wrapper over seed_http_classify_request(); see there for what is
 * accepted and for how the range is reported. Any of the out parameters may be
 * NULL. Nothing is written unless the return value is 1.
 */
extern int seed_http_parse_request(const char* request, size_t len,
                                   char out_tth[TTH_BASE32_LEN + 1],
                                   uint64_t* range_start, uint64_t* range_end);

/**
 * Everything this module is allowed to decide with.
 *
 * The daemon fills one of these in from its configuration and passes it to
 * seed_http_accept(); the connection keeps the pointer, so it must outlive every
 * connection started with it. Same shape, and same reasoning, as
 * struct seed_cc_policy: what may be served is handed over as data rather than
 * looked up through a back reference into a hub.
 */
struct seed_http_policy
{
	struct seed_cache* cache;           /** What is served. Required. */
	size_t max_concurrent_upload;       /** Bodies streaming at once. 0 = no limit. */
};

/**
 * Adopt an inbound HTTP connection and serve a cached file on it.
 *
 * The caller must relinquish ownership of @p con when this returns 1; when it
 * returns 0 nothing was adopted and the caller still owns the connection.
 *
 * @return 1 if adopted.
 */
extern int seed_http_accept(const struct seed_http_policy* policy, struct net_connection* con,
                            const struct ip_addr_encap* addr);

/** Transfers currently occupying an HTTP upload slot. */
extern size_t seed_http_active_uploads(void);

#endif /* HAVE_UHUB_SEEDER_HTTP_H */
