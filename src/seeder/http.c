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

#include "uhub_limits.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "util/cbuffer.h"
#include "util/tth.h"
#include "network/connection.h"
#include "network/ipcalc.h"
#include "seeder/cache.h"
#include "seeder/http.h"

/* How long (seconds) a client may stall before we drop it. The timeout wheel is
   only TIMEOUT_QUEUE_MAX buckets deep, so this must stay well below that; a
   transfer of any length is covered by re-arming on every byte that moves. */
#define SEED_HTTP_TIMEOUT 30

/* Body read/write granularity, and the most body we push per writable event so
   one large blob cannot monopolise the reactor. Both backends are level
   triggered, so returning early simply gets us called again. */
#define SEED_HTTP_CHUNK        (16 * 1024)
#define SEED_HTTP_WRITE_BUDGET (64 * 1024)

/* Content addressed URLs never change, so the response is immutable. */
#define SEED_HTTP_CACHE_CONTROL "Cache-Control: public, max-age=31536000, immutable\r\n"

#if SEED_HTTP_TIMEOUT >= TIMEOUT_QUEUE_MAX
#error "SEED_HTTP_TIMEOUT must fit inside the timeout wheel (TIMEOUT_QUEUE_MAX)"
#endif

/*
 * Transfers currently streaming a body, capped by
 * policy->max_concurrent_upload.
 *
 * This is a *separate* counter from the one seeder/cc.c keeps for the ADC
 * client-to-client endpoint: the two are different protocols with different
 * clients, so the configured limit applies to each on its own and not to their
 * sum. Single threaded daemon, so a plain counter is all the bookkeeping needed.
 */
static size_t seed_http_uploads = 0;

enum seed_http_phase
{
	SEED_HTTP_PHASE_READ, /* accumulating the request line and headers */
	SEED_HTTP_PHASE_WRITE /* draining the response headers, then the body */
};

struct seed_http_connection
{
	const struct seed_http_policy* policy;
	struct net_connection* connection;
	struct ip_addr_encap addr;
	enum seed_http_phase phase;

	size_t req_len;
	char   req[SEED_HTTP_REQ_MAX + 1]; /* always NUL terminated */

	struct cbuffer* response; /* status line and headers, built once */
	size_t resp_sent;

	/* Body source. The pin and the descriptor are acquired together and released
	   together in seed_http_destroy(), which is the single exit path. */
	int      pinned;          /* pin_tth is held in the cache */
	char     pin_tth[SEED_TTH_STR_LEN + 1];
	uint64_t entry_size;      /* size the cache recorded, for the read clamp */
	int      fd;              /* -1 when not open */
	int      counted;         /* this transfer is counted in seed_http_uploads */
	uint64_t offset;          /* next byte to read out of the file */
	uint64_t remaining;       /* body bytes still to send */

	char   chunk[SEED_HTTP_CHUNK];
	size_t chunk_len;
	size_t chunk_sent;
};

/*
 * The one and only teardown. Every error and completion path funnels through
 * here, which is what makes "the pin is released exactly once" checkable by
 * inspection: the pin is taken in exactly one place, recorded in b->pinned
 * immediately, and dropped only here -- and only when b->pinned is still set,
 * which it never is twice because the struct is freed on the way out.
 */
static void seed_http_destroy(struct seed_http_connection* b)
{
	LOG_TRACE("seed_http_destroy(): %p", (void*) b);

	if (b->fd >= 0)
	{
		close(b->fd);
		b->fd = -1;
	}

	if (b->pinned)
	{
		seed_cache_unpin(b->policy->cache, b->pin_tth);
		b->pinned = 0;
	}

	if (b->counted)
	{
		if (seed_http_uploads > 0)
			seed_http_uploads--;
		b->counted = 0;
	}

	if (b->connection)
	{
		net_con_close(b->connection);
		b->connection = NULL;
	}

	if (b->response)
	{
		cbuf_destroy(b->response);
		b->response = NULL;
	}

	hub_free(b);
}

/* -- request parsing ------------------------------------------------------ */

/* Bounded substring search; the request buffer is never assumed terminated. */
static const char* seed_http_find(const char* hay, size_t hay_len, const char* needle, size_t needle_len)
{
	size_t i;

	if (needle_len == 0 || hay_len < needle_len)
		return NULL;

	for (i = 0; i + needle_len <= hay_len; i++)
		if (memcmp(hay + i, needle, needle_len) == 0)
			return hay + i;
	return NULL;
}

/*
 * Parse a "Range: bytes=..." field value.
 *
 * Only a single byte range is honoured. Suffix ranges ("bytes=-N"), multi
 * ranges and anything malformed return 0, and the caller then serves the whole
 * entity -- RFC 9110 explicitly allows a server to ignore Range.
 *
 * @return 1 when a usable range was parsed.
 */
static int seed_http_parse_range(const char* v, size_t len, uint64_t* start, uint64_t* end)
{
	size_t i;
	size_t dash;
	uint64_t lo = 0;
	uint64_t hi = 0;
	int have_hi = 0;

	while (len && (*v == ' ' || *v == '\t'))
	{
		v++;
		len--;
	}
	while (len && (v[len - 1] == ' ' || v[len - 1] == '\t'))
		len--;

	if (len < 7 || strncasecmp(v, "bytes=", 6) != 0)
		return 0;
	v += 6;
	len -= 6;

	if (memchr(v, ',', len))
		return 0; /* multi range: not supported, ignored */

	dash = len;
	for (i = 0; i < len; i++)
	{
		if (v[i] == '-')
		{
			dash = i;
			break;
		}
	}
	if (dash == len || dash == 0)
		return 0; /* no dash at all, or a suffix range ("-N") */

	for (i = 0; i < dash; i++)
	{
		if (!is_num(v[i]))
			return 0;
		if (lo > (UINT64_MAX - (uint64_t) (v[i] - '0')) / 10)
			return 0; /* absurdly large offset */
		lo = (lo * 10) + (uint64_t) (v[i] - '0');
	}

	for (i = dash + 1; i < len; i++)
	{
		if (!is_num(v[i]))
			return 0;
		if (hi > (UINT64_MAX - (uint64_t) (v[i] - '0')) / 10)
			return 0;
		hi = (hi * 10) + (uint64_t) (v[i] - '0');
		have_hi = 1;
	}

	if (have_hi && hi < lo)
		return 0; /* inverted range is not a valid range set */

	*start = lo;
	*end = have_hi ? hi : SEED_HTTP_RANGE_NONE;
	return 1;
}

/* Does an If-None-Match field value match the entity tag of `tth`? */
static int seed_http_etag_matches(const char* v, size_t len, const char* tth)
{
	char tag[TTH_BASE32_LEN + 3];

	while (len && (*v == ' ' || *v == '\t'))
	{
		v++;
		len--;
	}
	while (len && (v[len - 1] == ' ' || v[len - 1] == '\t'))
		len--;

	if (len == 1 && v[0] == '*')
		return 1;

	/* Search for the quoted tag, which also covers a weak "W/" prefix and a
	   comma separated list of candidate tags. */
	tag[0] = '"';
	memcpy(tag + 1, tth, TTH_BASE32_LEN);
	tag[TTH_BASE32_LEN + 1] = '"';

	return seed_http_find(v, len, tag, TTH_BASE32_LEN + 2) != NULL;
}

enum seed_http_result seed_http_classify_request(const char* request, size_t len, struct seed_http_request* out)
{
	struct seed_http_request req;
	const char* end;
	const char* p;
	const char* q;
	const char* line;
	uint8_t root[TTH_SIZE];
	size_t path_len;

	memset(&req, 0, sizeof(req));
	req.range_end = SEED_HTTP_RANGE_NONE;
	if (out)
		*out = req;

	if (!request || len == 0 || len > SEED_HTTP_REQ_MAX)
		return SEED_HTTP_NOT_MINE;

	/* A NUL inside a request is never legitimate, and letting one through would
	   mean the length bounded parse here and any later string handling disagree
	   about where the request ends. */
	if (memchr(request, '\0', len))
		return SEED_HTTP_NOT_MINE;

	end = request + len;

	if (len >= 4 && memcmp(request, "GET ", 4) == 0)
	{
		p = request + 4;
	}
	else if (len >= 5 && memcmp(request, "HEAD ", 5) == 0)
	{
		p = request + 5;
		req.head_only = 1;
	}
	else
	{
		/* Some other method. Claim it only when it is aimed at our namespace, so
		   the metrics endpoint still sees everything else. */
		const char* sp = (const char*) memchr(request, ' ', (len < 24) ? len : 24);
		if (sp && (size_t) (end - sp) > 6 && memcmp(sp + 1, "/seed/", 6) == 0)
			return SEED_HTTP_BAD_METHOD;
		return SEED_HTTP_NOT_MINE;
	}

	if ((size_t) (end - p) < 6 || memcmp(p, "/seed/", 6) != 0)
		return SEED_HTTP_NOT_MINE;
	p += 6;

	/* From here on the request is ours: everything that fails is a 404, and the
	   same 404 as a TTH that simply is not cached, so a probe cannot tell a
	   malformed request from a cache miss. */

	/* The path component must be exactly a base32 TTH -- no separator, no dot
	   segment, no escape, nothing else can survive the length check. */
	path_len = 0;
	while (p + path_len < end && path_len <= TTH_BASE32_LEN)
	{
		char c = p[path_len];
		if (c == ' ' || c == '?' || c == '\r' || c == '\n')
			break;
		path_len++;
	}
	if (path_len != TTH_BASE32_LEN || p + path_len >= end)
		return SEED_HTTP_NOT_FOUND;
	if (p[path_len] != ' ' && p[path_len] != '?')
		return SEED_HTTP_NOT_FOUND;

	memcpy(req.tth, p, TTH_BASE32_LEN);
	req.tth[TTH_BASE32_LEN] = '\0';
	if (!tth_from_string(req.tth, root))
		return SEED_HTTP_NOT_FOUND;

	/* A query string cannot change which blob is addressed, so it is skipped. */
	q = p + path_len;
	if (*q == '?')
	{
		while (q < end && *q != ' ' && *q != '\r' && *q != '\n')
			q++;
		if (q >= end || *q != ' ')
			return SEED_HTTP_NOT_FOUND;
	}

	/* " HTTP/1.x\r\n" */
	if ((size_t) (end - q) < 11)
		return SEED_HTTP_NOT_FOUND;
	if (memcmp(q, " HTTP/1.", 8) != 0)
		return SEED_HTTP_NOT_FOUND;
	if (q[8] != '0' && q[8] != '1')
		return SEED_HTTP_NOT_FOUND;
	if (q[9] != '\r' || q[10] != '\n')
		return SEED_HTTP_NOT_FOUND;

	for (line = q + 11; line < end; )
	{
		const char* eol;
		const char* colon;
		size_t line_len;
		size_t name_len;

		if (*line == '\r' || *line == '\n')
			break; /* the blank line that ends the header block */

		eol = (const char*) memchr(line, '\n', (size_t) (end - line));
		if (!eol)
			break; /* truncated trailing header, nothing more to read */

		line_len = (size_t) (eol - line);
		if (line_len && line[line_len - 1] == '\r')
			line_len--;

		colon = (const char*) memchr(line, ':', line_len);
		if (colon)
		{
			name_len = (size_t) (colon - line);
			if (name_len == 5 && strncasecmp(line, "Range", 5) == 0)
			{
				uint64_t start = 0;
				uint64_t stop = SEED_HTTP_RANGE_NONE;
				if (seed_http_parse_range(colon + 1, line_len - name_len - 1, &start, &stop))
				{
					req.range_start = start;
					req.range_end = stop;
				}
			}
			else if (name_len == 13 && strncasecmp(line, "If-None-Match", 13) == 0)
			{
				if (seed_http_etag_matches(colon + 1, line_len - name_len - 1, req.tth))
					req.if_none_match = 1;
			}
		}

		line = eol + 1;
	}

	if (out)
		*out = req;
	return SEED_HTTP_OK;
}

int seed_http_parse_request(const char* request, size_t len, char out_tth[TTH_BASE32_LEN + 1], uint64_t* range_start, uint64_t* range_end)
{
	struct seed_http_request req;

	if (seed_http_classify_request(request, len, &req) != SEED_HTTP_OK)
		return 0;

	if (out_tth)
		memcpy(out_tth, req.tth, TTH_BASE32_LEN + 1);
	if (range_start)
		*range_start = req.range_start;
	if (range_end)
		*range_end = req.range_end;
	return 1;
}

/* -- responses ------------------------------------------------------------ */

/*
 * The media type is produced by the sniffer against a configured allowlist, so
 * it is already constrained -- but it ends up verbatim in a response header, so
 * strip anything that is not printable ASCII rather than trust that forever.
 */
static const char* seed_http_media_type(const struct seed_entry* entry, char* buf, size_t bufsize)
{
	size_t i;
	size_t n = 0;

	for (i = 0; i < SEED_MIME_MAX && entry->media_type[i]; i++)
	{
		unsigned char c = (unsigned char) entry->media_type[i];
		if (c < 0x20 || c >= 0x7f || c == ';' || c == ',')
			break;
		if (n + 1 >= bufsize)
			break;
		buf[n++] = (char) c;
	}
	buf[n] = '\0';
	return n ? buf : "application/octet-stream";
}

/* Queue a prepared response and switch the connection over to writing. */
static void seed_http_start_write(struct seed_http_connection* b, struct cbuffer* resp)
{
	b->response = resp;
	b->resp_sent = 0;
	b->phase = SEED_HTTP_PHASE_WRITE;
	net_con_update(b->connection, NET_EVENT_WRITE);
	net_con_set_timeout(b->connection, SEED_HTTP_TIMEOUT);
}

/* Small canned text/plain response, with no body to stream afterwards. */
static void seed_http_send_error(struct seed_http_connection* b, int code, const char* reason, const char* extra_headers)
{
	struct cbuffer* resp = cbuf_create(256);
	char body[64];
	int body_len = snprintf(body, sizeof(body), "%d %s\n", code, reason);

	if (body_len < 0)
		body_len = 0;

	cbuf_append_format(resp, "HTTP/1.1 %d %s\r\n", code, reason);
	cbuf_append(resp, "Content-Type: text/plain; charset=utf-8\r\n");
	cbuf_append_format(resp, "Content-Length: %d\r\n", body_len);
	if (extra_headers)
		cbuf_append(resp, extra_headers);
	cbuf_append(resp, "Connection: close\r\n\r\n");
	cbuf_append_bytes(resp, body, (size_t) body_len);

	seed_http_start_write(b, resp);
}

/*
 * Decide what to answer, and for a 200/206 acquire the pin and the descriptor
 * that keep the file alive for the whole transfer.
 */
static void seed_http_serve(struct seed_http_connection* b)
{
	struct seed_http_request req;
	struct seed_cache* cache = b->policy->cache;
	struct seed_entry entry;
	struct cbuffer* resp;
	char mime[SEED_MIME_MAX];
	uint64_t start;
	uint64_t stop;
	uint64_t length;
	int partial;
	int body;
	size_t max_uploads = b->policy->max_concurrent_upload;

	switch (seed_http_classify_request(b->req, b->req_len, &req))
	{
		case SEED_HTTP_NOT_MINE:
			/* The seeder's HTTP port serves the /seed/ namespace and nothing
			   else, so there is nobody to hand this on to. */
			seed_http_send_error(b, 404, "Not Found", NULL);
			return;

		case SEED_HTTP_BAD_METHOD:
			seed_http_send_error(b, 405, "Method Not Allowed", "Allow: GET, HEAD\r\n");
			return;

		case SEED_HTTP_NOT_FOUND:
			seed_http_send_error(b, 404, "Not Found", NULL);
			return;

		case SEED_HTTP_OK:
			break;
	}

	/*
	 * A HEAD or a conditional request only inspects the cache, so it must not
	 * count as an access: seed_cache_lookup() moves the entry to the head of the
	 * LRU and bumps its hit count, and merely asking about a file should not keep
	 * it alive. Only a request that will actually stream bytes is an access.
	 *
	 * Whether a body follows is not yet known here -- the range may turn out to
	 * be empty -- so the decision is made on what was *asked for*, which is what
	 * the client is charged for either way.
	 */
	body = !req.head_only && !req.if_none_match;

	/* A malformed TTH, an uncached one and a blocked one are deliberately
	   indistinguishable. */
	if (!(body ? seed_cache_lookup(cache, req.tth, &entry) : seed_cache_peek(cache, req.tth, &entry))
		|| seed_cache_is_blocked(cache, req.tth))
	{
		seed_http_send_error(b, 404, "Not Found", NULL);
		return;
	}

	if (req.if_none_match)
	{
		resp = cbuf_create(256);
		cbuf_append(resp, "HTTP/1.1 304 Not Modified\r\n");
		cbuf_append_format(resp, "ETag: \"%s\"\r\n", entry.tth);
		cbuf_append(resp, SEED_HTTP_CACHE_CONTROL);
		cbuf_append(resp, "Accept-Ranges: bytes\r\n");
		cbuf_append(resp, "Connection: close\r\n\r\n");
		seed_http_start_write(b, resp);
		return;
	}

	start = req.range_start;
	stop = req.range_end;
	partial = !(start == 0 && stop == SEED_HTTP_RANGE_NONE);

	if (partial)
	{
		if (entry.size == 0 || start >= entry.size)
		{
			char content_range[64];
			snprintf(content_range, sizeof(content_range), "Content-Range: bytes */%" PRIu64 "\r\n", entry.size);
			seed_http_send_error(b, 416, "Range Not Satisfiable", content_range);
			return;
		}
		if (stop == SEED_HTTP_RANGE_NONE || stop >= entry.size)
			stop = entry.size - 1;
	}
	else
	{
		stop = (entry.size == 0) ? 0 : entry.size - 1;
	}

	length = (entry.size == 0) ? 0 : (stop - start) + 1;

	/* Only a real body transfer occupies an upload slot; HEAD, 304 and the error
	   responses above are cheap and always answered. */
	if (!req.head_only && length > 0 && max_uploads > 0 && seed_http_uploads >= max_uploads)
	{
		LOG_TRACE("seed_http: upload limit (%lu) reached, refusing %s",
			(unsigned long) max_uploads, ip_convert_to_string(&b->addr));
		seed_http_send_error(b, 503, "Service Unavailable", "Retry-After: 5\r\n");
		return;
	}

	if (!req.head_only && length > 0)
	{
		/* Pin first and record it immediately, so that from this point on every
		   exit runs through seed_http_destroy() and drops it exactly once. */
		if (!seed_cache_pin(cache, entry.tth))
		{
			seed_http_send_error(b, 404, "Not Found", NULL);
			return;
		}

		memcpy(b->pin_tth, entry.tth, SEED_TTH_STR_LEN + 1);
		b->pinned = 1;
		b->entry_size = entry.size;

		b->fd = seed_cache_open_file(cache, b->pin_tth);
		if (b->fd < 0)
		{
			seed_http_send_error(b, 404, "Not Found", NULL);
			return;
		}

		b->offset = start;
		b->remaining = length;
		seed_http_uploads++;
		b->counted = 1;
	}

	resp = cbuf_create(512);
	if (partial)
		cbuf_append(resp, "HTTP/1.1 206 Partial Content\r\n");
	else
		cbuf_append(resp, "HTTP/1.1 200 OK\r\n");
	cbuf_append_format(resp, "Content-Type: %s\r\n", seed_http_media_type(&entry, mime, sizeof(mime)));
	cbuf_append_format(resp, "Content-Length: %" PRIu64 "\r\n", length);
	if (partial)
		cbuf_append_format(resp, "Content-Range: bytes %" PRIu64 "-%" PRIu64 "/%" PRIu64 "\r\n", start, stop, entry.size);
	cbuf_append_format(resp, "ETag: \"%s\"\r\n", entry.tth);
	cbuf_append(resp, SEED_HTTP_CACHE_CONTROL);
	cbuf_append(resp, "Accept-Ranges: bytes\r\n");
	cbuf_append(resp, "Connection: close\r\n\r\n");

	seed_http_start_write(b, resp);
}

/* -- event handling ------------------------------------------------------- */

static void seed_http_write_event(struct seed_http_connection* b, struct net_connection* con)
{
	size_t budget = SEED_HTTP_WRITE_BUDGET;
	size_t total = b->response ? cbuf_size(b->response) : 0;

	while (b->resp_sent < total)
	{
		ssize_t sent = net_con_send(con, cbuf_get(b->response) + b->resp_sent, total - b->resp_sent);
		if (sent < 0)
		{
			seed_http_destroy(b);
			return;
		}
		if (sent == 0)
			return; /* EWOULDBLOCK -- resume on the next writable event */
		b->resp_sent += (size_t) sent;
		net_con_set_timeout(con, SEED_HTTP_TIMEOUT);
	}

	while (b->remaining > 0 || b->chunk_sent < b->chunk_len)
	{
		if (budget == 0)
			return; /* yield the reactor; level triggered, so we come straight back */

		if (b->chunk_sent == b->chunk_len)
		{
			size_t want = SEED_HTTP_CHUNK;
			ssize_t got;

			if ((uint64_t) want > b->remaining)
				want = (size_t) b->remaining;

			got = seed_cache_read(b->policy->cache, b->fd, b->entry_size, b->offset, b->chunk, want);
			if (got <= 0)
			{
				/* The file shrank or the read failed. The response headers are
				   already out, so there is no way to report this other than by
				   cutting the connection short. */
				LOG_WARN("seed_http: read failed for TTH=%s at offset %" PRIu64, b->pin_tth, b->offset);
				seed_http_destroy(b);
				return;
			}

			b->chunk_len = (size_t) got;
			b->chunk_sent = 0;
			b->offset += (uint64_t) got;
			b->remaining -= (uint64_t) got;
		}

		while (b->chunk_sent < b->chunk_len)
		{
			ssize_t sent = net_con_send(con, b->chunk + b->chunk_sent, b->chunk_len - b->chunk_sent);
			if (sent < 0)
			{
				seed_http_destroy(b);
				return;
			}
			if (sent == 0)
				return; /* EWOULDBLOCK */
			b->chunk_sent += (size_t) sent;
			net_con_set_timeout(con, SEED_HTTP_TIMEOUT);
			budget = ((size_t) sent >= budget) ? 0 : budget - (size_t) sent;
		}
	}

	seed_http_destroy(b);
}

static void seed_http_net_event(struct net_connection* con, int events, void* arg)
{
	struct seed_http_connection* b = (struct seed_http_connection*) arg;

	if (events & NET_EVENT_TIMEOUT)
	{
		seed_http_destroy(b);
		return;
	}

	if (b->phase == SEED_HTTP_PHASE_READ && (events & NET_EVENT_READ))
	{
		ssize_t bytes = net_con_recv(con, b->req + b->req_len, SEED_HTTP_REQ_MAX - b->req_len);
		if (bytes < 0)
		{
			seed_http_destroy(b);
			return;
		}
		if (bytes == 0)
			return; /* EWOULDBLOCK/EINTR -- wait for more */

		b->req_len += (size_t) bytes;
		b->req[b->req_len] = '\0';
		net_con_set_timeout(con, SEED_HTTP_TIMEOUT);

		if (seed_http_find(b->req, b->req_len, "\r\n\r\n", 4))
		{
			seed_http_serve(b); /* transitions to the WRITE phase, or hands over */
			return;
		}

		if (b->req_len >= SEED_HTTP_REQ_MAX)
		{
			seed_http_send_error(b, 431, "Request Header Fields Too Large", NULL);
			return;
		}
		return;
	}

	if (b->phase == SEED_HTTP_PHASE_WRITE && (events & NET_EVENT_WRITE))
	{
		seed_http_write_event(b, con);
		return;
	}
}

int seed_http_accept(const struct seed_http_policy* policy, struct net_connection* con,
	const struct ip_addr_encap* addr)
{
	struct seed_http_connection* b;

	/* No cache, nothing to serve from, and nothing else listens on this port. */
	if (!policy || !policy->cache || !con || !addr)
		return 0;

	b = (struct seed_http_connection*) hub_malloc_zero(sizeof(struct seed_http_connection));
	if (!b)
		return 0; /* OOM -- the caller still owns the connection */

	LOG_TRACE("seed_http_accept(): %p from %s", (void*) b, ip_convert_to_string(addr));

	b->policy = policy;
	b->connection = con;
	b->phase = SEED_HTTP_PHASE_READ;
	b->fd = -1;
	memcpy(&b->addr, addr, sizeof(struct ip_addr_encap));

	net_con_reinitialize(con, seed_http_net_event, b, NET_EVENT_READ);
	net_con_set_timeout(con, SEED_HTTP_TIMEOUT);
	return 1;
}

size_t seed_http_active_uploads(void)
{
	return seed_http_uploads;
}
