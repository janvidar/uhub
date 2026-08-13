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

#include "seeder/fetch.h"
#include "seeder/cache.h"
#include "seeder/config.h"
#include "network/connection.h"
#include "network/dnsresolver.h"
#include "network/ipcalc.h"
#include "network/network.h"
#include "network/tls.h"
#include "seeder/url.h"
#include "uhub_limits.h"
#include "util/log.h"
#include "util/memory.h"

/*
 * enum seed_error has no code for "the remote end misbehaved", since it was
 * written for the ADC ingest path where the peer is a logged-in user. The
 * mapping used here is:
 *
 *   SEED_ERR_IO         - anything that went wrong before the body started:
 *                         DNS, policy refusal, connect, TLS, a response we
 *                         refused to parse, a timeout.
 *   SEED_ERR_TRUNCATED  - the body started but did not arrive in full.
 *   SEED_ERR_TOO_LARGE  - Content-Length over seed_max_file_size.
 *   anything else       - passed through from the seed cache unchanged.
 */

/*
 * Minimum TLS version for an outbound https fetch. uhub-seeder.conf has no
 * tls_version key -- it is a client here, not a server, and the peer is an
 * arbitrary web host -- so the floor is compiled in rather than configured.
 */
#define SEED_FETCH_TLS_VERSION "1.2"

/** Addresses kept from one name, to fail over between. */
#define SEED_FETCH_MAX_ADDRS 8

/** Read granularity for the response. */
#define SEED_FETCH_READ_CHUNK 8192

enum seed_fetch_state
{
	BF_ST_RESOLVE = 0,
	BF_ST_CONNECT,
	BF_ST_REQUEST,
	BF_ST_HEADERS,
	BF_ST_BODY
};

struct seed_fetch
{
	struct seed_cache*        cache;
	const struct seed_config* config; /* Borrowed; outlives the fetch. */
	seed_fetch_cb    cb;
	void*            cb_ptr;

	enum seed_fetch_state state;
	struct seed_url  url;      /* Current target; replaced wholesale on a redirect. */
	int              hop;      /* Redirects followed so far. */
	int              timeout;  /* Clamped seed_url_timeout, in seconds. */
	time_t           deadline; /* Absolute end of the whole fetch. */

	struct seed_addr_policy* policy;

	/* Provenance, copied: the caller's strings need not outlive this call. The
	   buffers match what struct seed_entry keeps, so nothing is lost here that
	   the cache would have stored. */
	char name[SEED_NAME_MAX];
	char origin_cid[64];
	char origin_nick[64];
	char origin_addr[64];

	/* Addresses the current host resolved to, all of them already validated. */
	struct ip_addr_encap addrs[SEED_FETCH_MAX_ADDRS];
	size_t num_addrs;
	size_t next_addr;
	char   peer[INET6_ADDRSTRLEN + 1]; /* The literal currently being connected to. */

	struct net_dns_job*        dns;
	struct net_connect_handle* connect_job;
	struct net_connection*     con;
	struct ssl_context_handle* ssl_ctx;
	struct seed_ingest*        ingest;

	char*  request;
	size_t request_len;
	size_t sent;

	char   hdr[SEED_FETCH_HDR_MAX];
	size_t hdr_len;

	uint64_t body_expect;
	uint64_t body_received;

	int releasing; /* Re-entrancy guard: teardown runs at most once. */
};

static int  seed_fetch_resolve(struct seed_fetch* job);
static int  seed_fetch_dns_cb(struct net_dns_job* dnsjob, const struct net_dns_result* result);
static void seed_fetch_connect_next(struct seed_fetch* job);
static void seed_fetch_connect_cb(struct net_connect_handle* handle, enum net_connect_status status,
                                  struct net_connection* con, void* ptr);
static void seed_fetch_io_cb(struct net_connection* con, int events, void* ptr);

/* ------------------------------------------------------------------- parsing */

const char* seed_fetch_error_string(enum seed_fetch_error err)
{
	switch (err)
	{
		case SEED_FETCH_ERR_NONE:        return "no error";
		case SEED_FETCH_ERR_STATUS:      return "malformed status line";
		case SEED_FETCH_ERR_HTTP_STATUS: return "unhandled HTTP status";
		case SEED_FETCH_ERR_HEADER:      return "malformed header line";
		case SEED_FETCH_ERR_TOO_LARGE:   return "response headers too large";
		case SEED_FETCH_ERR_LENGTH:      return "missing or invalid Content-Length";
		case SEED_FETCH_ERR_SMUGGLE:     return "both Content-Length and Transfer-Encoding";
		case SEED_FETCH_ERR_CHUNKED:     return "Transfer-Encoding is not supported";
		case SEED_FETCH_ERR_LOCATION:    return "redirect without a usable Location";
	}
	return "unknown error";
}

int seed_fetch_status_is_redirect(int status)
{
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

int seed_fetch_parse_status(const char* buf, size_t len, int* out_status)
{
	size_t i;
	int status;

	/* "HTTP/1.1 200" is the shortest well formed status line. */
	if (!buf || len < 12)
		return 0;

	for (i = 0; i < len; i++)
		if (buf[i] == '\0')
			return 0;

	if (memcmp(buf, "HTTP/1.", 7) != 0)
		return 0;
	if (buf[7] != '0' && buf[7] != '1')
		return 0;
	if (buf[8] != ' ')
		return 0;

	for (i = 9; i < 12; i++)
		if (buf[i] < '0' || buf[i] > '9')
			return 0;

	/* Either the line ends here (an empty reason phrase is legal) or a space
	   separates the code from the phrase. Anything else is not a status line. */
	if (len > 12 && buf[12] != ' ' && buf[12] != '\r')
		return 0;

	status = ((buf[9] - '0') * 100) + ((buf[10] - '0') * 10) + (buf[11] - '0');
	if (status < 100)
		return 0;

	if (out_status)
		*out_status = status;
	return 1;
}

/*
 * Index of the CRLF ending the line starting at @p pos, or (size_t) -1 if the
 * line is not well formed. Bare CR, bare LF and NUL are all refused: a parser
 * that accepts more than one line terminator is how a response gets framed one
 * way here and another way in a cache in front of it.
 */
static size_t bf_line_end(const char* buf, size_t pos, size_t limit)
{
	size_t i;

	for (i = pos; i < limit; i++)
	{
		if (buf[i] == '\0' || buf[i] == '\n')
			return (size_t) -1;
		if (buf[i] == '\r')
		{
			if (i + 1 >= limit || buf[i + 1] != '\n')
				return (size_t) -1;
			return i;
		}
	}
	return (size_t) -1;
}

/** Case insensitive comparison of a length-bounded field name. */
static int bf_name_is(const char* name, size_t len, const char* want)
{
	return len == strlen(want) && strncasecmp(name, want, len) == 0;
}

/** Strict unsigned decimal. Rejects empty, signs, spaces and overflow. */
static int bf_parse_u64(const char* s, size_t len, uint64_t* out)
{
	uint64_t value = 0;
	size_t i;

	if (!len || len > 20)
		return 0;

	for (i = 0; i < len; i++)
	{
		uint64_t digit;
		if (s[i] < '0' || s[i] > '9')
			return 0;
		digit = (uint64_t) (s[i] - '0');
		if (value > (UINT64_MAX - digit) / 10)
			return 0;
		value = (value * 10) + digit;
	}

	*out = value;
	return 1;
}

/** True if @p value contains the token "chunked" in a comma separated list. */
static int bf_has_chunked(const char* value, size_t len)
{
	size_t i = 0;

	while (i < len)
	{
		size_t start, end;
		while (i < len && (value[i] == ' ' || value[i] == '\t' || value[i] == ','))
			i++;
		start = i;
		while (i < len && value[i] != ',')
			i++;
		end = i;
		while (end > start && (value[end - 1] == ' ' || value[end - 1] == '\t'))
			end--;
		if (bf_name_is(value + start, end - start, "chunked"))
			return 1;
	}
	return 0;
}

/** Copy a length-bounded value into a fixed buffer. Silently truncates. */
static void bf_copy_value(char* dst, size_t dst_size, const char* value, size_t len)
{
	if (len >= dst_size)
		len = dst_size - 1;
	memcpy(dst, value, len);
	dst[len] = '\0';
}

/*
 * Parse one header line. @return 1 on success, 0 with @p err set on refusal.
 */
static int bf_parse_header_line(const char* line, size_t len, struct seed_fetch_response* out,
                                enum seed_fetch_error* err)
{
	size_t colon;
	size_t i;
	const char* value;
	size_t vlen;

	if (!len)
	{
		*err = SEED_FETCH_ERR_HEADER;
		return 0;
	}

	/* An obs-fold continuation line. RFC 9110 lets a recipient reject these,
	   and unfolding them is a documented smuggling primitive. */
	if (line[0] == ' ' || line[0] == '\t')
	{
		*err = SEED_FETCH_ERR_HEADER;
		return 0;
	}

	colon = len;
	for (i = 0; i < len; i++)
	{
		if (line[i] == ':')
		{
			colon = i;
			break;
		}
	}

	/* No colon at all, or an empty field name. */
	if (colon == 0 || colon == len)
	{
		*err = SEED_FETCH_ERR_HEADER;
		return 0;
	}

	/* Field name must be visible ASCII with no whitespace -- in particular no
	   space before the colon, which some parsers accept and others do not. */
	for (i = 0; i < colon; i++)
	{
		unsigned char c = (unsigned char) line[i];
		if (c <= 32 || c >= 127)
		{
			*err = SEED_FETCH_ERR_HEADER;
			return 0;
		}
	}

	value = line + colon + 1;
	vlen = len - colon - 1;
	while (vlen && (*value == ' ' || *value == '\t'))
	{
		value++;
		vlen--;
	}
	while (vlen && (value[vlen - 1] == ' ' || value[vlen - 1] == '\t'))
		vlen--;

	if (bf_name_is(line, colon, "content-length"))
	{
		uint64_t length;

		/* A repeated Content-Length is refused even when the values agree:
		   there is no reason for an image host to send one twice, and it is
		   the cheapest half of a smuggling attempt. */
		if (out->have_content_length || !bf_parse_u64(value, vlen, &length))
		{
			*err = SEED_FETCH_ERR_LENGTH;
			return 0;
		}
		out->have_content_length = 1;
		out->content_length = length;
	}
	else if (bf_name_is(line, colon, "transfer-encoding"))
	{
		out->have_transfer_encoding = 1;
		if (bf_has_chunked(value, vlen))
			out->chunked = 1;
	}
	else if (bf_name_is(line, colon, "location"))
	{
		/* An unusably long Location is left empty rather than refused here, so
		   that a 200 carrying one is still fetched; a redirect without a
		   usable Location is caught below. */
		if (vlen && vlen < sizeof(out->location))
			bf_copy_value(out->location, sizeof(out->location), value, vlen);
	}
	else if (bf_name_is(line, colon, "content-type"))
	{
		size_t n = vlen;
		for (i = 0; i < vlen; i++)
		{
			if (value[i] == ';' || value[i] == ' ')
			{
				n = i;
				break;
			}
		}
		bf_copy_value(out->content_type, sizeof(out->content_type), value, n);
	}

	return 1;
}

enum seed_fetch_parse seed_fetch_parse_response(const char* buf, size_t len,
                                                struct seed_fetch_response* out,
                                                enum seed_fetch_error* err)
{
	enum seed_fetch_error local = SEED_FETCH_ERR_NONE;
	size_t scan, i, region, pos, nl;
	size_t terminator = (size_t) -1;

	if (!err)
		err = &local;
	*err = SEED_FETCH_ERR_NONE;

	if (!out)
		return SEED_FETCH_PARSE_ERROR;
	memset(out, 0, sizeof(*out));

	if (!buf)
	{
		*err = SEED_FETCH_ERR_STATUS;
		return SEED_FETCH_PARSE_ERROR;
	}

	/* Look for the end of the header block, but never beyond the cap. */
	scan = (len < SEED_FETCH_HDR_MAX) ? len : SEED_FETCH_HDR_MAX;
	for (i = 0; i + 4 <= scan; i++)
	{
		if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
		{
			terminator = i;
			break;
		}
	}

	if (terminator == (size_t) -1)
	{
		if (len >= SEED_FETCH_HDR_MAX)
		{
			*err = SEED_FETCH_ERR_TOO_LARGE;
			return SEED_FETCH_PARSE_ERROR;
		}
		return SEED_FETCH_PARSE_INCOMPLETE;
	}

	out->header_len = terminator + 4;

	/* Every line, status line included, ends within this region. */
	region = terminator + 2;

	nl = bf_line_end(buf, 0, region);
	if (nl == (size_t) -1 || !seed_fetch_parse_status(buf, nl, &out->status))
	{
		*err = SEED_FETCH_ERR_STATUS;
		return SEED_FETCH_PARSE_ERROR;
	}
	pos = nl + 2;

	while (pos < region)
	{
		nl = bf_line_end(buf, pos, region);
		if (nl == (size_t) -1)
		{
			*err = SEED_FETCH_ERR_HEADER;
			return SEED_FETCH_PARSE_ERROR;
		}

		if (nl - pos > SEED_FETCH_HDR_LINE_MAX)
		{
			*err = SEED_FETCH_ERR_TOO_LARGE;
			return SEED_FETCH_PARSE_ERROR;
		}

		if (++out->header_lines > SEED_FETCH_HDR_MAX_LINES)
		{
			*err = SEED_FETCH_ERR_TOO_LARGE;
			return SEED_FETCH_PARSE_ERROR;
		}

		if (!bf_parse_header_line(buf + pos, nl - pos, out, err))
			return SEED_FETCH_PARSE_ERROR;

		pos = nl + 2;
	}

	/* Framing first: a response that frames its body two ways is refused
	   whatever its status. */
	if (out->have_content_length && out->have_transfer_encoding)
	{
		*err = SEED_FETCH_ERR_SMUGGLE;
		return SEED_FETCH_PARSE_ERROR;
	}

	/*
	 * v1 deliberately has no chunked decoder. Writing one means adding new
	 * attacker-facing length parsing to a codebase whose ADC parser has had
	 * repeated out-of-bounds reads, to serve a case that every image host
	 * covers with Content-Length anyway. When it is added it should arrive
	 * together with a fuzz target under autotest/fuzz/. Until then this is an
	 * explicit refusal with a log line, not a silent truncation.
	 */
	if (out->have_transfer_encoding)
	{
		*err = SEED_FETCH_ERR_CHUNKED;
		return SEED_FETCH_PARSE_ERROR;
	}

	if (out->status == 200)
	{
		/* Without Content-Length the body length is signalled by connection
		   close -- which is exactly the signal the far end controls. */
		if (!out->have_content_length)
		{
			*err = SEED_FETCH_ERR_LENGTH;
			return SEED_FETCH_PARSE_ERROR;
		}
	}
	else if (seed_fetch_status_is_redirect(out->status))
	{
		if (!out->location[0])
		{
			*err = SEED_FETCH_ERR_LOCATION;
			return SEED_FETCH_PARSE_ERROR;
		}
	}
	else
	{
		*err = SEED_FETCH_ERR_HTTP_STATUS;
		return SEED_FETCH_PARSE_ERROR;
	}

	return SEED_FETCH_PARSE_OK;
}

static int bf_is_alpha(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/** True if @p s starts with "scheme:" per RFC 3986. */
static int bf_is_absolute_uri(const char* s)
{
	size_t i;

	if (!bf_is_alpha(s[0]))
		return 0;

	for (i = 1; s[i]; i++)
	{
		if (s[i] == ':')
			return 1;
		if (!bf_is_alpha(s[i]) && !(s[i] >= '0' && s[i] <= '9')
			&& s[i] != '+' && s[i] != '-' && s[i] != '.')
			return 0;
	}
	return 0;
}

/** Render "host" or "[host]" for an IPv6 literal. @return 1 on success. */
static int bf_format_host(char* out, size_t out_size, const char* host)
{
	int n;

	if (strchr(host, ':'))
		n = snprintf(out, out_size, "[%s]", host);
	else
		n = snprintf(out, out_size, "%s", host);

	return (n >= 0 && (size_t) n < out_size) ? n : -1;
}

int seed_fetch_resolve_location(const struct seed_url* base, const char* location,
                                char* out, size_t out_size)
{
	char hostbuf[SEED_URL_MAX_HOST + 2];
	char portbuf[8];
	const char* scheme;
	int n;

	if (!base || !location || !out || out_size == 0)
		return 0;

	while (*location == ' ' || *location == '\t')
		location++;
	if (!*location)
		return 0;

	/*
	 * An absolute URI is passed through untouched, including one with a scheme
	 * we do not speak: seed_url_parse() is what turns "file:///etc/passwd" into
	 * a refusal. Treating it as a relative path instead would quietly turn it
	 * into a fetchable path on the current host.
	 */
	if (bf_is_absolute_uri(location))
	{
		n = snprintf(out, out_size, "%s", location);
		return (n >= 0 && (size_t) n < out_size);
	}

	scheme = base->tls ? "https" : "http";

	if (bf_format_host(hostbuf, sizeof(hostbuf), base->host) < 0)
		return 0;

	portbuf[0] = '\0';
	if (base->port != (base->tls ? 443 : 80))
		snprintf(portbuf, sizeof(portbuf), ":%u", (unsigned) base->port);

	/* Scheme relative: "//host/path" inherits only the scheme. */
	if (location[0] == '/' && location[1] == '/')
		n = snprintf(out, out_size, "%s:%s", scheme, location);
	else if (location[0] == '/')
		n = snprintf(out, out_size, "%s://%s%s%s", scheme, hostbuf, portbuf, location);
	else
	{
		/*
		 * Relative to the directory of the base path. Dot segments are left in
		 * place: this string is only ever handed back to seed_url_parse() and
		 * then to the origin, which resolves its own paths.
		 */
		char dir[SEED_URL_MAX_PATH];
		const char* query = strchr(base->path, '?');
		size_t plen = query ? (size_t) (query - base->path) : strlen(base->path);

		while (plen > 0 && base->path[plen - 1] != '/')
			plen--;
		if (plen == 0 || plen >= sizeof(dir))
			return 0;

		memcpy(dir, base->path, plen);
		dir[plen] = '\0';

		n = snprintf(out, out_size, "%s://%s%s%s%s", scheme, hostbuf, portbuf, dir, location);
	}

	return (n >= 0 && (size_t) n < out_size);
}

/* ------------------------------------------------------------------ lifetime */

static const char* bf_scheme(const struct seed_fetch* job)
{
	return job->url.tls ? "https" : "http";
}

/*
 * Release everything tied to one attempt: the DNS job, the connect handle, the
 * connection, the TLS context, the ingest and the request buffer. Every field
 * is cleared, so this is safe to call twice and is also what a redirect uses to
 * start the next hop from a clean slate.
 */
static void seed_fetch_drop_connection(struct seed_fetch* job)
{
	if (job->dns)
	{
		net_dns_job_cancel(job->dns);
		job->dns = NULL;
	}
	if (job->connect_job)
	{
		net_connect_destroy(job->connect_job);
		job->connect_job = NULL;
	}
	if (job->con)
	{
		net_con_close(job->con);
		job->con = NULL;
	}
	if (job->ssl_ctx)
	{
		/* Safe with an SSL object still referencing it: OpenSSL refcounts the
		   context, so it is not really freed until the connection's SSL is. */
		net_ssl_context_destroy(job->ssl_ctx);
		job->ssl_ctx = NULL;
	}
	if (job->ingest)
	{
		seed_ingest_abort(job->ingest, SEED_ERR_TRUNCATED);
		job->ingest = NULL;
	}

	hub_free(job->request);
	job->request = NULL;
	job->request_len = 0;
	job->sent = 0;
	job->hdr_len = 0;
	job->body_expect = 0;
	job->body_received = 0;
	job->num_addrs = 0;
	job->next_addr = 0;
}

/*
 * The one and only way a fetch ends.
 *
 * The handle is freed *before* the callback runs, so there is no window in
 * which the callback could reach a half-torn-down job, and re-entering
 * seed_fetch_start() from the callback is safe. `releasing` makes a second call
 * a no-op, which is what guarantees the callback fires at most once no matter
 * which path got here.
 */
static void seed_fetch_release(struct seed_fetch* job, int invoke, enum seed_error err,
                               const struct seed_entry* entry)
{
	seed_fetch_cb cb;
	void* ptr;

	if (!job || job->releasing)
		return;
	job->releasing = 1;

	seed_fetch_drop_connection(job);
	seed_addr_policy_destroy(job->policy);
	job->policy = NULL;

	cb = job->cb;
	ptr = job->cb_ptr;
	hub_free(job);

	if (invoke && cb)
		cb(ptr, err, entry);
}

static void seed_fetch_fail(struct seed_fetch* job, enum seed_error err, const char* why)
{
	LOG_INFO("seedfetch: %s://%s:%u%s failed: %s", bf_scheme(job), job->url.host,
		(unsigned) job->url.port, job->url.path, why ? why : seed_error_string(err));
	seed_fetch_release(job, 1, err, NULL);
}

void seed_fetch_cancel(struct seed_fetch* job)
{
	seed_fetch_release(job, 0, SEED_OK, NULL);
}

/** The total deadline, checked on every event; @see seed_fetch_io_cb. */
static int seed_fetch_past_deadline(const struct seed_fetch* job)
{
	return time(NULL) > job->deadline;
}

/* -------------------------------------------------------------------- policy */

static int seed_fetch_host_allowed(const struct seed_config* config, const char* host)
{
	if (config->seed_url_deny_hosts && *config->seed_url_deny_hosts
		&& seed_host_matches_list(host, config->seed_url_deny_hosts))
	{
		LOG_INFO("seedfetch: \"%s\" is on seed_url_deny_hosts; not fetching.", host);
		return 0;
	}

	if (config->seed_url_allow_hosts && *config->seed_url_allow_hosts
		&& !seed_host_matches_list(host, config->seed_url_allow_hosts))
	{
		LOG_INFO("seedfetch: \"%s\" is not on seed_url_allow_hosts; not fetching.", host);
		return 0;
	}

	return 1;
}

/* -------------------------------------------------------- resolve and connect */

static int seed_fetch_resolve(struct seed_fetch* job)
{
	job->state = BF_ST_RESOLVE;

	/*
	 * The lookup is done here, not left to net_con_connect(), because that
	 * function resolves whatever name it is handed -- so passing it a hostname
	 * would resolve the name a second time, and nothing stops the second answer
	 * from being 127.0.0.1. What gets connected to below is a literal.
	 */
	job->dns = net_dns_gethostbyname(job->url.host, AF_UNSPEC, seed_fetch_dns_cb, job);
	if (!job->dns)
	{
		LOG_WARN("seedfetch: unable to start a DNS lookup for \"%s\".", job->url.host);
		return 0;
	}
	return 1;
}

static int seed_fetch_af_usable(int af)
{
	return af != AF_INET6 || net_is_ipv6_supported();
}

static int seed_fetch_dns_cb(struct net_dns_job* dnsjob, const struct net_dns_result* result)
{
	struct seed_fetch* job = (struct seed_fetch*) net_dns_job_get_ptr(dnsjob);
	struct ip_addr_encap* addr;

	/* The resolver frees the job once this returns; never cancel it from here. */
	job->dns = NULL;

	if (seed_fetch_past_deadline(job))
	{
		seed_fetch_fail(job, SEED_ERR_IO, "timed out while resolving");
		return 1;
	}

	if (!result)
	{
		seed_fetch_fail(job, SEED_ERR_IO, "DNS error");
		return 1;
	}

	if (!net_dns_result_size(result))
	{
		seed_fetch_fail(job, SEED_ERR_IO, "host not found");
		return 1;
	}

	/*
	 * Every answer has to pass, not merely one of them. A name that answers
	 * with a mix of public and private addresses is either hostile or broken,
	 * and "pick a good one" only hands the attacker a race to win: the address
	 * actually connected to is chosen by the kernel's ordering, not by us.
	 */
	addr = net_dns_result_first(result);
	while (addr)
	{
		if (!seed_addr_is_permitted(job->policy, addr))
		{
			LOG_INFO("seedfetch: \"%s\" resolves to the disallowed address %s; not fetching.",
				job->url.host, ip_convert_to_string(addr));
			seed_fetch_fail(job, SEED_ERR_IO, "host resolves to a disallowed address");
			return 1;
		}

		if (job->num_addrs < SEED_FETCH_MAX_ADDRS && seed_fetch_af_usable(addr->af))
			job->addrs[job->num_addrs++] = *addr;

		addr = net_dns_result_next(result);
	}

	if (!job->num_addrs)
	{
		seed_fetch_fail(job, SEED_ERR_IO, "no usable address");
		return 1;
	}

	job->next_addr = 0;
	seed_fetch_connect_next(job);
	return 1;
}

static void seed_fetch_connect_next(struct seed_fetch* job)
{
	const char* literal;

	if (seed_fetch_past_deadline(job))
	{
		seed_fetch_fail(job, SEED_ERR_IO, "timed out before connecting");
		return;
	}

	if (job->next_addr >= job->num_addrs)
	{
		seed_fetch_fail(job, SEED_ERR_IO, "could not connect to any resolved address");
		return;
	}

	/* ip_convert_to_string() hands back a static buffer; copy it at once. */
	literal = ip_convert_to_string(&job->addrs[job->next_addr]);
	job->next_addr++;
	if (!literal || !*literal)
	{
		seed_fetch_fail(job, SEED_ERR_IO, "unusable address");
		return;
	}
	snprintf(job->peer, sizeof(job->peer), "%s", literal);

	job->state = BF_ST_CONNECT;
	job->connect_job = net_con_connect(job->peer, job->url.port, seed_fetch_connect_cb, job);
	if (!job->connect_job)
		seed_fetch_fail(job, SEED_ERR_IO, "unable to start the connection");
}

/** Read the address the socket actually landed on. @return 1 on success. */
static int seed_fetch_peer_address(struct net_connection* con, struct ip_addr_encap* out)
{
	struct sockaddr_storage storage;
	socklen_t len = sizeof(storage);
	int sd = net_con_get_sd(con);

	memset(out, 0, sizeof(*out));
	memset(&storage, 0, sizeof(storage));

	if (sd == -1 || getpeername(sd, (struct sockaddr*) &storage, &len) == -1)
		return 0;

	if (storage.ss_family == AF_INET6)
	{
		struct sockaddr_in6* sa6 = (struct sockaddr_in6*) &storage;
		out->af = AF_INET6;
		memcpy(&out->internal_ip_data.in6, &sa6->sin6_addr, sizeof(struct in6_addr));
		return 1;
	}

	if (storage.ss_family == AF_INET)
	{
		struct sockaddr_in* sa4 = (struct sockaddr_in*) &storage;
		out->af = AF_INET;
		memcpy(&out->internal_ip_data.in, &sa4->sin_addr, sizeof(struct in_addr));
		return 1;
	}

	return 0;
}

/*
 * Build the request. Note what is *not* here: no Authorization, no Cookie, no
 * Referer. The hub has no business proving an identity to a host a user named,
 * and a Referer would leak which hub is mirroring what.
 *
 * Accept-Encoding is pinned to identity because a compressed response would
 * defeat the size cap: the store counts the bytes it receives, and a few
 * kilobytes of gzip expands to gigabytes.
 */
static char* seed_fetch_build_request(struct seed_fetch* job, size_t* out_len)
{
	char hostbuf[SEED_URL_MAX_HOST + 10];
	size_t cap;
	char* request;
	int n;

	n = bf_format_host(hostbuf, sizeof(hostbuf), job->url.host);
	if (n < 0)
		return NULL;

	if (job->url.port != (job->url.tls ? 443 : 80))
	{
		size_t used = (size_t) n;
		n = snprintf(hostbuf + used, sizeof(hostbuf) - used, ":%u", (unsigned) job->url.port);
		if (n < 0 || (size_t) n >= sizeof(hostbuf) - used)
			return NULL;
	}

	cap = strlen(job->url.path) + sizeof(hostbuf) + sizeof(PRODUCT_STRING) + 256;
	request = hub_malloc(cap);
	if (!request)
		return NULL;

	n = snprintf(request, cap,
		"GET %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: " PRODUCT_STRING "\r\n"
		"Accept: image/*\r\n"
		"Accept-Encoding: identity\r\n"
		"Connection: close\r\n"
		"\r\n",
		job->url.path, hostbuf);

	if (n < 0 || (size_t) n >= cap)
	{
		hub_free(request);
		return NULL;
	}

	*out_len = (size_t) n;
	return request;
}

/** @return 1 when the handshake is under way, 0 when the job has been failed. */
static int seed_fetch_tls_start(struct seed_fetch* job)
{
	const struct seed_config* config = job->config;
	ssize_t ret;

	job->ssl_ctx = net_ssl_context_create(SEED_FETCH_TLS_VERSION, NULL, NULL);
	if (!job->ssl_ctx)
	{
		seed_fetch_fail(job, SEED_ERR_IO, "unable to create a TLS client context");
		return 0;
	}

	if (config->seed_url_verify_tls)
	{
		/*
		 * seed_url_verify_tls promises the certificate is checked, so if it
		 * cannot be checked the fetch is refused rather than quietly done
		 * unverified. Practically this fires when the host has no system trust
		 * store for the TLS library to load.
		 */
		if (!net_ssl_context_set_client_verify(job->ssl_ctx, job->url.host))
		{
			seed_fetch_fail(job, SEED_ERR_IO,
				"seed_url_verify_tls is enabled but the certificate cannot be verified "
				"(no usable trust store); refusing rather than fetching unverified");
			return 0;
		}
	}
	else
	{
		LOG_WARN("seedfetch: fetching https://%s without verifying its certificate "
			"(seed_url_verify_tls is off).", job->url.host);
	}

	net_con_update(job->con, NET_EVENT_READ | NET_EVENT_WRITE);

	ret = net_con_ssl_handshake(job->con, net_con_ssl_mode_client, job->ssl_ctx);
	if (ret < 0)
	{
		seed_fetch_fail(job, SEED_ERR_IO, "TLS handshake failed");
		return 0;
	}
	return 1;
}

static void seed_fetch_connect_cb(struct net_connect_handle* handle, enum net_connect_status status,
                                  struct net_connection* con, void* ptr)
{
	struct seed_fetch* job = (struct seed_fetch*) ptr;
	struct ip_addr_encap peer;

	(void) handle;
	job->connect_job = NULL; /* the handle destroys itself once this returns */

	if (status != net_connect_status_ok)
	{
		LOG_DEBUG("seedfetch: connect to %s:%u failed (status %d).",
			job->peer, (unsigned) job->url.port, (int) status);
		seed_fetch_connect_next(job);
		return;
	}

	job->con = con;

	/*
	 * Belt and braces. The address was validated before connect(), but the
	 * socket is the only thing that knows where it actually landed, so ask it
	 * -- before a single request byte goes out. This closes the residual gap
	 * between validation and connection without touching connection.c.
	 */
	if (!seed_fetch_peer_address(con, &peer) || !seed_addr_is_permitted(job->policy, &peer))
	{
		seed_fetch_fail(job, SEED_ERR_IO, "the connection landed on a disallowed address");
		return;
	}

	if (seed_fetch_past_deadline(job))
	{
		seed_fetch_fail(job, SEED_ERR_IO, "timed out while connecting");
		return;
	}

	job->request = seed_fetch_build_request(job, &job->request_len);
	if (!job->request)
	{
		seed_fetch_fail(job, SEED_ERR_IO, "unable to build the request");
		return;
	}
	job->sent = 0;
	job->state = BF_ST_REQUEST;

	net_con_reinitialize(con, seed_fetch_io_cb, job, NET_EVENT_WRITE);

	/* An *idle* timeout: it is reset by every byte, so on its own a peer
	   dribbling one byte just under it would hold this slot forever. The total
	   deadline in seed_fetch_io_cb() is what actually bounds the fetch. */
	net_con_set_timeout(con, job->timeout);

	if (job->url.tls)
		seed_fetch_tls_start(job);
}

/* ------------------------------------------------------------ response body */

static void seed_fetch_complete(struct seed_fetch* job)
{
	enum seed_error err = SEED_OK;
	struct seed_entry entry;
	struct seed_ingest* ingest = job->ingest;

	/* seed_ingest_finish() consumes the ingest whether or not it succeeds. */
	job->ingest = NULL;

	memset(&entry, 0, sizeof(entry));
	if (!seed_ingest_finish(ingest, &entry, &err))
	{
		seed_fetch_fail(job, err, seed_error_string(err));
		return;
	}

	LOG_INFO("seedfetch: mirrored %s://%s%s as %s (%" PRIu64 " bytes, %s).",
		bf_scheme(job), job->url.host, job->url.path, entry.tth,
		entry.size, entry.media_type);

	/* The entry is a snapshot on this stack frame, and seed_fetch_release()
	   invokes the callback before returning, so it is still live when it runs. */
	seed_fetch_release(job, 1, SEED_OK, &entry);
}

/** @return 1 on success, 0 when the job has been failed and released. */
static int seed_fetch_begin_body(struct seed_fetch* job, const struct seed_fetch_response* response)
{
	struct seed_ingest_request request;
	enum seed_error err = SEED_OK;
	uint64_t max_size = (uint64_t) job->config->seed_max_file_size * 1024 * 1024;

	if (response->content_length == 0)
	{
		seed_fetch_fail(job, SEED_ERR_TRUNCATED, "empty response body");
		return 0;
	}

	/* Refused before a single body byte is read. */
	if (response->content_length > max_size)
	{
		LOG_INFO("seedfetch: %s://%s%s announced %" PRIu64 " bytes, over seed_max_file_size.",
			bf_scheme(job), job->url.host, job->url.path, response->content_length);
		seed_fetch_fail(job, SEED_ERR_TOO_LARGE, "Content-Length over seed_max_file_size");
		return 0;
	}

	memset(&request, 0, sizeof(request));
	request.expect_tth = NULL; /* the hash of a mirrored URL is not known in advance */
	request.announced_size = response->content_length;
	request.name = job->name[0] ? job->name : NULL;
	request.origin_cid = job->origin_cid[0] ? job->origin_cid : NULL;
	request.origin_nick = job->origin_nick[0] ? job->origin_nick : NULL;
	request.origin_addr = job->origin_addr[0] ? job->origin_addr : NULL;

	job->ingest = seed_ingest_begin(job->cache, &request, &err);
	if (!job->ingest)
	{
		seed_fetch_fail(job, err, seed_error_string(err));
		return 0;
	}

	job->body_expect = response->content_length;
	job->body_received = 0;
	job->state = BF_ST_BODY;
	return 1;
}

/** Stream bytes into the store. @return 1 on success, 0 once released. */
static int seed_fetch_body_write(struct seed_fetch* job, const char* data, size_t len)
{
	int ret;

	if (!len)
		return 1;

	/* More than was announced is either a framing bug or an attempt to walk
	   past the size that was admitted; either way the response is a lie. */
	if ((uint64_t) len > job->body_expect - job->body_received)
	{
		seed_fetch_fail(job, SEED_ERR_IO, "more body bytes than Content-Length announced");
		return 0;
	}

	ret = seed_ingest_write(job->ingest, data, len);
	if (ret != 0)
	{
		enum seed_error err = (enum seed_error) (-ret);
		seed_ingest_abort(job->ingest, err);
		job->ingest = NULL;
		seed_fetch_fail(job, err, seed_error_string(err));
		return 0;
	}

	job->body_received += (uint64_t) len;
	return 1;
}

/* ---------------------------------------------------------------- redirects */

/*
 * Follow a redirect. Always returns 0: whichever way this goes, the connection
 * the caller was reading from is closed by the time it returns.
 *
 * A hop is a complete re-run of the pipeline -- parse, host lists, resolve,
 * validate every address, connect, re-check the peer -- against the new URL.
 * Nothing is carried over from the previous host but the deadline and the hop
 * count, and seed_url_redirect_ok() refuses an https->http downgrade.
 */
static int seed_fetch_redirect(struct seed_fetch* job, const struct seed_fetch_response* response)
{
	const struct seed_config* config = job->config;
	char target[SEED_URL_MAX_LEN];
	struct seed_url next;
	enum seed_url_error err;

	if (!seed_fetch_resolve_location(&job->url, response->location, target, sizeof(target)))
	{
		seed_fetch_fail(job, SEED_ERR_IO, "unusable redirect target");
		return 0;
	}

	err = seed_url_parse(target, config->seed_url_allow_ports, &next);
	if (err != SEED_URL_OK)
	{
		seed_fetch_fail(job, SEED_ERR_IO, seed_url_error_string(err));
		return 0;
	}

	if (!seed_url_redirect_ok(&job->url, &next, job->hop, config->seed_url_max_redirects))
	{
		seed_fetch_fail(job, SEED_ERR_IO, "redirect refused");
		return 0;
	}

	if (!seed_fetch_host_allowed(config, next.host))
	{
		seed_fetch_fail(job, SEED_ERR_IO, "redirect target host is not allowed");
		return 0;
	}

	seed_fetch_drop_connection(job);
	job->url = next;
	job->hop++;

	LOG_DEBUG("seedfetch: following redirect %d to %s://%s:%u%s",
		job->hop, bf_scheme(job), job->url.host, (unsigned) job->url.port, job->url.path);

	if (seed_fetch_past_deadline(job))
		seed_fetch_fail(job, SEED_ERR_IO, "timed out following a redirect");
	else if (!seed_fetch_resolve(job))
		seed_fetch_fail(job, SEED_ERR_IO, "unable to start a DNS lookup for the redirect target");

	return 0;
}

/* ------------------------------------------------------------------- reading */

/*
 * Feed one read into the state machine.
 *
 * @return 1 to keep reading from the same connection, 0 when neither the
 *         connection nor the job may be touched again by the caller -- the job
 *         has either been released or restarted on a new connection.
 */
static int seed_fetch_consume(struct seed_fetch* job, const char* data, size_t len)
{
	if (job->state == BF_ST_HEADERS)
	{
		struct seed_fetch_response response;
		enum seed_fetch_error err = SEED_FETCH_ERR_NONE;
		enum seed_fetch_parse result;
		size_t room = sizeof(job->hdr) - job->hdr_len;
		size_t take = (len < room) ? len : room;
		size_t trailing;

		memcpy(job->hdr + job->hdr_len, data, take);
		job->hdr_len += take;

		result = seed_fetch_parse_response(job->hdr, job->hdr_len, &response, &err);

		if (result == SEED_FETCH_PARSE_INCOMPLETE)
		{
			/* The buffer is full and the block still has not ended. */
			if (take < len)
			{
				seed_fetch_fail(job, SEED_ERR_IO,
					seed_fetch_error_string(SEED_FETCH_ERR_TOO_LARGE));
				return 0;
			}
			return 1;
		}

		if (result != SEED_FETCH_PARSE_OK)
		{
			seed_fetch_fail(job, SEED_ERR_IO, seed_fetch_error_string(err));
			return 0;
		}

		if (seed_fetch_status_is_redirect(response.status))
			return seed_fetch_redirect(job, &response);

		if (!seed_fetch_begin_body(job, &response))
			return 0;

		/* Body bytes that arrived alongside the headers: first whatever sits
		   past the header block in the buffer, then the tail of this read that
		   did not fit into it. */
		trailing = job->hdr_len - response.header_len;
		if (!seed_fetch_body_write(job, job->hdr + response.header_len, trailing))
			return 0;
		if (take < len && !seed_fetch_body_write(job, data + take, len - take))
			return 0;
	}
	else if (!seed_fetch_body_write(job, data, len))
		return 0;

	if (job->body_received >= job->body_expect)
	{
		seed_fetch_complete(job);
		return 0;
	}
	return 1;
}

static void seed_fetch_read(struct seed_fetch* job, struct net_connection* con)
{
	char buf[SEED_FETCH_READ_CHUNK];

	for (;;)
	{
		ssize_t ret = net_con_recv(con, buf, sizeof(buf));

		if (ret > 0)
		{
			if (!seed_fetch_consume(job, buf, (size_t) ret))
				return;
			continue;
		}

		if (ret == 0)
			return; /* would block: wait for the next read event */

		/* Closed or errored. A complete body is a success even if the close
		   arrives in the same event; anything else is a truncated transfer. */
		seed_fetch_fail(job, (job->state == BF_ST_BODY) ? SEED_ERR_TRUNCATED : SEED_ERR_IO,
			"connection closed before the response was complete");
		return;
	}
}

static void seed_fetch_io_cb(struct net_connection* con, int events, void* ptr)
{
	struct seed_fetch* job = (struct seed_fetch*) ptr;

	/*
	 * net_con_set_timeout() is an idle timeout, reset by every byte, so a peer
	 * dribbling one byte under it would hold this slot open indefinitely. The
	 * total deadline is therefore re-checked on every single event.
	 */
	if (seed_fetch_past_deadline(job))
	{
		seed_fetch_fail(job, SEED_ERR_IO, "exceeded seed_url_timeout");
		return;
	}

	if (events & (NET_EVENT_TIMEOUT | NET_EVENT_ERROR))
	{
		seed_fetch_fail(job, (job->state == BF_ST_BODY) ? SEED_ERR_TRUNCATED : SEED_ERR_IO,
			(events & NET_EVENT_TIMEOUT) ? "idle timeout" : "connection error");
		return;
	}

	/* Phase 1: write the request. Driven by a WRITE event on plain TCP, or by
	   the READ event the TLS layer raises once the handshake completes. */
	if (job->state == BF_ST_REQUEST)
	{
		while (job->sent < job->request_len)
		{
			ssize_t ret = net_con_send(con, job->request + job->sent, job->request_len - job->sent);
			if (ret > 0)
			{
				job->sent += (size_t) ret;
				continue;
			}
			if (ret == 0)
			{
				net_con_update(con, NET_EVENT_WRITE); /* would block; retry when writable */
				return;
			}
			seed_fetch_fail(job, SEED_ERR_IO, "unable to send the request");
			return;
		}

		job->state = BF_ST_HEADERS;
		net_con_update(con, NET_EVENT_READ);
		return;
	}

	/* Phase 2: headers, then stream the body straight into the store. */
	if (events & NET_EVENT_READ)
		seed_fetch_read(job, con);
}

/* --------------------------------------------------------------------- start */

static void bf_copy_string(char* dst, size_t dst_size, const char* src)
{
	if (!src)
	{
		dst[0] = '\0';
		return;
	}
	snprintf(dst, dst_size, "%s", src);
}

struct seed_fetch* seed_fetch_start(struct seed_cache* cache,
                                    const struct seed_config* config,
                                    const char* url,
                                    const struct seed_ingest_request* req,
                                    seed_fetch_cb cb, void* ptr)
{
	struct seed_fetch* job;
	struct seed_url parsed;
	enum seed_url_error err;

	if (!config || !url || !req || !cb)
		return NULL;

	if (!config->seed_url_mirror)
	{
		LOG_DEBUG("seedfetch: seed_url_mirror is off; not fetching.");
		return NULL;
	}

	if (!cache)
	{
		LOG_DEBUG("seedfetch: no seed cache; not fetching.");
		return NULL;
	}

	/* The hash of a mirrored URL cannot be known before the bytes arrive, so an
	   announced TTH here would mean the caller confused this with ADC ingest. */
	if (req->expect_tth)
	{
		LOG_ERROR("seedfetch: expect_tth must be NULL when mirroring a URL.");
		return NULL;
	}

	err = seed_url_parse(url, config->seed_url_allow_ports, &parsed);
	if (err != SEED_URL_OK)
	{
		LOG_DEBUG("seedfetch: refusing URL (%s).", seed_url_error_string(err));
		return NULL;
	}

	if (!seed_fetch_host_allowed(config, parsed.host))
		return NULL;

	job = hub_malloc_zero(sizeof(struct seed_fetch));
	if (!job)
		return NULL;

	job->cache = cache;
	job->config = config;
	job->cb = cb;
	job->cb_ptr = ptr;
	job->url = parsed;

	job->timeout = config->seed_url_timeout;
	if (job->timeout < 1)
		job->timeout = 1;
	if (job->timeout > TIMEOUT_QUEUE_MAX)
		job->timeout = TIMEOUT_QUEUE_MAX; /* the timeout wheel cannot hold longer */
	job->deadline = time(NULL) + job->timeout;

	bf_copy_string(job->name, sizeof(job->name), req->name);
	bf_copy_string(job->origin_cid, sizeof(job->origin_cid), req->origin_cid);
	bf_copy_string(job->origin_nick, sizeof(job->origin_nick), req->origin_nick);
	bf_copy_string(job->origin_addr, sizeof(job->origin_addr), req->origin_addr);

	job->policy = seed_addr_policy_create(config->seed_url_allow_private);
	if (!job->policy)
	{
		hub_free(job);
		return NULL;
	}

	LOG_DEBUG("seedfetch: fetching %s://%s:%u%s", bf_scheme(job), job->url.host,
		(unsigned) job->url.port, job->url.path);

	/* The lookup is always asynchronous, so no callback can run before this
	   function returns and the handle is always safe to hand back. */
	if (!seed_fetch_resolve(job))
	{
		seed_fetch_release(job, 0, SEED_OK, NULL);
		return NULL;
	}

	return job;
}
