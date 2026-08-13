#include "system.h"

#include <sys/stat.h>
#include <dirent.h>

#include "seeder/fetch.h"
#include "seeder/cache.h"
#include "seeder/config.h"
#include "network/dnsresolver.h"
#include "network/network.h"
#include "seeder/url.h"
#include "util/memory.h"

/*
 * Everything here runs offline. The HTTP response parser is a pure function, so
 * it is fed byte strings directly; the policy decisions that refuse a fetch do
 * so before any socket is created, so seed_fetch_start() can be called for real
 * and observed to return NULL.
 */

#define BF_DIR "test_seedfetch.tmp"

static struct seed_cache*  bf_cache = NULL;
static struct seed_config  bf_config;
static struct seed_fetch_response bf_resp;
static enum seed_fetch_error bf_err;
static int bf_callbacks;

/* ------------------------------------------------------------------ helpers */

static void bf_rmtree(const char* path)
{
	DIR* dir = opendir(path);
	struct dirent* ent;

	if (!dir)
	{
		unlink(path);
		return;
	}

	while ((ent = readdir(dir)) != NULL)
	{
		char child[1024];
		struct stat st;

		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;

		snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
		if (stat(child, &st) == 0 && S_ISDIR(st.st_mode))
			bf_rmtree(child);
		else
			unlink(child);
	}
	closedir(dir);
	rmdir(path);
}

static enum seed_fetch_parse bf_parse(const char* text)
{
	bf_err = SEED_FETCH_ERR_NONE;
	return seed_fetch_parse_response(text, strlen(text), &bf_resp, &bf_err);
}

static int bf_accepts(const char* text)
{
	return bf_parse(text) == SEED_FETCH_PARSE_OK && bf_err == SEED_FETCH_ERR_NONE;
}

static int bf_rejects(const char* text, enum seed_fetch_error want)
{
	return bf_parse(text) == SEED_FETCH_PARSE_ERROR && bf_err == want;
}

/** @return the status code, or -1 if the line was refused. */
static int bf_status(const char* line)
{
	int status = -1;
	if (!seed_fetch_parse_status(line, strlen(line), &status))
		return -1;
	return status;
}

/** Resolve a Location against @p base_url; @return 1 when the result matches. */
static int bf_location_is(const char* base_url, const char* location, const char* want)
{
	struct seed_url base;
	char out[SEED_URL_MAX_LEN];

	if (seed_url_parse(base_url, NULL, &base) != SEED_URL_OK)
		return 0;
	if (!seed_fetch_resolve_location(&base, location, out, sizeof(out)))
		return 0;
	return strcmp(out, want) == 0;
}

static void bf_cb(void* ptr, enum seed_error err, const struct seed_entry* entry)
{
	(void) ptr; (void) err; (void) entry;
	bf_callbacks++;
}

/** Start a fetch of @p url with the default provenance. */
static struct seed_fetch* bf_start(const char* url)
{
	struct seed_ingest_request req;
	memset(&req, 0, sizeof(req));
	req.name = "embedded.png";
	req.origin_nick = "tester";
	return seed_fetch_start(bf_cache, &bf_config, url, &req, bf_cb, NULL);
}

/** Replace one owned config string. */
static void bf_set(char** field, const char* value)
{
	hub_free(*field);
	*field = hub_strdup(value);
}

/* -------------------------------------------------------------- status line */

EXO_TEST(seedfetch_status_200, { return bf_status("HTTP/1.1 200 OK") == 200; });
EXO_TEST(seedfetch_status_301, { return bf_status("HTTP/1.1 301 Moved Permanently") == 301; });
EXO_TEST(seedfetch_status_302, { return bf_status("HTTP/1.1 302 Found") == 302; });
EXO_TEST(seedfetch_status_404, { return bf_status("HTTP/1.1 404 Not Found") == 404; });
EXO_TEST(seedfetch_status_http10, { return bf_status("HTTP/1.0 200 OK") == 200; });

/* An empty reason phrase is legal. */
EXO_TEST(seedfetch_status_no_reason, { return bf_status("HTTP/1.1 204") == 204; });
EXO_TEST(seedfetch_status_no_reason_cr, { return bf_status("HTTP/1.1 204\r") == 204; });

EXO_TEST(seedfetch_status_empty, { return bf_status("") == -1; });
EXO_TEST(seedfetch_status_truncated, { return bf_status("HTTP/1.1 20") == -1; });
EXO_TEST(seedfetch_status_http2, { return bf_status("HTTP/2 200 OK") == -1; });
EXO_TEST(seedfetch_status_http12, { return bf_status("HTTP/1.2 200 OK") == -1; });
EXO_TEST(seedfetch_status_no_space, { return bf_status("HTTP/1.1200 OK") == -1; });
EXO_TEST(seedfetch_status_leading_space, { return bf_status(" HTTP/1.1 200 OK") == -1; });
EXO_TEST(seedfetch_status_non_digit, { return bf_status("HTTP/1.1 2O0 OK") == -1; });
EXO_TEST(seedfetch_status_junk_after_code, { return bf_status("HTTP/1.1 200OK") == -1; });
EXO_TEST(seedfetch_status_garbage, { return bf_status("ICY 200 OK") == -1; });

EXO_TEST(seedfetch_status_embedded_nul, {
	static const char line[] = "HTTP/1.1 2\0 200 OK";
	int status = -1;
	return seed_fetch_parse_status(line, sizeof(line) - 1, &status) == 0;
});

EXO_TEST(seedfetch_status_is_redirect, {
	return seed_fetch_status_is_redirect(301)
		&& seed_fetch_status_is_redirect(302)
		&& seed_fetch_status_is_redirect(303)
		&& seed_fetch_status_is_redirect(307)
		&& seed_fetch_status_is_redirect(308);
});

EXO_TEST(seedfetch_status_is_not_redirect, {
	return !seed_fetch_status_is_redirect(200)
		&& !seed_fetch_status_is_redirect(304)
		&& !seed_fetch_status_is_redirect(404)
		&& !seed_fetch_status_is_redirect(0);
});

/* ------------------------------------------------------- response: complete */

EXO_TEST(seedfetch_response_incomplete, {
	return bf_parse("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n") == SEED_FETCH_PARSE_INCOMPLETE;
});

EXO_TEST(seedfetch_response_incomplete_empty, {
	return bf_parse("") == SEED_FETCH_PARSE_INCOMPLETE;
});

EXO_TEST(seedfetch_response_minimal, {
	return bf_accepts("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
		&& bf_resp.status == 200
		&& bf_resp.have_content_length
		&& bf_resp.content_length == 4
		&& bf_resp.header_lines == 1;
});

/* header_len is where the body starts, terminator included. */
EXO_TEST(seedfetch_response_header_len, {
	const char* text = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nBODY";
	bf_err = SEED_FETCH_ERR_NONE;
	return seed_fetch_parse_response(text, strlen(text), &bf_resp, &bf_err) == SEED_FETCH_PARSE_OK
		&& bf_resp.header_len == strlen(text) - 4
		&& memcmp(text + bf_resp.header_len, "BODY", 4) == 0;
});

EXO_TEST(seedfetch_response_content_type, {
	return bf_accepts("HTTP/1.1 200 OK\r\nContent-Type: image/png; charset=x\r\nContent-Length: 9\r\n\r\n")
		&& strcmp(bf_resp.content_type, "image/png") == 0;
});

EXO_TEST(seedfetch_response_no_headers, {
	/* A 200 with no headers at all has no Content-Length either. */
	return bf_rejects("HTTP/1.1 200 OK\r\n\r\n", SEED_FETCH_ERR_LENGTH);
});

EXO_TEST(seedfetch_response_bad_status_line, {
	return bf_rejects("HTTP/2 200 OK\r\nContent-Length: 4\r\n\r\n", SEED_FETCH_ERR_STATUS);
});

/* A lone LF is not a line terminator here; mixing them is how framing differs
   between one parser and the next. */
EXO_TEST(seedfetch_response_bare_lf_status, {
	return bf_rejects("HTTP/1.1 200 OK\nContent-Length: 4\r\n\r\n", SEED_FETCH_ERR_STATUS);
});

EXO_TEST(seedfetch_response_bare_lf_header, {
	return bf_rejects("HTTP/1.1 200 OK\r\nX: y\nContent-Length: 4\r\n\r\n", SEED_FETCH_ERR_HEADER);
});

EXO_TEST(seedfetch_response_unhandled_status, {
	return bf_rejects("HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\n", SEED_FETCH_ERR_HTTP_STATUS);
});

EXO_TEST(seedfetch_response_unhandled_204, {
	return bf_rejects("HTTP/1.1 204 No Content\r\n\r\n", SEED_FETCH_ERR_HTTP_STATUS);
});

/* ---------------------------------------------------------- Content-Length */

EXO_TEST(seedfetch_length_zero, {
	return bf_accepts("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		&& bf_resp.content_length == 0;
});

EXO_TEST(seedfetch_length_padded, {
	return bf_accepts("HTTP/1.1 200 OK\r\nContent-Length:   1234  \r\n\r\n")
		&& bf_resp.content_length == 1234;
});

EXO_TEST(seedfetch_length_max, {
	return bf_accepts("HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n")
		&& bf_resp.content_length == UINT64_MAX;
});

EXO_TEST(seedfetch_length_overflow, {
	return bf_rejects("HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
		SEED_FETCH_ERR_LENGTH);
});

EXO_TEST(seedfetch_length_overflow_long, {
	return bf_rejects("HTTP/1.1 200 OK\r\nContent-Length: 999999999999999999999999\r\n\r\n",
		SEED_FETCH_ERR_LENGTH);
});

EXO_TEST(seedfetch_length_negative, {
	return bf_rejects("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", SEED_FETCH_ERR_LENGTH);
});

EXO_TEST(seedfetch_length_plus, {
	return bf_rejects("HTTP/1.1 200 OK\r\nContent-Length: +4\r\n\r\n", SEED_FETCH_ERR_LENGTH);
});

EXO_TEST(seedfetch_length_trailing_junk, {
	return bf_rejects("HTTP/1.1 200 OK\r\nContent-Length: 12abc\r\n\r\n", SEED_FETCH_ERR_LENGTH);
});

EXO_TEST(seedfetch_length_empty, {
	return bf_rejects("HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n", SEED_FETCH_ERR_LENGTH);
});

EXO_TEST(seedfetch_length_list, {
	return bf_rejects("HTTP/1.1 200 OK\r\nContent-Length: 4, 4\r\n\r\n", SEED_FETCH_ERR_LENGTH);
});

/* Repeated even with identical values: no image host does this. */
EXO_TEST(seedfetch_length_duplicate, {
	return bf_rejects("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n",
		SEED_FETCH_ERR_LENGTH);
});

EXO_TEST(seedfetch_length_duplicate_differing, {
	return bf_rejects("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 9999\r\n\r\n",
		SEED_FETCH_ERR_LENGTH);
});

EXO_TEST(seedfetch_length_absent, {
	return bf_rejects("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n", SEED_FETCH_ERR_LENGTH);
});

EXO_TEST(seedfetch_length_case_insensitive, {
	return bf_accepts("HTTP/1.1 200 OK\r\ncOnTeNt-LeNgTh: 7\r\n\r\n")
		&& bf_resp.content_length == 7;
});

/* ------------------------------------------------------ Transfer-Encoding */

EXO_TEST(seedfetch_chunked_refused, {
	return bf_rejects("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
		SEED_FETCH_ERR_CHUNKED)
		&& bf_resp.chunked;
});

EXO_TEST(seedfetch_chunked_refused_listed, {
	return bf_rejects("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
		SEED_FETCH_ERR_CHUNKED)
		&& bf_resp.chunked;
});

/* Any other transfer coding is equally unsupported. */
EXO_TEST(seedfetch_transfer_encoding_other_refused, {
	return bf_rejects("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", SEED_FETCH_ERR_CHUNKED)
		&& !bf_resp.chunked;
});

/* The request-smuggling shape: framed two ways at once. */
EXO_TEST(seedfetch_smuggle_cl_then_te, {
	return bf_rejects("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n",
		SEED_FETCH_ERR_SMUGGLE);
});

EXO_TEST(seedfetch_smuggle_te_then_cl, {
	return bf_rejects("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n",
		SEED_FETCH_ERR_SMUGGLE);
});

/* Framing is judged before the status, so a 404 framed both ways still reports
   the smuggling shape rather than the status. */
EXO_TEST(seedfetch_smuggle_beats_status, {
	return bf_rejects("HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n",
		SEED_FETCH_ERR_SMUGGLE);
});

/* ------------------------------------------------------------ header lines */

EXO_TEST(seedfetch_header_no_colon, {
	return bf_rejects("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nthis-line-has-no-colon\r\n\r\n",
		SEED_FETCH_ERR_HEADER);
});

EXO_TEST(seedfetch_header_empty_name, {
	return bf_rejects("HTTP/1.1 200 OK\r\n: value\r\nContent-Length: 4\r\n\r\n",
		SEED_FETCH_ERR_HEADER);
});

EXO_TEST(seedfetch_header_space_before_colon, {
	return bf_rejects("HTTP/1.1 200 OK\r\nContent-Length : 4\r\n\r\n", SEED_FETCH_ERR_HEADER);
});

/* obs-fold continuation. */
EXO_TEST(seedfetch_header_obs_fold, {
	return bf_rejects("HTTP/1.1 200 OK\r\nX-Thing: a\r\n  continued\r\nContent-Length: 4\r\n\r\n",
		SEED_FETCH_ERR_HEADER);
});

EXO_TEST(seedfetch_header_unknown_ignored, {
	return bf_accepts("HTTP/1.1 200 OK\r\nX-Whatever: 1\r\nSet-Cookie: a=b\r\nContent-Length: 5\r\n\r\n")
		&& bf_resp.content_length == 5
		&& bf_resp.header_lines == 3;
});

/* Exactly SEED_FETCH_HDR_MAX_LINES header lines is accepted, one more is not. */
static char* bf_build_lines(size_t count, size_t* out_len)
{
	size_t cap = 64 + (count * 32);
	char* buf = hub_malloc(cap);
	size_t len;
	size_t i;

	if (!buf)
		return NULL;

	len = (size_t) snprintf(buf, cap, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n");
	for (i = 1; i < count; i++)
		len += (size_t) snprintf(buf + len, cap - len, "X%04u: y\r\n", (unsigned) i);
	len += (size_t) snprintf(buf + len, cap - len, "\r\n");

	*out_len = len;
	return buf;
}

EXO_TEST(seedfetch_header_lines_at_cap, {
	size_t len = 0;
	char* buf = bf_build_lines(SEED_FETCH_HDR_MAX_LINES, &len);
	int ok;
	if (!buf) return 0;
	ok = seed_fetch_parse_response(buf, len, &bf_resp, &bf_err) == SEED_FETCH_PARSE_OK
		&& bf_resp.header_lines == SEED_FETCH_HDR_MAX_LINES;
	hub_free(buf);
	return ok;
});

EXO_TEST(seedfetch_header_lines_over_cap, {
	size_t len = 0;
	char* buf = bf_build_lines(SEED_FETCH_HDR_MAX_LINES + 1, &len);
	int ok;
	if (!buf) return 0;
	ok = seed_fetch_parse_response(buf, len, &bf_resp, &bf_err) == SEED_FETCH_PARSE_ERROR
		&& bf_err == SEED_FETCH_ERR_TOO_LARGE;
	hub_free(buf);
	return ok;
});

/* One header line of exactly SEED_FETCH_HDR_LINE_MAX bytes is fine; longer is not. */
static char* bf_build_long_line(size_t line_len, size_t* out_len)
{
	size_t cap = line_len + 128;
	char* buf = hub_malloc(cap);
	size_t len;

	if (!buf)
		return NULL;

	len = (size_t) snprintf(buf, cap, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX: ");
	while (len < line_len + strlen("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"))
		buf[len++] = 'y';
	len += (size_t) snprintf(buf + len, cap - len, "\r\n\r\n");

	*out_len = len;
	return buf;
}

EXO_TEST(seedfetch_header_line_at_cap, {
	size_t len = 0;
	char* buf = bf_build_long_line(SEED_FETCH_HDR_LINE_MAX, &len);
	int ok;
	if (!buf) return 0;
	ok = seed_fetch_parse_response(buf, len, &bf_resp, &bf_err) == SEED_FETCH_PARSE_OK;
	hub_free(buf);
	return ok;
});

EXO_TEST(seedfetch_header_line_over_cap, {
	size_t len = 0;
	char* buf = bf_build_long_line(SEED_FETCH_HDR_LINE_MAX + 1, &len);
	int ok;
	if (!buf) return 0;
	ok = seed_fetch_parse_response(buf, len, &bf_resp, &bf_err) == SEED_FETCH_PARSE_ERROR
		&& bf_err == SEED_FETCH_ERR_TOO_LARGE;
	hub_free(buf);
	return ok;
});

/* A header block that never ends: below the byte cap it is merely incomplete,
   at the cap it is refused rather than buffered further. */
EXO_TEST(seedfetch_header_block_below_cap, {
	char* buf = hub_malloc(SEED_FETCH_HDR_MAX);
	int ok;
	if (!buf) return 0;
	memset(buf, 'a', SEED_FETCH_HDR_MAX);
	ok = seed_fetch_parse_response(buf, SEED_FETCH_HDR_MAX - 1, &bf_resp, &bf_err)
		== SEED_FETCH_PARSE_INCOMPLETE;
	hub_free(buf);
	return ok;
});

EXO_TEST(seedfetch_header_block_over_cap, {
	char* buf = hub_malloc(SEED_FETCH_HDR_MAX + 1024);
	int ok;
	if (!buf) return 0;
	memset(buf, 'a', SEED_FETCH_HDR_MAX + 1024);
	ok = seed_fetch_parse_response(buf, SEED_FETCH_HDR_MAX + 1024, &bf_resp, &bf_err)
		== SEED_FETCH_PARSE_ERROR
		&& bf_err == SEED_FETCH_ERR_TOO_LARGE;
	hub_free(buf);
	return ok;
});

/* A well formed block whose terminator falls past the byte cap is refused too. */
EXO_TEST(seedfetch_header_block_terminator_past_cap, {
	char* buf = hub_malloc(SEED_FETCH_HDR_MAX + 64);
	size_t len = SEED_FETCH_HDR_MAX + 60;
	int ok;
	if (!buf) return 0;
	memset(buf, 'a', SEED_FETCH_HDR_MAX + 64);
	memcpy(buf, "HTTP/1.1 200 OK\r\nX: ", 20);
	memcpy(buf + len - 4, "\r\n\r\n", 4);
	ok = seed_fetch_parse_response(buf, len, &bf_resp, &bf_err) == SEED_FETCH_PARSE_ERROR
		&& bf_err == SEED_FETCH_ERR_TOO_LARGE;
	hub_free(buf);
	return ok;
});

/* ---------------------------------------------------------------- redirects */

EXO_TEST(seedfetch_redirect_location, {
	return bf_accepts("HTTP/1.1 302 Found\r\nLocation: http://cdn.example.org/x.png\r\n\r\n")
		&& bf_resp.status == 302
		&& strcmp(bf_resp.location, "http://cdn.example.org/x.png") == 0;
});

EXO_TEST(seedfetch_redirect_relative_location, {
	return bf_accepts("HTTP/1.1 301 Moved\r\nLocation: /other/x.png\r\n\r\n")
		&& strcmp(bf_resp.location, "/other/x.png") == 0;
});

/* A redirect needs no Content-Length. */
EXO_TEST(seedfetch_redirect_no_length, {
	return bf_accepts("HTTP/1.1 307 Temporary Redirect\r\nLocation: /a\r\n\r\n");
});

EXO_TEST(seedfetch_redirect_without_location, {
	return bf_rejects("HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n", SEED_FETCH_ERR_LOCATION);
});

EXO_TEST(seedfetch_redirect_empty_location, {
	return bf_rejects("HTTP/1.1 302 Found\r\nLocation:\r\n\r\n", SEED_FETCH_ERR_LOCATION);
});

/* A Location longer than a header line may be trips the line cap first -- which
   is why the length guard on the Location buffer itself never fires in
   practice, the line cap being the smaller of the two. */
EXO_TEST(seedfetch_redirect_overlong_location, {
	size_t cap = SEED_FETCH_HDR_LINE_MAX + 256;
	char* buf = hub_malloc(cap);
	size_t len;
	int ok;
	if (!buf) return 0;
	len = (size_t) snprintf(buf, cap, "HTTP/1.1 302 Found\r\nLocation: http://a.example/");
	while (len < SEED_FETCH_HDR_LINE_MAX + 40)
		buf[len++] = 'p';
	len += (size_t) snprintf(buf + len, cap - len, "\r\n\r\n");
	ok = seed_fetch_parse_response(buf, len, &bf_resp, &bf_err) == SEED_FETCH_PARSE_ERROR
		&& bf_err == SEED_FETCH_ERR_TOO_LARGE;
	hub_free(buf);
	return ok;
});

/* ------------------------------------------------- Location -> absolute URL */

EXO_TEST(seedfetch_location_absolute, {
	return bf_location_is("http://a.example/dir/page.html", "https://b.example/x.png",
		"https://b.example/x.png");
});

/* A foreign scheme is passed through untouched so seed_url_parse() can refuse
   it -- treating it as a path would turn it into something fetchable. */
EXO_TEST(seedfetch_location_foreign_scheme, {
	return bf_location_is("http://a.example/dir/page.html", "file:///etc/passwd",
		"file:///etc/passwd");
});

EXO_TEST(seedfetch_location_scheme_relative, {
	return bf_location_is("https://a.example/dir/page.html", "//b.example/x.png",
		"https://b.example/x.png");
});

EXO_TEST(seedfetch_location_absolute_path, {
	return bf_location_is("http://a.example/dir/page.html", "/x.png", "http://a.example/x.png");
});

EXO_TEST(seedfetch_location_relative_path, {
	return bf_location_is("http://a.example/dir/page.html", "x.png", "http://a.example/dir/x.png");
});

EXO_TEST(seedfetch_location_relative_from_root, {
	return bf_location_is("http://a.example/", "x.png", "http://a.example/x.png");
});

/* The query of the base is not part of its directory. */
EXO_TEST(seedfetch_location_relative_ignores_query, {
	return bf_location_is("http://a.example/dir/page.html?v=1", "x.png",
		"http://a.example/dir/x.png");
});

EXO_TEST(seedfetch_location_keeps_port, {
	return bf_location_is("http://a.example:8080/dir/page.html", "/x.png",
		"http://a.example:8080/x.png");
});

EXO_TEST(seedfetch_location_default_port_elided, {
	return bf_location_is("https://a.example:443/dir/page.html", "/x.png",
		"https://a.example/x.png");
});

EXO_TEST(seedfetch_location_ipv6_base, {
	return bf_location_is("http://[2001:db8::1]/dir/page.html", "/x.png",
		"http://[2001:db8::1]/x.png");
});

EXO_TEST(seedfetch_location_empty, {
	struct seed_url base;
	char out[SEED_URL_MAX_LEN];
	return seed_url_parse("http://a.example/", NULL, &base) == SEED_URL_OK
		&& seed_fetch_resolve_location(&base, "", out, sizeof(out)) == 0
		&& seed_fetch_resolve_location(&base, "   ", out, sizeof(out)) == 0;
});

EXO_TEST(seedfetch_location_no_room, {
	struct seed_url base;
	char out[8];
	return seed_url_parse("http://a.example/", NULL, &base) == SEED_URL_OK
		&& seed_fetch_resolve_location(&base, "/some/rather/long/path.png", out, sizeof(out)) == 0;
});

EXO_TEST(seedfetch_error_strings, {
	return strcmp(seed_fetch_error_string(SEED_FETCH_ERR_NONE), "no error") == 0
		&& strcmp(seed_fetch_error_string(SEED_FETCH_ERR_CHUNKED), "unknown error") != 0
		&& strcmp(seed_fetch_error_string((enum seed_fetch_error) 999), "unknown error") == 0;
});

/* -------------------------------------------------------- policy: no socket */

EXO_TEST(seedfetch_setup, {
	struct seed_cache_config cache_config;

	if (net_initialize() != 0)
		return 0;

	bf_rmtree(BF_DIR);

	seed_config_defaults(&bf_config);
	bf_set(&bf_config.seed_cache_dir, BF_DIR);
	bf_config.seed_url_mirror = 1;
	bf_config.seed_cache_size = 1;
	bf_config.seed_max_file_size = 1;
	bf_config.seed_max_entries = 16;
	bf_config.seed_entry_ttl = 0;
	bf_config.seed_max_concurrent_ingest = 4;

	memset(&cache_config, 0, sizeof(cache_config));
	cache_config.dir = BF_DIR;
	cache_config.max_bytes = 1024 * 1024;
	cache_config.max_file_size = 1024 * 1024;
	cache_config.max_entries = 16;
	cache_config.max_concurrent_ingest = 4;

	bf_cache = seed_cache_open(&cache_config);
	bf_callbacks = 0;
	return bf_cache != NULL;
});

/* seed_url_mirror off: refused outright, and without calling the callback. */
EXO_TEST(seedfetch_start_refused_when_mirror_off, {
	struct seed_fetch* job;
	bf_config.seed_url_mirror = 0;
	job = bf_start("http://cdn.example.org/x.png");
	bf_config.seed_url_mirror = 1;
	return job == NULL && bf_callbacks == 0;
});

EXO_TEST(seedfetch_start_refused_without_config, {
	struct seed_ingest_request req;
	memset(&req, 0, sizeof(req));
	return seed_fetch_start(bf_cache, NULL, "http://cdn.example.org/x.png", &req, bf_cb, NULL) == NULL
		&& bf_callbacks == 0;
});

EXO_TEST(seedfetch_start_refused_without_store, {
	struct seed_ingest_request req;
	memset(&req, 0, sizeof(req));
	return seed_fetch_start(NULL, &bf_config, "http://cdn.example.org/x.png", &req, bf_cb, NULL) == NULL
		&& bf_callbacks == 0;
});

/* The hash of a mirrored URL is not knowable in advance. */
EXO_TEST(seedfetch_start_refused_with_expect_tth, {
	struct seed_ingest_request req;
	memset(&req, 0, sizeof(req));
	req.expect_tth = "OZ4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXAI";
	return seed_fetch_start(bf_cache, &bf_config, "http://cdn.example.org/x.png", &req, bf_cb, NULL) == NULL
		&& bf_callbacks == 0;
});

EXO_TEST(seedfetch_start_refused_bad_scheme, {
	return bf_start("ftp://cdn.example.org/x.png") == NULL
		&& bf_start("file:///etc/passwd") == NULL
		&& bf_start("cdn.example.org/x.png") == NULL
		&& bf_callbacks == 0;
});

EXO_TEST(seedfetch_start_refused_userinfo, {
	return bf_start("http://user:pass@cdn.example.org/x.png") == NULL && bf_callbacks == 0;
});

/* Port outside seed_url_allow_ports ("80,443" by default). */
EXO_TEST(seedfetch_start_refused_port, {
	return bf_start("http://cdn.example.org:8080/x.png") == NULL
		&& bf_start("http://cdn.example.org:22/x.png") == NULL
		&& bf_callbacks == 0;
});

EXO_TEST(seedfetch_start_allows_listed_port, {
	struct seed_fetch* job;
	bf_set(&bf_config.seed_url_allow_ports, "80,443,8080");
	job = bf_start("http://93.184.216.34:8080/x.png");
	if (job)
		seed_fetch_cancel(job);
	bf_set(&bf_config.seed_url_allow_ports, "80,443");
	return job != NULL && bf_callbacks == 0;
});

EXO_TEST(seedfetch_start_refused_denied_host, {
	struct seed_fetch* job;
	bf_set(&bf_config.seed_url_deny_hosts, "internal.example.org");
	/* Suffix match: a subdomain of a denied host is denied too. */
	job = bf_start("http://images.internal.example.org/x.png");
	bf_set(&bf_config.seed_url_deny_hosts, "");
	return job == NULL && bf_callbacks == 0;
});

EXO_TEST(seedfetch_start_refused_not_on_allow_list, {
	struct seed_fetch* job;
	bf_set(&bf_config.seed_url_allow_hosts, "cdn.example.org");
	job = bf_start("http://other.example.net/x.png");
	bf_set(&bf_config.seed_url_allow_hosts, "");
	return job == NULL && bf_callbacks == 0;
});

/*
 * A fetch that passes every up-front check is started and then cancelled while
 * the DNS lookup is still outstanding. The address is a numeric literal, so the
 * resolver touches no network. Cancelling must release the lookup and the
 * handle without ever invoking the callback.
 */
EXO_TEST(seedfetch_cancel_during_dns, {
	struct seed_fetch* job = bf_start("http://93.184.216.34/x.png");
	if (!job)
		return 0;
	seed_fetch_cancel(job);
	net_dns_wait_idle();
	net_dns_process();
	return bf_callbacks == 0;
});

/* Two outstanding fetches cancelled together: neither may deliver. */
EXO_TEST(seedfetch_cancel_two, {
	struct seed_fetch* a = bf_start("http://93.184.216.34/a.png");
	struct seed_fetch* b = bf_start("http://93.184.216.35/b.png");
	if (!a || !b)
		return 0;
	seed_fetch_cancel(a);
	seed_fetch_cancel(b);
	net_dns_wait_idle();
	net_dns_process();
	return bf_callbacks == 0;
});

/*
 * End to end, still without a socket: the host is a literal in TEST-NET-2,
 * which the address policy denies. The lookup completes, every answer is
 * checked, the fetch is refused, and the callback fires exactly once.
 */
EXO_TEST(seedfetch_denied_address_after_resolve, {
	struct seed_fetch* job;
	bf_callbacks = 0;
	job = bf_start("http://198.51.100.7/x.png");
	if (!job)
		return 0;
	net_dns_wait_idle();
	net_dns_process();
	return bf_callbacks == 1;
});

EXO_TEST(seedfetch_cleanup, {
	net_dns_wait_idle();
	net_dns_process();
	seed_cache_close(bf_cache);
	bf_cache = NULL;
	bf_rmtree(BF_DIR);
	seed_config_free(&bf_config);
	return net_destroy() == 0;
});
