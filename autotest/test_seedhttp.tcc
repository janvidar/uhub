#include "system.h"

#include <sys/stat.h>
#include <dirent.h>

#include "seeder/http.h"
#include "seeder/cache.h"
#include "util/memory.h"
#include "util/tth.h"

/*
 * Unit tests for the seeder's HTTP request classifier (seed_http_parse_request /
 * seed_http_classify_request in seeder/http.c). This is the network-facing
 * parser that decides whether an incoming request on the seeder's HTTP port asks
 * for a cached file, and which one. The tests drive it directly with crafted
 * request text -- no socket needed.
 *
 * The last few tests stand up a real (empty) seed cache to show that a request
 * the parser happily accepts still resolves to nothing when the TTH is not
 * cached: parsing and lookup are deliberately separate, and both miss the same
 * way.
 */

/* A well formed TTH: exactly 39 characters from the base32 alphabet. */
#define BH_TTH  "OZ4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXAI"
#define BH_TTH2 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

static char bh_tth[TTH_BASE32_LEN + 1];
static uint64_t bh_start;
static uint64_t bh_end;

/* Run the classifier over a NUL terminated request literal. */
static int bh_parse(const char* req)
{
	memset(bh_tth, 0, sizeof(bh_tth));
	bh_start = 12345;
	bh_end = 12345;
	return seed_http_parse_request(req, strlen(req), bh_tth, &bh_start, &bh_end);
}

/* ...and the same, but explicitly length delimited (may contain NUL). */
static int bh_parse_n(const char* req, size_t len)
{
	memset(bh_tth, 0, sizeof(bh_tth));
	bh_start = 12345;
	bh_end = 12345;
	return seed_http_parse_request(req, len, bh_tth, &bh_start, &bh_end);
}

static enum seed_http_result bh_classify(const char* req, struct seed_http_request* out)
{
	return seed_http_classify_request(req, strlen(req), out);
}

/* Build "GET /seed/<path> HTTP/1.1\r\n\r\n" style requests without repetition. */
static const char* bh_req(const char* method, const char* path, const char* headers)
{
	static char buf[512];
	snprintf(buf, sizeof(buf), "%s %s HTTP/1.1\r\nHost: hub.example\r\n%s\r\n", method, path, headers ? headers : "");
	return buf;
}

/* --- happy path ---------------------------------------------------------- */

EXO_TEST(seedhttp_get_valid, {
	return bh_parse("GET /seed/" BH_TTH " HTTP/1.1\r\nHost: hub.example\r\n\r\n") == 1;
});

EXO_TEST(seedhttp_get_valid_extracts_tth, {
	bh_parse("GET /seed/" BH_TTH " HTTP/1.1\r\nHost: hub.example\r\n\r\n");
	return strcmp(bh_tth, BH_TTH) == 0;
});

/* A request with no Range reports the whole entity. */
EXO_TEST(seedhttp_get_valid_no_range, {
	bh_parse("GET /seed/" BH_TTH " HTTP/1.1\r\n\r\n");
	return bh_start == 0 && bh_end == SEED_HTTP_RANGE_NONE;
});

/* A different TTH comes back verbatim, so the extraction is not a fluke. */
EXO_TEST(seedhttp_get_valid_second_tth, {
	bh_parse("GET /seed/" BH_TTH2 " HTTP/1.1\r\n\r\n");
	return strcmp(bh_tth, BH_TTH2) == 0;
});

/* HTTP/1.0 clients are served too. */
EXO_TEST(seedhttp_get_http10, {
	return bh_parse("GET /seed/" BH_TTH " HTTP/1.0\r\n\r\n") == 1;
});

/* A query string cannot change which blob is addressed, so it is ignored. */
EXO_TEST(seedhttp_get_query_string, {
	return bh_parse("GET /seed/" BH_TTH "?v=2 HTTP/1.1\r\n\r\n") == 1;
});

EXO_TEST(seedhttp_get_query_string_extracts_tth, {
	bh_parse("GET /seed/" BH_TTH "?v=2 HTTP/1.1\r\n\r\n");
	return strcmp(bh_tth, BH_TTH) == 0;
});

/* --- method -------------------------------------------------------------- */

EXO_TEST(seedhttp_head_accepted, {
	return bh_parse("HEAD /seed/" BH_TTH " HTTP/1.1\r\n\r\n") == 1;
});

EXO_TEST(seedhttp_head_sets_head_only, {
	struct seed_http_request r;
	bh_classify("HEAD /seed/" BH_TTH " HTTP/1.1\r\n\r\n", &r);
	return r.head_only == 1;
});

EXO_TEST(seedhttp_get_clears_head_only, {
	struct seed_http_request r;
	bh_classify("GET /seed/" BH_TTH " HTTP/1.1\r\n\r\n", &r);
	return r.head_only == 0;
});

EXO_TEST(seedhttp_post_rejected, {
	return bh_parse(bh_req("POST", "/seed/" BH_TTH, NULL)) == 0;
});

EXO_TEST(seedhttp_put_rejected, {
	return bh_parse(bh_req("PUT", "/seed/" BH_TTH, NULL)) == 0;
});

EXO_TEST(seedhttp_delete_rejected, {
	return bh_parse(bh_req("DELETE", "/seed/" BH_TTH, NULL)) == 0;
});

/* A non-GET/HEAD method aimed at /seed/ is ours to refuse with a 405, rather
   than something to pass on to the metrics endpoint. */
EXO_TEST(seedhttp_post_is_bad_method, {
	return bh_classify(bh_req("POST", "/seed/" BH_TTH, NULL), NULL) == SEED_HTTP_BAD_METHOD;
});

/* The method is matched case-sensitively, as HTTP requires. */
EXO_TEST(seedhttp_lowercase_get_rejected, {
	return bh_parse("get /seed/" BH_TTH " HTTP/1.1\r\n\r\n") == 0;
});

/* Anything not under /seed/ is left alone for the metrics endpoint. */
EXO_TEST(seedhttp_metrics_path_not_mine, {
	return bh_classify("GET /metrics HTTP/1.1\r\nAuthorization: Bearer x\r\n\r\n", NULL) == SEED_HTTP_NOT_MINE;
});

EXO_TEST(seedhttp_post_metrics_not_mine, {
	return bh_classify("POST /metrics HTTP/1.1\r\n\r\n", NULL) == SEED_HTTP_NOT_MINE;
});

/* --- TTH shape ----------------------------------------------------------- */

/* 38 characters: one short. */
EXO_TEST(seedhttp_tth_too_short, {
	return bh_parse("GET /seed/OZ4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXA HTTP/1.1\r\n\r\n") == 0;
});

/* 40 characters: one too many. */
EXO_TEST(seedhttp_tth_too_long, {
	return bh_parse("GET /seed/" BH_TTH "A HTTP/1.1\r\n\r\n") == 0;
});

/* '0', '1', '8' and '9' are outside the base32 alphabet. */
EXO_TEST(seedhttp_tth_digit_zero, {
	return bh_parse("GET /seed/0Z4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXAI HTTP/1.1\r\n\r\n") == 0;
});

EXO_TEST(seedhttp_tth_digit_one, {
	return bh_parse("GET /seed/1Z4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXAI HTTP/1.1\r\n\r\n") == 0;
});

EXO_TEST(seedhttp_tth_digit_eight, {
	return bh_parse("GET /seed/8Z4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXAI HTTP/1.1\r\n\r\n") == 0;
});

EXO_TEST(seedhttp_tth_digit_nine, {
	return bh_parse("GET /seed/OZ4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXA9 HTTP/1.1\r\n\r\n") == 0;
});

/* Lowercase is not the same TTH, and must not be folded into one. */
EXO_TEST(seedhttp_tth_lowercase, {
	return bh_parse("GET /seed/oz4v2gdgzlgxqkawxqbdit4km7hrfcwhmlpexai HTTP/1.1\r\n\r\n") == 0;
});

EXO_TEST(seedhttp_tth_mixed_case, {
	return bh_parse("GET /seed/OZ4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXAi HTTP/1.1\r\n\r\n") == 0;
});

/* A malformed TTH is still under /seed/, so it is a 404, not a hand-over. */
EXO_TEST(seedhttp_bad_tth_is_not_found, {
	return bh_classify("GET /seed/oz4v2gdgzlgxqkawxqbdit4km7hrfcwhmlpexai HTTP/1.1\r\n\r\n", NULL) == SEED_HTTP_NOT_FOUND;
});

/* --- path traversal and neighbouring paths -------------------------------- */

EXO_TEST(seedhttp_traversal_dotdot, {
	return bh_parse(bh_req("GET", "/seed/../../etc/passwd", NULL)) == 0;
});

EXO_TEST(seedhttp_traversal_encoded_dotdot, {
	return bh_parse(bh_req("GET", "/seed/%2e%2e/x", NULL)) == 0;
});

/* A traversal that is exactly 39 characters long still fails the alphabet. */
EXO_TEST(seedhttp_traversal_39_chars, {
	return bh_parse(bh_req("GET", "/seed/../../../../../../../../etc/passwd", NULL)) == 0;
});

/* A valid TTH followed by more path is not a valid blob request. */
EXO_TEST(seedhttp_tth_with_trailing_path, {
	return bh_parse(bh_req("GET", "/seed/" BH_TTH "/../../etc/passwd", NULL)) == 0;
});

EXO_TEST(seedhttp_double_slash, {
	return bh_parse(bh_req("GET", "/seed//x", NULL)) == 0;
});

EXO_TEST(seedhttp_wrong_prefix, {
	return bh_parse(bh_req("GET", "/blobx/" BH_TTH, NULL)) == 0;
});

/* "/blobx/..." is not our namespace at all -- the metrics endpoint may have it. */
EXO_TEST(seedhttp_wrong_prefix_not_mine, {
	return bh_classify(bh_req("GET", "/blobx/" BH_TTH, NULL), NULL) == SEED_HTTP_NOT_MINE;
});

EXO_TEST(seedhttp_prefix_without_slash, {
	return bh_classify(bh_req("GET", "/blob", NULL), NULL) == SEED_HTTP_NOT_MINE;
});

EXO_TEST(seedhttp_empty_tth, {
	return bh_parse(bh_req("GET", "/seed/", NULL)) == 0;
});

EXO_TEST(seedhttp_empty_tth_is_not_found, {
	return bh_classify(bh_req("GET", "/seed/", NULL), NULL) == SEED_HTTP_NOT_FOUND;
});

EXO_TEST(seedhttp_root_path, {
	return bh_classify(bh_req("GET", "/", NULL), NULL) == SEED_HTTP_NOT_MINE;
});

/* A leading dot segment does not sneak past the literal prefix compare. */
EXO_TEST(seedhttp_relative_prefix, {
	return bh_classify(bh_req("GET", "/./seed/" BH_TTH, NULL), NULL) == SEED_HTTP_NOT_MINE;
});

/* --- ranges -------------------------------------------------------------- */

EXO_TEST(seedhttp_range_closed, {
	bh_parse(bh_req("GET", "/seed/" BH_TTH, "Range: bytes=0-99\r\n"));
	return bh_start == 0 && bh_end == 99;
});

EXO_TEST(seedhttp_range_closed_offset, {
	bh_parse(bh_req("GET", "/seed/" BH_TTH, "Range: bytes=100-199\r\n"));
	return bh_start == 100 && bh_end == 199;
});

/* Open ended "N-" runs to the end of the entity. */
EXO_TEST(seedhttp_range_open_ended, {
	bh_parse(bh_req("GET", "/seed/" BH_TTH, "Range: bytes=100-\r\n"));
	return bh_start == 100 && bh_end == SEED_HTTP_RANGE_NONE;
});

/* The unit token is case-insensitive. */
EXO_TEST(seedhttp_range_unit_case, {
	bh_parse(bh_req("GET", "/seed/" BH_TTH, "range: BYTES=5-9\r\n"));
	return bh_start == 5 && bh_end == 9;
});

/* Suffix ranges are not supported; ignoring Range is always allowed. */
EXO_TEST(seedhttp_range_suffix_ignored, {
	bh_parse(bh_req("GET", "/seed/" BH_TTH, "Range: bytes=-50\r\n"));
	return bh_start == 0 && bh_end == SEED_HTTP_RANGE_NONE;
});

EXO_TEST(seedhttp_range_malformed_ignored, {
	bh_parse(bh_req("GET", "/seed/" BH_TTH, "Range: bytes=abc\r\n"));
	return bh_start == 0 && bh_end == SEED_HTTP_RANGE_NONE;
});

EXO_TEST(seedhttp_range_no_dash_ignored, {
	bh_parse(bh_req("GET", "/seed/" BH_TTH, "Range: bytes=100\r\n"));
	return bh_start == 0 && bh_end == SEED_HTTP_RANGE_NONE;
});

EXO_TEST(seedhttp_range_wrong_unit_ignored, {
	bh_parse(bh_req("GET", "/seed/" BH_TTH, "Range: items=0-9\r\n"));
	return bh_start == 0 && bh_end == SEED_HTTP_RANGE_NONE;
});

/* Multi ranges would need a multipart response; they are ignored wholesale. */
EXO_TEST(seedhttp_range_multi_ignored, {
	bh_parse(bh_req("GET", "/seed/" BH_TTH, "Range: bytes=0-9,20-29\r\n"));
	return bh_start == 0 && bh_end == SEED_HTTP_RANGE_NONE;
});

/* An inverted range is not a valid range set. */
EXO_TEST(seedhttp_range_inverted_ignored, {
	bh_parse(bh_req("GET", "/seed/" BH_TTH, "Range: bytes=99-0\r\n"));
	return bh_start == 0 && bh_end == SEED_HTTP_RANGE_NONE;
});

/* A range that cannot fit in 64 bits is refused rather than wrapped. */
EXO_TEST(seedhttp_range_overflow_ignored, {
	bh_parse(bh_req("GET", "/seed/" BH_TTH, "Range: bytes=999999999999999999999999-\r\n"));
	return bh_start == 0 && bh_end == SEED_HTTP_RANGE_NONE;
});

/* Whitespace around the value is tolerated. */
EXO_TEST(seedhttp_range_whitespace, {
	bh_parse(bh_req("GET", "/seed/" BH_TTH, "Range:   bytes=7-8  \r\n"));
	return bh_start == 7 && bh_end == 8;
});

/* An ignored range still leaves the request valid. */
EXO_TEST(seedhttp_range_malformed_still_matches, {
	return bh_parse(bh_req("GET", "/seed/" BH_TTH, "Range: bytes=abc\r\n")) == 1;
});

/* --- If-None-Match ------------------------------------------------------- */

EXO_TEST(seedhttp_inm_match, {
	struct seed_http_request r;
	bh_classify(bh_req("GET", "/seed/" BH_TTH, "If-None-Match: \"" BH_TTH "\"\r\n"), &r);
	return r.if_none_match == 1;
});

EXO_TEST(seedhttp_inm_no_match, {
	struct seed_http_request r;
	bh_classify(bh_req("GET", "/seed/" BH_TTH, "If-None-Match: \"" BH_TTH2 "\"\r\n"), &r);
	return r.if_none_match == 0;
});

EXO_TEST(seedhttp_inm_absent, {
	struct seed_http_request r;
	bh_classify(bh_req("GET", "/seed/" BH_TTH, NULL), &r);
	return r.if_none_match == 0;
});

EXO_TEST(seedhttp_inm_wildcard, {
	struct seed_http_request r;
	bh_classify(bh_req("GET", "/seed/" BH_TTH, "If-None-Match: *\r\n"), &r);
	return r.if_none_match == 1;
});

EXO_TEST(seedhttp_inm_weak, {
	struct seed_http_request r;
	bh_classify(bh_req("GET", "/seed/" BH_TTH, "If-None-Match: W/\"" BH_TTH "\"\r\n"), &r);
	return r.if_none_match == 1;
});

EXO_TEST(seedhttp_inm_list, {
	struct seed_http_request r;
	bh_classify(bh_req("GET", "/seed/" BH_TTH, "If-None-Match: \"" BH_TTH2 "\", \"" BH_TTH "\"\r\n"), &r);
	return r.if_none_match == 1;
});

/* The tag must be quoted; a bare token is not an entity tag. */
EXO_TEST(seedhttp_inm_unquoted, {
	struct seed_http_request r;
	bh_classify(bh_req("GET", "/seed/" BH_TTH, "If-None-Match: " BH_TTH "\r\n"), &r);
	return r.if_none_match == 0;
});

EXO_TEST(seedhttp_inm_header_name_case, {
	struct seed_http_request r;
	bh_classify(bh_req("GET", "/seed/" BH_TTH, "if-none-match: \"" BH_TTH "\"\r\n"), &r);
	return r.if_none_match == 1;
});

/* --- malformed and hostile input ----------------------------------------- */

EXO_TEST(seedhttp_empty_string, {
	return bh_parse("") == 0;
});

EXO_TEST(seedhttp_null_pointer, {
	return seed_http_parse_request(NULL, 0, bh_tth, &bh_start, &bh_end) == 0;
});

EXO_TEST(seedhttp_zero_length, {
	return bh_parse_n("GET /seed/" BH_TTH " HTTP/1.1\r\n\r\n", 0) == 0;
});

/* Truncated after the method. */
EXO_TEST(seedhttp_truncated_method, {
	return bh_parse("GET ") == 0;
});

/* Truncated in the middle of the path. */
EXO_TEST(seedhttp_truncated_path, {
	return bh_parse("GET /seed/OZ4V2GDG") == 0;
});

/* Truncated right after a complete TTH: no version, no CRLF. */
EXO_TEST(seedhttp_truncated_after_tth, {
	return bh_parse("GET /seed/" BH_TTH) == 0;
});

/* Truncated inside the version token. */
EXO_TEST(seedhttp_truncated_version, {
	return bh_parse("GET /seed/" BH_TTH " HTTP/1.") == 0;
});

/* A complete request line with no CRLF is not a complete request line. */
EXO_TEST(seedhttp_no_crlf, {
	return bh_parse("GET /seed/" BH_TTH " HTTP/1.1") == 0;
});

/* A bare LF terminator is not HTTP either. */
EXO_TEST(seedhttp_bare_lf, {
	return bh_parse("GET /seed/" BH_TTH " HTTP/1.1\n\n") == 0;
});

/* No version at all (HTTP/0.9 style) is refused. */
EXO_TEST(seedhttp_no_version, {
	return bh_parse("GET /seed/" BH_TTH "\r\n\r\n") == 0;
});

EXO_TEST(seedhttp_bad_version, {
	return bh_parse("GET /seed/" BH_TTH " HTTP/2.0\r\n\r\n") == 0;
});

/* An embedded NUL is never legitimate, and never gets to confuse the parser. */
EXO_TEST(seedhttp_embedded_nul_in_path, {
	char req[128];
	size_t n = 0;
	memcpy(req, "GET /seed/" BH_TTH " HTTP/1.1\r\n\r\n", 10 + TTH_BASE32_LEN + 13);
	n = 10 + TTH_BASE32_LEN + 13;
	req[12] = '\0';
	return bh_parse_n(req, n) == 0;
});

EXO_TEST(seedhttp_embedded_nul_in_headers, {
	char req[256];
	size_t n = 0;
	memcpy(req, "GET /seed/" BH_TTH " HTTP/1.1\r\nX: y\r\n\r\n", 10 + TTH_BASE32_LEN + 19);
	n = 10 + TTH_BASE32_LEN + 19;
	req[n - 5] = '\0'; /* inside the trailing header value */
	return bh_parse_n(req, n) == 0;
});

/* A request larger than the parser is willing to look at is refused outright,
   never truncated into something that happens to parse. */
/* "GET /seed/<tth> HTTP/1.1\r\nX: " -- a valid request line plus an open header
   whose value is then padded out to whatever total length a test wants. */
#define BH_PAD_HEAD "GET /seed/" BH_TTH " HTTP/1.1\r\nX: "

/* Fill req[0..n) with a padded request of exactly n bytes. */
static void bh_padded(char* req, size_t n)
{
	size_t head = strlen(BH_PAD_HEAD);
	memcpy(req, BH_PAD_HEAD, head);
	memset(req + head, 'x', n - head - 4);
	memcpy(req + n - 4, "\r\n\r\n", 4);
}

EXO_TEST(seedhttp_64k_request, {
	size_t n = 64 * 1024;
	char* req = (char*) hub_malloc(n);
	int ok;
	if (!req) return 0;
	bh_padded(req, n);
	ok = (bh_parse_n(req, n) == 0);
	hub_free(req);
	return ok;
});

/* One byte past the cap is refused; the cap itself is honoured exactly. */
EXO_TEST(seedhttp_request_at_cap, {
	char req[SEED_HTTP_REQ_MAX + 8];
	bh_padded(req, SEED_HTTP_REQ_MAX);
	return bh_parse_n(req, SEED_HTTP_REQ_MAX) == 1;
});

EXO_TEST(seedhttp_request_over_cap, {
	char req[SEED_HTTP_REQ_MAX + 8];
	bh_padded(req, SEED_HTTP_REQ_MAX + 1);
	return bh_parse_n(req, SEED_HTTP_REQ_MAX + 1) == 0;
});

/* A long run of header lines does not disturb the request line result. */
EXO_TEST(seedhttp_many_headers, {
	char req[2048];
	size_t n = 0;
	int i;
	n += (size_t) snprintf(req + n, sizeof(req) - n, "GET /seed/%s HTTP/1.1\r\n", BH_TTH);
	for (i = 0; i < 40; i++)
		n += (size_t) snprintf(req + n, sizeof(req) - n, "X-Pad-%d: value\r\n", i);
	n += (size_t) snprintf(req + n, sizeof(req) - n, "Range: bytes=3-4\r\n\r\n");
	return bh_parse_n(req, n) == 1 && bh_start == 3 && bh_end == 4;
});

/* The out parameters are optional. */
EXO_TEST(seedhttp_null_out_params, {
	const char* req = "GET /seed/" BH_TTH " HTTP/1.1\r\n\r\n";
	return seed_http_parse_request(req, strlen(req), NULL, NULL, NULL) == 1;
});

/* A rejected request never writes through the out parameters. */
EXO_TEST(seedhttp_reject_leaves_out_params, {
	bh_parse(bh_req("GET", "/seed/nope", NULL));
	return bh_start == 12345 && bh_end == 12345 && bh_tth[0] == '\0';
});

/* --- a well formed TTH that is not cached --------------------------------- */

#define BH_DIR "test_seedhttp.tmp"

static struct seed_cache* bh_cache = NULL;

static void bh_rmtree(const char* path)
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
			bh_rmtree(child);
		else
			unlink(child);
	}
	closedir(dir);
	rmdir(path);
}

EXO_TEST(seedhttp_store_setup, {
	struct seed_cache_config cfg;

	bh_rmtree(BH_DIR);
	memset(&cfg, 0, sizeof(cfg));
	cfg.dir = BH_DIR;
	cfg.max_bytes = 1024 * 1024;
	cfg.max_file_size = 1024 * 1024;
	cfg.max_entries = 16;
	cfg.max_concurrent_ingest = 4;

	bh_cache = seed_cache_open(&cfg);
	return bh_cache != NULL;
});

/* The parser accepts it, and the cache still has nothing to serve: a cache miss
   and a malformed request are answered the same way on the wire. */
EXO_TEST(seedhttp_uncached_tth_parses, {
	return bh_parse("GET /seed/" BH_TTH " HTTP/1.1\r\n\r\n") == 1;
});

EXO_TEST(seedhttp_uncached_tth_lookup_misses, {
	return seed_cache_peek(bh_cache, bh_tth, NULL) == 0;
});

/* And with no cache configured at all, the same request resolves to nothing. */
EXO_TEST(seedhttp_no_store_lookup_misses, {
	return seed_cache_peek(NULL, BH_TTH, NULL) == 0;
});

/* Nothing is adopted without a cache to serve from, so the caller keeps the
   connection rather than leaking it. */
EXO_TEST(seedhttp_accept_refused_without_cache, {
	struct seed_http_policy policy;
	memset(&policy, 0, sizeof(policy));
	return seed_http_accept(&policy, NULL, NULL) == 0
		&& seed_http_accept(NULL, NULL, NULL) == 0;
});

EXO_TEST(seedhttp_no_uploads_in_flight, {
	return seed_http_active_uploads() == 0;
});

EXO_TEST(seedhttp_store_cleanup, {
	seed_cache_close(bh_cache);
	bh_cache = NULL;
	bh_rmtree(BH_DIR);
	return 1;
});
