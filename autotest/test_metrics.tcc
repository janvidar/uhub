#include "system.h"
#include "core/metrics.h"

/*
 * Unit tests for the metrics HTTP request classifier (metrics_classify_request
 * in core/metrics.c). This is the network-facing parser that decides whether an
 * incoming request is a valid, authorized GET for the configured metrics path.
 * The tests drive it directly with crafted request text -- no socket needed --
 * against a fixed path "/metrics" and token "s3cr3t".
 */

#define M_PATH  "/metrics"
#define M_TOKEN "s3cr3t"
#define CLASSIFY(req) metrics_classify_request((req), M_PATH, M_TOKEN)

/* --- happy path ---------------------------------------------------------- */

EXO_TEST(metrics_ok_basic, {
	return CLASSIFY("GET /metrics HTTP/1.1\r\nAuthorization: Bearer s3cr3t\r\n\r\n") == METRICS_OK;
});

/* Query string is stripped before the path is compared. */
EXO_TEST(metrics_ok_query_string, {
	return CLASSIFY("GET /metrics?foo=bar HTTP/1.1\r\nAuthorization: Bearer s3cr3t\r\n\r\n") == METRICS_OK;
});

/* Authorization may be preceded by other headers. */
EXO_TEST(metrics_ok_other_headers_first, {
	return CLASSIFY("GET /metrics HTTP/1.1\r\nHost: hub.example\r\nAccept: */*\r\nAuthorization: Bearer s3cr3t\r\n\r\n") == METRICS_OK;
});

/* Header name and the "Bearer" scheme are matched case-insensitively. */
EXO_TEST(metrics_ok_header_case_insensitive, {
	return CLASSIFY("GET /metrics HTTP/1.1\r\nauthorization: bEaReR s3cr3t\r\n\r\n") == METRICS_OK;
});

/* A tab may separate "Bearer" from the token, with surrounding whitespace. */
EXO_TEST(metrics_ok_tab_and_whitespace, {
	return CLASSIFY("GET /metrics HTTP/1.1\r\nAuthorization:  Bearer\ts3cr3t \r\n\r\n") == METRICS_OK;
});

/* --- method ------------------------------------------------------------- */

EXO_TEST(metrics_bad_method_post, {
	return CLASSIFY("POST /metrics HTTP/1.1\r\nAuthorization: Bearer s3cr3t\r\n\r\n") == METRICS_BAD_METHOD;
});

/* The method check is case-sensitive: only "GET " serves metrics. */
EXO_TEST(metrics_bad_method_lowercase, {
	return CLASSIFY("get /metrics HTTP/1.1\r\nAuthorization: Bearer s3cr3t\r\n\r\n") == METRICS_BAD_METHOD;
});

/* --- path --------------------------------------------------------------- */

EXO_TEST(metrics_not_found_wrong_path, {
	return CLASSIFY("GET /wrong HTTP/1.1\r\nAuthorization: Bearer s3cr3t\r\n\r\n") == METRICS_NOT_FOUND;
});

/* A wrong path is rejected as 404 before any token check. */
EXO_TEST(metrics_not_found_precedes_auth, {
	return CLASSIFY("GET /nope HTTP/1.1\r\n\r\n") == METRICS_NOT_FOUND;
});

EXO_TEST(metrics_uri_too_long, {
	char req[700];
	size_t n = 0;
	memcpy(req, "GET /", 5); n = 5;
	memset(req + n, 'a', 600); n += 600;   /* path far longer than the 512 buffer */
	memcpy(req + n, " HTTP/1.1\r\n\r\n", 13); n += 13;
	req[n] = '\0';
	return CLASSIFY(req) == METRICS_URI_TOO_LONG;
});

/* --- authorization ------------------------------------------------------ */

EXO_TEST(metrics_forbidden_no_auth, {
	return CLASSIFY("GET /metrics HTTP/1.1\r\nHost: hub.example\r\n\r\n") == METRICS_FORBIDDEN;
});

EXO_TEST(metrics_forbidden_wrong_token, {
	return CLASSIFY("GET /metrics HTTP/1.1\r\nAuthorization: Bearer wrong\r\n\r\n") == METRICS_FORBIDDEN;
});

/* Token comparison is length-aware: a prefix of the real token is rejected. */
EXO_TEST(metrics_forbidden_token_prefix, {
	return CLASSIFY("GET /metrics HTTP/1.1\r\nAuthorization: Bearer s3cr\r\n\r\n") == METRICS_FORBIDDEN;
});

/* ...and so is a token that has the real token as a prefix. */
EXO_TEST(metrics_forbidden_token_superstring, {
	return CLASSIFY("GET /metrics HTTP/1.1\r\nAuthorization: Bearer s3cr3tXY\r\n\r\n") == METRICS_FORBIDDEN;
});

/* A non-Bearer scheme is not accepted. */
EXO_TEST(metrics_forbidden_basic_scheme, {
	return CLASSIFY("GET /metrics HTTP/1.1\r\nAuthorization: Basic s3cr3t\r\n\r\n") == METRICS_FORBIDDEN;
});

/* "Bearer" glued to the token (no separator) is not a valid credential. */
EXO_TEST(metrics_forbidden_bearer_no_separator, {
	return CLASSIFY("GET /metrics HTTP/1.1\r\nAuthorization: Bearers3cr3t\r\n\r\n") == METRICS_FORBIDDEN;
});

/* An over-long token (>= the 256-byte scratch buffer) is refused, not truncated. */
EXO_TEST(metrics_forbidden_token_too_long, {
	char req[512];
	size_t n = 0;
	memcpy(req, "GET /metrics HTTP/1.1\r\nAuthorization: Bearer ", 45); n = 45;
	memset(req + n, 'x', 300); n += 300;   /* token far longer than 256 */
	memcpy(req + n, "\r\n\r\n", 4); n += 4;
	req[n] = '\0';
	return CLASSIFY(req) == METRICS_FORBIDDEN;
});
