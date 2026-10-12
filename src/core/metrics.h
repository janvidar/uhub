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

#ifndef HAVE_UHUB_METRICS_H
#define HAVE_UHUB_METRICS_H

struct hub_info;
struct net_connection;
struct ip_addr_encap;

/**
 * Take ownership of a freshly-probed HTTP connection and answer it: the
 * Prometheus metrics endpoint, or the redirect to http_redirect_addr. The
 * connection has already been accepted and added to the reactor by the probe;
 * this swaps in the HTTP read/write callbacks and drives the request to
 * completion, closing the connection when done.
 *
 * The caller (probe.c) must relinquish ownership of the connection after this
 * call (set its own pointer to NULL) -- the metrics handler now owns it.
 *
 * Only call this when metrics_http_wanted() says so.
 */
extern void metrics_handle_connection(struct hub_info* hub, struct net_connection* con, struct ip_addr_encap* addr);

/**
 * Outcome of classifying a complete metrics HTTP request. Each non-OK value
 * maps to the corresponding HTTP error the handler returns.
 */
enum metrics_result
{
	METRICS_OK = 0,       /* authorized GET for the configured metrics path (-> 200) */
	METRICS_BAD_METHOD,   /* not a GET (-> 405) */
	METRICS_URI_TOO_LONG, /* request-target longer than can be buffered (-> 414) */
	METRICS_NOT_FOUND,    /* path does not match metrics_path (-> 404) */
	METRICS_FORBIDDEN,    /* missing or incorrect bearer token (-> 403) */
	METRICS_REDIRECT,     /* not for the metrics endpoint; send to http_redirect_addr (-> 307) */
};

/**
 * Classify a complete HTTP request against the configured metrics path and
 * token. Pure function: parses the NUL-terminated request text and returns the
 * outcome with no I/O and no global state, so it can be unit-tested directly.
 * `metrics_token` is the expected bearer token (compared length-aware).
 */
extern enum metrics_result metrics_classify_request(const char* req, const char* metrics_path, const char* metrics_token);

/**
 * Route a complete HTTP request on the hub port. With metrics on (non-NULL
 * metrics_token) a request for metrics_path is classified as above; any other
 * request is METRICS_REDIRECT when `redirect` is set, and METRICS_NOT_FOUND --
 * or METRICS_BAD_METHOD, as before -- when it is not. Pure, like
 * metrics_classify_request().
 */
extern enum metrics_result http_classify_request(const char* req, const char* metrics_path, const char* metrics_token, int redirect);

/**
 * Returns 1 if url can go into a Location header and an HTML attribute as it
 * is: http:// or https://, then at least one character and no whitespace,
 * control characters, quotes or angle brackets. The config check says the
 * same, but is skipped on builds without POSIX regex.
 */
extern int http_redirect_valid_url(const char* url);

/**
 * Returns 1 if the hub answers HTTP on its port at all: the metrics endpoint
 * is on (with a token), or http_redirect_addr holds a usable URL.
 */
extern int metrics_http_wanted(struct hub_info* hub);

#endif /* HAVE_UHUB_METRICS_H */
