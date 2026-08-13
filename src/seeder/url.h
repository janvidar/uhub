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
 * SSRF defence for the hub-seeded blob fetcher.
 *
 * When the hub fetches a URL that some user typed into chat, the attacker
 * chooses the destination. This file provides the two pure checks that stand
 * between that string and a socket:
 *
 *   1. seed_url_parse()        - a deliberately narrow URL parser.
 *   2. seed_addr_is_permitted() - a deny table for the addresses a fetch may
 *                                 not reach (loopback, RFC1918, link-local and
 *                                 in particular 169.254.169.254).
 *
 * Neither performs any I/O, name resolution included: the address check takes
 * an already-resolved address so the caller can re-run it on every address a
 * name resolves to, and again on every redirect hop. Nothing here is safe to
 * skip because "the hostname looked fine" - DNS rebinding means the name says
 * nothing about the address.
 */

#ifndef HAVE_UHUB_SEEDER_URL_H
#define HAVE_UHUB_SEEDER_URL_H

#include "system.h"
#include "network/ipcalc.h"

enum seed_url_error
{
	SEED_URL_OK = 0,
	SEED_URL_ERR_SCHEME,      /* not http/https */
	SEED_URL_ERR_SYNTAX,      /* malformed */
	SEED_URL_ERR_USERINFO,    /* credentials embedded in the URL */
	SEED_URL_ERR_PORT,        /* port not in the allowed set */
	SEED_URL_ERR_TOO_LONG,
};

#define SEED_URL_MAX_LEN  2048
#define SEED_URL_MAX_HOST 256
#define SEED_URL_MAX_PATH 1024

struct seed_url
{
	int      tls;                        /* 1 for https */
	char     host[SEED_URL_MAX_HOST];    /* no brackets for IPv6 literals, lowercased */
	uint16_t port;
	char     path[SEED_URL_MAX_PATH];    /* always begins with '/' */
};

/**
 * Parse and validate a URL.
 *
 * Accepts only "http://" and "https://" (case insensitive). Everything else -
 * "file:", "gopher:", "data:", a scheme relative "//host/path", or a bare
 * hostname - is rejected. Userinfo ("user:pass@host") is rejected outright
 * rather than ignored, since it is the classic way of making a URL appear to
 * point somewhere it does not.
 *
 * The host is copied without its brackets for an IPv6 literal, and lowercased,
 * so that it can be compared directly against an allow/deny list. Control
 * characters, whitespace and non-ASCII bytes are rejected anywhere in the URL.
 * A missing path becomes "/", a query string is preserved and a "#fragment" is
 * stripped.
 *
 * @param url          NUL terminated URL. Note that a C string cannot carry an
 *                     embedded NUL: parsing stops there, and no byte past it
 *                     can reach the output.
 * @param allow_ports  Comma separated list of permitted ports, e.g. "80,443".
 *                     NULL or empty permits any port. Unlike some other
 *                     implementations this is applied to the *effective* port,
 *                     so an implicit 80 or 443 is checked as well.
 * @param out          Filled in only on success; zeroed on entry regardless.
 *
 * @return SEED_URL_OK on success, otherwise the reason for rejection.
 */
extern enum seed_url_error seed_url_parse(const char* url, const char* allow_ports, struct seed_url* out);

/** Human readable name for an error, for logging. */
extern const char* seed_url_error_string(enum seed_url_error err);

struct seed_addr_policy;

/**
 * Build the deny table.
 *
 * @param allow_private  When non-zero the operator has opted out and every
 *                       address is permitted. When zero the loopback, private,
 *                       link-local, CGNAT, documentation, multicast and
 *                       reserved ranges are denied, for both IPv4 and IPv6,
 *                       including the IPv4-mapped IPv6 form of each.
 * @return NULL on allocation failure.
 */
extern struct seed_addr_policy* seed_addr_policy_create(int allow_private);

extern void seed_addr_policy_destroy(struct seed_addr_policy*);

/**
 * @return 1 if the hub may connect to this address, 0 if it must refuse.
 *         A NULL policy or address returns 0: this check fails closed.
 */
extern int seed_addr_is_permitted(struct seed_addr_policy*, const struct ip_addr_encap* addr);

/**
 * Check a redirect target. @return 1 if the hop is allowed.
 * Refuses: hop >= max_redirects, https->http downgrade, and a target identical
 * to the source.
 */
extern int seed_url_redirect_ok(const struct seed_url* from, const struct seed_url* to, int hop, int max_redirects);

/**
 * Suffix match for the allow/deny host lists. "example.com" matches
 * "a.example.com" but NOT "notexample.com". Matching is case insensitive; an
 * empty or NULL list matches nothing.
 */
extern int seed_host_matches_list(const char* host, const char* list);

#endif /* HAVE_UHUB_SEEDER_URL_H */
