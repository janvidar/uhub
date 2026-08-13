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
#include "util/list.h"
#include "util/memory.h"
#include "network/ipcalc.h"
#include "seeder/url.h"

/*
 * The deny table, as CIDR strings.
 *
 * These are handed to ip_convert_address_to_range() rather than built with
 * ip_mask_create_left()/ip_mask_create_right() directly: those two count
 * *trailing zero bits* for AF_INET6 but *leading one bits* for AF_INET, and
 * getting that backwards silently produces a mask of the wrong width (a /32
 * that behaves like a /96). Going through the CIDR parser keeps that quirk in
 * exactly one place, where it is already handled and already tested.
 */
static const char* seed_deny_ranges[] = {
	/* IPv4 */
	"0.0.0.0/8",          /* "this network" */
	"10.0.0.0/8",         /* RFC1918 */
	"100.64.0.0/10",      /* RFC6598 carrier grade NAT */
	"127.0.0.0/8",        /* loopback */
	"169.254.0.0/16",     /* link local - cloud instance metadata lives here */
	"172.16.0.0/12",      /* RFC1918 */
	"192.0.0.0/24",       /* IETF protocol assignments */
	"192.0.2.0/24",       /* TEST-NET-1 */
	"192.88.99.0/24",     /* 6to4 relay anycast */
	"192.168.0.0/16",     /* RFC1918 */
	"198.18.0.0/15",      /* benchmarking */
	"198.51.100.0/24",    /* TEST-NET-2 */
	"203.0.113.0/24",     /* TEST-NET-3 */
	"224.0.0.0/4",        /* multicast */
	"240.0.0.0/4",        /* reserved */
	"255.255.255.255/32", /* limited broadcast */

	/* IPv6 */
	"::/128",             /* unspecified */
	"::1/128",            /* loopback */
	"::ffff:0:0/96",      /* IPv4-mapped - the classic deny-list bypass */
	"64:ff9b::/96",       /* NAT64 */
	"100::/64",           /* discard-only */
	"2001:db8::/32",      /* documentation */
	"2002::/16",          /* 6to4 */
	"fc00::/7",           /* unique local */
	"fe80::/10",          /* link local */
	"ff00::/8",           /* multicast */
};

struct seed_addr_policy
{
	int allow_private;
	struct linked_list* ranges; /* struct ip_range*, empty when allow_private */
};

/* hub_free is a macro, so it cannot be passed to list_clear() directly. */
static void seed_free_range(void* ptr)
{
	hub_free(ptr);
}

struct seed_addr_policy* seed_addr_policy_create(int allow_private)
{
	struct seed_addr_policy* policy;
	size_t n;

	policy = (struct seed_addr_policy*) hub_malloc_zero(sizeof(struct seed_addr_policy));
	if (!policy)
		return NULL;

	policy->allow_private = allow_private;
	policy->ranges = list_create();
	if (!policy->ranges)
	{
		hub_free(policy);
		return NULL;
	}

	if (allow_private)
		return policy;

	for (n = 0; n < (sizeof(seed_deny_ranges) / sizeof(seed_deny_ranges[0])); n++)
	{
		struct ip_range* range = (struct ip_range*) hub_malloc_zero(sizeof(struct ip_range));
		if (!range)
		{
			seed_addr_policy_destroy(policy);
			return NULL;
		}

		if (!ip_convert_address_to_range(seed_deny_ranges[n], range))
		{
			/* A typo in the table above would silently open a hole; fail closed. */
			hub_free(range);
			seed_addr_policy_destroy(policy);
			return NULL;
		}
		list_append(policy->ranges, range);
	}

	return policy;
}

void seed_addr_policy_destroy(struct seed_addr_policy* policy)
{
	if (!policy)
		return;

	if (policy->ranges)
	{
		list_clear(policy->ranges, &seed_free_range);
		list_destroy(policy->ranges);
	}
	hub_free(policy);
}

int seed_addr_is_permitted(struct seed_addr_policy* policy, const struct ip_addr_encap* addr)
{
	struct ip_addr_encap probe;
	struct ip_range* range;
	struct node* cursor = NULL;

	if (!policy || !addr)
		return 0;

	if (policy->allow_private)
		return 1;

	/* ip_in_range() takes a non-const address. */
	memcpy(&probe, addr, sizeof(probe));

	LIST_FOREACH_SAFE(struct ip_range*, range, policy->ranges, cursor,
	{
		if (ip_in_range(&probe, range))
			return 0;
	});

	return 1;
}

const char* seed_url_error_string(enum seed_url_error err)
{
	switch (err)
	{
		case SEED_URL_OK:            return "ok";
		case SEED_URL_ERR_SCHEME:    return "unsupported scheme";
		case SEED_URL_ERR_SYNTAX:    return "malformed url";
		case SEED_URL_ERR_USERINFO:  return "credentials in url";
		case SEED_URL_ERR_PORT:      return "port not allowed";
		case SEED_URL_ERR_TOO_LONG:  return "url too long";
	}
	return "unknown error";
}

static int seed_is_digit(char c)
{
	return (c >= '0' && c <= '9');
}

static int seed_is_alnum(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || seed_is_digit(c);
}

/* Characters permitted in a registered name. Deliberately excludes '%': a
 * percent-encoded host is a well known way of smuggling one host past a filter
 * and having the resolver see another. */
static int seed_is_host_char(char c)
{
	return seed_is_alnum(c) || c == '-' || c == '.';
}

static char seed_lower(char c)
{
	return (c >= 'A' && c <= 'Z') ? (char) (c - 'A' + 'a') : c;
}

/* True when the list holds no port at all, in which case any port is allowed. */
static int seed_port_list_is_empty(const char* list)
{
	if (!list)
		return 1;
	while (*list)
	{
		if (*list != ',' && *list != ' ' && *list != '\t')
			return 0;
		list++;
	}
	return 1;
}

static int seed_port_in_list(uint16_t port, const char* list)
{
	const char* p = list;

	while (*p)
	{
		unsigned long value = 0;
		int digits = 0;

		while (*p == ',' || *p == ' ' || *p == '\t')
			p++;

		while (seed_is_digit(*p))
		{
			if (digits < 6)
				value = (value * 10) + (unsigned long) (*p - '0');
			digits++;
			p++;
		}

		while (*p == ' ' || *p == '\t')
			p++;

		/* Only a run of digits that reaches a separator is an entry; "80x" is not. */
		if (digits > 0 && digits <= 5 && (*p == ',' || *p == '\0') && value == (unsigned long) port)
			return 1;

		while (*p && *p != ',')
			p++;
	}
	return 0;
}

/*
 * Validate a bracketed IPv6 literal. The character check comes first so that
 * only something already shaped like an address reaches the resolver-backed
 * validator.
 */
static int seed_host_is_ipv6_literal(const char* host)
{
	size_t n;
	int colons = 0;

	for (n = 0; host[n]; n++)
	{
		char c = host[n];
		if (c == ':')
			colons++;
		else if (!seed_is_digit(c) && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') && c != '.')
			return 0;
	}

	if (n == 0 || colons == 0)
		return 0;

	return ip_is_valid_ipv6(host);
}

/*
 * Validate a registered name (or an IPv4 literal, which is a subset of the
 * same character set). A leading or trailing '.' and an empty label are all
 * rejected: "example.com." resolves the same as "example.com" but would slip
 * past a suffix based allow list.
 */
static int seed_host_is_valid_name(const char* host, size_t len)
{
	size_t n;

	if (len == 0)
		return 0;

	if (!seed_is_alnum(host[0]) || !seed_is_alnum(host[len - 1]))
		return 0;

	for (n = 0; n < len; n++)
	{
		if (!seed_is_host_char(host[n]))
			return 0;
		if (n > 0 && host[n] == '.' && host[n - 1] == '.')
			return 0;
	}
	return 1;
}

enum seed_url_error seed_url_parse(const char* url, const char* allow_ports, struct seed_url* out)
{
	const char* p;
	const char* auth_end;
	const char* host_start;
	const char* host_end;
	const char* port_start = NULL;
	const char* path_start;
	const char* path_end;
	size_t len, host_len, path_len, n;
	unsigned long port_value;
	int digits;
	int tls;
	uint16_t port;

	if (!url || !out)
		return SEED_URL_ERR_SYNTAX;

	memset(out, 0, sizeof(*out));

	len = strlen(url);
	if (len > SEED_URL_MAX_LEN)
		return SEED_URL_ERR_TOO_LONG;

	/*
	 * Reject control characters, whitespace and non-ASCII anywhere in the
	 * URL. An embedded NUL cannot be observed through a const char*, but it
	 * terminates the scan below, so no byte past it can reach *out.
	 */
	for (n = 0; n < len; n++)
	{
		unsigned char c = (unsigned char) url[n];
		if (c <= 0x20 || c >= 0x7f)
			return SEED_URL_ERR_SYNTAX;
	}

	if (!strncasecmp(url, "https://", 8))
	{
		tls = 1;
		port = 443;
		p = url + 8;
	}
	else if (!strncasecmp(url, "http://", 7))
	{
		tls = 0;
		port = 80;
		p = url + 7;
	}
	else
		return SEED_URL_ERR_SCHEME;

	/* The authority runs until the first '/', '?' or '#', or the end. */
	auth_end = p;
	while (*auth_end && *auth_end != '/' && *auth_end != '?' && *auth_end != '#')
		auth_end++;

	if (memchr(p, '@', (size_t) (auth_end - p)))
		return SEED_URL_ERR_USERINFO;

	if (*p == '[')
	{
		host_start = p + 1;
		host_end = (const char*) memchr(host_start, ']', (size_t) (auth_end - host_start));
		if (!host_end)
			return SEED_URL_ERR_SYNTAX;

		if (host_end + 1 == auth_end)
			port_start = NULL;
		else if (host_end[1] == ':')
			port_start = host_end + 2;
		else
			return SEED_URL_ERR_SYNTAX; /* junk between ']' and the port */
	}
	else
	{
		host_start = p;
		host_end = p;
		while (host_end < auth_end && *host_end != ':')
			host_end++;
		port_start = (host_end < auth_end) ? host_end + 1 : NULL;
	}

	host_len = (size_t) (host_end - host_start);
	if (host_len == 0)
		return SEED_URL_ERR_SYNTAX;
	if (host_len >= sizeof(out->host))
		return SEED_URL_ERR_TOO_LONG;

	memcpy(out->host, host_start, host_len);
	out->host[host_len] = '\0';
	for (n = 0; n < host_len; n++)
		out->host[n] = seed_lower(out->host[n]);

	if (host_start != p)
	{
		/* Bracketed: must be an IPv6 literal, nothing else. */
		if (!seed_host_is_ipv6_literal(out->host))
		{
			memset(out, 0, sizeof(*out));
			return SEED_URL_ERR_SYNTAX;
		}
	}
	else if (!seed_host_is_valid_name(out->host, host_len))
	{
		memset(out, 0, sizeof(*out));
		return SEED_URL_ERR_SYNTAX;
	}

	if (port_start)
	{
		port_value = 0;
		digits = 0;
		for (p = port_start; p < auth_end; p++)
		{
			if (!seed_is_digit(*p))
			{
				memset(out, 0, sizeof(*out));
				return SEED_URL_ERR_PORT;
			}
			if (digits < 6)
				port_value = (port_value * 10) + (unsigned long) (*p - '0');
			digits++;
		}

		if (digits == 0 || digits > 5 || port_value < 1 || port_value > 65535)
		{
			memset(out, 0, sizeof(*out));
			return SEED_URL_ERR_PORT;
		}
		port = (uint16_t) port_value;
	}

	/*
	 * The port allow list is applied to the effective port, the implicit 80
	 * and 443 included. Checking only explicit ports would let
	 * "http://internal/" through a list of "443".
	 */
	if (!seed_port_list_is_empty(allow_ports) && !seed_port_in_list(port, allow_ports))
	{
		memset(out, 0, sizeof(*out));
		return SEED_URL_ERR_PORT;
	}

	out->tls = tls;
	out->port = port;

	if (*auth_end == '\0' || *auth_end == '#')
	{
		out->path[0] = '/';
		out->path[1] = '\0';
		return SEED_URL_OK;
	}

	path_start = auth_end;
	path_end = (const char*) strchr(path_start, '#');
	if (!path_end)
		path_end = url + len;
	path_len = (size_t) (path_end - path_start);

	if (*path_start == '?')
	{
		/* A query with no path: "http://host?q" is "/?q". */
		if (path_len + 1 >= sizeof(out->path))
		{
			memset(out, 0, sizeof(*out));
			return SEED_URL_ERR_TOO_LONG;
		}
		out->path[0] = '/';
		memcpy(out->path + 1, path_start, path_len);
		out->path[path_len + 1] = '\0';
	}
	else
	{
		if (path_len >= sizeof(out->path))
		{
			memset(out, 0, sizeof(*out));
			return SEED_URL_ERR_TOO_LONG;
		}
		memcpy(out->path, path_start, path_len);
		out->path[path_len] = '\0';
	}

	return SEED_URL_OK;
}

int seed_url_redirect_ok(const struct seed_url* from, const struct seed_url* to, int hop, int max_redirects)
{
	if (!from || !to)
		return 0;

	if (hop < 0 || max_redirects <= 0 || hop >= max_redirects)
		return 0;

	/* Never fall out of TLS; http -> https is fine. */
	if (from->tls && !to->tls)
		return 0;

	if (from->tls == to->tls &&
		from->port == to->port &&
		strcasecmp(from->host, to->host) == 0 &&
		strcmp(from->path, to->path) == 0)
		return 0;

	return 1;
}

int seed_host_matches_list(const char* host, const char* list)
{
	size_t host_len;
	const char* p;

	if (!host || !list)
		return 0;

	host_len = strlen(host);
	if (host_len == 0)
		return 0;

	p = list;
	while (*p)
	{
		const char* entry;
		size_t entry_len;

		while (*p == ',' || *p == ' ' || *p == '\t')
			p++;

		entry = p;
		while (*p && *p != ',')
			p++;
		entry_len = (size_t) (p - entry);

		/* Trim trailing whitespace, and a leading dot as in ".example.com". */
		while (entry_len > 0 && (entry[entry_len - 1] == ' ' || entry[entry_len - 1] == '\t'))
			entry_len--;
		while (entry_len > 0 && entry[0] == '.')
		{
			entry++;
			entry_len--;
		}

		if (entry_len == 0)
			continue;

		if (entry_len == host_len && strncasecmp(host, entry, entry_len) == 0)
			return 1;

		/* Suffix match, but only on a label boundary: "example.com" must not
		 * match "notexample.com". */
		if (host_len > entry_len &&
			host[host_len - entry_len - 1] == '.' &&
			strncasecmp(host + (host_len - entry_len), entry, entry_len) == 0)
			return 1;
	}

	return 0;
}
