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
#include "util/log.h"
#include "util/memory.h"
#include "adc/message.h"
#include "network/connection.h"
#include "network/tls.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/regserver.h"
#include "uhub_limits.h"

/* Maximum number of response bytes we read; we only need the HTTP status line. */
#define REGSERVER_RESPONSE_MAX 512

/*
 * State for a single in-flight registration announce. Exactly one of these
 * exists per hub at a time, stored in hub->regserver while the POST is pending.
 */
struct regserver
{
	struct hub_info* hub;
	struct regserver_url url;

	struct net_connect_handle* connect_job; /* non-NULL only before connect completes */
	struct net_connection* con;             /* non-NULL once connected */
	struct ssl_context_handle* ssl_ctx;     /* dedicated client TLS context (https only) */

	char* request;       /* full HTTP request (headers + IINF body) */
	size_t request_len;
	size_t sent;         /* bytes of request already written */

	char response[REGSERVER_RESPONSE_MAX]; /* bounded; holds at least the status line */
	size_t recv_len;
};

int regserver_parse_url(const char* url, struct regserver_url* out)
{
	const char* p = url;
	const char* host_start;
	const char* host_end;
	size_t host_len;
	size_t path_len;

	if (!url || !out)
		return 0;

	memset(out, 0, sizeof(*out));

	if (!strncasecmp(p, "http://", 7))
	{
		out->use_tls = 0;
		out->port = 80;
		p += 7;
	}
	else if (!strncasecmp(p, "https://", 8))
	{
		out->use_tls = 1;
		out->port = 443;
		p += 8;
	}
	else
		return 0;

	/* Host: a bracketed IPv6 literal, or everything up to ':', '/' or end. */
	if (*p == '[')
	{
		host_start = ++p;
		host_end = strchr(p, ']');
		if (!host_end)
			return 0;
		p = host_end + 1;
	}
	else
	{
		host_start = p;
		while (*p && *p != ':' && *p != '/')
			p++;
		host_end = p;
	}

	host_len = (size_t) (host_end - host_start);
	if (host_len == 0 || host_len >= sizeof(out->host))
		return 0;
	memcpy(out->host, host_start, host_len);
	out->host[host_len] = '\0';

	/* Optional ":port". */
	if (*p == ':')
	{
		char* end = NULL;
		long port;
		p++;
		port = strtol(p, &end, 10);
		if (end == p || port < 1 || port > 65535)
			return 0;
		out->port = (uint16_t) port;
		p = end;
	}

	/* Path: the rest of the string, or "/register" when absent. */
	if (*p == '\0')
	{
		memcpy(out->path, "/register", sizeof("/register"));
		return 1;
	}

	if (*p != '/')
		return 0; /* unexpected junk after host[:port] */

	path_len = strlen(p);
	if (path_len >= sizeof(out->path))
		return 0;
	memcpy(out->path, p, path_len + 1);
	return 1;
}

/* True if a "host[:port]" string already carries a ":port", accounting for a
 * bracketed IPv6 literal where the colons inside the brackets are not a port. */
static int hostport_has_port(const char* hostport)
{
	if (*hostport == '[')
	{
		const char* close = strchr(hostport, ']');
		return close && close[1] == ':';
	}
	return strchr(hostport, ':') != NULL;
}

int regserver_hub_url(const char* hub_address, int use_tls, int server_port, char* out, size_t out_size)
{
	const char* scheme;
	const char* hostport;
	char portbuf[8];
	int n;

	if (!hub_address || !*hub_address || !out || out_size == 0)
		return 0;

	if (!strncasecmp(hub_address, "adc://", 6))
	{
		scheme = "adc://";
		hostport = hub_address + 6;
	}
	else if (!strncasecmp(hub_address, "adcs://", 7))
	{
		scheme = "adcs://";
		hostport = hub_address + 7;
	}
	else if (strstr(hub_address, "://"))
	{
		/* Some other scheme (http://, dchub://, ...) was configured; an ADC
		 * registration must advertise an adc:// or adcs:// URL, so refuse. */
		return 0;
	}
	else
	{
		scheme = use_tls ? "adcs://" : "adc://";
		hostport = hub_address;
	}

	if (!*hostport)
		return 0; /* scheme but no host */

	portbuf[0] = '\0';
	if (!hostport_has_port(hostport))
	{
		if (server_port < 1 || server_port > 65535)
			return 0;
		snprintf(portbuf, sizeof(portbuf), ":%d", server_port);
	}

	n = snprintf(out, out_size, "%s%s%s", scheme, hostport, portbuf);
	if (n < 0 || (size_t) n >= out_size)
		return 0;
	return 1;
}

/*
 * Build the raw IINF line submitted as the POST body. This reuses the hub's
 * static info command (CT/AP/VE/NI/DE) and appends the descriptive HH/WS/NE/OW
 * fields. The HH hub address is normalized to a complete adc:// or adcs:// URL
 * with a port (see regserver_hub_url) so the registration server gets a
 * reachable address. Live counters (UC/SS/SF) are deliberately omitted: they
 * are zero at startup and the hub list's pinger gathers them later. Returns a
 * NUL-terminated string (caller frees) or NULL.
 */
static char* regserver_build_payload(struct hub_info* hub)
{
	struct adc_message* info = adc_msg_copy(hub->command_info);
	char* body;
	size_t len;

	if (!info)
		return NULL;

	{
		char hh[256 + 8];
		if (regserver_hub_url(hub->config->hub_address, hub->config->tls_enable,
				hub->config->server_port, hh, sizeof(hh)))
			adc_msg_add_named_argument_string(info, "HH", hh);
	}
	if (*hub->config->hub_website)
		adc_msg_add_named_argument_string(info, "WS", hub->config->hub_website);
	if (*hub->config->hub_network)
		adc_msg_add_named_argument_string(info, "NE", hub->config->hub_network);
	if (*hub->config->hub_owner)
		adc_msg_add_named_argument_string(info, "OW", hub->config->hub_owner);

	/* info->cache is the serialized "IINF ...\n" line; strip trailing EOL. */
	len = info->length;
	while (len > 0 && (info->cache[len - 1] == '\n' || info->cache[len - 1] == '\r'))
		len--;

	body = hub_malloc(len + 1);
	if (body)
	{
		memcpy(body, info->cache, len);
		body[len] = '\0';
	}
	adc_msg_free(info);
	return body;
}

/* Build the full HTTP/1.1 request. Returns malloc'd buffer (caller frees) or NULL. */
static char* regserver_build_request(struct regserver* rs, const char* body, size_t* out_len)
{
	size_t body_len = strlen(body);
	size_t cap = strlen(rs->url.path) + strlen(rs->url.host) + body_len + 256;
	char* req = hub_malloc(cap);
	int n;

	if (!req)
		return NULL;

	n = snprintf(req, cap,
		"POST %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: " PRODUCT_STRING "\r\n"
		"Content-Type: text/plain\r\n"
		"Content-Length: %zu\r\n"
		"Connection: close\r\n"
		"\r\n"
		"%s",
		rs->url.path, rs->url.host, body_len, body);

	if (n < 0 || (size_t) n >= cap)
	{
		hub_free(req);
		return NULL;
	}
	*out_len = (size_t) n;
	return req;
}

/* Tear down all state and clear hub->regserver. Safe to call once per announce. */
static void regserver_finish(struct regserver* rs)
{
	struct hub_info* hub = rs->hub;

	if (rs->connect_job)
	{
		net_connect_destroy(rs->connect_job);
		rs->connect_job = NULL;
	}
	if (rs->con)
	{
		net_con_close(rs->con);
		rs->con = NULL;
	}
	if (rs->ssl_ctx)
	{
		/* Safe even with an SSL object still referencing it: OpenSSL refcounts
		 * the context, so it is not really freed until the connection's SSL is. */
		net_ssl_context_destroy(rs->ssl_ctx);
		rs->ssl_ctx = NULL;
	}
	hub_free(rs->request);
	hub_free(rs);

	if (hub)
		hub->regserver = NULL;
}

/* True if the buffered response carries an "HTTP/1.x 202 ..." status line. */
static int regserver_response_is_accepted(const char* resp)
{
	const char* sp;
	if (strncmp(resp, "HTTP/1.", 7) != 0)
		return 0;
	sp = strchr(resp, ' ');
	if (!sp)
		return 0;
	return strncmp(sp + 1, "202", 3) == 0;
}

static void regserver_io_cb(struct net_connection* con, int events, void* ptr)
{
	struct regserver* rs = (struct regserver*) ptr;

	if (events & (NET_EVENT_TIMEOUT | NET_EVENT_ERROR))
	{
		/* If the peer closed after replying we may already hold the status
		 * line; otherwise treat it as a failed registration. */
		rs->response[rs->recv_len] = '\0';
		if (rs->recv_len && rs->sent == rs->request_len)
			LOG_INFO("regserver: %s response from %s:%u.",
				regserver_response_is_accepted(rs->response) ? "accepted (202)" : "rejected",
				rs->url.host, (unsigned) rs->url.port);
		else
			LOG_WARN("regserver: registration to %s:%u failed (no response).",
				rs->url.host, (unsigned) rs->url.port);
		regserver_finish(rs);
		return;
	}

	/* Phase 1: write the request. Driven by either a WRITE event (plain TCP)
	 * or the READ event the TLS layer raises once the handshake completes. */
	if (rs->sent < rs->request_len)
	{
		while (rs->sent < rs->request_len)
		{
			ssize_t r = net_con_send(con, rs->request + rs->sent, rs->request_len - rs->sent);
			if (r > 0)
			{
				rs->sent += (size_t) r;
				continue;
			}
			if (r == 0)
			{
				net_con_update(con, NET_EVENT_WRITE); /* would block; retry on writable */
				return;
			}
			LOG_WARN("regserver: failed sending request to %s:%u.",
				rs->url.host, (unsigned) rs->url.port);
			regserver_finish(rs);
			return;
		}
		net_con_update(con, NET_EVENT_READ);
		return;
	}

	/* Phase 2: read the response status line. */
	if (events & NET_EVENT_READ)
	{
		while (rs->recv_len < sizeof(rs->response) - 1)
		{
			ssize_t r = net_con_recv(con, rs->response + rs->recv_len,
				sizeof(rs->response) - 1 - rs->recv_len);
			if (r > 0)
			{
				rs->recv_len += (size_t) r;
				continue;
			}
			if (r == 0)
			{
				/* Would block: wait for more unless we already have a line. */
				if (memchr(rs->response, '\n', rs->recv_len))
					break;
				return;
			}
			break; /* connection closed/error: evaluate what we have */
		}

		rs->response[rs->recv_len] = '\0';
		LOG_INFO("regserver: %s response from %s:%u.",
			regserver_response_is_accepted(rs->response) ? "accepted (202)" : "rejected",
			rs->url.host, (unsigned) rs->url.port);
		regserver_finish(rs);
	}
}

static void regserver_connect_cb(struct net_connect_handle* handle, enum net_connect_status status, struct net_connection* con, void* ptr)
{
	struct regserver* rs = (struct regserver*) ptr;
	rs->connect_job = NULL; /* the handle auto-destroys after this callback returns */

	if (status != net_connect_status_ok)
	{
		LOG_WARN("regserver: could not connect to %s:%u (status %d); hub not registered.",
			rs->url.host, (unsigned) rs->url.port, (int) status);
		regserver_finish(rs);
		return;
	}

	rs->con = con;
	net_con_reinitialize(con, regserver_io_cb, rs, NET_EVENT_WRITE);
	net_con_set_timeout(con, TIMEOUT_CONNECTED);

	if (rs->url.use_tls)
	{
		net_con_update(con, NET_EVENT_READ | NET_EVENT_WRITE);
		net_con_ssl_handshake(con, net_con_ssl_mode_client, rs->ssl_ctx);
	}
}

void regserver_announce(struct hub_info* hub)
{
	struct regserver* rs;
	char* body;

	if (!hub->config->reg_server_url || !*hub->config->reg_server_url)
		return; /* disabled: no URL configured */

	if (hub->regserver)
		return; /* an announce is already in flight */

	rs = hub_malloc_zero(sizeof(struct regserver));
	if (!rs)
		return;
	rs->hub = hub;

	if (!regserver_parse_url(hub->config->reg_server_url, &rs->url))
	{
		LOG_ERROR("regserver: invalid reg_server_url \"%s\"; expected http(s)://host[:port][/path].",
			hub->config->reg_server_url);
		hub_free(rs);
		return;
	}

	body = regserver_build_payload(hub);
	if (!body)
	{
		hub_free(rs);
		return; /* OOM */
	}

	rs->request = regserver_build_request(rs, body, &rs->request_len);
	hub_free(body);
	if (!rs->request)
	{
		hub_free(rs);
		return; /* OOM */
	}

	hub->regserver = rs;

	/* https needs a client TLS context. Create a dedicated one rather than
	 * reusing hub->ctx, which only exists when inbound tls_enable is set. */
	if (rs->url.use_tls)
	{
		rs->ssl_ctx = net_ssl_context_create(hub->config->tls_version,
			hub->config->tls_ciphersuite, hub->config->tls_ciphersuites);
		if (!rs->ssl_ctx)
		{
			LOG_ERROR("regserver: could not create TLS client context; hub not registered.");
			regserver_finish(rs);
			return;
		}
	}

	LOG_INFO("regserver: announcing hub to %s://%s:%u%s",
		rs->url.use_tls ? "https" : "http", rs->url.host, (unsigned) rs->url.port, rs->url.path);

	rs->connect_job = net_con_connect(rs->url.host, rs->url.port, regserver_connect_cb, rs);
	if (!rs->connect_job)
	{
		LOG_WARN("regserver: could not start connection to %s:%u; hub not registered.",
			rs->url.host, (unsigned) rs->url.port);
		regserver_finish(rs);
	}
}

void regserver_cleanup(struct hub_info* hub)
{
	if (hub->regserver)
		regserver_finish(hub->regserver);
}
