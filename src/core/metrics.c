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
#include "util/cbuffer.h"
#include "util/list.h"
#include "network/connection.h"
#include "network/network.h"
#include "network/ipcalc.h"
#include "adc/adcconst.h"
#include "adc/message.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/user.h"
#include "core/usermanager.h"
#include "core/ioqueue.h"
#include "core/metrics.h"

/* Hard cap on the request bytes we are willing to buffer before giving up. The
   metrics endpoint only ever needs the request line plus a small header block,
   so anything beyond this is malformed or hostile. */
#define METRICS_REQ_MAX 4096

/* How long (seconds) a metrics client may take to send a complete request or
   receive the response before we drop it. */
#define METRICS_TIMEOUT 10

enum metrics_phase
{
	METRICS_PHASE_READ,   /* still accumulating the HTTP request */
	METRICS_PHASE_WRITE,  /* draining the prepared response */
};

struct metrics_connection
{
	struct hub_info* hub;
	struct net_connection* connection;
	struct ip_addr_encap addr;
	enum metrics_phase phase;
	size_t req_len;                  /* bytes accumulated in req */
	char req[METRICS_REQ_MAX + 1];   /* request accumulator, always NUL-terminated */
	struct cbuffer* response;        /* full HTTP response, built once */
	size_t resp_sent;                /* bytes of response already written */
};

static void metrics_destroy(struct metrics_connection* m)
{
	LOG_TRACE("metrics_destroy(): %p", m);
	if (m->connection)
	{
		net_con_close(m->connection);
		m->connection = NULL;
	}
	if (m->response)
	{
		cbuf_destroy(m->response);
		m->response = NULL;
	}
	hub_free(m);
}

/*
 * Length-aware comparison that does not short-circuit on the first differing
 * byte of equal-length inputs, so the configured token is not trivially
 * recoverable by timing the response. (Lengths may differ in timing; the token
 * length is not the secret.)
 */
static int token_equal(const char* a, const char* b)
{
	size_t la = strlen(a);
	size_t lb = strlen(b);
	size_t n = (la < lb) ? la : lb;
	size_t i;
	unsigned char diff = (unsigned char) (la != lb);
	for (i = 0; i < n; i++)
		diff |= (unsigned char) (a[i] ^ b[i]);
	return diff == 0;
}

/*
 * Build the Prometheus text-exposition body. Everything here is read straight
 * from the existing hub/network counters except the metrics.* counters added
 * for this endpoint. The connection is plain or TLS transparently -- net_con_*
 * handles the encryption, so this code is unaware of which transport is in use.
 */
static void metrics_build_body(struct hub_info* hub, struct cbuffer* body)
{
	struct net_statistics* intermediate = NULL;
	struct net_statistics* total = NULL;
	size_t uptime = (size_t) difftime(time(0), hub->tm_started);

	net_stats_get(&intermediate, &total);

#define METRIC(name, type, help) \
	cbuf_append(body, "# HELP " name " " help "\n# TYPE " name " " type "\n")

	METRIC("uhub_uptime_seconds", "gauge", "Seconds since the hub started.");
	cbuf_append_format(body, "uhub_uptime_seconds " PRINTF_SIZE_T "\n", uptime);

	METRIC("uhub_users", "gauge", "Currently logged-in users.");
	cbuf_append_format(body, "uhub_users " PRINTF_SIZE_T "\n", hub->users->count);

	METRIC("uhub_users_peak", "gauge", "Peak number of logged-in users.");
	cbuf_append_format(body, "uhub_users_peak " PRINTF_SIZE_T "\n", hub->users->count_peak);

	METRIC("uhub_users_max", "gauge", "Configured maximum number of users.");
	cbuf_append_format(body, "uhub_users_max %d\n", hub->config->max_users);

	METRIC("uhub_shared_bytes", "gauge", "Total bytes shared by connected users.");
	cbuf_append_format(body, "uhub_shared_bytes %" PRIu64 "\n", hub_get_shared_size(hub));

	METRIC("uhub_shared_files", "gauge", "Total files shared by connected users.");
	cbuf_append_format(body, "uhub_shared_files %" PRIu64 "\n", hub_get_shared_files(hub));

	METRIC("uhub_logins_total", "counter", "Successful user logins.");
	cbuf_append_format(body, "uhub_logins_total %" PRIu64 "\n", hub->metrics.logins);

	METRIC("uhub_login_failures_total", "counter", "Rejected or failed login attempts.");
	cbuf_append_format(body, "uhub_login_failures_total %" PRIu64 "\n", hub->metrics.login_failures);

	METRIC("uhub_logouts_total", "counter", "Logged-in users that disconnected.");
	cbuf_append_format(body, "uhub_logouts_total %" PRIu64 "\n", hub->metrics.logouts);

	METRIC("uhub_chat_messages_total", "counter", "Public chat messages accepted for routing.");
	cbuf_append_format(body, "uhub_chat_messages_total %" PRIu64 "\n", hub->metrics.chat_messages);

	METRIC("uhub_searches_total", "counter", "Search requests accepted for routing.");
	cbuf_append_format(body, "uhub_searches_total %" PRIu64 "\n", hub->metrics.searches);

	METRIC("uhub_search_results_total", "counter", "Search results relayed.");
	cbuf_append_format(body, "uhub_search_results_total %" PRIu64 "\n", hub->metrics.search_results);

	METRIC("uhub_private_messages_total", "counter", "Private chat messages accepted for routing.");
	cbuf_append_format(body, "uhub_private_messages_total %" PRIu64 "\n", hub->metrics.private_messages);

	METRIC("uhub_connect_requests_total", "counter", "Active connect requests (ConnectToMe).");
	cbuf_append_format(body, "uhub_connect_requests_total %" PRIu64 "\n", hub->metrics.connect_requests);

	METRIC("uhub_rev_connect_requests_total", "counter", "Passive connect requests (ReverseConnectToMe).");
	cbuf_append_format(body, "uhub_rev_connect_requests_total %" PRIu64 "\n", hub->metrics.rev_connect_requests);

	METRIC("uhub_broadcasts_total", "counter", "Messages broadcast to all users.");
	cbuf_append_format(body, "uhub_broadcasts_total %" PRIu64 "\n", hub->metrics.broadcasts);

	METRIC("uhub_feature_casts_total", "counter", "Feature-cast messages routed to subscribers.");
	cbuf_append_format(body, "uhub_feature_casts_total %" PRIu64 "\n", hub->metrics.feature_casts);

	METRIC("uhub_net_tx_bytes_total", "counter", "Total bytes transmitted by the hub.");
	cbuf_append_format(body, "uhub_net_tx_bytes_total " PRINTF_SIZE_T "\n", hub->stats.net_tx_total);

	METRIC("uhub_net_rx_bytes_total", "counter", "Total bytes received by the hub.");
	cbuf_append_format(body, "uhub_net_rx_bytes_total " PRINTF_SIZE_T "\n", hub->stats.net_rx_total);

	/* The net_statistics "total" only folds in the current window on the stats
	   timer tick, so add the not-yet-flushed intermediate window for an accurate
	   running count. */
	METRIC("uhub_connections_accepted_total", "counter", "Connections accepted.");
	cbuf_append_format(body, "uhub_connections_accepted_total " PRINTF_SIZE_T "\n", total->accept + intermediate->accept);

	METRIC("uhub_connections_closed_total", "counter", "Connections closed.");
	cbuf_append_format(body, "uhub_connections_closed_total " PRINTF_SIZE_T "\n", total->closed + intermediate->closed);

	METRIC("uhub_connections_errors_total", "counter", "Connection errors.");
	cbuf_append_format(body, "uhub_connections_errors_total " PRINTF_SIZE_T "\n", total->errors + intermediate->errors);

	METRIC("uhub_tls_accept_total", "counter", "Inbound TLS handshakes accepted.");
	cbuf_append_format(body, "uhub_tls_accept_total " PRINTF_SIZE_T "\n", total->tls_accept + intermediate->tls_accept);

	METRIC("uhub_tls_connect_total", "counter", "Outbound TLS handshakes completed.");
	cbuf_append_format(body, "uhub_tls_connect_total " PRINTF_SIZE_T "\n", total->tls_connect + intermediate->tls_connect);

	METRIC("uhub_tls_error_total", "counter", "TLS errors.");
	cbuf_append_format(body, "uhub_tls_error_total " PRINTF_SIZE_T "\n", total->tls_error + intermediate->tls_error);

	METRIC("uhub_tls_close_total", "counter", "TLS connections closed.");
	cbuf_append_format(body, "uhub_tls_close_total " PRINTF_SIZE_T "\n", total->tls_close + intermediate->tls_close);

	/* Current send/receive rates (bytes/sec, normalised over the stats window). */
	METRIC("uhub_net_tx_rate_bytes", "gauge", "Current transmit rate in bytes per second.");
	cbuf_append_format(body, "uhub_net_tx_rate_bytes " PRINTF_SIZE_T "\n", hub->stats.net_tx);

	METRIC("uhub_net_rx_rate_bytes", "gauge", "Current receive rate in bytes per second.");
	cbuf_append_format(body, "uhub_net_rx_rate_bytes " PRINTF_SIZE_T "\n", hub->stats.net_rx);

	METRIC("uhub_net_tx_rate_bytes_peak", "gauge", "Peak transmit rate in bytes per second.");
	cbuf_append_format(body, "uhub_net_tx_rate_bytes_peak " PRINTF_SIZE_T "\n", hub->stats.net_tx_peak);

	METRIC("uhub_net_rx_rate_bytes_peak", "gauge", "Peak receive rate in bytes per second.");
	cbuf_append_format(body, "uhub_net_rx_rate_bytes_peak " PRINTF_SIZE_T "\n", hub->stats.net_rx_peak);

	/* A single pass over the logged-in users produces the per-user breakdowns:
	   IP family, active vs passive (whether a routable IP is advertised), the
	   aggregate send-queue backlog, and the credential-class histogram. */
	{
		struct hub_user* user;
		size_t ipv4 = 0, ipv6 = 0, active = 0, passive = 0;
		size_t send_queue_bytes = 0;
		size_t cred_guest = 0, cred_registered = 0, cred_operator = 0, cred_admin = 0, cred_bot = 0;

		LIST_FOREACH(struct hub_user*, user, hub->users->list,
		{
			if (user->id.addr.af == AF_INET6)
				ipv6++;
			else
				ipv4++;

			/* The hub always injects I4/I6 (the observed address), so presence of
			   an IP says nothing about reachability. A client signals active mode
			   by advertising its own port (U4/U6); the hub never injects those, so
			   their presence means the client offered a way to be connected to. */
			if (user->info &&
				(adc_msg_has_named_argument(user->info, ADC_INF_FLAG_IPV4_UDP_PORT) ||
				 adc_msg_has_named_argument(user->info, ADC_INF_FLAG_IPV6_UDP_PORT)))
				active++;
			else
				passive++;

			if (user->send_queue)
				send_queue_bytes += ioq_send_get_bytes(user->send_queue);

			switch (user->credentials)
			{
				case auth_cred_guest:    cred_guest++; break;
				case auth_cred_user:     cred_registered++; break;
				case auth_cred_bot:
				case auth_cred_ubot:     cred_bot++; break;
				case auth_cred_operator:
				case auth_cred_opbot:
				case auth_cred_opubot:   cred_operator++; break;
				case auth_cred_admin:
				case auth_cred_super:    cred_admin++; break;
				default: break;
			}
		});

		METRIC("uhub_users_ipv4", "gauge", "Logged-in users connected over IPv4.");
		cbuf_append_format(body, "uhub_users_ipv4 " PRINTF_SIZE_T "\n", ipv4);

		METRIC("uhub_users_ipv6", "gauge", "Logged-in users connected over IPv6.");
		cbuf_append_format(body, "uhub_users_ipv6 " PRINTF_SIZE_T "\n", ipv6);

		METRIC("uhub_users_active", "gauge", "Users advertising a routable address (can accept TCP).");
		cbuf_append_format(body, "uhub_users_active " PRINTF_SIZE_T "\n", active);

		METRIC("uhub_users_passive", "gauge", "Users not advertising a routable address (passive).");
		cbuf_append_format(body, "uhub_users_passive " PRINTF_SIZE_T "\n", passive);

		METRIC("uhub_send_queue_bytes", "gauge", "Total bytes queued for sending across all users.");
		cbuf_append_format(body, "uhub_send_queue_bytes " PRINTF_SIZE_T "\n", send_queue_bytes);

		METRIC("uhub_users_by_credential", "gauge", "Logged-in users by credential class.");
		cbuf_append_format(body, "uhub_users_by_credential{credential=\"guest\"} " PRINTF_SIZE_T "\n", cred_guest);
		cbuf_append_format(body, "uhub_users_by_credential{credential=\"registered\"} " PRINTF_SIZE_T "\n", cred_registered);
		cbuf_append_format(body, "uhub_users_by_credential{credential=\"bot\"} " PRINTF_SIZE_T "\n", cred_bot);
		cbuf_append_format(body, "uhub_users_by_credential{credential=\"operator\"} " PRINTF_SIZE_T "\n", cred_operator);
		cbuf_append_format(body, "uhub_users_by_credential{credential=\"admin\"} " PRINTF_SIZE_T "\n", cred_admin);
	}

#undef METRIC
}

/* Prepare the full HTTP response and switch the connection over to writing it. */
static void metrics_send_response(struct metrics_connection* m, int code, const char* reason, const char* content_type, struct cbuffer* body, const char* extra_headers)
{
	struct cbuffer* resp = cbuf_create(body ? cbuf_size(body) + 256 : 256);

	cbuf_append_format(resp, "HTTP/1.1 %d %s\r\n", code, reason);
	cbuf_append_format(resp, "Content-Type: %s\r\n", content_type);
	cbuf_append_format(resp, "Content-Length: " PRINTF_SIZE_T "\r\n", body ? cbuf_size(body) : (size_t) 0);
	if (extra_headers)
		cbuf_append(resp, extra_headers);
	cbuf_append(resp, "Connection: close\r\n\r\n");
	if (body)
		cbuf_append_bytes(resp, cbuf_get(body), cbuf_size(body));

	m->response = resp;
	m->resp_sent = 0;
	m->phase = METRICS_PHASE_WRITE;
	net_con_update(m->connection, NET_EVENT_WRITE);
}

/* Tiny canned text/plain error response. */
static void metrics_send_error(struct metrics_connection* m, int code, const char* reason, const char* extra_headers)
{
	struct cbuffer* body = cbuf_create(64);
	cbuf_append_format(body, "%d %s\n", code, reason);
	metrics_send_response(m, code, reason, "text/plain; charset=utf-8", body, extra_headers);
	cbuf_destroy(body);
}

/*
 * The request line and headers are complete. Validate method, path and token,
 * then queue either the metrics document or an error response.
 */
static void metrics_handle_request(struct metrics_connection* m)
{
	struct hub_config* config = m->hub->config;
	const char* req = m->req;
	const char* p;
	char path[512];
	size_t path_len;
	const char* line;

	/* Method: only GET serves metrics. */
	if (strncmp(req, "GET ", 4) != 0)
	{
		metrics_send_error(m, 405, "Method Not Allowed", "Allow: GET\r\n");
		return;
	}

	/* Path: from after "GET " up to the next space, stripping any query string. */
	p = req + 4;
	path_len = 0;
	while (p[path_len] && p[path_len] != ' ' && p[path_len] != '?'
		&& p[path_len] != '\r' && p[path_len] != '\n')
	{
		if (path_len >= sizeof(path) - 1)
		{
			metrics_send_error(m, 414, "URI Too Long", NULL);
			return;
		}
		path[path_len] = p[path_len];
		path_len++;
	}
	path[path_len] = '\0';

	if (strcmp(path, config->metrics_path) != 0)
	{
		metrics_send_error(m, 404, "Not Found", NULL);
		return;
	}

	/* Authorization: Bearer <token> -- scan the header lines case-insensitively. */
	{
		int authorized = 0;
		line = strstr(req, "\r\n");
		while (line)
		{
			line += 2; /* step over the CRLF onto the next header line */
			if (line[0] == '\r' || line[0] == '\0')
				break; /* reached the blank line that ends the headers */

			if (strncasecmp(line, "Authorization:", 14) == 0)
			{
				const char* v = line + 14;
				const char* end;
				char token[256];
				size_t tlen = 0;

				while (*v == ' ' || *v == '\t')
					v++;
				if (strncasecmp(v, "Bearer", 6) == 0 && (v[6] == ' ' || v[6] == '\t'))
				{
					v += 6;
					while (*v == ' ' || *v == '\t')
						v++;
					end = v;
					while (*end && *end != '\r' && *end != '\n')
						end++;
					/* trim trailing whitespace */
					while (end > v && (end[-1] == ' ' || end[-1] == '\t'))
						end--;
					tlen = (size_t) (end - v);
					if (tlen < sizeof(token))
					{
						memcpy(token, v, tlen);
						token[tlen] = '\0';
						if (token_equal(token, config->metrics_token))
							authorized = 1;
					}
				}
				break; /* only the first Authorization header matters */
			}
			line = strstr(line, "\r\n");
		}

		if (!authorized)
		{
			metrics_send_error(m, 403, "Forbidden", "WWW-Authenticate: Bearer\r\n");
			return;
		}
	}

	/* Authorized GET for the metrics path -- serve the document. */
	{
		struct cbuffer* body = cbuf_create(2048);
		metrics_build_body(m->hub, body);
		metrics_send_response(m, 200, "OK", "text/plain; version=0.0.4; charset=utf-8", body, NULL);
		cbuf_destroy(body);
	}
}

static void metrics_net_event(struct net_connection* con, int events, void* arg)
{
	struct metrics_connection* m = (struct metrics_connection*) arg;

	if (events & NET_EVENT_TIMEOUT)
	{
		metrics_destroy(m);
		return;
	}

	if (m->phase == METRICS_PHASE_READ && (events & NET_EVENT_READ))
	{
		ssize_t bytes = net_con_recv(con, m->req + m->req_len, METRICS_REQ_MAX - m->req_len);
		if (bytes < 0)
		{
			metrics_destroy(m);
			return;
		}
		if (bytes == 0)
			return; /* EWOULDBLOCK/EINTR -- wait for more */

		m->req_len += (size_t) bytes;
		m->req[m->req_len] = '\0';

		if (strstr(m->req, "\r\n\r\n"))
		{
			metrics_handle_request(m); /* transitions to WRITE phase */
			return;
		}

		if (m->req_len >= METRICS_REQ_MAX)
		{
			metrics_send_error(m, 431, "Request Header Fields Too Large", NULL);
			return;
		}
		return;
	}

	if (m->phase == METRICS_PHASE_WRITE && (events & NET_EVENT_WRITE))
	{
		size_t total = cbuf_size(m->response);
		while (m->resp_sent < total)
		{
			ssize_t sent = net_con_send(con, cbuf_get(m->response) + m->resp_sent, total - m->resp_sent);
			if (sent < 0)
			{
				metrics_destroy(m);
				return;
			}
			if (sent == 0)
				return; /* EWOULDBLOCK -- resume on the next writable event */
			m->resp_sent += (size_t) sent;
		}
		/* Response fully written. */
		metrics_destroy(m);
		return;
	}
}

void metrics_handle_connection(struct hub_info* hub, struct net_connection* con, struct ip_addr_encap* addr)
{
	struct metrics_connection* m = (struct metrics_connection*) hub_malloc_zero(sizeof(struct metrics_connection));
	if (!m)
	{
		net_con_close(con); /* OOM -- just drop it */
		return;
	}

	LOG_TRACE("metrics_handle_connection(): %p from %s", m, ip_convert_to_string(addr));

	m->hub = hub;
	m->connection = con;
	m->phase = METRICS_PHASE_READ;
	memcpy(&m->addr, addr, sizeof(struct ip_addr_encap));

	net_con_reinitialize(con, metrics_net_event, m, NET_EVENT_READ);
	net_con_set_timeout(con, METRICS_TIMEOUT);
}
