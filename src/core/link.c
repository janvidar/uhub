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
#include <openssl/rand.h>
#include "util/memory.h"
#include "util/misc.h"
#include "util/tiger.h"
#include "adc/adctypes.h"
#include "core/link.h"

static int link_const_time_equal(const char* a, const char* b, size_t len)
{
	unsigned char diff = 0;
	size_t i;
	for (i = 0; i < len; i++)
		diff |= (unsigned char) (a[i] ^ b[i]);
	return diff == 0;
}

void link_auth_response(const char* secret, const char* nonce, char* out)
{
	size_t sl = secret ? strlen(secret) : 0;
	size_t nl = nonce ? strlen(nonce) : 0;
	uint64_t mac[3];
	char* buf;

	/* tiger() reads its input as bytes; a heap buffer is suitably aligned. */
	buf = hub_malloc(sl + nl + 1);
	if (!buf)
	{
		out[0] = 0;
		return;
	}
	if (sl) memcpy(buf, secret, sl);
	if (nl) memcpy(buf + sl, nonce, nl);

	tiger((uint64_t*) buf, (uint64_t) (sl + nl), mac);
	base32_encode((unsigned char*) mac, TIGERSIZE, out);
	out[LINK_AUTH_RESPONSE_LEN] = 0;
	hub_free(buf);
}

int link_auth_verify(const char* secret, const char* nonce, const char* response)
{
	char expected[LINK_AUTH_RESPONSE_LEN + 1];

	if (!response || strlen(response) != LINK_AUTH_RESPONSE_LEN)
		return 0;

	link_auth_response(secret, nonce, expected);
	return link_const_time_equal(response, expected, LINK_AUTH_RESPONSE_LEN);
}

int link_make_nonce(char* out)
{
	unsigned char raw[TIGERSIZE];

	if (RAND_bytes(raw, sizeof(raw)) != 1)
	{
		out[0] = 0;
		return 0;
	}
	base32_encode(raw, TIGERSIZE, out);
	out[LINK_NONCE_LEN] = 0;
	return 1;
}

/* ------------------------------------------------------------------------- *
 * Networked link handshake (B1b).
 *
 * Links reuse the normal hub port: the connecting hub sends "LCHA <nonce>" as
 * its first bytes, which probe.c detects (like HSUP/TLS) and hands to
 * link_accept(). Both sides then run a symmetric mutual challenge-response:
 *
 *   ->  LCHA <nonce>        (each side challenges the other)
 *   <-  LRES <response>     response = base32(tiger(secret || peer_nonce))
 *   <-  LOK                 sent once we have verified the peer's LRES
 *
 * A side is "established" once it has both verified the peer's LRES (the peer
 * knows the secret) and received the peer's LOK (the peer verified ours).
 * ------------------------------------------------------------------------- */

#include <stdarg.h>
#include "util/log.h"
#include "util/list.h"
#include "network/connection.h"
#include "network/ipcalc.h"
#include "core/config.h"
#include "core/hub.h"

#define LINK_RECV_MAX 1024
#define LINK_TIMEOUT  30

enum link_state
{
	link_state_handshake,
	link_state_established,
};

struct hub_link
{
	struct hub_info* hub;
	struct net_connection* connection;
	struct net_connect_handle* connect_job; /* outbound only, while connecting */
	enum link_state state;
	int is_client;                          /* 1 = we initiated, 0 = we accepted */
	int peer_verified;                      /* we verified the peer's LRES */
	int got_ok;                             /* we received the peer's LOK */
	char nonce[LINK_NONCE_LEN + 1];         /* the challenge WE sent */
	char recvbuf[LINK_RECV_MAX];
	size_t recvlen;
	char* peer_desc;                        /* for logging */
};

/* All active links (singleton hub), for teardown. */
static struct linked_list* g_links = 0;

static void link_disconnect(struct hub_link* link)
{
	if (link->connect_job)
	{
		net_connect_destroy(link->connect_job);
		link->connect_job = 0;
	}
	if (link->connection)
	{
		net_con_close(link->connection);
		link->connection = 0;
	}
	if (g_links)
		list_remove(g_links, link);
	hub_free(link->peer_desc);
	hub_free(link);
}

static int link_sendf(struct hub_link* link, const char* fmt, ...)
{
	char buf[128];
	va_list ap;
	int n;
	ssize_t w;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n <= 0 || n >= (int) sizeof(buf))
		return -1;

	/* Handshake messages are tiny and the socket buffer is empty, so a single
	   write always completes. TODO: buffer if links ever carry bulk traffic. */
	w = net_con_send(link->connection, buf, (size_t) n);
	return (w == n) ? 0 : -1;
}

/* Process one complete handshake line (NUL-terminated, no newline).
   Returns 0 to continue, -1 to close the link (caller disconnects). */
static int link_process_line(struct hub_link* link, const char* line)
{
	const char* secret = link->hub->config->link_secret;

	if (strncmp(line, "LCHA ", 5) == 0)
	{
		char resp[LINK_AUTH_RESPONSE_LEN + 1];
		link_auth_response(secret, line + 5, resp);
		return link_sendf(link, "LRES %s\n", resp);
	}
	else if (strncmp(line, "LRES ", 5) == 0)
	{
		if (!link_auth_verify(secret, link->nonce, line + 5))
		{
			LOG_WARN("link: authentication failed from %s", link->peer_desc);
			link_sendf(link, "LERR\n");
			return -1;
		}
		link->peer_verified = 1;
		if (link_sendf(link, "LOK\n") < 0)
			return -1;
	}
	else if (strcmp(line, "LOK") == 0)
	{
		link->got_ok = 1;
	}
	else if (strcmp(line, "LERR") == 0)
	{
		LOG_WARN("link: peer %s reported authentication failure", link->peer_desc);
		return -1;
	}
	else
	{
		LOG_WARN("link: unexpected handshake message from %s", link->peer_desc);
		return -1;
	}

	if (link->peer_verified && link->got_ok && link->state != link_state_established)
	{
		link->state = link_state_established;
		net_con_clear_timeout(link->connection);
		LOG_INFO("link established with %s (%s)", link->peer_desc,
			link->is_client ? "outbound" : "inbound");
	}
	return 0;
}

static int link_handle_read(struct hub_link* link)
{
	char* start;
	char* nl;
	size_t remain;
	ssize_t r = net_con_recv(link->connection, link->recvbuf + link->recvlen,
		LINK_RECV_MAX - link->recvlen - 1);

	if (r == 0)
		return 0;  /* EWOULDBLOCK */
	if (r < 0)
		return -1; /* closed/error */

	link->recvlen += (size_t) r;
	link->recvbuf[link->recvlen] = 0;

	start = link->recvbuf;
	while ((nl = memchr(start, '\n', (link->recvbuf + link->recvlen) - start)) != NULL)
	{
		*nl = 0;
		if (nl > start && nl[-1] == '\r')
			nl[-1] = 0;
		if (link_process_line(link, start) < 0)
			return -1;
		start = nl + 1;
	}

	remain = (link->recvbuf + link->recvlen) - start;
	memmove(link->recvbuf, start, remain);
	link->recvlen = remain;

	if (link->recvlen >= LINK_RECV_MAX - 1)
	{
		LOG_WARN("link: oversized handshake line from %s", link->peer_desc);
		return -1;
	}
	return 0;
}

static void link_net_event(struct net_connection* con, int events, void* arg)
{
	struct hub_link* link = (struct hub_link*) arg;
	(void) con;

	if (events & NET_EVENT_TIMEOUT)
	{
		LOG_WARN("link: handshake timed out with %s", link->peer_desc);
		link_disconnect(link);
		return;
	}
	if (events & NET_EVENT_ERROR)
	{
		link_disconnect(link);
		return;
	}
	if (events & NET_EVENT_READ)
	{
		if (link_handle_read(link) < 0)
			link_disconnect(link);
	}
}

static struct hub_link* link_create_internal(struct hub_info* hub, int is_client, const char* desc)
{
	struct hub_link* link = hub_malloc_zero(sizeof(struct hub_link));
	if (!link)
		return 0;
	link->hub = hub;
	link->is_client = is_client;
	link->state = link_state_handshake;
	link->peer_desc = hub_strdup(desc ? desc : "?");
	if (g_links)
		list_append(g_links, link);
	return link;
}

static int link_begin_handshake(struct hub_link* link)
{
	if (!link_make_nonce(link->nonce))
		return -1;
	return link_sendf(link, "LCHA %s\n", link->nonce);
}

int link_accept(struct hub_info* hub, struct net_connection* con, struct ip_addr_encap* addr)
{
	struct hub_link* link;

	if (!*hub->config->link_secret)
	{
		LOG_WARN("link: rejecting link from %s (link_secret not configured)", ip_convert_to_string(addr));
		return 0; /* caller closes the connection */
	}

	link = link_create_internal(hub, 0, ip_convert_to_string(addr));
	if (!link)
		return 0;

	link->connection = con;
	net_con_reinitialize(con, link_net_event, link, NET_EVENT_READ);
	net_con_set_timeout(con, LINK_TIMEOUT);

	/* The peer's "LCHA <nonce>" is still buffered (probe used peek), so our
	   first read will see it; send our own challenge now. */
	if (link_begin_handshake(link) < 0)
		link_disconnect(link);
	return 1; /* ownership taken (even if we just closed it) */
}

static void link_connect_callback(struct net_connect_handle* handle, enum net_connect_status status, struct net_connection* con, void* ptr)
{
	struct hub_link* link = (struct hub_link*) ptr;
	(void) handle;

	link->connect_job = 0;
	if (status != net_connect_status_ok || !con)
	{
		LOG_WARN("link: could not connect to %s (status %d)", link->peer_desc, (int) status);
		link_disconnect(link);
		return;
	}

	link->connection = con;
	net_con_reinitialize(con, link_net_event, link, NET_EVENT_READ);
	net_con_set_timeout(con, LINK_TIMEOUT);
	if (link_begin_handshake(link) < 0)
		link_disconnect(link);
}

static void link_connect(struct hub_info* hub, const char* peer)
{
	char host[256];
	const char* colon = strrchr(peer, ':');
	size_t hlen;
	int port;
	struct hub_link* link;

	if (!colon || colon == peer)
	{
		LOG_ERROR("link: invalid link_peer '%s' (expected host:port)", peer);
		return;
	}
	hlen = (size_t) (colon - peer);
	if (hlen >= sizeof(host))
	{
		LOG_ERROR("link: link_peer host too long");
		return;
	}
	memcpy(host, peer, hlen);
	host[hlen] = 0;
	port = uhub_atoi(colon + 1);
	if (port <= 0 || port > 65535)
	{
		LOG_ERROR("link: invalid port in link_peer '%s'", peer);
		return;
	}

	link = link_create_internal(hub, 1, peer);
	if (!link)
		return;

	link->connect_job = net_con_connect(host, (uint16_t) port, link_connect_callback, link);
	if (!link->connect_job)
	{
		LOG_ERROR("link: unable to start connection to %s", peer);
		link_disconnect(link);
		return;
	}
	LOG_INFO("link: connecting to upstream hub %s...", peer);
}

void link_start(struct hub_info* hub)
{
	g_links = list_create();

	if (*hub->config->link_peer)
	{
		if (!*hub->config->link_secret)
			LOG_ERROR("link_peer is set but link_secret is empty; not linking");
		else
			link_connect(hub, hub->config->link_peer);
	}
}

void link_stop(struct hub_info* hub)
{
	struct hub_link* link;
	(void) hub;

	if (!g_links)
		return;

	while ((link = (struct hub_link*) list_get_first(g_links)) != NULL)
		link_disconnect(link); /* removes itself from g_links */

	list_destroy(g_links);
	g_links = 0;
}
