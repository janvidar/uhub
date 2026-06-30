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
 *   <-  LACK                sent once we have verified the peer's LRES
 *
 * A side is "established" once it has both verified the peer's LRES (the peer
 * knows the secret) and received the peer's LACK (the peer verified ours).
 * ------------------------------------------------------------------------- */

#include <stdarg.h>
#include <stdlib.h>
#include "util/log.h"
#include "util/list.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "network/connection.h"
#include "network/network.h"
#include "network/ipcalc.h"
#include <sys/un.h>
#include <unistd.h>
#include "core/config.h"
#include "core/hub.h"
#include "core/user.h"
#include "core/usermanager.h"
#include "core/route.h"

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
	int got_ok;                             /* we received the peer's LACK */
	char nonce[LINK_NONCE_LEN + 1];         /* the challenge WE sent */
	char recvbuf[LINK_RECV_MAX];
	size_t recvlen;
	char* peer_desc;                        /* for logging */
	int granted_node_id;                    /* coordinator side: window index granted to this link, or -1 */
};

/* All active links (singleton hub), for teardown. */
static struct linked_list* g_links = 0;

/* Coordinator side (this hub is node 0 of a cluster): bitmap of which window
   indices [0, g_win_count) are in use, so we can lease free windows to members
   that connect with node_id = -1. NULL on a non-coordinator. */
static char* g_win_used = 0;
static int   g_win_count = 0;

/* Reserve the lowest free window index (>0; 0 is the coordinator's own); mark it
   used and return it, or -1 if the cluster is full / we are not a coordinator. */
static int link_grant_window(void)
{
	int i;
	if (!g_win_used)
		return -1;
	for (i = 1; i < g_win_count; i++)
	{
		if (!g_win_used[i])
		{
			g_win_used[i] = 1;
			return i;
		}
	}
	return -1;
}

static void link_release_window(int idx)
{
	if (g_win_used && idx > 0 && idx < g_win_count)
		g_win_used[idx] = 0;
}

/* Coordinator election: each participating node has an election id -- 0 for a
   forced coordinator (node_id == 0), a random value for an electing node
   (node_id == -1). On each link the lower id wins and coordinates; the loser
   leases. g_window_set is 1 once this node holds a usable SID window. */
static uint64_t g_election_id = 0;
static int      g_window_set  = 0;

/* This node won the election: ensure it owns window 0 and can grant windows. */
static void link_become_coordinator(struct hub_info* hub)
{
	int n = hub->config->node_count;
	if (n < 2)
		n = 2;

	if (!g_win_used)
	{
		g_win_count = n;
		g_win_used = (char*) hub_malloc_zero((size_t) g_win_count);
		if (g_win_used)
			g_win_used[0] = 1; /* window 0 is the coordinator's own */
	}
	if (!g_window_set)
	{
		/* We were pending (node_id = -1): claim window 0 for ourselves. */
		sid_t w = SID_MAX / (sid_t) g_win_count;
		uman_set_sid_window(hub->users, 1, w - 1);
		g_window_set = 1;
	}
	LOG_INFO("link: won SID-window election -> coordinator (window 0 of %d)", g_win_count);
}

static void link_send_inf(struct hub_link* link, struct hub_user* user);
static void link_send_roster(struct hub_link* link);
static void link_handle_remote_inf(struct hub_link* link, const char* binf);
static void link_handle_remote_quit(struct hub_link* link, const char* sidstr);
static void link_handle_route(struct hub_link* link, const char* adcstr);
static void link_remove_remote_users(struct hub_link* link);

static void link_disconnect(struct hub_link* link)
{
	/* Netsplit: drop every remote user we learned over this link before the
	   link struct goes away, telling local clients those users have quit. */
	link_remove_remote_users(link);

	/* Coordinator side: return this member's leased window to the free pool. */
	link_release_window(link->granted_node_id);

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

	if (strncmp(line, "LINF ", 5) == 0)
	{
		/* Roster entry / INF update from the peer. Only valid once the link is
		   authenticated. */
		if (link->state != link_state_established)
			return -1;
		link_handle_remote_inf(link, line + 5);
		return 0;
	}

	if (strncmp(line, "LQUI ", 5) == 0)
	{
		if (link->state != link_state_established)
			return -1;
		link_handle_remote_quit(link, line + 5);
		return 0;
	}

	if (strncmp(line, "LDSC ", 5) == 0)
	{
		/* Hub description (topic) change from a peer. Apply locally without
		   re-propagating (loop-safe on a full mesh). */
		if (link->state != link_state_established)
			return -1;
		hub_update_description(link->hub, line + 5, 0);
		return 0;
	}

	if (strncmp(line, "LBAN ", 5) == 0)
	{
		/* Cluster-wide ban from a peer: "LBAN <cid> <nick>". Apply locally
		   (ban + disconnect a matching local user) without re-propagating. */
		const char* p = line + 5;
		const char* sp = strchr(p, ' ');
		char cid[MAX_CID_LEN + 1];
		size_t clen;
		if (link->state != link_state_established || !sp)
			return -1;
		clen = (size_t) (sp - p);
		if (clen > MAX_CID_LEN)
			clen = MAX_CID_LEN;
		memcpy(cid, p, clen);
		cid[clen] = 0;
		hub_apply_ban(link->hub, cid, sp + 1, 0);
		return 0;
	}

	if (strncmp(line, "LRTE ", 5) == 0)
	{
		if (link->state != link_state_established)
			return -1;
		link_handle_route(link, line + 5);
		return 0;
	}

	if (strncmp(line, "LELC ", 5) == 0)
	{
		/* Coordinator election: compare ids; the lower one coordinates. */
		uint64_t peerid;
		uint64_t myid;
		int i_win;
		if (link->state != link_state_established)
			return -1;
		peerid = strtoull(line + 5, NULL, 16);
		myid = (link->hub->config->node_id == 0) ? 0 : g_election_id;
		/* Lower id wins; an exact tie (astronomically unlikely) is broken by
		   the link role so both ends agree -- the acceptor coordinates. */
		i_win = (myid < peerid) || (myid == peerid && link->is_client == 0);
		if (i_win)
		{
			link_become_coordinator(link->hub);
		}
		else if (!g_window_set)
		{
			/* We lost and still need a window: lease one from the winner. */
			link_sendf(link, "LWRQ\n");
		}
		return 0;
	}

	if (strcmp(line, "LWRQ") == 0)
	{
		/* Coordinator: a member is requesting a SID window lease. */
		int idx;
		sid_t w, lo, hi;
		if (link->state != link_state_established)
			return -1;
		idx = link_grant_window();
		if (idx < 0)
		{
			LOG_WARN("link: no free SID window to lease to %s", link->peer_desc);
			link_sendf(link, "LERR\n");
			return -1;
		}
		w  = SID_MAX / (sid_t) g_win_count;
		lo = (sid_t) idx * w;
		if (lo == 0) lo = 1; /* SID 0 reserved */
		hi = (sid_t) idx * w + w - 1;
		link->granted_node_id = idx;
		link_sendf(link, "LWIN %u %u\n", (unsigned) lo, (unsigned) hi);
		LOG_INFO("link: leased SID window [%u, %u] (node %d) to %s",
			(unsigned) lo, (unsigned) hi, idx, link->peer_desc);
		return 0;
	}

	if (strncmp(line, "LWIN ", 5) == 0)
	{
		/* Member: the coordinator granted us a window; apply it. */
		char* end;
		unsigned long lo, hi;
		if (link->state != link_state_established)
			return -1;
		lo = strtoul(line + 5, &end, 10);
		hi = strtoul(end, &end, 10);
		if (hi <= lo)
		{
			LOG_WARN("link: invalid window grant from %s", link->peer_desc);
			return -1;
		}
		uman_set_sid_window(link->hub->users, (sid_t) lo, (sid_t) hi);
		g_window_set = 1;
		LOG_INFO("link: leased SID window [%lu, %lu] from %s", lo, hi, link->peer_desc);
		return 0;
	}

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
		if (link_sendf(link, "LACK\n") < 0)
			return -1;
	}
	else if (strcmp(line, "LACK") == 0)
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

		/* Send our local roster snapshot so the peer learns our users. */
		link_send_roster(link);

		/* Coordinator election: nodes that participate (forced coordinator
		   node_id == 0, or electing node_id == -1) announce their election id.
		   The lower id wins and coordinates; see the LELC handler. The window
		   lease (LWRQ) is deferred until the election decides who is member. */
		if (link->hub->config->node_id <= 0)
			link_sendf(link, "LELC %016llx\n", (unsigned long long) g_election_id);
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
	link->granted_node_id = -1;
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

/* -------------------------------------------------------------------------
 * Unix-domain-socket transport.
 *
 * On a multi-core box one logical hub runs as several worker processes that
 * share the client port (SO_REUSEPORT) and link to each other. Those inter-
 * worker links must NOT use the shared client port -- a TCP connection there
 * would be load-balanced to an arbitrary worker -- so they run over per-worker
 * Unix domain sockets instead. The link protocol itself is transport-agnostic;
 * only the listen/connect plumbing differs.
 * ------------------------------------------------------------------------- */

static struct net_connection* g_uds_listen = 0;
static char g_uds_path[108] = {0}; /* sun_path is ~108 bytes */

/* Attach a freshly connected/accepted link fd (TCP or UDS) to a new link and
   start the handshake. Takes ownership of fd. */
static int link_attach_fd(struct hub_info* hub, int fd, int is_client, const char* desc)
{
	struct hub_link* link;
	struct net_connection* con;

	if (!*hub->config->link_secret)
	{
		LOG_WARN("link: rejecting link from %s (link_secret not configured)", desc);
		net_close(fd);
		return 0;
	}
	if (net_set_nonblocking(fd, 1) == -1)
	{
		net_close(fd);
		return 0;
	}
	con = net_con_create();
	if (!con)
	{
		net_close(fd);
		return 0;
	}
	link = link_create_internal(hub, is_client, desc);
	if (!link)
	{
		net_con_destroy(con);
		net_close(fd);
		return 0;
	}
	link->connection = con;
	net_con_initialize(con, fd, link_net_event, link, NET_EVENT_READ);
	net_con_set_timeout(con, LINK_TIMEOUT);
	if (link_begin_handshake(link) < 0)
		link_disconnect(link);
	return 1;
}

static void link_uds_on_accept(struct net_connection* con, int event, void* arg)
{
	struct hub_info* hub = (struct hub_info*) arg;
	struct ip_addr_encap dummy;
	int server_fd = net_con_get_sd(con);
	(void) event;

	memset(&dummy, 0, sizeof(dummy));
	for (;;)
	{
		int fd = net_accept(server_fd, &dummy);
		if (fd == -1)
			break; /* drained (EWOULDBLOCK) or error */
		link_attach_fd(hub, fd, 0, "unix-socket");
	}
}

static int link_uds_listen(struct hub_info* hub, const char* path)
{
	struct sockaddr_un addr;
	int sd;

	if (strlen(path) >= sizeof(addr.sun_path))
	{
		LOG_ERROR("link: link_socket path too long: %s", path);
		return -1;
	}

	sd = net_socket_create(AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1)
		return -1;

	unlink(path); /* clear a stale socket from a previous run */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (net_bind(sd, (struct sockaddr*) &addr, sizeof(addr)) == -1)
	{
		LOG_ERROR("link: unable to bind link socket %s", path);
		net_close(sd);
		return -1;
	}
	if (net_listen(sd, 16) == -1 || net_set_nonblocking(sd, 1) == -1)
	{
		net_close(sd);
		unlink(path);
		return -1;
	}

	g_uds_listen = net_con_create();
	if (!g_uds_listen)
	{
		net_close(sd);
		unlink(path);
		return -1;
	}
	net_con_initialize(g_uds_listen, sd, link_uds_on_accept, hub, NET_EVENT_READ);
	strncpy(g_uds_path, path, sizeof(g_uds_path) - 1);
	LOG_INFO("link: listening for hub links on unix socket %s", path);
	return 0;
}

static void link_uds_connect(struct hub_info* hub, const char* path)
{
	struct sockaddr_un addr;
	int sd;

	if (strlen(path) >= sizeof(addr.sun_path))
	{
		LOG_ERROR("link: link_peer path too long: %s", path);
		return;
	}

	sd = net_socket_create(AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1)
		return;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	/* The socket is still blocking here; a local UDS connect completes
	   immediately, so we avoid the async-connect machinery. */
	if (net_connect(sd, (struct sockaddr*) &addr, sizeof(addr)) == -1)
	{
		LOG_WARN("link: unable to connect to peer hub socket %s", path);
		net_close(sd);
		return;
	}
	if (link_attach_fd(hub, sd, 1, path))
		LOG_INFO("link: connected to peer hub on unix socket %s", path);
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
	struct hub_config* cfg = hub->config;
	g_links = list_create();

	/* Election state. A forced coordinator (node_id == 0) uses id 0 and always
	   wins; an electing node (node_id == -1) uses a random id. Both announce
	   their id over each link (LELC) and the lower wins. g_window_set is true
	   for any node that already holds a window (statically configured node_id
	   >= 0); an electing node starts pending until it wins or leases. */
	g_window_set = (cfg->node_id >= 0) ? 1 : 0;
	g_election_id = 0;
	if (cfg->node_id < 0)
		RAND_bytes((unsigned char*) &g_election_id, sizeof(g_election_id));

	/* Federation config sanity: if this hub participates in linking at all
	   (connects out, or accepts links via a shared secret) but its SIDs are not
	   partitioned, local SIDs from different hubs overlap and collide when
	   rosters are exchanged. Warn loudly -- set node_count to the cluster size
	   and a unique node_id on every node. (node_id >= node_count is caught
	   separately in uman_init.) */
	if ((*cfg->link_peer || *cfg->link_secret) && cfg->node_count <= 1 && cfg->node_id >= 0)
		LOG_WARN("Hub linking is configured but node_count is 1: SIDs are not "
		         "partitioned and will collide across linked hubs. Set node_count "
		         "to the cluster size and a unique node_id on each node "
		         "(or node_id = -1 to lease a window dynamically).");

	/* Coordinator (node 0 of a cluster): track window usage so members that
	   connect with node_id = -1 can lease a free window. Window 0 is ours. */
	if (cfg->node_id == 0 && cfg->node_count > 1)
	{
		g_win_count = cfg->node_count;
		g_win_used = (char*) hub_malloc_zero((size_t) g_win_count);
		if (g_win_used)
			g_win_used[0] = 1;
		LOG_INFO("link: cluster coordinator (node 0 of %d); leasing SID windows on request", g_win_count);
	}

	/* Inbound links: a TCP listener already exists on the client port (probe.c
	   detects "LCHA"); additionally listen on a Unix socket if configured, for
	   same-host worker-to-worker links that bypass the shared client port. */
	if (*cfg->link_socket)
		link_uds_listen(hub, cfg->link_socket);

	/* link_peer may be a comma-separated list of peers (to form a mesh of
	   worker processes); connect to each. A peer beginning with "/" is a Unix
	   socket path, otherwise host:port over TCP. */
	if (*cfg->link_peer)
	{
		if (!*cfg->link_secret)
		{
			LOG_ERROR("link_peer is set but link_secret is empty; not linking");
		}
		else
		{
			char* list = hub_strdup(cfg->link_peer);
			char* save = 0;
			char* peer;
			if (list)
			{
				for (peer = strtok_r(list, ",", &save); peer; peer = strtok_r(0, ",", &save))
				{
					while (*peer == ' ' || *peer == '\t')
						peer++;
					if (!*peer)
						continue;
					if (peer[0] == '/')
						link_uds_connect(hub, peer);
					else
						link_connect(hub, peer);
				}
				hub_free(list);
			}
		}
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

	if (g_uds_listen)
	{
		net_con_close(g_uds_listen);
		g_uds_listen = 0;
	}
	if (*g_uds_path)
	{
		unlink(g_uds_path);
		g_uds_path[0] = 0;
	}

	hub_free(g_win_used);
	g_win_used = 0;
	g_win_count = 0;
}

/* Send one user's INF to the peer as "LINF <binf>". user->info->cache is a
   complete "BINF <sid> ...\n" line, so it terminates the LINF line itself. */
static void link_send_inf(struct hub_link* link, struct hub_user* user)
{
	if (!user->info || !user->info->cache)
		return;
	net_con_send(link->connection, "LINF ", 5);
	net_con_send(link->connection, user->info->cache, user->info->length);
}

/* Send a snapshot of our local users to the peer (one LINF per user). Remote
   users are never relayed (avoids loops in a >2-node mesh; that's B4). */
static void link_send_roster(struct hub_link* link)
{
	struct hub_user* user;
	LIST_FOREACH(struct hub_user*, user, link->hub->users->list,
	{
		if (user_is_logged_in(user) && !user_is_remote(user))
			link_send_inf(link, user);
	});
}

/* Forward a local user's INF (join or update) to every established link. */
void link_broadcast_local_inf(struct hub_info* hub, struct hub_user* user)
{
	struct hub_link* link;
	(void) hub;
	if (!g_links || user_is_remote(user))
		return;
	LIST_FOREACH(struct hub_link*, link, g_links,
	{
		if (link->state == link_state_established)
			link_send_inf(link, user);
	});
}

/* Forward a local user's departure to every established link. */
void link_broadcast_local_quit(struct hub_info* hub, struct hub_user* user)
{
	struct hub_link* link;
	char buf[64];
	int n;
	(void) hub;
	if (!g_links || user_is_remote(user))
		return;
	n = snprintf(buf, sizeof(buf), "LQUI %s\n", sid_to_string(user->id.sid));
	if (n <= 0 || n >= (int) sizeof(buf))
		return;
	LIST_FOREACH(struct hub_link*, link, g_links,
	{
		if (link->state == link_state_established)
			net_con_send(link->connection, buf, (size_t) n);
	});
}

/* Propagate a hub description (topic) change to every established link. The
   description is already ADC-escaped, so it has no spaces or newlines and is
   safe to send as a single LDSC token. */
void link_broadcast_description(struct hub_info* hub, const char* escaped_desc)
{
	struct hub_link* link;
	(void) hub;
	if (!g_links || !escaped_desc)
		return;
	LIST_FOREACH(struct hub_link*, link, g_links,
	{
		if (link->state == link_state_established)
		{
			net_con_send(link->connection, "LDSC ", 5);
			net_con_send(link->connection, escaped_desc, strlen(escaped_desc));
			net_con_send(link->connection, "\n", 1);
		}
	});
}

/* Propagate a ban to every established link. Format: "LBAN <cid> <nick>", with
   the CID first (fixed-width base32, no spaces) and the nick taking the rest of
   the line (it may legitimately contain spaces). */
void link_broadcast_ban(struct hub_info* hub, const char* cid, const char* nick)
{
	struct hub_link* link;
	char buf[256];
	int n;
	(void) hub;
	if (!g_links)
		return;
	n = snprintf(buf, sizeof(buf), "LBAN %s %s\n", cid ? cid : "", nick ? nick : "");
	if (n <= 0 || n >= (int) sizeof(buf))
		return;
	LIST_FOREACH(struct hub_link*, link, g_links,
	{
		if (link->state == link_state_established)
			net_con_send(link->connection, buf, (size_t) n);
	});
}

/* Inject a remote user from a peer's INF, and announce it to local clients. */
static void link_handle_remote_inf(struct hub_link* link, const char* binf)
{
	struct adc_message* info = adc_msg_parse(binf, strlen(binf));
	struct hub_user* user;

	if (!info)
	{
		LOG_WARN("link: malformed remote INF from %s", link->peer_desc);
		return;
	}

	/* Existing SID -> this is an INF update for a remote user we already hold. */
	user = uman_get_user_by_sid(link->hub->users, info->source);
	if (user)
	{
		if (user->origin_link != link)
		{
			/* SID owned by a local user or another link -- ignore (B5). */
			adc_msg_free(info);
			return;
		}
		adc_msg_free(user->info);
		user->info = adc_msg_incref(info);
		adc_msg_free(info);
		route_info_message(link->hub, user); /* relay the update to local clients */
		return;
	}

	user = user_create_remote(link->hub, link, info);
	if (!user)
	{
		adc_msg_free(info);
		return;
	}

	if (uman_add_remote(link->hub->users, user) != 0)
	{
		/* SID/nick/CID already in use across the cluster (B5 will resolve such
		   collisions; for now we just drop the duplicate). */
		LOG_WARN("link: remote user %s (sid %s) rejected as duplicate from %s",
			user->id.nick, sid_to_string(user->id.sid), link->peer_desc);
		user_destroy(user);
		adc_msg_free(info);
		return;
	}
	adc_msg_free(info); /* user holds its own reference */

	LOG_INFO("link: injected remote user %s (sid %s) from %s",
		user->id.nick, sid_to_string(user->id.sid), link->peer_desc);

	/* Announce the federated user to our local clients. */
	route_info_message(link->hub, user);
}

/* A remote user (sid) has left the peer hub: remove it locally. */
static void link_handle_remote_quit(struct hub_link* link, const char* sidstr)
{
	sid_t sid = string_to_sid(sidstr);
	struct hub_user* user = sid ? uman_get_user_by_sid(link->hub->users, sid) : NULL;

	if (!user || user->origin_link != link)
		return; /* unknown SID or not learned over this link */

	LOG_INFO("link: remote user %s (sid %s) left, from %s",
		user->id.nick, sidstr, link->peer_desc);
	uman_send_quit_message(link->hub, link->hub->users, user);
	uman_remove_remote(link->hub->users, user);
	user_destroy(user);
}

/* Forward a directed ADC message to the peer that owns the target user. */
void link_forward_message(struct hub_link* link, struct adc_message* msg)
{
	if (!link || link->state != link_state_established || !msg || !msg->cache)
		return;
	LOG_DEBUG("link: forwarding directed message to %s", link->peer_desc);
	/* "LRTE " + the full ADC message (which ends in '\n'). */
	net_con_send(link->connection, "LRTE ", 5);
	net_con_send(link->connection, msg->cache, msg->length);
}

/* Relay a locally-originated public chat/search broadcast to every link, once
   each. Presence (INF/QUI) is excluded -- it uses the B3 delta path -- and
   messages whose source is a remote user are not relayed (loop prevention: a
   broadcast that arrived over a link is delivered locally only). */
void link_relay_broadcast(struct hub_info* hub, struct adc_message* msg)
{
	struct hub_user* src;
	struct hub_link* link;

	switch (msg->cmd)
	{
		case ADC_CMD_BMSG:
		case ADC_CMD_FMSG:
		case ADC_CMD_BSCH:
		case ADC_CMD_FSCH:
			break;
		default:
			return; /* not a relayable broadcast (e.g. BINF presence) */
	}

	if (!g_links)
		return;

	src = uman_get_user_by_sid(hub->users, msg->source);
	if (!src || user_is_remote(src))
		return; /* only relay messages that originated on this hub */

	LIST_FOREACH(struct hub_link*, link, g_links,
	{
		if (link->state == link_state_established)
			link_forward_message(link, msg);
	});
}

/* A peer forwarded a directed message whose target is on our side: re-route it
   locally. The original sender is a remote user we already hold. */
static void link_handle_route(struct hub_link* link, const char* adcstr)
{
	struct adc_message* msg = adc_msg_parse(adcstr, strlen(adcstr));
	struct hub_user* sender;

	if (!msg)
	{
		LOG_WARN("link: malformed routed message from %s", link->peer_desc);
		return;
	}

	/* route_message() dereferences the source user for echo (E) messages, so a
	   known sender is required; it is the remote user we learned over a link. */
	sender = uman_get_user_by_sid(link->hub->users, msg->source);
	if (sender)
	{
		LOG_DEBUG("link: delivering routed message from sid %s (via %s)",
			sid_to_string(msg->source), link->peer_desc);
		route_message(link->hub, sender, msg);
	}
	else
		LOG_WARN("link: routed message from unknown sid via %s", link->peer_desc);

	adc_msg_free(msg);
}

/* Remove every remote user learned over `link` (netsplit / link teardown). */
static void link_remove_remote_users(struct hub_link* link)
{
	struct linked_list* doomed;
	struct hub_user* user;

	if (!link->hub || !link->hub->users)
		return;

	doomed = list_create();
	if (!doomed)
		return;

	LIST_FOREACH(struct hub_user*, user, link->hub->users->list,
	{
		if (user->origin_link == link)
			list_append(doomed, user);
	});

	while ((user = (struct hub_user*) list_get_first(doomed)) != NULL)
	{
		list_remove(doomed, user);
		LOG_INFO("link: removing remote user %s (link to %s lost)", user->id.nick, link->peer_desc);
		uman_send_quit_message(link->hub, link->hub->users, user);
		uman_remove_remote(link->hub->users, user);
		user_destroy(user);
	}
	list_destroy(doomed);
}
