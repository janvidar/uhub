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
#include "adc/message.h"
#include "adc/sid.h"
#include "network/connection.h"
#include "network/ipcalc.h"
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
	int got_ok;                             /* we received the peer's LOK */
	char nonce[LINK_NONCE_LEN + 1];         /* the challenge WE sent */
	char recvbuf[LINK_RECV_MAX];
	size_t recvlen;
	char* peer_desc;                        /* for logging */
};

/* All active links (singleton hub), for teardown. */
static struct linked_list* g_links = 0;

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

	if (strncmp(line, "LQUIT ", 6) == 0)
	{
		if (link->state != link_state_established)
			return -1;
		link_handle_remote_quit(link, line + 6);
		return 0;
	}

	if (strncmp(line, "LROUTE ", 7) == 0)
	{
		if (link->state != link_state_established)
			return -1;
		link_handle_route(link, line + 7);
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

		/* Send our local roster snapshot so the peer learns our users. */
		link_send_roster(link);
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
	struct hub_config* cfg = hub->config;
	g_links = list_create();

	/* Federation config sanity: if this hub participates in linking at all
	   (connects out, or accepts links via a shared secret) but its SIDs are not
	   partitioned, local SIDs from different hubs overlap and collide when
	   rosters are exchanged. Warn loudly -- set node_count to the cluster size
	   and a unique node_id on every node. (node_id >= node_count is caught
	   separately in uman_init.) */
	if ((*cfg->link_peer || *cfg->link_secret) && cfg->node_count <= 1)
		LOG_WARN("Hub linking is configured but node_count is 1: SIDs are not "
		         "partitioned and will collide across linked hubs. Set node_count "
		         "to the cluster size and a unique node_id on each node.");

	if (*cfg->link_peer)
	{
		if (!*cfg->link_secret)
			LOG_ERROR("link_peer is set but link_secret is empty; not linking");
		else
			link_connect(hub, cfg->link_peer);
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
	n = snprintf(buf, sizeof(buf), "LQUIT %s\n", sid_to_string(user->id.sid));
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
	/* "LROUTE " + the full ADC message (which ends in '\n'). */
	net_con_send(link->connection, "LROUTE ", 7);
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
