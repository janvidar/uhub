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

#ifndef HAVE_UHUB_LINK_H
#define HAVE_UHUB_LINK_H

#include <time.h>
#include "adc/adctypes.h"

/*
 * Hub-to-hub link authentication primitives.
 *
 * Two hubs establish a link by proving knowledge of a shared secret
 * (the `link_secret` config) via a nonce challenge-response, rather than
 * sending the secret over the wire. The response is a truncated HMAC-SHA256
 * keyed on the secret, over the sender's role and both sides' nonces:
 *
 *   base32(HMAC-SHA256(secret, "uhub-link-v2 <C|S> <client_nonce> <server_nonce>")[0:24])
 *
 * Binding the role is what stops a reflection: a hub's answer to its own
 * challenge, echoed back at it, is computed for the wrong role and does not
 * verify. This replaced v1's base32(tiger(secret || peer_nonce)); there is
 * deliberately no fallback, so every linked hub must run the same version.
 *
 * These primitives are pure (no hub state, no networking) so they can be unit
 * tested directly; the networked handshake in link.c is built on top.
 *
 * TODO (auth hardening): the shared `link_secret` is a plaintext config value
 * with the same drawbacks as plaintext passwords -- one secret for all peers,
 * no per-hub identity, no rotation/revocation, readable by anyone with config
 * access. The handshake also authenticates only itself: it is not bound to the
 * TLS session a hub with tls_enable dials its peers over, and without TLS the
 * traffic after it is neither encrypted nor integrity-protected, so the
 * transport must be trusted. The better long-term mechanism is mutual TLS with per-peer
 * certificate pinning -- per-hub identity, revocable, and protecting the whole
 * session.
 */

/* 24 MAC bytes (192 bits) encode to 39 base32 characters, like a CID. */
#define LINK_AUTH_MAC_BYTES    24
#define LINK_AUTH_RESPONSE_LEN MAX_CID_LEN
#define LINK_NONCE_LEN         MAX_CID_LEN

/**
 * Whether `nonce` is well-formed: exactly LINK_NONCE_LEN base32 characters.
 */
extern int link_nonce_valid(const char* nonce);

/**
 * Compute the auth response sent by one side of a link. from_client is 1 if
 * the sender is the side that opened the connection, 0 for the side that
 * accepted it; the nonces are always passed client-first. Both nonces must be
 * valid and distinct, and the secret non-empty.
 * @param out must be at least LINK_AUTH_RESPONSE_LEN + 1 bytes; NUL-terminated,
 *            and the empty string if any input is invalid.
 */
extern void link_auth_response(const char* secret, const char* client_nonce,
	const char* server_nonce, int from_client, char* out);

/**
 * Constant-time verify that `response` is what the side named by from_client
 * would send for (secret, client_nonce, server_nonce). Returns 1 if valid,
 * 0 otherwise (including on any invalid input).
 */
extern int link_auth_verify(const char* secret, const char* client_nonce,
	const char* server_nonce, int from_client, const char* response);

/**
 * Generate a fresh random nonce (base32-encoded).
 * @param out must be at least LINK_NONCE_LEN + 1 bytes; NUL-terminated.
 * @return 1 on success, 0 if the CSPRNG failed.
 */
extern int link_make_nonce(char* out);

struct hub_info;
struct hub_user;
struct net_connection;
struct ip_addr_encap;

/**
 * Forward a local user's INF to every established link (a live join, or an INF
 * update). No-op if the user is remote or no links exist.
 */
extern void link_broadcast_local_inf(struct hub_info* hub, struct hub_user* user);

/**
 * Forward a local user's departure (LQUI) to every established link.
 */
extern void link_broadcast_local_quit(struct hub_info* hub, struct hub_user* user);

/**
 * Propagate a hub description (topic) change to every established link. The
 * description must already be ADC-escaped.
 */
extern void link_broadcast_description(struct hub_info* hub, const char* escaped_desc);

/**
 * Propagate a cluster-wide ban (cid and/or nick) to every established link.
 * expiry is an absolute unix time (0 = permanent).
 */
extern void link_broadcast_ban(struct hub_info* hub, const char* cid, const char* nick, time_t expiry, const char* reason);

/**
 * Propagate a cluster-wide unban (nick, CID or IP/range) to every established link.
 */
extern void link_broadcast_unban(struct hub_info* hub, const char* target);

struct hub_user;

/**
 * Master-slave auth (slave side). link_auth_query() asks the master whether a
 * nick is registered; link_auth_proxy_verify() forwards a password
 * challenge-response to the master to verify. Both return 1 if the request was
 * sent over a master link (the login should pause), 0 if no master is reachable.
 * Only that link may answer, and if it drops first the login is refused.
 * link_auth_pending_forget() drops a user from the pending registry when it is
 * disconnected before the master replies.
 */
extern int link_auth_query(struct hub_info* hub, struct hub_user* user, const char* nick);
extern int link_auth_proxy_verify(struct hub_info* hub, struct hub_user* user, const char* challenge, const char* response);
extern void link_auth_pending_forget(struct hub_user* user);
/* 1 while `user` has a request to the master that is still unanswered. */
extern int link_auth_pending_has(struct hub_user* user);

struct adc_message;
struct hub_link;

/**
 * Forward a directed ADC message (PM, search result, connect, ...) over a link
 * to the peer hub that owns the target user. The peer re-routes it to its local
 * target. No-op if the link is not established.
 */
extern void link_forward_message(struct hub_link* link, struct adc_message* msg);

/**
 * Relay a locally-originated public chat/search broadcast to all established
 * links (once each). No-op for presence messages or messages that originated
 * on another hub (loop prevention).
 */
extern void link_relay_broadcast(struct hub_info* hub, struct adc_message* msg);

/**
 * Take over a probed incoming connection whose first bytes were the link
 * handshake ("LCHA ..."), and run the server side of the link handshake.
 * Called from probe.c, mirroring how an ADC client connection is detected.
 *
 * @return 1 if the connection was taken over (caller must not close it),
 *         0 if the link was rejected (caller closes the connection).
 */
extern int link_accept(struct hub_info* hub, struct net_connection* con, struct ip_addr_encap* addr);

/**
 * Run the link protocol on an already-connected connection: link_accept() is
 * this with is_client = 0. is_client says which side of the handshake we are
 * (1 = we opened the connection); a side that opened it starts TLS first when
 * tls_enable is set. desc names the peer in log messages.
 *
 * @return 1 if the connection was taken over, 0 if rejected (caller closes it).
 */
extern int link_adopt(struct hub_info* hub, struct net_connection* con, int is_client, const char* desc);

/**
 * Start hub-to-hub linking: initiate the outbound link if link_peer is set
 * (requires link_secret). Incoming links arrive on the normal hub port and are
 * detected by probe.c. No-op when link_peer is not configured.
 */
extern void link_start(struct hub_info* hub);

/**
 * Tear down the link listener and all active links.
 */
extern void link_stop(struct hub_info* hub);

#endif /* HAVE_UHUB_LINK_H */
