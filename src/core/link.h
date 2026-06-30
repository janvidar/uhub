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

#include "adc/adctypes.h"

/*
 * Hub-to-hub link authentication primitives.
 *
 * Two hubs establish a link by proving knowledge of a shared secret
 * (the `link_secret` config) via a nonce challenge-response, rather than
 * sending the secret over the wire. The response is base32(tiger(secret ||
 * nonce)) -- the same keyed-hash construction HBRI uses for its tokens.
 *
 * These primitives are pure (no hub state, no networking) so they can be unit
 * tested directly; the networked handshake in link.c (B1b) is built on top.
 *
 * TODO (auth hardening): the shared `link_secret` is a plaintext config value
 * with the same drawbacks as plaintext passwords -- one secret for all peers,
 * no per-hub identity, no rotation/revocation, readable by anyone with config
 * access. Since links already run over TLS, the better long-term mechanism is
 * mutual-TLS with per-peer certificate pinning (each hub has a keypair; peers
 * pin each other's cert fingerprint) -- per-hub identity, revocable, no shared
 * secret on the wire or at rest. An asymmetric keypair challenge (e.g. ed25519
 * signed nonce) is an alternative. The shared-secret scheme here is the v1
 * baseline; see the plan's B1 note.
 */

/* base32(tiger(...)) is a 39-char value, like a CID. */
#define LINK_AUTH_RESPONSE_LEN MAX_CID_LEN
#define LINK_NONCE_LEN         MAX_CID_LEN

/**
 * Compute the auth response for (secret, nonce): base32(tiger(secret || nonce)).
 * @param out must be at least LINK_AUTH_RESPONSE_LEN + 1 bytes; NUL-terminated.
 */
extern void link_auth_response(const char* secret, const char* nonce, char* out);

/**
 * Constant-time verify that `response` matches the expected response for
 * (secret, nonce). Returns 1 if valid, 0 otherwise.
 */
extern int link_auth_verify(const char* secret, const char* nonce, const char* response);

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
 */
extern void link_broadcast_ban(struct hub_info* hub, const char* cid, const char* nick);

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
