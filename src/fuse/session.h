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

#ifndef HAVE_UHUB_FUSE_SESSION_H
#define HAVE_UHUB_FUSE_SESSION_H

#include "system.h"
#include "adc/adctypes.h"
#include "fuse/render.h"

#include "network/ipcalc.h"
#include "tools/adcclient.h"

struct fs_config;

struct ADC_client;
struct fs_bridge;
struct fs_chatlog;
struct fs_roster;
struct fs_transfer;
struct timeout_evt;

/**
 * The hub, as one mount sees it.
 *
 * Everything here belongs to the ADC thread. A FUSE thread reaches it only
 * through fs_bridge_submit(), never directly, so nothing in here is locked.
 *
 * The session logs in as an ordinary client -- it is one -- and keeps what the
 * hub tells it: the roster, the hub's own INF, and whether the connection is
 * encrypted. When the connection drops the roster is emptied rather than kept
 * as a last known state: users/ would otherwise list people who are not there,
 * and a stale directory that looks live is worse than an empty one.
 */

#define FS_RECONNECT_MIN 1
#define FS_RECONNECT_MAX 60

enum fs_session_state
{
	FS_SESSION_OFFLINE = 0,
	FS_SESSION_CONNECTING,
	FS_SESSION_ONLINE,
	FS_SESSION_FATAL,      /** A pinned keyprint did not match. Do not retry. */
};

struct fs_session
{
	struct ADC_client* client;
	struct fs_bridge* bridge;
	struct fs_roster* roster;

	char* address;         /** The adc:// or adcs:// URL, as configured. */
	char* nick;
	char* password;        /** May be NULL. */

	enum fs_session_state state;

	/* What the hub said about itself, for hub/. */
	char* hub_name;
	char* hub_description;
	char* hub_version;
	char* tls_version;     /** NULL while the connection is plaintext. */
	char* tls_cipher;

	/* What has been said. main is the hub's chat; private is what was said to
	   us and what we said to somebody, which would otherwise be a
	   conversation with only one side of it written down. */
	struct fs_chatlog* chat_main;
	struct fs_chatlog* chat_private;

	/* Downloads, the cache they land in, and the port peers dial to deliver
	   them. NULL when the mount was built without a transfer port. */
	struct fs_transfer* transfer;

	struct timeout_evt* timer;
	size_t backoff;

	/** Set when the ADC thread should leave its loop. */
	int running;

	time_t mounted;        /** For the timestamps on synthetic directories. */
};

/**
 * Build the session, without connecting anything.
 *
 * @p config is read and not retained; the strings it needs are copied.
 * @return NULL on OOM or an unusable configuration.
 */
extern struct fs_session* fs_session_create(const struct fs_config* config);

/**
 * Give the session its transfer machinery, before fs_session_start().
 *
 * Separate from creation because the two need each other: the transfer layer
 * asks the hub through the session, and the session cannot announce what it
 * supports until the transfer layer has told it which port and protocols are
 * real. The session takes ownership.
 */
extern void fs_session_set_transfer(struct fs_session* session, struct fs_transfer* transfer);

extern void fs_session_destroy(struct fs_session* session);

/** Start connecting. @return 1 on success. */
extern int fs_session_start(struct fs_session* session);

/**
 * Run the event loop until fs_session_stop() is called. This is the ADC
 * thread's whole life.
 */
extern void fs_session_run(struct fs_session* session);

/**
 * Ask the loop to stop. Safe to call from another thread -- it only sets a
 * flag and wakes the loop through the bridge.
 */
extern void fs_session_stop(struct fs_session* session);

/**
 * The name hub/state goes by: "offline", "connecting", "online" or "failed".
 * "failed" is terminal -- a pinned keyprint that did not match is not retried.
 */
extern const char* fs_session_state_name(const struct fs_session* session);

/** Longest chat message the mount will send. */
#define FS_CHAT_MAX 1024

/**
 * Say @p text in the hub's main chat.
 * @return 0, or a negative errno (-ENOTCONN when not logged in).
 */
extern int fs_session_send_chat(struct fs_session* session, const char* text);

/**
 * Send @p text privately to the user with @p cid.
 * @return 0, -ENOENT when nobody on the hub has that CID, or -ENOTCONN.
 */
extern int fs_session_send_pm(struct fs_session* session, const char* cid, const char* text);

/**
 * Enough of another user to dial them.
 *
 * The address is the one the *hub* reported, which the hub overwrote with the
 * one it observed (check_network() in src/core/inf.c) -- never one taken out of
 * a CTM, and never one the peer chose for itself.
 */
struct fs_peer
{
	sid_t sid;
	char cid[MAX_CID_LEN + 1];
	char support[ADC_SUPPORT_MAX];
	struct ip_addr_encap addr;
};

/** @return 1 if that SID is on the hub and has an address we can dial. */
extern int fs_session_peer_by_sid(struct fs_session* session, sid_t sid, struct fs_peer* out);

/**
 * Ask the hub who has @p tth, as a BSCH naming that hash and nothing else.
 * @return 1 if it was sent.
 */
extern int fs_session_send_search_tth(struct fs_session* session, const char* tth, const char* token);

/**
 * Tell @p to to connect to us on @p port and quote @p token.
 *
 * The mount is the one listening, so this is how it asks for a file: the peer
 * dials in, and the transfer is requested over that connection. It is also the
 * only arrangement that works when the peer is passive.
 *
 * @return 1 if it was sent.
 */
extern int fs_session_send_ctm(struct fs_session* session, sid_t to, const char* protocol,
                               uint16_t port, const char* token);

/** Our own CID, as the hub knows us. Never NULL once logged in. */
extern const char* fs_session_own_cid(struct fs_session* session);

/** Fill in @p ctx with the parts of the session the renderer reads. */
extern void fs_session_render_ctx(struct fs_session* session, struct fs_render_ctx* ctx);

#endif /* HAVE_UHUB_FUSE_SESSION_H */
