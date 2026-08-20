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
 * The uhub-seeder daemon's connection to its hub.
 *
 * The seeder is an ordinary ADC client: it logs in as a registered bot with
 * the configured nick and password and then behaves like any other user on the
 * hub. This module owns that one connection and everything that follows from
 * it -- the login, the reconnect loop, the roster of who else is online, and
 * the dispatch of the handful of events the seeder actually reacts to (chat,
 * TTH searches, CTM and RCM).
 *
 * It is deliberately the only part of the daemon that knows about
 * src/tools/adcclient.c. Everything above it (the cache, the client-connection
 * layer, the command handlers) sees hub users as struct seed_user and sends
 * through the seed_hub_send_*() calls below, so none of them has to care that
 * the transport delivers raw struct adc_message payloads.
 *
 * Ownership rule for every callback in struct seed_hub_callbacks: all pointers
 * handed to a callback -- including the struct seed_user and every string --
 * belong to this module and are valid only for the duration of the call. A
 * callback that needs to keep anything must copy it. In particular a
 * struct seed_user* is not stable: it may be freed the moment that user parts.
 */

#ifndef HAVE_UHUB_SEEDER_HUBCONN_H
#define HAVE_UHUB_SEEDER_HUBCONN_H

#include "system.h"
#include "adc/adctypes.h"
#include "adc/sid.h"

struct adc_message;
struct seed_config;
struct seed_hub;
struct seed_roster;

/**
 * ADC CT (client type) bits, as they appear in a BINF. A user's CT is a bit
 * mask, so an operator that is also a bot carries both bits; test with '&',
 * never with '=='.
 */
#define SEED_CT_BOT        1
#define SEED_CT_REGISTERED 2
#define SEED_CT_OPERATOR   4
#define SEED_CT_SUPER      8
#define SEED_CT_ADMIN      16
#define SEED_CT_HUB        32

/** Room for an SU feature list, including the terminating NUL. */
#define SEED_SUPPORT_MAX 64

/** Longest client-to-client token accepted from, or sent to, a peer. */
#define SEED_TOKEN_MAX 64

/** Longest CTM/RCM protocol string accepted, e.g. "ADCS/0.10". */
#define SEED_PROTOCOL_MAX 31

/**
 * Longest board name, excluding NUL. Fixed by BBS0, which also restricts the
 * character set to [A-Za-z0-9._-] -- a name is protocol text and never a path
 * component, and the set permits '.', so ".." is a legal board name.
 */
#define SEED_BBS_BOARD_MAX 64

/** Buffer for a subject, including NUL. Matches the post document's own bound. */
#define SEED_BBS_SUBJECT_MAX 512

/* Also defined by seeder/cache.h; identical, and guarded so hubconn.h can be
   included without dragging the cache in. */
#ifndef SEED_TTH_STR_LEN
#define SEED_TTH_STR_LEN 39  /** Length of a base32 TTH, excluding NUL. */
#endif

/** First reconnect delay, in seconds. */
#define SEED_RECONNECT_MIN 1

/** Longest reconnect delay, in seconds. The backoff doubles up to this. */
#define SEED_RECONNECT_MAX 60

/**
 * One other user on the hub, as far as the seeder cares.
 *
 * The CID and the address are what make this worth keeping: to fetch a file
 * from whoever posted it the seeder needs to know who they are and where they
 * are, and the hub only says so once, in the BINF that announced them.
 */
struct seed_user
{
	sid_t sid;
	char cid[MAX_CID_LEN + 1];
	char nick[MAX_NICK_LEN + 1];
	char address[INET6_ADDRSTRLEN + 1];
	int  client_type;      /** CT bits, see SEED_CT_*; 0 when the user sent none. */

	/**
	 * The user's SU feature list, verbatim ("TCP4,UDP4,ADCS"), or "" if it
	 * advertised none. What decides whether a transfer to this peer can be
	 * encrypted, and which revision of ADCS to name when asking for one.
	 */
	char support[SEED_SUPPORT_MAX];
};

/**
 * A BBS0 board, as the hub described it in an IBBD.
 *
 * Every field here is the hub's own testimony and can be checked against
 * nothing. @c permissions in particular is what the hub says this session may
 * do, is stated per session, and is not a security boundary: an operation it
 * appears to allow may still be refused when it arrives.
 */
struct seed_bbs_board
{
	char board[SEED_BBS_BOARD_MAX + 1];   /** BD. The board's identity. */
	char name[SEED_BBS_SUBJECT_MAX];      /** NI, a human readable title. "" when absent. */
	unsigned int permissions;             /** PE, a bitmask; see ADC_BBS_PERM_*. */
	uint64_t max_size;                    /** MS, the largest post document the board accepts. */
	uint64_t newest;                      /** TS of the newest entry, 0 on an empty board. */
	uint64_t oldest;                       /** OT, the oldest timestamp the hub will replay. */
	uint64_t num_posts;                   /** NP, excluding tombstones. 0 when absent. */
	int removed;                          /** 1 when RM1 says the board is gone. */
};

/**
 * One index entry, as the hub sent it in an IBBL.
 *
 * A tombstone -- an entry withdrawn, carrying RM1 -- is required to carry only
 * TR, BD and TS, so every other field may legitimately be empty on one. Check
 * @c removed before reading anything else.
 *
 * The fields copied out of the document (@c parent, @c subject and the author's
 * claimed @c author_cid) are hints until the document has been fetched and
 * verified, at which point the document is authoritative and these are not.
 */
struct seed_bbs_entry
{
	char tth[SEED_TTH_STR_LEN + 1];       /** TR. The post's identity. */
	uint64_t size;                        /** SI, as declared by the author. Not a bound. */
	char board[SEED_BBS_BOARD_MAX + 1];   /** BD. */
	char author_cid[MAX_CID_LEN + 1];     /** ID, the CID the hub accepted the post from. */
	char nick[MAX_NICK_LEN + 1];          /** NI, informative. Never used to attribute a post. */
	char parent[SEED_TTH_STR_LEN + 1];    /** PA, "" in a post that starts a thread. */
	char thread[SEED_TTH_STR_LEN + 1];    /** TH, derived by the hub and never verified. */
	char subject[SEED_BBS_SUBJECT_MAX];   /** SJ, "" when absent. */
	uint64_t timestamp;                   /** TS. The board's order, and the resume cursor. */
	int removed;                          /** 1 when this is a tombstone. */
};

/**
 * A search result, as extracted from a DRES.
 *
 * The seeder answers searches and also issues them, to find a peer holding a
 * post document whose author has left. Only a result naming a TTH is of any use
 * for that, so a result without one never reaches a callback.
 */
struct seed_result
{
	sid_t from;                           /** The SID that answered. */
	char tth[SEED_TTH_STR_LEN + 1];       /** TR. */
	uint64_t size;                        /** SI, 0 when absent. */
	char token[SEED_TOKEN_MAX + 1];       /** TO, "" when the responder echoed none. */
};

/**
 * What the owner of the connection wants to hear about. Every member may be
 * NULL, in which case that event is dropped.
 */
struct seed_hub_callbacks
{
	void (*on_logged_in)(void* ptr);
	void (*on_disconnected)(void* ptr);

	/** Chat. text is already unescaped. private_msg is 1 for a PM addressed to us. */
	void (*on_chat)(void* ptr, const struct seed_user* from, const char* text, int private_msg);

	/** A TTH search. tth is SEED_TTH_STR_LEN base32 chars; token may be "". */
	void (*on_search)(void* ptr, const struct seed_user* from, const char* tth, const char* token);

	/** CTM: the peer wants us to connect to it. */
	void (*on_connect_req)(void* ptr, const struct seed_user* from, const char* protocol, uint16_t port, const char* token);

	/** RCM: the peer wants us to send it a CTM. */
	void (*on_revconnect_req)(void* ptr, const struct seed_user* from, const char* protocol, const char* token);

	/** A DRES answering one of our own searches. */
	void (*on_search_result)(void* ptr, const struct seed_result* result);

	/**
	 * A BBS0 board descriptor. Sent once per board after login, and again
	 * whenever any field changes -- including when this session's permissions
	 * change, or the board goes away (@c removed).
	 */
	void (*on_bbs_board)(void* ptr, const struct seed_bbs_board* board);

	/** A BBS0 index entry, or a tombstone when @c removed is set. */
	void (*on_bbs_entry)(void* ptr, const struct seed_bbs_entry* entry);
};

/**
 * Create the hub connection. Nothing is connected until seed_hub_start().
 *
 * The configuration is copied, so @p config need not outlive the call. @p cb is
 * copied too; @p ptr is handed back to every callback untouched.
 *
 * @return the connection, or NULL if it could not be created.
 */
extern struct seed_hub* seed_hub_create(const struct seed_config* config, const struct seed_hub_callbacks* cb, void* ptr);

/**
 * Disconnect (if connected), cancel the reconnect timer and release everything.
 * Safe on NULL.
 *
 * Must not be called from inside one of the callbacks: the connection is still
 * dispatching at that point. Set a flag and destroy it from the event loop.
 */
extern void seed_hub_destroy(struct seed_hub* hub);

/**
 * Begin connecting. From here on the connection maintains itself: a failed
 * connect, a rejected login or a hub that goes away are all retried with
 * exponential backoff (SEED_RECONNECT_MIN doubling to SEED_RECONNECT_MAX,
 * reset on a successful login).
 *
 * One condition is not retried: a hub that fails the keyprint pinned in
 * seed_hub_url is either misconfigured or being impersonated, and neither
 * mends itself with time. The connection is dropped, the reason is logged at
 * FATAL, and no further attempt is made until seed_hub_start() is called again.
 *
 * A seed_hub_url with no "?kp=" is not verified at all -- see the security
 * contract in tools/adcclient.h -- and warns once per attempt instead.
 *
 * Requires the network backend to be up (net_initialize()), since the reconnect
 * timer lives on its timeout queue.
 *
 * @return 1 if the first attempt was started, 0 if the configuration is unusable.
 */
extern int seed_hub_start(struct seed_hub* hub);

/**
 * The directory every cached file is published under, as it appears in the FN
 * of a search result: "/seed/<name>".
 *
 * Invented, because the seeder has no share to mirror and clients cope badly
 * with a filename carrying no path at all. It names nothing on disk and is
 * never used to look anything up -- a download asks for its file by TTH.
 */
#define SEED_SHARE_DIR "seed"

/**
 * Set the SU feature list the seeder advertises, e.g. "TCP4,ADCS".
 *
 * This is how the rest of the hub learns the seeder is worth dialling. Without
 * TCP4 (or TCP6) it is taken for a passive client and never connected to, which
 * leaves it unable to serve the passive users it exists for; without ADCS no
 * client has reason to offer an encrypted transfer.
 *
 * Claim only what is true. ADCS belongs here only when the transfer port has a
 * certificate to complete a handshake with, and TCP4/TCP6 only for a family the
 * listener is actually bound to -- a peer that acts on a false claim gets a
 * transfer that never connects rather than one that falls back.
 *
 * Applied to every subsequent connection attempt, so it must be set before
 * seed_hub_start(); an open connection keeps the SU it logged in with.
 *
 * @return 1 if stored, 0 for a NULL hub or a list that does not fit.
 */
extern int seed_hub_set_support(struct seed_hub* hub, const char* su);

/**
 * Stop connecting and drop the connection, without freeing anything. A stopped
 * connection never reconnects on its own; seed_hub_start() resumes it.
 */
extern void seed_hub_stop(struct seed_hub* hub);

/** 1 while the login has completed and messages may be sent. */
extern int seed_hub_is_logged_in(struct seed_hub* hub);

/** Our own SID on the hub, or 0 when not logged in. */
extern sid_t seed_hub_own_sid(struct seed_hub* hub);

/**
 * Our own CID -- the one clients see in the user list and pin against a client
 * connection. Stable across restarts (see the PID file, below). Never NULL.
 */
extern const char* seed_hub_own_cid(struct seed_hub* hub);

/**
 * Look a user up in the roster. The result is owned by the roster and is
 * invalidated when that user parts or updates, so it must not be retained
 * across a return to the event loop.
 *
 * @return the user, or NULL if no such user is online.
 */
extern const struct seed_user* seed_hub_user_by_sid(struct seed_hub* hub, sid_t sid);
extern const struct seed_user* seed_hub_user_by_cid(struct seed_hub* hub, const char* cid);

/** Number of other users currently on the hub (excluding ourselves). */
extern size_t seed_hub_user_count(struct seed_hub* hub);

/**
 * Answer a TTH search with a DRES. @p name is escaped internally; @p token is
 * the searcher's TO value and is echoed back when it is not empty.
 *
 * @return 1 if the reply was queued, 0 if not logged in or the arguments are
 *         unusable (a TTH that is not SEED_TTH_STR_LEN base32 characters).
 */
extern int seed_hub_send_result(struct seed_hub* hub, sid_t to, const char* tth, uint64_t size,
	const char* name, int slots, const char* token);

/** Tell a peer to connect to us on @p port. @return 1 if queued. */
extern int seed_hub_send_ctm(struct seed_hub* hub, sid_t to, const char* protocol, uint16_t port, const char* token);

/** Ask a peer to send us a CTM. @return 1 if queued. */
extern int seed_hub_send_rcm(struct seed_hub* hub, sid_t to, const char* protocol, const char* token);

/** Send a private message. @p text is escaped internally. @return 1 if queued. */
extern int seed_hub_send_pm(struct seed_hub* hub, sid_t to, const char* text);

/**
 * Did this hub announce BBS0 in its ISUP?
 *
 * The hub's announcement is what authorises the extension, so nothing may send
 * BBL until this answers 1. It is per connection and is not cached across a
 * reconnect, and a hub may withdraw the feature mid-session with "RMBBS0",
 * after which every subscription is cancelled and this answers 0 again.
 */
extern int seed_hub_bbs_available(struct seed_hub* hub);

/**
 * Subscribe to @p board, replaying every entry from @p from_ts onwards and then
 * receiving entries as the hub accepts them.
 *
 * Pass the highest timestamp already seen, *not* one second later: timestamps
 * are not unique, and a cursor advanced past the last entry received would skip
 * a post accepted in the same second. The cost is that the final second arrives
 * twice, which the caller discards by keying on TR.
 *
 * A second subscription to a board replaces the first and replays from the newly
 * requested timestamp.
 *
 * @return 1 if the request was queued, 0 when not logged in, the hub never
 *         announced BBS0, or the board name is not one BBS0 permits.
 */
extern int seed_hub_send_bbs_subscribe(struct seed_hub* hub, const char* board, uint64_t from_ts);

/** Cancel a subscription (HBBL with RM1). @return 1 if queued. */
extern int seed_hub_send_bbs_cancel(struct seed_hub* hub, const char* board);

/**
 * Ask for one entry by hash rather than subscribing (HBBL with TR).
 *
 * This is a question, not a subscription: the hub answers with the single
 * matching entry, or with status code 76 where it holds none, and the session's
 * subscriptions are untouched either way.
 *
 * @return 1 if queued.
 */
extern int seed_hub_send_bbs_request(struct seed_hub* hub, const char* board, const char* tth);

/**
 * Search the hub for a file by exact TTH (a BSCH carrying TR).
 *
 * This is how a post document is found once its author has gone: the hub serves
 * no post bodies, so the only other source is whichever client has read it and
 * kept it. Answers arrive as on_search_result().
 *
 * @param token echoed by responders in TO, so an answer can be matched to the
 *              question. May be NULL or "" for none.
 * @return 1 if the search was queued.
 */
extern int seed_hub_send_search_tth(struct seed_hub* hub, const char* tth, const char* token);


/* -------------------------------------------------------------------------
 * The pieces below are the parsing and bookkeeping this module is built from.
 * They are exposed so the test suite can drive them without a socket; nothing
 * outside hubconn.c and the tests is expected to call them.
 * ------------------------------------------------------------------------- */

/** A TTH search, as extracted from a BSCH/FSCH. */
struct seed_search
{
	char tth[SEED_TTH_STR_LEN + 1];
	char token[SEED_TOKEN_MAX + 1];   /** "" when the searcher sent no TO. */
};

/** A CTM or RCM, as extracted from the wire. */
struct seed_connect
{
	char     protocol[SEED_PROTOCOL_MAX + 1];
	uint16_t port;                    /** 0 for an RCM, which names no port. */
	char     token[SEED_TOKEN_MAX + 1];
};

/**
 * Extract the TTH and token from a search.
 *
 * Only a search carrying a TR argument is a search a seed cache can answer --
 * there is no substring index over the cache -- so anything else is rejected
 * here rather than being surfaced and dropped later.
 *
 * @return 1 if @p out was filled, 0 if the message carries no usable TR.
 */
extern int seed_hub_parse_search(struct adc_message* msg, struct seed_search* out);

/**
 * Parse a CTM ("<protocol> <port> <token>") or an RCM ("<protocol> <token>").
 * A missing field, an over-long protocol or token, or a port outside 1..65535
 * is a parse failure: junk is refused here so no caller has to re-check it.
 *
 * @return 1 if @p out was filled, 0 on a malformed message.
 */
extern int seed_hub_parse_ctm(struct adc_message* msg, struct seed_connect* out);
extern int seed_hub_parse_rcm(struct adc_message* msg, struct seed_connect* out);

/**
 * Extract a board descriptor from an IBBD, or an index entry from an IBBL.
 *
 * Both refuse an entry missing a field BBS0 makes REQUIRED, or carrying one
 * that is malformed -- a board name outside the permitted character set, a TTH
 * that is not 39 base32 characters, a non-numeric timestamp. A tombstone is
 * held to the shorter list of fields BBS0 requires of one.
 *
 * @return 1 if @p out was filled, 0 on a message that is not usable.
 */
extern int seed_hub_parse_bbs_board(struct adc_message* msg, struct seed_bbs_board* out);
extern int seed_hub_parse_bbs_entry(struct adc_message* msg, struct seed_bbs_entry* out);

/**
 * Extract a search result from a DRES. Only a result naming a TTH is usable to
 * a content-addressed cache, so anything else is refused here.
 *
 * @return 1 if @p out was filled, 0 otherwise.
 */
extern int seed_hub_parse_result(struct adc_message* msg, struct seed_result* out);

/** 1 if @p board is a name BBS0 permits: 1..64 of [A-Za-z0-9._-]. */
extern int seed_hub_bbs_board_valid(const char* board);

/**
 * The next reconnect delay after @p seconds, in seconds. Pass 0 for the first
 * delay. Doubles from SEED_RECONNECT_MIN and saturates at SEED_RECONNECT_MAX,
 * so it never returns 0 and never busy-loops.
 */
extern unsigned int seed_hub_backoff_next(unsigned int seconds);

/**
 * Build the DRES answering a search. The caller owns the result. @p name is
 * escaped; an empty name falls back to the TTH. @p token is echoed as the TO
 * argument when non-empty.
 *
 * @return the message, or NULL if the TTH is not a base32 TTH.
 */
extern struct adc_message* seed_hub_build_result(sid_t from, sid_t to, const char* tth, uint64_t size,
	const char* name, int slots, const char* token);

/**
 * Read the seeder's PID from <cache_dir>/pid, generating and persisting one
 * (mode 0600) on first run.
 *
 * The PID is what fixes the CID, and clients pin the CID they saw in the user
 * list, so it has to survive a restart. It is random rather than derived from
 * the password: a PID is broadcast to the hub at login, so deriving it from a
 * secret would leak that secret.
 *
 * @return 1 on success (@p pid holds MAX_CID_LEN base32 characters), 0 if no
 *         PID could be read or written.
 */
extern int seed_hub_pid_load(const char* cache_dir, char* pid);

/** Convenience predicates over seed_user::client_type. */
extern int seed_user_is_bot(const struct seed_user* user);
extern int seed_user_is_operator(const struct seed_user* user);
extern int seed_user_is_registered(const struct seed_user* user);
extern int seed_user_is_hub(const struct seed_user* user);

/**
 * The roster: who else is on the hub, indexed by SID and by CID.
 *
 * Kept separate from struct seed_hub so it can be tested on its own. Entries
 * are owned by the roster; a pointer returned from it is valid until that user
 * is updated or removed.
 */
extern struct seed_roster* seed_roster_create(void);
extern void seed_roster_destroy(struct seed_roster* roster);

/** Insert @p user, or update the entry that already holds its SID. */
extern const struct seed_user* seed_roster_update(struct seed_roster* roster, const struct seed_user* user);

/** @return 1 if a user was removed, 0 if the SID was not in the roster. */
extern int seed_roster_remove(struct seed_roster* roster, sid_t sid);

extern void seed_roster_clear(struct seed_roster* roster);
extern size_t seed_roster_size(struct seed_roster* roster);
extern const struct seed_user* seed_roster_get_sid(struct seed_roster* roster, sid_t sid);
extern const struct seed_user* seed_roster_get_cid(struct seed_roster* roster, const char* cid);

#endif /* HAVE_UHUB_SEEDER_HUBCONN_H */
