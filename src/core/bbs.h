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

#ifndef HAVE_UHUB_BBS_H
#define HAVE_UHUB_BBS_H

#include <stddef.h>
#include <time.h>

#include "util/credentials.h"

struct adc_message;
struct bbs_entry;
struct bbs_index;
struct hub_config;
struct hub_info;
struct hub_user;
struct linked_list;

/**
 * BBS0: bulletin boards.
 *
 * A board is the unit of subscription, of permission and of ordering. This
 * header covers the boards themselves -- what they are and who may do what on
 * them. The index of posts on a board lives in bbs_index.h, and the protocol
 * that carries them is in the bbs_handle_* functions further down.
 */

/** Board names are protocol text: 1-64 characters of [A-Za-z0-9._-]. */
#define BBS_MAX_BOARD_NAME 64

/**
 * A permission on a board. The value is the index into bbs_board::cred, and
 * (1 << value) is the matching bit of the "PE" field on the wire -- so
 * bbs_perm_post is index 1 and PE bit 2, and so on.
 */
enum bbs_permission
{
	bbs_perm_subscribe = 0,    /**<< Subscribe to the board and receive its index entries. */
	bbs_perm_post = 1,         /**<< Post a new thread. */
	bbs_perm_reply = 2,        /**<< Reply to an existing post. */
	bbs_perm_withdraw_own = 3, /**<< Withdraw a post of one's own. */
	bbs_perm_withdraw_any = 4, /**<< Withdraw any post on the board. */
	bbs_perm_count = 5
};

/**
 * Sentinel for "nobody holds this permission, whatever their credentials".
 *
 * auth_cred_none cannot be used for that: it is the *lowest* credential, and
 * permissions are granted by "required <= held", so it would grant the
 * permission to everyone rather than to no one.
 */
#define BBS_CRED_NEVER (-1)

struct bbs_board
{
	char name[BBS_MAX_BOARD_NAME + 1]; /**<< Board name ("BD"). */
	char* title;                       /**<< Human-readable title ("NI"), or NULL. */
	char* description;                 /**<< Human-readable description ("DE"), or NULL. */
	size_t max_size;                   /**<< Largest post document accepted, in bytes ("MS"). */
	int replay_days;                   /**<< Days of backlog the hub will replay; 0 = no age limit. */
	int cred[bbs_perm_count];           /**<< Credential required per permission, or BBS_CRED_NEVER. */
};

struct bbs_handle
{
	struct linked_list* boards; /**<< struct bbs_board*, in the order they were configured. */
	struct bbs_index* index;    /**<< The post index (see bbs_index.h). */
};

/**
 * The oldest timestamp the hub will replay on a board -- the "OT" of the board
 * descriptor.
 *
 * This is the later of the board's replay_days cutoff and the oldest entry it
 * still holds, so that OT never promises more than the index can deliver.
 *
 * @param now the current time.
 */
extern time_t bbs_board_oldest_replay(struct bbs_handle* handle, const struct bbs_board* board, time_t now);

/**
 * Load the bulletin board configuration.
 *
 * @param config the hub configuration.
 * @param out receives the handle, or NULL when bulletin boards are disabled.
 * @return 0 on success (including when disabled), -1 when the configuration is
 *         broken and the hub must not start.
 */
extern int bbs_initialize(struct hub_config* config, struct bbs_handle** out);

/**
 * Release a handle returned by bbs_initialize(). Tolerates NULL.
 */
extern void bbs_shutdown(struct bbs_handle* handle);

/**
 * Look up a board by name. Board names are case-sensitive.
 *
 * @return the board, or NULL if there is none by that name.
 */
extern struct bbs_board* bbs_board_find(struct bbs_handle* handle, const char* name);

/**
 * @return 1 if @p name is a syntactically valid board name, 0 otherwise.
 */
extern int bbs_board_name_is_valid(const char* name);

/**
 * Compute the "PE" bitmask a session holds on a board.
 *
 * PE tells a client what to offer the user; it is not a security boundary, so
 * every operation is re-checked against this when it arrives.
 *
 * A session that may not subscribe holds nothing at all: the hub never tells it
 * the board exists, so 0 is returned rather than the remaining bits.
 *
 * @return the sum of the ADC_BBS_PERM_* bits granted to @p credentials.
 */
extern int bbs_board_permissions(const struct bbs_board* board, enum auth_credentials credentials);

/**
 * Parse one line of the boards configuration file.
 *
 * Exposed for the benefit of the tests; bbs_initialize() drives it over the
 * whole file. A blank or comment-only line yields NULL with @p *error set to 0.
 *
 * @param line the line to parse. Not modified.
 * @param error set to 1 if the line was malformed, 0 otherwise.
 * @return a newly allocated board, or NULL. Free with bbs_board_free().
 */
extern struct bbs_board* bbs_board_parse(const char* line, int* error);

/**
 * Free a board returned by bbs_board_parse(). Tolerates NULL.
 */
extern void bbs_board_free(struct bbs_board* board);

/**
 * @return 1 if this hub serves bulletin boards.
 */
extern int bbs_is_enabled(struct hub_info* hub);

/**
 * Send the board descriptor ("BBD") for one board to one session.
 *
 * The descriptor states what the *receiving session* may do, so it is built per
 * user rather than cached. Sending is silently skipped where the session holds
 * no permission on the board: withholding the descriptor is the whole of the
 * mechanism for hiding a board.
 */
extern void bbs_send_board_descriptor(struct hub_info* hub, struct hub_user* user,
                                      const struct bbs_board* board);

/**
 * Send a descriptor for every board this session may subscribe to.
 *
 * Called as the session enters the NORMAL state, following the pattern by which
 * a hub sends the INF of every user at login. A session that did not offer
 * BBS0 in its SUP receives nothing.
 */
extern void bbs_send_board_list(struct hub_info* hub, struct hub_user* user);

/**
 * A session's standing request to receive a board's index entries.
 *
 * The cursor is the point the session has been sent up to. It exists so that a
 * re-subscription can be told from a fresh one; the stream itself needs no
 * state, because an accepted post goes out to every subscriber as it arrives.
 */
struct bbs_subscription
{
	struct bbs_board* board;
	time_t cursor;
};

/**
 * Handle an "HBBL": subscribe to a board, resume from a timestamp, cancel a
 * subscription, or ask for one index entry.
 *
 * @return 0 on success, -1 if the command was refused (a status message has
 *         then been sent to the user).
 */
extern int bbs_handle_subscribe(struct hub_info* hub, struct hub_user* user,
                                struct adc_message* cmd);

/**
 * Handle an "HBBP": submit a post, or withdraw one.
 *
 * @return 0 on success, -1 if the command was refused (a status message has
 *         then been sent to the user).
 */
extern int bbs_handle_post(struct hub_info* hub, struct hub_user* user,
                           struct adc_message* cmd);

/**
 * Drop every subscription a session holds. Called when the user goes away.
 */
extern void bbs_user_unsubscribe_all(struct hub_user* user);

/**
 * @return the session's subscription to @p board, or NULL.
 */
extern struct bbs_subscription* bbs_user_subscription(struct hub_user* user,
                                                      const struct bbs_board* board);

/**
 * Send one index entry ("BBL") to a session, or a tombstone where the entry is
 * withdrawn.
 */
extern void bbs_send_entry(struct hub_info* hub, struct hub_user* user,
                           const char* board, const struct bbs_entry* entry);

/**
 * Drop every session's subscription to a board, for when the board goes away
 * or a session loses the permission to read it.
 */
extern void bbs_cancel_subscriptions(struct hub_info* hub, const struct bbs_board* board);

#endif /* HAVE_UHUB_BBS_H */
