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

#ifndef HAVE_UHUB_SEEDER_COMMANDS_H
#define HAVE_UHUB_SEEDER_COMMANDS_H

#include <stddef.h>

#include "adc/adctypes.h"

/**
 * Operator administration of the seed cache.
 *
 * While the cache lived in the hub these were hub commands (!blobstats,
 * !blobinfo, ...). The seeder is a bot on the hub instead, so the same
 * operations arrive as private messages to it: "stats", "list 50",
 * "block <tth> dmca", with the '!' that a hub command would need being
 * optional here.
 *
 * The operator is holding other people's content on their own disk, so
 * inspecting it, removing it and refusing it again afterwards has to be a first
 * class operation -- info() in particular is what answers a takedown request
 * months later, which is why it reports provenance and not just size.
 *
 * Everything here is single threaded and runs on the daemon's main loop; no
 * call blocks. Replies are handed back one line at a time through a callback,
 * so this module never needs to know how a message reaches the hub.
 */

struct seed_bbs;
struct seed_cache;
struct seed_commands;

/** Longest verb accepted. No real verb comes close; see seed_command_parse(). */
#define SEED_COMMAND_VERB_MAX 31

/** Default and largest number of entries "list" will report. */
#define SEED_COMMAND_LIST_DEFAULT 20
#define SEED_COMMAND_LIST_MAX 200

/**
 * ADC CT bits, as they appear in a user's INF. These are flags and not a rank:
 * an admin is 20 (16|4) and a super user is 12 (8|4), so both carry the
 * operator bit and "operator or above" is a mask test rather than an equality
 * test. Comparing for equality would refuse an admin.
 */
#define SEED_CT_BOT        1
#define SEED_CT_REGISTERED 2
#define SEED_CT_OPERATOR   4
#define SEED_CT_SUPER      8
#define SEED_CT_ADMIN      16
#define SEED_CT_HUB        32

/** Bits a user must carry to run an operator command, and an admin one. */
#define SEED_CRED_OPERATOR (SEED_CT_OPERATOR)
#define SEED_CRED_ADMIN    (SEED_CT_OPERATOR | SEED_CT_ADMIN)

/** Sends one line of reply back to the user who asked. */
typedef void (*seed_command_reply)(void* ptr, sid_t to, const char* text);

extern struct seed_commands* seed_commands_create(struct seed_cache* cache, seed_command_reply reply, void* ptr);

/**
 * Give the command handler the bulletin board engine, so "boards" can report on
 * it. Borrowed, and must outlive the handler.
 *
 * Set separately rather than passed to seed_commands_create() because the board
 * engine is built after the command handler: it needs the client-to-client
 * policy, which needs the CID the hub connection settles on.
 *
 * Without it, "boards" reports that board seeding is not enabled.
 */
extern void seed_commands_set_bbs(struct seed_commands* cmds, struct seed_bbs* bbs);
extern void seed_commands_destroy(struct seed_commands* cmds);

/**
 * Handle a private message. @p client_type is the sender's CT bits.
 *
 * @return 1 if the text was a command (a reply has been sent), 0 if it was not
 *         addressed to us as one and should be ignored.
 */
extern int seed_commands_handle(struct seed_commands* cmds, sid_t from, int client_type, const char* text);

/**
 * A command line split into its verb and the rest. @c args points into the
 * caller's string and is never NULL; it is "" when nothing followed the verb.
 */
struct seed_command_line
{
	char verb[SEED_COMMAND_VERB_MAX + 1];
	const char* args;
};

/**
 * Split a private message into a verb and its arguments. Pure: no I/O, no
 * global state, so it is driven directly by the unit tests.
 *
 * Leading white space and one optional '!' or '+' prefix are skipped, and the
 * verb is folded to lower case. A verb longer than SEED_COMMAND_VERB_MAX is
 * truncated, which cannot collide with a real verb because every real verb is
 * far shorter.
 *
 * @return 1 when a verb was found, 0 for an empty or white space only message,
 *         which is not a command and must be ignored.
 */
extern int seed_command_parse(const char* text, struct seed_command_line* out);

/** Outcome of the authorisation check, decided before a command runs. */
enum seed_command_access
{
	SEED_ACCESS_OK = 0,  /** Known verb, and this user may run it. */
	SEED_ACCESS_DENIED,  /** Refused. Says nothing about whether the verb exists. */
	SEED_ACCESS_UNKNOWN  /** No such verb, told to a user who could have run one. */
};

/**
 * Decide whether @p client_type may run @p verb.
 *
 * Refusal outranks an unknown verb on purpose: a user who could not have run
 * any command gets SEED_ACCESS_DENIED whether the verb exists or not, so
 * probing for command names learns nothing.
 */
extern enum seed_command_access seed_command_check_access(const char* verb, int client_type);

/**
 * Clamp the argument of "list" to a sane count. A missing, malformed,
 * non-positive or absurd count comes back as the default or the maximum rather
 * than as an error.
 */
extern int seed_command_parse_limit(const char* args);

/**
 * Copy @p text into @p out with everything that is not printable replaced by a
 * space, and truncate it to fit.
 *
 * Names, media types and CIDs in the cache came from a peer. A reply is a chat
 * message and is line oriented, so a newline in a stored name would otherwise
 * let a crafted file name forge extra lines of operator output. Never fails;
 * an empty or NULL string becomes "-".
 */
extern void seed_command_sanitize(const char* text, char* out, size_t outlen);

#endif /* HAVE_UHUB_SEEDER_COMMANDS_H */
