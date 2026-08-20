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

#ifndef HAVE_UHUB_SEEDER_BBS_H
#define HAVE_UHUB_SEEDER_BBS_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "seeder/cache.h"
#include "seeder/hubconn.h"

/**
 * Keeping BBS0 bulletin boards readable.
 *
 * A BBS0 hub holds an index and no bytes. A post is a file named by its Tiger
 * tree hash, and it travels between clients over the ordinary search and
 * transfer machinery -- so a board is only as durable as the clients that
 * happen to still hold its posts. When the author of a thread leaves, and
 * nobody who read it is online, the index still lists the post and nobody can
 * read it.
 *
 * BBS0 says what to do about that in as many words: a hub operator who wants a
 * board to be durable should run a client that subscribes to it and fetches and
 * serves every post. This is that client. Nothing here needs any cooperation
 * from the hub beyond the extension itself, and nothing distinguishes the
 * seeder from any other subscriber.
 *
 * What it does, in order:
 *
 *   1. Offers BBS0 at login, which is what makes the hub send descriptors.
 *   2. Subscribes to every board it is permitted to read, resuming from the
 *      highest timestamp it has already seen on that board.
 *   3. Fetches the document behind every entry -- from the author while they
 *      are still online, and otherwise from whoever answers a search for its
 *      hash.
 *   4. Reads each fetched document and goes after the attachments its body
 *      links to, which are ordinary magnet embeds and outlive a post exactly as
 *      badly as the post outlives its author.
 *   5. Serves all of it by exact hash, for as long as the cache holds it.
 *
 * Automatic fetching is the one thing here a general purpose client must not
 * do. BBS0 tells a client never to fetch merely because an entry arrived,
 * because a prompt fetch identifies a reader who was online and subscribed at
 * that moment, and a board makes that census systematic. The seeder is the
 * deployment the specification carves out for: it is not a reader, it fetches
 * everything without regard to what anyone is reading, and it therefore
 * discloses nothing about any user. What it does disclose is itself, which is
 * the point -- it exists to be the source that is still there.
 *
 * Everything is single threaded and runs on the daemon's main loop. No call
 * blocks on the network; seed_bbs_tick() is where deferred work happens.
 */

struct seed_bbs;
struct seed_cc_policy;
struct seed_config;
struct seed_hub;

/**
 * Boards tracked at once.
 *
 * A board table is filled by the hub, so it needs a ceiling. A hub with more
 * boards than this is not a configuration anybody runs, and the boards past the
 * limit are logged rather than silently ignored.
 */
#define SEED_BBS_MAX_BOARDS 64

/**
 * Outstanding pieces of work: documents to fetch, attachments to fetch, and
 * documents already held whose attachments have not been checked.
 *
 * Bounded because the hub decides how fast entries arrive. When it is full the
 * newest arrival is refused and counted, and the next replay from the board's
 * start picks up whatever was missed -- so a full queue delays work rather than
 * losing it.
 */
#define SEED_BBS_MAX_WANTS 1024

/** Requests in flight at once. Deliberately far below the cache's own ingest
 *  budget, so board seeding never crowds out chat attachments. */
#define SEED_BBS_MAX_INFLIGHT 4

/**
 * Documents read back from the cache per tick, to look at what they link to.
 *
 * This is local work rather than a transfer, so it occupies no request slot and
 * would otherwise be paced by nothing at all: replaying a board whose posts are
 * already held is entirely scans, and without a cap a single tick would read
 * every one of them before returning to the event loop.
 */
#define SEED_BBS_MAX_SCANS_PER_TICK 8

/**
 * Seconds to wait for a peer that was asked for a document before giving up on
 * that attempt.
 *
 * A solicited transfer that never happens produces no completion of its own --
 * the grant simply expires -- so this, and not a callback, is what ends an
 * attempt. It is comfortably longer than the grant's own lifetime.
 */
#define SEED_BBS_ASK_TIMEOUT 90

/**
 * Attempts made on one hash before it is given up on.
 *
 * Every attempt is followed by a longer wait than the last, so this is a span
 * of hours rather than a burst. A post whose sources are all offline now may
 * have one online in an hour, and an index entry that outlives every copy of
 * its document is a thing BBS0 expects a client to retry rather than discard.
 */
#define SEED_BBS_MAX_ATTEMPTS 6

/** First retry delay, in seconds. Doubles per attempt up to the maximum. */
#define SEED_BBS_RETRY_MIN 60

/** Longest retry delay, in seconds. */
#define SEED_BBS_RETRY_MAX 3600

/** What the operator commands report. */
struct seed_bbs_stats
{
	size_t   boards;          /** Boards known. */
	size_t   subscribed;      /** Boards currently subscribed to. */
	size_t   queued;          /** Pieces of work waiting. */
	size_t   inflight;        /** Requests outstanding with a peer. */
	uint64_t posts_fetched;   /** Post documents cached this run. */
	uint64_t posts_failed;    /** Post documents given up on this run. */
	uint64_t attachments;     /** Attachments cached this run. */
	uint64_t withdrawn;       /** Tombstones honoured this run. */
	uint64_t dropped;         /** Work refused because the queue was full. */
	int      gap;             /** 1 when some board's history is out of reach. */
};

/**
 * Create the engine. Every pointer is borrowed and must outlive it.
 *
 * @p config supplies seed_bbs_enable and the rest of the seed_bbs_* keys, and
 * seed_max_file_size, which bounds a post document exactly as it bounds any
 * other cached file.
 *
 * Returns an engine even when seed_bbs_enable is off, so a caller need not
 * branch on the configuration: a disabled engine accepts every event and does
 * nothing with any of them. It is the hub connection that then never offers
 * BBS0, so no descriptors arrive in the first place.
 *
 * @return the engine, or NULL if it could not be created.
 */
extern struct seed_bbs* seed_bbs_create(struct seed_cache* cache,
                                        const struct seed_cc_policy* cc,
                                        struct seed_hub* hub,
                                        const struct seed_config* config);

/**
 * Persist the resume cursors and release the engine. Safe on NULL. Must be
 * called before the cache it was created with is closed.
 */
extern void seed_bbs_destroy(struct seed_bbs* bbs);

/**
 * The connection reached, or left, the state where it can carry BBL.
 *
 * A subscription belongs to a connection and does not survive one, so every
 * board is marked unsubscribed on login and resubscribed when the hub
 * re-announces it. The cursors are not touched: they are what makes a
 * reconnect cheap.
 */
extern void seed_bbs_on_logged_in(struct seed_bbs* bbs);
extern void seed_bbs_on_disconnected(struct seed_bbs* bbs);

/**
 * A board descriptor arrived. Adds or updates the board, subscribes to it if
 * this session may read it and is not already subscribed, and forgets it when
 * the descriptor says the board is gone.
 */
extern void seed_bbs_on_board(struct seed_bbs* bbs, const struct seed_bbs_board* board);

/**
 * An index entry arrived.
 *
 * Advances the board's cursor, queues the document for fetching where it is not
 * already held, and honours a tombstone by deleting the cached copy -- which is
 * a request from the hub, honoured because the seeder is a cache and not an
 * archive. Replies to a withdrawn post are separate posts and are left alone.
 *
 * An entry for a hash already queued or already cached is not work; BBS0
 * requires resuming from the highest timestamp seen rather than one past it, so
 * the final second of every subscription arrives twice by design.
 */
extern void seed_bbs_on_entry(struct seed_bbs* bbs, const struct seed_bbs_entry* entry);

/**
 * A search result arrived. Where it answers a search this engine issued, the
 * responder is asked for the bytes.
 */
extern void seed_bbs_on_search_result(struct seed_bbs* bbs, const struct seed_result* result);

/**
 * A solicited download ended. Where it was a post document, the document is
 * read and the attachments its body links to are queued in turn.
 *
 * Not every request produces one of these -- see the contract on
 * seed_cc_policy::on_download -- so this shortens a wait rather than being what
 * ends it.
 */
extern void seed_bbs_on_download(struct seed_bbs* bbs, const char* tth, enum seed_error err,
                                 const struct seed_entry* entry);

/**
 * Do whatever is due: start requests, time out attempts, schedule retries.
 *
 * Called from the daemon's periodic timer. Everything this module does that is
 * not a direct reaction to a message happens here, so nothing it does can
 * delay a message being handled.
 */
extern void seed_bbs_tick(struct seed_bbs* bbs, time_t now);

extern void seed_bbs_get_stats(struct seed_bbs* bbs, struct seed_bbs_stats* out);

/* -------------------------------------------------------------------------
 * The pieces below are exposed so the test suite can drive them without a hub.
 * ------------------------------------------------------------------------- */

/**
 * Is @p board one the operator allows, given a comma separated @p allowed list?
 *
 * Pure. An empty or NULL list allows every board, which is the default: a hub
 * that announces a board this session may read is taken at its word. Matching
 * is on whole names and is case sensitive, as BBS0 requires of board names.
 */
extern int seed_bbs_board_allowed(const char* board, const char* allowed);

/**
 * The delay before attempt number @p attempts is made, in seconds.
 *
 * Pure. Doubles from SEED_BBS_RETRY_MIN and saturates at SEED_BBS_RETRY_MAX, so
 * it never returns 0 and a hash nobody holds is asked after less and less
 * often rather than for ever at the same rate.
 */
extern unsigned int seed_bbs_retry_delay(unsigned int attempts);

#endif /* HAVE_UHUB_SEEDER_BBS_H */
