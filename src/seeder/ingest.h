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

#ifndef HAVE_UHUB_SEEDER_INGEST_H
#define HAVE_UHUB_SEEDER_INGEST_H

#include <stddef.h>

#include "seeder/cache.h"
#include "seeder/embed.h"
#include "seeder/url.h"

/**
 * The policy layer that decides what the seeder goes and fetches.
 *
 * Everything below this file knows how to move bytes; this is the part that
 * decides whether to. Inside the hub the same job was done by
 * src/core/blobingest.c, which could consult the ACL directly. The seeder is an
 * ordinary client, so it cannot: what it sees of another user is the CT bit mask
 * in their INF, and the mapping from the configured seed_min_credentials onto
 * those bits is an approximation of the hub's own credential ladder rather than
 * a reading of it. See seed_ingest_ct_permitted().
 *
 * Nothing here ever blocks or delays a chat message. A message is scanned, a
 * request may be sent, and the fetch that follows -- if the peer answers at all
 * -- completes long afterwards.
 */

struct seed_cc_policy;
struct seed_config;
struct seed_hub;
struct seed_ingest_trigger;
struct seed_user;

/**
 * At most this many embeds are acted on per message. A chat line is capped at
 * MAX_ADC_CMD_LEN anyway, so this only bounds how much work one message can ask
 * for -- posting a wall of magnets must not turn into a fetch storm.
 */
#define SEED_INGEST_MAX_PER_MESSAGE 4

/** Concurrent URL mirror fetches across the daemon. */
#define SEED_INGEST_MAX_FETCHES 4

/* -------------------------------------------------------------- pure policy */

/**
 * May a user carrying @p client_type cause an ingest, given the configured
 * @p min_credentials ("guest", "user", "operator", "super" or "admin")?
 *
 * Pure: no I/O, no globals.
 *
 * @p client_type is the CT bit mask out of the poster's INF, so this is a mask
 * test and never an equality test: a super user is 12 (8|4) and an admin is 20
 * (16|4), and both therefore carry the operator bit. Comparing for equality
 * would refuse an admin.
 *
 * An unrecognised or empty @p min_credentials falls back to "user", which is
 * also the configured default: anyone who can post could otherwise make the
 * seeder spend disk on their behalf.
 *
 * @return 1 when the user clears the bar.
 */
extern int seed_ingest_ct_permitted(int client_type, const char* min_credentials);

/**
 * One URL embed found in a message.
 */
struct seed_ingest_url
{
	char url[SEED_URL_MAX_LEN];
	char name[SEED_EMBED_MAX_NAME]; /** The link label, "" when it was empty. */
};

/**
 * Scan an already-unescaped rich text message for "![alt](http...)" image
 * embeds. Pure, total, and safe on attacker-controlled input, exactly as
 * seed_scan_message() is -- and like it, it never reads past the terminating
 * NUL and emits one entry per occurrence.
 *
 * Only the inline image form is recognised: a plain "[text](http...)" link is a
 * link to a page and not something to mirror. The URL is captured verbatim; it
 * is seed_url_parse() and the address policy in seeder/fetch.c that decide
 * whether it may be fetched.
 *
 * @return the number of entries written to @p out.
 */
extern size_t seed_ingest_scan_urls(const char* text, struct seed_ingest_url* out, size_t max);

/**
 * Pick the magnet embeds in @p text that are worth asking a peer for.
 *
 * Drops everything the seeder has no reason to request: a TTH the cache already
 * holds, one an operator has blocked, and a repeat of a TTH already selected
 * from the same message. Consults the cache but touches no network, and inspects
 * with seed_cache_peek() so that scanning a message is never itself an access.
 *
 * @param cache may be NULL, in which case nothing is selected.
 * @param max   entries @p out has room for; no more are ever selected, which is
 *              what bounds one message to SEED_INGEST_MAX_PER_MESSAGE requests.
 * @return the number of entries written to @p out.
 */
extern size_t seed_ingest_select(struct seed_cache* cache, const char* text,
                                 struct seed_embed* out, size_t max);

/* ------------------------------------------------------------ the daemon side */

/**
 * Create the trigger. Every pointer is borrowed and must outlive it; @p config
 * supplies seed_min_credentials, seed_client_port and the seed_url_* keys.
 *
 * @return the trigger, or NULL if it could not be created.
 */
extern struct seed_ingest_trigger* seed_ingest_trigger_create(struct seed_cache* cache,
                                                              const struct seed_cc_policy* cc,
                                                              struct seed_hub* hub,
                                                              const struct seed_config* config);

/**
 * Cancel every fetch still in flight and release the trigger. Safe on NULL.
 * Must be called before the cache it was created with is closed.
 */
extern void seed_ingest_trigger_destroy(struct seed_ingest_trigger* trigger);

/**
 * React to a chat message: request whatever it embeds that the seeder does not
 * already hold. Never fails visibly and never blocks; a message that asks for
 * nothing, or whose poster does not clear seed_min_credentials, is simply
 * ignored.
 *
 * @return the number of requests sent, which is useful mostly to a test.
 */
extern size_t seed_ingest_on_chat(struct seed_ingest_trigger* trigger,
                                  const struct seed_user* from, const char* text);

/** URL mirror fetches currently in flight. */
extern size_t seed_ingest_active_fetches(struct seed_ingest_trigger* trigger);

#endif /* HAVE_UHUB_SEEDER_INGEST_H */
