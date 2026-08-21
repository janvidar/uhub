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

#ifndef HAVE_UHUB_SEEDER_GRANT_H
#define HAVE_UHUB_SEEDER_GRANT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "seeder/cache.h"

/**
 * Connection grants: the seeder's record of the client transfers it is
 * currently expecting.
 *
 * In the hub this table belonged to the hub, because the hub was the party that
 * minted tokens. The seeder is an ordinary client, so it is now the seeder's
 * own: it issues a token for every transfer it solicits -- whether it is
 * answering somebody's search or asking a peer to hand over content -- and
 * accepts on a client connection exactly the tokens it issued itself, to the
 * CID it issued them to, within SEED_GRANT_TTL.
 *
 * That is the whole of the authorisation on the client port. The port is
 * reachable, pre-authentication, by anyone who can open a socket, so a grant is
 * the only thing that distinguishes a peer the seeder is talking to from a
 * stranger: no grant, no data, in either direction.
 *
 * A grant is single use. seeder/cc.c releases it the moment the CINF quoting it
 * is accepted, so neither a replay nor a second parallel connection can ride the
 * same token.
 *
 * Everything here is single threaded and runs on the daemon's main loop.
 */

/** Longest token accepted. A token is echoed back to a peer, so it is bounded. */
#define SEED_TOKEN_MAX 64

/** Room for a named download's file name, including NUL. */
#define SEED_GRANT_FILENAME_MAX 64

/** Seconds a grant stays valid after it was issued. */
#define SEED_GRANT_TTL 60

/**
 * Ceiling on the whole table.
 *
 * Grants are minted in response to peer traffic -- a hub user sending RCM gets
 * one per request -- so without a ceiling the table is sized by whoever is
 * talking to us. One entry costs roughly half a kilobyte once the index nodes
 * are counted, so this bounds the table at well under a megabyte.
 *
 * The number itself: a grant lives SEED_GRANT_TTL (60) seconds, so 1024 is the
 * steady state of about seventeen new solicited connections per second, which
 * is an order of magnitude more than a cache seeder ever legitimately has in
 * flight. It is deliberately above seeder/cc.c's own SEED_CC_MAX_GRANTS (256),
 * so that the tighter self-imposed limit on outbound download requests still
 * takes effect before this one does.
 */
#define SEED_GRANT_MAX_TOTAL 1024

/**
 * Ceiling on the grants outstanding for any one CID.
 *
 * The table ceiling alone would let a single peer fill it and deny everyone
 * else, so each CID gets a slice. A DC client sets up a handful of connections
 * at once -- one upload plus a few download slots, plus retries -- so sixteen
 * concurrent, unconsumed grants is already generous, and it takes 64 distinct
 * peers to reach SEED_GRANT_MAX_TOTAL.
 */
#define SEED_GRANT_MAX_PER_CID 16

/**
 * Length of a CID, excluding NUL. A CID has the same shape as a TTH: 39
 * characters from the base32 alphabet. Kept as its own name because the two are
 * different things that merely happen to be the same size.
 */
#define SEED_CID_LEN 39

struct seed_grants;

/**
 * One grant, as copied out to a caller. This is a snapshot, not a handle:
 * holding one neither keeps the grant alive nor stops it expiring.
 */
struct seed_grant
{
	char     token[SEED_TOKEN_MAX + 1];
	char     cid[SEED_CID_LEN + 1];      /** The peer this grant was issued to. */
	char     tth[SEED_TTH_STR_LEN + 1];  /** Content named by the grant, "" if none. */

	/**
	 * What to ask for when the wanted thing has no hash yet: a file name such
	 * as "files.xml.bz2". Empty for an ordinary content-addressed download.
	 *
	 * A grant carries one or the other and never both. The distinction decides
	 * whether the reply is verified against a hash that was known in advance,
	 * so it is recorded explicitly rather than inferred from the shape of a
	 * string.
	 */
	char     filename[SEED_GRANT_FILENAME_MAX];

	/**
	 * A ranged download: the first byte and how many of them. @c length is 0
	 * for the ordinary whole-file case.
	 *
	 * A range cannot be checked against the TTH -- a hash covers a whole file
	 * and there is no leaf-hash support here to check a part of one with -- so
	 * a grant records that it is one, and the transfer hands its bytes to the
	 * caller instead of ingesting them into the cache as verified content.
	 */
	uint64_t start;
	uint64_t length;
	int      is_download;                /** The seeder connects to receive, not to serve. */
	uint64_t size;                       /** Announced size of a download, 0 if unknown. */
	char     name[SEED_NAME_MAX];        /** Display name of a download, "" if unknown. */
	time_t   expires;
};

/** @return an empty table, or NULL on failure. */
extern struct seed_grants* seed_grants_create(void);

/** Free the table and every grant still in it. NULL is accepted. */
extern void seed_grants_destroy(struct seed_grants* grants);

/**
 * Record a grant for @p cid to open a client connection quoting @p token.
 *
 * @param tth the content the connection is for, or NULL when the grant names
 *            none (an upload: the peer chooses what to CGET, and can only ever
 *            get something already cached).
 * @param now the time the grant is issued; it expires SEED_GRANT_TTL later.
 *
 * Both ceilings are enforced here rather than left to the caller, because every
 * caller has to honour them and one that forgot is what made an unauthenticated
 * RCM able to grow this table without bound. A refusal is clean: nothing is
 * evicted to make room, so a peer that has reached its slice can be denied but
 * can never cost another peer the grant it is holding.
 *
 * @return 1 if the grant was recorded, 0 otherwise (bad arguments; a token, CID
 *         or TTH that is not of a shape the seeder ever issues; or
 *         SEED_GRANT_MAX_TOTAL / SEED_GRANT_MAX_PER_CID already reached).
 */
extern int seed_grant_issue(struct seed_grants* grants, const char* token, const char* cid,
                            const char* tth, time_t now);

/**
 * Record a grant for a connection the seeder means to *download* over rather
 * than serve on: it sends the CGET itself and ingests the reply.
 *
 * A download grant must name its TTH -- what the seeder ingests is not something
 * a peer gets to choose -- and is otherwise an ordinary grant, so the CID
 * binding and the TTL apply to it just the same.
 *
 * @param size the announced size, or 0 when unknown.
 * @param name the display name, or NULL.
 * @return 1 if the grant was recorded.
 */
extern int seed_grant_issue_download(struct seed_grants* grants, const char* token, const char* cid,
                                     const char* tth, uint64_t size, const char* name, time_t now);

/**
 * Record a download grant for a file named rather than hashed: a peer's file
 * list, which cannot be asked for by TTH because its hash is not knowable
 * until it has been received.
 *
 * The reply to such a request is therefore not verified against anything, and
 * that is the whole of the difference. What limits it is what limited it
 * before: we chose the peer, we chose the name, and the cache's per-file
 * ceiling bounds what arrives. A peer still cannot decide *what* is asked for,
 * which is the property this module exists to keep.
 *
 * @param filename must be non-empty, free of '/' and of spaces, and short
 *                 enough to fit; anything else is refused.
 * @return 1 if the grant was recorded.
 */
extern int seed_grant_issue_filelist(struct seed_grants* grants, const char* token, const char* cid,
                                     const char* filename, time_t now);

/**
 * Record a download grant for part of a file.
 *
 * For content too large to be worth holding whole -- a mount reading one page
 * out of a film. What arrives cannot be verified against the TTH, so it is
 * never cached as though it had been: it goes to the caller's sink and nowhere
 * else. @see seed_cc_policy::on_body.
 *
 * @param length must be non-zero.
 * @return 1 if the grant was recorded.
 */
extern int seed_grant_issue_range(struct seed_grants* grants, const char* token, const char* cid,
                                  const char* tth, uint64_t start, uint64_t length, time_t now);

/**
 * Look up the unexpired grant for @p token.
 *
 * @param cid when given, the grant must have been issued to this CID. Passing
 *            NULL checks the token alone, which is only safe because a token is
 *            never issued to more than one peer.
 * @param out receives a copy of the grant. May be NULL. Always cleared first.
 * @return 1 when a matching, unexpired grant exists.
 */
extern int seed_grant_check(struct seed_grants* grants, const char* token, const char* cid,
                            time_t now, struct seed_grant* out);

/**
 * Is the unexpired grant for @p token one issued in order to download?
 *
 * @param out receives a copy of the grant. May be NULL. Always cleared first.
 * @return 1 when it is.
 */
extern int seed_grant_is_download(struct seed_grants* grants, const char* token, time_t now,
                                  struct seed_grant* out);

/** Drop the grant for @p token, if any. */
extern void seed_grant_release(struct seed_grants* grants, const char* token);

/** Drop every grant that expired at or before @p now. */
extern void seed_grant_sweep(struct seed_grants* grants, time_t now);

/** Grants outstanding, expired ones included until they are swept. */
extern size_t seed_grant_count(struct seed_grants* grants);

/**
 * Mint a fresh token: 15 random bytes as 24 base32 characters, which need no
 * ADC escaping and are comfortably inside SEED_TOKEN_MAX.
 *
 * @return 1 on success, 0 when the system random source failed.
 */
extern int seed_grant_make_token(char out[SEED_TOKEN_MAX + 1]);

#endif /* HAVE_UHUB_SEEDER_GRANT_H */
