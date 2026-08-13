#include "system.h"

#include "seeder/grant.h"
#include "util/memory.h"

/*
 * The seeder's grant table (seeder/grant.c) under load and at its limits.
 *
 * A grant is the only thing that authorises a connection on the seeder's
 * transfer port, and one is minted in response to peer traffic -- an RCM from
 * any logged-in hub user gets one, with a token the peer chose. That makes the
 * table's growth an attacker's variable, so what is exercised here is mostly
 * the refusal behaviour: the ceiling on the table as a whole, the fair-share
 * ceiling that stops one peer consuming it, and the accounting that has to give
 * a slice back on every one of the three ways a grant can leave (expiry,
 * release, and replacement by a repeat of its token).
 *
 * The rest is the semantics the transfer port depends on and must not drift:
 * single use, the exact `expires <= now' boundary, and a download grant naming
 * the content it is for.
 *
 * test_seedcc.tcc covers the same table from the connection's side. This file
 * drives it directly, with an explicit `now' rather than the wall clock, so the
 * boundary cases are exact rather than nearly.
 */

/* A CID and a TTH are both exactly 39 characters from the base32 alphabet. */
#define SG_CID  "CIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define SG_CID2 "CIDBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define SG_TTH  "OZ4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXAI"

/* How many distinct peers it takes to fill the table. */
#define SG_CIDS (SEED_GRANT_MAX_TOTAL / SEED_GRANT_MAX_PER_CID)

static struct seed_grants* sg = NULL;

/* A well formed, distinct CID per index: base32 digits of @p n, padded with the
   base32 zero. Injective, so no two indices ever collide. */
static void sg_make_cid(char out[SEED_CID_LEN + 1], unsigned n)
{
	static const char b32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	unsigned i;

	memset(out, 'A', SEED_CID_LEN);
	out[SEED_CID_LEN] = '\0';

	for (i = 0; i < SEED_CID_LEN && n; i++)
	{
		out[i] = b32[n & 31];
		n >>= 5;
	}
}

/* Empty the table whatever is in it, so each group starts from a known state. */
static int sg_reset(void)
{
	seed_grant_sweep(sg, (time_t) 1 << 40);
	return seed_grant_count(sg) == 0;
}

EXO_TEST(seedgrant_setup, {
	sg = seed_grants_create();
	return sg != NULL && seed_grant_count(sg) == 0;
});

/* --- the round trip ------------------------------------------------------- */

EXO_TEST(seedgrant_issue_check_release_round_trip, {
	struct seed_grant g;
	time_t now = 1000;

	if (!sg_reset()) return 0;
	if (!seed_grant_issue(sg, "roundtrip", SG_CID, NULL, now)) return 0;
	if (seed_grant_count(sg) != 1) return 0;

	if (!seed_grant_check(sg, "roundtrip", SG_CID, now, &g)) return 0;
	if (strcmp(g.token, "roundtrip") != 0) return 0;
	if (strcmp(g.cid, SG_CID) != 0) return 0;
	if (g.tth[0] != '\0') return 0;
	if (g.is_download) return 0;
	if (g.expires != now + SEED_GRANT_TTL) return 0;

	seed_grant_release(sg, "roundtrip");
	return seed_grant_count(sg) == 0 &&
	       seed_grant_check(sg, "roundtrip", SG_CID, now, NULL) == 0;
});

/* A grant is bound to the peer it was issued to. */
EXO_TEST(seedgrant_rejects_another_cid, {
	time_t now = 1000;

	if (!sg_reset()) return 0;
	if (!seed_grant_issue(sg, "bound", SG_CID, NULL, now)) return 0;
	if (seed_grant_check(sg, "bound", SG_CID2, now, NULL)) return 0;
	return seed_grant_check(sg, "bound", SG_CID, now, NULL) == 1;
});

/* A near miss on the token is a miss: nothing resolves by prefix. */
EXO_TEST(seedgrant_rejects_a_token_prefix, {
	time_t now = 1000;

	if (seed_grant_check(sg, "boun", SG_CID, now, NULL)) return 0;
	if (seed_grant_check(sg, "bounde", SG_CID, now, NULL)) return 0;
	if (seed_grant_check(sg, "bounc", SG_CID, now, NULL)) return 0;
	return seed_grant_check(sg, "", SG_CID, now, NULL) == 0;
});

EXO_TEST(seedgrant_null_arguments_refused, {
	return seed_grant_issue(NULL, "t", SG_CID, NULL, 1000) == 0 &&
	       seed_grant_check(NULL, "t", SG_CID, 1000, NULL) == 0 &&
	       seed_grant_is_download(NULL, "t", 1000, NULL) == 0 &&
	       seed_grant_count(NULL) == 0 &&
	       seed_grant_issue(sg, NULL, SG_CID, NULL, 1000) == 0 &&
	       seed_grant_issue(sg, "t", NULL, NULL, 1000) == 0;
});

/* --- single use ----------------------------------------------------------- */

/* seeder/cc.c releases the grant the moment the CINF quoting it is accepted, so
   neither a replay nor a second parallel connection can ride the same token. */
EXO_TEST(seedgrant_is_single_use, {
	time_t now = 2000;

	if (!sg_reset()) return 0;
	if (!seed_grant_issue(sg, "onceonly", SG_CID, NULL, now)) return 0;
	if (!seed_grant_check(sg, "onceonly", SG_CID, now, NULL)) return 0;

	seed_grant_release(sg, "onceonly");

	if (seed_grant_check(sg, "onceonly", SG_CID, now, NULL)) return 0;
	if (seed_grant_check(sg, "onceonly", NULL, now, NULL)) return 0;

	/* Releasing what is already gone is harmless. */
	seed_grant_release(sg, "onceonly");
	seed_grant_release(sg, "neverexisted");
	return seed_grant_count(sg) == 0;
});

/* --- the expiry boundary -------------------------------------------------- */

/* `expires <= now' in both the check and the sweep: a grant is dead on the
   second it expires, not the second after. */
EXO_TEST(seedgrant_expires_at_the_boundary, {
	time_t now = 3000;
	time_t expires = now + SEED_GRANT_TTL;

	if (!sg_reset()) return 0;
	if (!seed_grant_issue(sg, "boundary", SG_CID, NULL, now)) return 0;

	if (!seed_grant_check(sg, "boundary", SG_CID, expires - 1, NULL)) return 0;
	if (seed_grant_check(sg, "boundary", SG_CID, expires, NULL)) return 0;
	if (seed_grant_check(sg, "boundary", SG_CID, expires + 1, NULL)) return 0;

	/* Still in the table until swept, and the sweep draws the line in the
	   same place. */
	if (seed_grant_count(sg) != 1) return 0;
	seed_grant_sweep(sg, expires - 1);
	if (seed_grant_count(sg) != 1) return 0;
	seed_grant_sweep(sg, expires);
	return seed_grant_count(sg) == 0;
});

/* --- a repeated token ----------------------------------------------------- */

EXO_TEST(seedgrant_repeat_replaces_its_predecessor, {
	struct seed_grant g;
	time_t now = 4000;

	if (!sg_reset()) return 0;
	if (!seed_grant_issue(sg, "repeat", SG_CID, NULL, now)) return 0;
	if (!seed_grant_issue(sg, "repeat", SG_CID, SG_TTH, now + 5)) return 0;

	if (seed_grant_count(sg) != 1) return 0;
	if (!seed_grant_check(sg, "repeat", SG_CID, now, &g)) return 0;
	if (strcmp(g.tth, SG_TTH) != 0) return 0;
	return g.expires == now + 5 + SEED_GRANT_TTL;
});

/* The replaced grant must give its slice back, or a peer would lose a slot
   every time it reused a token and reach its ceiling early. */
EXO_TEST(seedgrant_repeat_does_not_double_count_the_cid, {
	time_t now = 4000;
	unsigned i;
	char token[32];

	if (!sg_reset()) return 0;

	/* The same token ten times over is still one grant against the slice. */
	for (i = 0; i < 10; i++)
		if (!seed_grant_issue(sg, "repeat", SG_CID, NULL, now)) return 0;
	if (seed_grant_count(sg) != 1) return 0;

	/* So the rest of the slice is still there to be used. */
	for (i = 1; i < SEED_GRANT_MAX_PER_CID; i++)
	{
		snprintf(token, sizeof(token), "fill%u", i);
		if (!seed_grant_issue(sg, token, SG_CID, NULL, now)) return 0;
	}
	if (seed_grant_count(sg) != SEED_GRANT_MAX_PER_CID) return 0;

	/* And no further, which is what says the slice was counted at all. */
	return seed_grant_issue(sg, "onemore", SG_CID, NULL, now) == 0;
});

/* Reissuing a token to a different peer moves the accounting with it. */
EXO_TEST(seedgrant_repeat_moves_the_cid_accounting, {
	time_t now = 4000;

	/* Carries on from the previous test: SG_CID is at its ceiling. */
	if (seed_grant_count(sg) != SEED_GRANT_MAX_PER_CID) return 0;
	if (seed_grant_issue(sg, "onemore", SG_CID, NULL, now)) return 0;

	/* Hand one of its grants to another peer. */
	if (!seed_grant_issue(sg, "repeat", SG_CID2, NULL, now)) return 0;
	if (seed_grant_count(sg) != SEED_GRANT_MAX_PER_CID) return 0;
	if (seed_grant_check(sg, "repeat", SG_CID, now, NULL)) return 0;
	if (!seed_grant_check(sg, "repeat", SG_CID2, now, NULL)) return 0;

	/* The first peer got its slot back, and exactly one. */
	if (!seed_grant_issue(sg, "onemore", SG_CID, NULL, now)) return 0;
	return seed_grant_issue(sg, "yetmore", SG_CID, NULL, now) == 0;
});

/* --- the per-CID ceiling -------------------------------------------------- */

EXO_TEST(seedgrant_per_cid_ceiling_refuses_cleanly, {
	time_t now = 5000;
	unsigned i;
	char token[32];

	if (!sg_reset()) return 0;

	for (i = 0; i < SEED_GRANT_MAX_PER_CID; i++)
	{
		snprintf(token, sizeof(token), "slice%u", i);
		if (!seed_grant_issue(sg, token, SG_CID, NULL, now)) return 0;
	}
	if (seed_grant_count(sg) != SEED_GRANT_MAX_PER_CID) return 0;

	/* Over the line, and nothing already held is evicted to make room. */
	if (seed_grant_issue(sg, "over", SG_CID, NULL, now)) return 0;
	if (seed_grant_count(sg) != SEED_GRANT_MAX_PER_CID) return 0;
	if (seed_grant_check(sg, "over", SG_CID, now, NULL)) return 0;

	for (i = 0; i < SEED_GRANT_MAX_PER_CID; i++)
	{
		snprintf(token, sizeof(token), "slice%u", i);
		if (!seed_grant_check(sg, token, SG_CID, now, NULL)) return 0;
	}
	return 1;
});

/* The whole point of the per-CID ceiling: one peer at its limit is not a denial
   of service against anybody else. */
EXO_TEST(seedgrant_per_cid_ceiling_does_not_stop_another_cid, {
	time_t now = 5000;
	unsigned i;
	char token[32];

	if (seed_grant_issue(sg, "over", SG_CID, NULL, now)) return 0;

	for (i = 0; i < SEED_GRANT_MAX_PER_CID; i++)
	{
		snprintf(token, sizeof(token), "other%u", i);
		if (!seed_grant_issue(sg, token, SG_CID2, NULL, now)) return 0;
		if (!seed_grant_check(sg, token, SG_CID2, now, NULL)) return 0;
	}
	return seed_grant_count(sg) == 2 * SEED_GRANT_MAX_PER_CID;
});

/* A download grant is an ordinary grant, so it is on the same slice. */
EXO_TEST(seedgrant_per_cid_ceiling_covers_downloads, {
	time_t now = 5000;

	return seed_grant_issue_download(sg, "dlover", SG_CID, SG_TTH, 4096, "x.bin", now) == 0;
});

EXO_TEST(seedgrant_release_returns_the_cid_slice, {
	time_t now = 5000;

	seed_grant_release(sg, "slice0");
	if (!seed_grant_issue(sg, "over", SG_CID, NULL, now)) return 0;
	return seed_grant_issue(sg, "over2", SG_CID, NULL, now) == 0;
});

EXO_TEST(seedgrant_expiry_returns_the_cid_slice, {
	time_t now = 5000;
	unsigned i;
	char token[32];

	seed_grant_sweep(sg, now + SEED_GRANT_TTL);
	if (seed_grant_count(sg) != 0) return 0;

	/* Both peers can fill their slice again from scratch. */
	for (i = 0; i < SEED_GRANT_MAX_PER_CID; i++)
	{
		snprintf(token, sizeof(token), "again%u", i);
		if (!seed_grant_issue(sg, token, SG_CID, NULL, now + 100)) return 0;
		snprintf(token, sizeof(token), "again2_%u", i);
		if (!seed_grant_issue(sg, token, SG_CID2, NULL, now + 100)) return 0;
	}
	if (seed_grant_issue(sg, "over", SG_CID, NULL, now + 100)) return 0;
	return seed_grant_count(sg) == 2 * SEED_GRANT_MAX_PER_CID;
});

/* --- the table ceiling ---------------------------------------------------- */

EXO_TEST(seedgrant_table_ceiling_refuses_cleanly, {
	time_t now = 6000;
	unsigned c, i;
	char cid[SEED_CID_LEN + 1];
	char token[32];

	if (!sg_reset()) return 0;

	for (c = 0; c < SG_CIDS; c++)
	{
		sg_make_cid(cid, c + 1);
		for (i = 0; i < SEED_GRANT_MAX_PER_CID; i++)
		{
			snprintf(token, sizeof(token), "full%u_%u", c, i);
			if (!seed_grant_issue(sg, token, cid, NULL, now)) return 0;
		}
	}
	if (seed_grant_count(sg) != SEED_GRANT_MAX_TOTAL) return 0;

	/* A peer nobody has heard from yet is refused, and refusal is all it is:
	   the table is unchanged and every grant in it still resolves. */
	sg_make_cid(cid, 9999);
	if (seed_grant_issue(sg, "overflow", cid, NULL, now)) return 0;
	if (seed_grant_issue_download(sg, "overflowdl", cid, SG_TTH, 1, NULL, now)) return 0;
	if (seed_grant_count(sg) != SEED_GRANT_MAX_TOTAL) return 0;
	if (seed_grant_check(sg, "overflow", NULL, now, NULL)) return 0;

	sg_make_cid(cid, 1);
	return seed_grant_check(sg, "full0_0", cid, now, NULL) == 1;
});

/* Re-issuing an existing token at the ceiling replaces rather than adds, so it
   must still be allowed -- the table does not grow by it. */
EXO_TEST(seedgrant_repeat_is_allowed_at_the_table_ceiling, {
	time_t now = 6000;
	char cid[SEED_CID_LEN + 1];

	if (seed_grant_count(sg) != SEED_GRANT_MAX_TOTAL) return 0;

	sg_make_cid(cid, 1);
	if (!seed_grant_issue(sg, "full0_0", cid, SG_TTH, now + 1)) return 0;
	return seed_grant_count(sg) == SEED_GRANT_MAX_TOTAL;
});

/* --- lookups against a full table ----------------------------------------- */

/*
 * The table used to be a linked list walked with strcmp, so every issue and
 * every CINF cost a scan of it and filling it was quadratic. It is indexed now.
 *
 * These are correctness assertions, not timing ones -- a wall-clock threshold in
 * a test only tells you what the machine was doing that afternoon. What is
 * asserted is that thousands of operations against a table held at its 1024
 * entry ceiling all resolve to the right entry and nothing else; that they
 * complete at all is the rest of the claim.
 */
EXO_TEST(seedgrant_every_entry_in_a_full_table_resolves, {
	struct seed_grant g;
	time_t now = 6000;
	unsigned c, i;
	char cid[SEED_CID_LEN + 1];
	char token[32];

	if (seed_grant_count(sg) != SEED_GRANT_MAX_TOTAL) return 0;

	for (c = 0; c < SG_CIDS; c++)
	{
		sg_make_cid(cid, c + 1);
		for (i = 0; i < SEED_GRANT_MAX_PER_CID; i++)
		{
			snprintf(token, sizeof(token), "full%u_%u", c, i);
			if (!seed_grant_check(sg, token, cid, now, &g)) return 0;
			if (strcmp(g.token, token) != 0) return 0;
			if (strcmp(g.cid, cid) != 0) return 0;
			/* ... and to that CID only. */
			sg_make_cid(cid, c + 2);
			if (seed_grant_check(sg, token, cid, now, NULL)) return 0;
			sg_make_cid(cid, c + 1);
		}
	}
	return 1;
});

EXO_TEST(seedgrant_thousands_of_misses_on_a_full_table, {
	time_t now = 6000;
	unsigned i;
	char token[32];

	for (i = 0; i < 5000; i++)
	{
		snprintf(token, sizeof(token), "absent%u", i);
		if (seed_grant_check(sg, token, NULL, now, NULL)) return 0;
		if (seed_grant_is_download(sg, token, now, NULL)) return 0;
	}
	return seed_grant_count(sg) == SEED_GRANT_MAX_TOTAL;
});

EXO_TEST(seedgrant_thousands_of_cycles_on_a_full_table, {
	time_t now = 6000;
	unsigned i;
	char cid[SEED_CID_LEN + 1];

	sg_make_cid(cid, 1);

	/* Consume and reissue at the ceiling, which is what a busy seeder does:
	   the table stays exactly full and the entry stays exactly one entry. */
	for (i = 0; i < 5000; i++)
	{
		if (!seed_grant_check(sg, "full0_0", cid, now, NULL)) return 0;
		seed_grant_release(sg, "full0_0");
		if (seed_grant_check(sg, "full0_0", cid, now, NULL)) return 0;
		if (seed_grant_count(sg) != SEED_GRANT_MAX_TOTAL - 1) return 0;
		if (!seed_grant_issue(sg, "full0_0", cid, NULL, now)) return 0;
	}
	return seed_grant_count(sg) == SEED_GRANT_MAX_TOTAL;
});

/* --- the sweep ------------------------------------------------------------ */

/* The sweep used to restart its walk after every removal, so clearing a table
   of expired grants was quadratic in the size of the table. */
EXO_TEST(seedgrant_sweep_drops_the_expired_and_keeps_the_live, {
	time_t old = 7000;
	time_t fresh = old + SEED_GRANT_TTL;
	unsigned c, i, stale_cids = SG_CIDS / 2;
	char cid[SEED_CID_LEN + 1];
	char token[32];

	if (!sg_reset()) return 0;

	/* Half the table expiring at old + TTL ... */
	for (c = 0; c < stale_cids; c++)
	{
		sg_make_cid(cid, c + 1);
		for (i = 0; i < SEED_GRANT_MAX_PER_CID; i++)
		{
			snprintf(token, sizeof(token), "stale%u_%u", c, i);
			if (!seed_grant_issue(sg, token, cid, NULL, old)) return 0;
		}
	}
	/* ... and half expiring a whole TTL later. */
	for (c = stale_cids; c < SG_CIDS; c++)
	{
		sg_make_cid(cid, c + 1);
		for (i = 0; i < SEED_GRANT_MAX_PER_CID; i++)
		{
			snprintf(token, sizeof(token), "live%u_%u", c, i);
			if (!seed_grant_issue(sg, token, cid, NULL, fresh)) return 0;
		}
	}
	if (seed_grant_count(sg) != SEED_GRANT_MAX_TOTAL) return 0;

	/* One pass takes all 512 expired entries and leaves the other 512. */
	seed_grant_sweep(sg, old + SEED_GRANT_TTL);
	if (seed_grant_count(sg) != SEED_GRANT_MAX_TOTAL / 2) return 0;

	for (c = 0; c < stale_cids; c++)
	{
		for (i = 0; i < SEED_GRANT_MAX_PER_CID; i++)
		{
			snprintf(token, sizeof(token), "stale%u_%u", c, i);
			if (seed_grant_check(sg, token, NULL, old, NULL)) return 0;
		}
	}
	for (c = stale_cids; c < SG_CIDS; c++)
	{
		sg_make_cid(cid, c + 1);
		for (i = 0; i < SEED_GRANT_MAX_PER_CID; i++)
		{
			snprintf(token, sizeof(token), "live%u_%u", c, i);
			if (!seed_grant_check(sg, token, cid, old, NULL)) return 0;
		}
	}

	/* The swept peers got their slices back with their entries. */
	sg_make_cid(cid, 1);
	for (i = 0; i < SEED_GRANT_MAX_PER_CID; i++)
	{
		snprintf(token, sizeof(token), "after%u", i);
		if (!seed_grant_issue(sg, token, cid, NULL, fresh)) return 0;
	}
	if (seed_grant_issue(sg, "afterover", cid, NULL, fresh)) return 0;

	/* A sweep that has nothing to do is not disturbed by the live prefix. */
	seed_grant_sweep(sg, old);
	if (seed_grant_count(sg) != SEED_GRANT_MAX_TOTAL / 2 + SEED_GRANT_MAX_PER_CID) return 0;

	seed_grant_sweep(sg, fresh + SEED_GRANT_TTL);
	return seed_grant_count(sg) == 0;
});

EXO_TEST(seedgrant_sweep_of_an_empty_table, {
	seed_grant_sweep(sg, 0);
	seed_grant_sweep(sg, 1 << 30);
	seed_grant_sweep(NULL, 0);
	return seed_grant_count(sg) == 0;
});

/* --- download grants ------------------------------------------------------ */

/* What the seeder ingests is not something a peer gets to choose, so a download
   grant that does not name its content is not a grant. */
EXO_TEST(seedgrant_download_requires_a_tth, {
	time_t now = 8000;

	if (!sg_reset()) return 0;

	if (seed_grant_issue_download(sg, "nodl", SG_CID, NULL, 4096, "x.bin", now)) return 0;
	if (seed_grant_count(sg) != 0) return 0;

	/* And it must be a TTH, not merely non-NULL. */
	if (seed_grant_issue_download(sg, "nodl", SG_CID, "notatth", 4096, "x.bin", now)) return 0;
	if (seed_grant_issue_download(sg, "nodl", SG_CID, "", 4096, "x.bin", now)) return 0;
	if (seed_grant_issue_download(sg, "nodl", SG_CID, SG_TTH "X", 4096, "x.bin", now)) return 0;
	return seed_grant_count(sg) == 0;
});

EXO_TEST(seedgrant_download_round_trip, {
	struct seed_grant g;
	time_t now = 8000;

	if (!seed_grant_issue_download(sg, "dl", SG_CID, SG_TTH, 4096, "wanted.bin", now)) return 0;
	if (seed_grant_count(sg) != 1) return 0;

	if (!seed_grant_is_download(sg, "dl", now, &g)) return 0;
	if (strcmp(g.tth, SG_TTH) != 0) return 0;
	if (strcmp(g.name, "wanted.bin") != 0) return 0;
	if (g.size != 4096) return 0;
	if (!g.is_download) return 0;

	/* It is an ordinary grant besides, so the CID binding and the TTL apply. */
	if (!seed_grant_check(sg, "dl", SG_CID, now, NULL)) return 0;
	if (seed_grant_check(sg, "dl", SG_CID2, now, NULL)) return 0;
	if (seed_grant_is_download(sg, "dl", now + SEED_GRANT_TTL, NULL)) return 0;

	seed_grant_release(sg, "dl");
	return seed_grant_is_download(sg, "dl", now, NULL) == 0 &&
	       seed_grant_count(sg) == 0;
});

/* An upload grant is not a download grant, whatever else it is. */
EXO_TEST(seedgrant_upload_is_not_a_download, {
	time_t now = 8000;

	if (!seed_grant_issue(sg, "up", SG_CID, SG_TTH, now)) return 0;
	if (seed_grant_is_download(sg, "up", now, NULL)) return 0;
	return seed_grant_check(sg, "up", SG_CID, now, NULL) == 1;
});

/* Replacing a download grant with a plain one clears what made it a download,
   rather than leaving the old flags on the token. */
EXO_TEST(seedgrant_repeat_clears_the_download_flags, {
	struct seed_grant g;
	time_t now = 8000;

	if (!sg_reset()) return 0;
	if (!seed_grant_issue_download(sg, "swap", SG_CID, SG_TTH, 4096, "wanted.bin", now)) return 0;
	if (!seed_grant_issue(sg, "swap", SG_CID, NULL, now)) return 0;

	if (seed_grant_is_download(sg, "swap", now, NULL)) return 0;
	if (!seed_grant_check(sg, "swap", SG_CID, now, &g)) return 0;
	return g.is_download == 0 && g.size == 0 && g.name[0] == '\0' && g.tth[0] == '\0';
});

/* --- input shapes --------------------------------------------------------- */

EXO_TEST(seedgrant_malformed_cid_refused, {
	time_t now = 9000;

	if (!sg_reset()) return 0;
	return seed_grant_issue(sg, "bad", "short", NULL, now) == 0 &&
	       seed_grant_issue(sg, "bad", "", NULL, now) == 0 &&
	       seed_grant_issue(sg, "bad", SG_CID "X", NULL, now) == 0 &&
	       seed_grant_issue(sg, "bad", "cid!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", NULL, now) == 0 &&
	       seed_grant_count(sg) == 0;
});

EXO_TEST(seedgrant_oversized_token_refused, {
	char token[SEED_TOKEN_MAX + 8];
	time_t now = 9000;

	memset(token, 'A', sizeof(token) - 1);
	token[sizeof(token) - 1] = '\0';
	if (seed_grant_issue(sg, token, SG_CID, NULL, now)) return 0;

	/* Exactly at the limit is still a token we could have minted. */
	token[SEED_TOKEN_MAX] = '\0';
	if (!seed_grant_issue(sg, token, SG_CID, NULL, now)) return 0;
	if (!seed_grant_check(sg, token, SG_CID, now, NULL)) return 0;

	seed_grant_release(sg, token);
	return seed_grant_count(sg) == 0;
});

EXO_TEST(seedgrant_minted_tokens_are_distinct, {
	char a[SEED_TOKEN_MAX + 1];
	char b[SEED_TOKEN_MAX + 1];

	if (!seed_grant_make_token(a) || !seed_grant_make_token(b)) return 0;
	if (strlen(a) != 24 || strlen(b) != 24) return 0;
	return strcmp(a, b) != 0;
});

/* --- teardown ------------------------------------------------------------- */

/* Destroying a table that still holds grants must free them all; the ASan build
   is what actually checks this. */
EXO_TEST(seedgrant_destroy_a_populated_table, {
	struct seed_grants* doomed = seed_grants_create();
	time_t now = 9000;
	unsigned c, i;
	char cid[SEED_CID_LEN + 1];
	char token[32];

	if (!doomed) return 0;

	for (c = 0; c < SG_CIDS; c++)
	{
		sg_make_cid(cid, c + 1);
		for (i = 0; i < SEED_GRANT_MAX_PER_CID; i++)
		{
			snprintf(token, sizeof(token), "doomed%u_%u", c, i);
			if (!seed_grant_issue(doomed, token, cid, NULL, now)) return 0;
		}
	}
	if (seed_grant_count(doomed) != SEED_GRANT_MAX_TOTAL) return 0;

	seed_grants_destroy(doomed);
	seed_grants_destroy(NULL);
	return 1;
});

EXO_TEST(seedgrant_teardown, {
	time_t now = 9000;

	/* Left non-empty on purpose: the table owns what is still in it. */
	if (!seed_grant_issue(sg, "leftover", SG_CID, NULL, now)) return 0;
	seed_grants_destroy(sg);
	sg = NULL;
	return 1;
});
