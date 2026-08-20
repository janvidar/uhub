#include "system.h"
#include "uhub_limits.h"
#include "util/memory.h"
#include "adc/message.h"
#include "adc/adcconst.h"
#include "adc/sid.h"
#include "seeder/bbs.h"
#include "seeder/hubconn.h"

/*
 * BBS0 bulletin boards: the wire parsing the seeder does on IBBD and IBBL, the
 * board name rules, and the two pure policy functions the fetch queue is paced
 * by. Driven without a hub -- the parsing is deliberately separate from the
 * transport so it can be.
 */

#define BB_TTH    "KX3TQ7ZVN5PLQGKD3NDBK6ZTZG5PYQXSNMFYVJH"
#define BB_PARENT "5FR2HYQVGRDLKZ7BEBWMHFVXBHTIVJYQBFY4MOY"
#define BB_THREAD "QQ4KJ7NM2XHVBWTYW4CN3PZFV6UJVN2DBLQ5A5A"
#define BB_CID    "IPJJWEPPPLCA3PF2ZCRRYO4F2ZX2EV2JMW2KC3I"

static struct adc_message* bb_msg(const char* line)
{
	return adc_msg_parse(line, strlen(line));
}

static struct seed_bbs_board bb_board;
static struct seed_bbs_entry bb_entry;
static struct seed_result bb_result;

/* Poison the output first, so a test can tell a written field from a stale one. */
static int bb_parse_board(const char* line)
{
	struct adc_message* msg = bb_msg(line);
	int ok;

	memset(&bb_board, 0xAA, sizeof(bb_board));
	ok = msg && seed_hub_parse_bbs_board(msg, &bb_board);
	adc_msg_free(msg);
	return ok;
}

static int bb_parse_entry(const char* line)
{
	struct adc_message* msg = bb_msg(line);
	int ok;

	memset(&bb_entry, 0xAA, sizeof(bb_entry));
	ok = msg && seed_hub_parse_bbs_entry(msg, &bb_entry);
	adc_msg_free(msg);
	return ok;
}

static int bb_parse_result(const char* line)
{
	struct adc_message* msg = bb_msg(line);
	int ok;

	memset(&bb_result, 0xAA, sizeof(bb_result));
	ok = msg && seed_hub_parse_result(msg, &bb_result);
	adc_msg_free(msg);
	return ok;
}

/* -------------------------------------------------------------- board names */

EXO_TEST(seedbbs_board_name_simple, {
	return seed_hub_bbs_board_valid("general") == 1;
});

/* Dots separate hierarchy by convention, and carry no meaning here. */
EXO_TEST(seedbbs_board_name_dotted, {
	return seed_hub_bbs_board_valid("dev.adc") == 1;
});

EXO_TEST(seedbbs_board_name_full_alphabet, {
	return seed_hub_bbs_board_valid("aZ09._-") == 1;
});

EXO_TEST(seedbbs_board_name_empty, {
	return seed_hub_bbs_board_valid("") == 0 && seed_hub_bbs_board_valid(NULL) == 0;
});

/* A separator is not in the permitted set. Nor is a space. */
EXO_TEST(seedbbs_board_name_slash, {
	return seed_hub_bbs_board_valid("a/b") == 0;
});

EXO_TEST(seedbbs_board_name_backslash, {
	return seed_hub_bbs_board_valid("a\\b") == 0;
});

EXO_TEST(seedbbs_board_name_space, {
	return seed_hub_bbs_board_valid("a b") == 0;
});

/*
 * ".." is a legal board name: the character set excludes the separators but
 * permits '.'. This is exactly why a board name must never be used as a path
 * component, and the test records that it parses rather than that it is safe.
 */
EXO_TEST(seedbbs_board_name_dotdot_is_legal, {
	return seed_hub_bbs_board_valid("..") == 1;
});

EXO_TEST(seedbbs_board_name_too_long, {
	char name[SEED_BBS_BOARD_MAX + 8];
	memset(name, 'a', sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	return seed_hub_bbs_board_valid(name) == 0;
});

EXO_TEST(seedbbs_board_name_at_limit, {
	char name[SEED_BBS_BOARD_MAX + 1];
	memset(name, 'a', SEED_BBS_BOARD_MAX);
	name[SEED_BBS_BOARD_MAX] = '\0';
	return seed_hub_bbs_board_valid(name) == 1;
});

/* -------------------------------------------------------- board descriptors */

/* The example from the BBS0 specification. */
EXO_TEST(seedbbs_descriptor_full, {
	int ok = bb_parse_board("IBBD BDgeneral NIGeneral\\sdiscussion DEAnything\\sabout\\sthis\\shub"
		" PE7 MS262144 TS1786439662 OT1767225600 NP311\n");
	if (ok)
		ok = strcmp(bb_board.board, "general") == 0;
	if (ok)
		ok = strcmp(bb_board.name, "General discussion") == 0;
	if (ok)
		ok = bb_board.permissions == 7 && bb_board.max_size == 262144;
	if (ok)
		ok = bb_board.newest == 1786439662 && bb_board.oldest == 1767225600;
	if (ok)
		ok = bb_board.num_posts == 311 && bb_board.removed == 0;
	return ok;
});

/* NP and NI are informative, so their absence is not a failure. */
EXO_TEST(seedbbs_descriptor_minimal, {
	int ok = bb_parse_board("IBBD BDgeneral PE1 MS1024 TS0 OT0\n");
	if (ok)
		ok = bb_board.num_posts == 0 && bb_board.name[0] == '\0';
	return ok;
});

/* Each of PE, MS, TS and OT is REQUIRED. */
EXO_TEST(seedbbs_descriptor_missing_permissions, {
	return bb_parse_board("IBBD BDgeneral MS1024 TS0 OT0\n") == 0;
});

EXO_TEST(seedbbs_descriptor_missing_max_size, {
	return bb_parse_board("IBBD BDgeneral PE1 TS0 OT0\n") == 0;
});

EXO_TEST(seedbbs_descriptor_missing_newest, {
	return bb_parse_board("IBBD BDgeneral PE1 MS1024 OT0\n") == 0;
});

EXO_TEST(seedbbs_descriptor_missing_oldest, {
	return bb_parse_board("IBBD BDgeneral PE1 MS1024 TS0\n") == 0;
});

EXO_TEST(seedbbs_descriptor_missing_board, {
	return bb_parse_board("IBBD PE1 MS1024 TS0 OT0\n") == 0;
});

EXO_TEST(seedbbs_descriptor_bad_board_name, {
	return bb_parse_board("IBBD BDa/b PE1 MS1024 TS0 OT0\n") == 0;
});

EXO_TEST(seedbbs_descriptor_non_numeric_permissions, {
	return bb_parse_board("IBBD BDgeneral PEall MS1024 TS0 OT0\n") == 0;
});

/*
 * A removal is accepted on the board name alone. The only thing to do with one
 * is forget the board, and holding it to the full field list would mean
 * ignoring it -- leaving a subscription to a board that is gone.
 */
EXO_TEST(seedbbs_descriptor_removed_needs_only_the_name, {
	int ok = bb_parse_board("IBBD BDgeneral RM1\n");
	if (ok)
		ok = bb_board.removed == 1 && strcmp(bb_board.board, "general") == 0;
	return ok;
});

/* Other RM values are reserved and mean nothing yet. */
EXO_TEST(seedbbs_descriptor_removed_other_value, {
	int ok = bb_parse_board("IBBD BDgeneral PE1 MS1024 TS0 OT0 RM2\n");
	if (ok)
		ok = bb_board.removed == 0;
	return ok;
});

/* An unrecognised field is ignored, as ADC requires of every command. */
EXO_TEST(seedbbs_descriptor_unknown_field_ignored, {
	return bb_parse_board("IBBD BDgeneral PE1 MS1024 TS0 OT0 ZZwhatever\n") == 1;
});

/* ------------------------------------------------------------- index entries */

/* The example from the BBS0 specification. */
EXO_TEST(seedbbs_entry_full, {
	int ok = bb_parse_entry("IBBL TR" BB_TTH " SI412 BDgeneral ID" BB_CID
		" NIjanvidar TH" BB_THREAD " SJHub\\supgrade\\son\\sSaturday TS1786439662\n");
	if (ok)
		ok = strcmp(bb_entry.tth, BB_TTH) == 0 && bb_entry.size == 412;
	if (ok)
		ok = strcmp(bb_entry.board, "general") == 0;
	if (ok)
		ok = strcmp(bb_entry.author_cid, BB_CID) == 0;
	if (ok)
		ok = strcmp(bb_entry.nick, "janvidar") == 0;
	if (ok)
		ok = strcmp(bb_entry.thread, BB_THREAD) == 0;
	if (ok)
		ok = strcmp(bb_entry.subject, "Hub upgrade on Saturday") == 0;
	if (ok)
		ok = bb_entry.timestamp == 1786439662 && bb_entry.removed == 0;
	if (ok)
		ok = bb_entry.parent[0] == '\0';
	return ok;
});

EXO_TEST(seedbbs_entry_reply_has_parent, {
	int ok = bb_parse_entry("IBBL TR" BB_TTH " SI412 BDgeneral ID" BB_CID
		" PA" BB_PARENT " TH" BB_THREAD " TS100\n");
	if (ok)
		ok = strcmp(bb_entry.parent, BB_PARENT) == 0;
	return ok;
});

/*
 * TH is a convenience the hub derives and nothing ever verifies. Where it is
 * absent from a post that starts a thread, that post is its own thread root.
 */
EXO_TEST(seedbbs_entry_thread_defaults_to_self, {
	int ok = bb_parse_entry("IBBL TR" BB_TTH " SI412 BDgeneral ID" BB_CID " TS100\n");
	if (ok)
		ok = strcmp(bb_entry.thread, BB_TTH) == 0;
	return ok;
});

/* A reply with no TH is left with none: its root is not its own hash, and
   guessing one would be inventing the hub's testimony. */
EXO_TEST(seedbbs_entry_reply_without_thread, {
	int ok = bb_parse_entry("IBBL TR" BB_TTH " SI412 BDgeneral ID" BB_CID
		" PA" BB_PARENT " TS100\n");
	if (ok)
		ok = bb_entry.thread[0] == '\0';
	return ok;
});

EXO_TEST(seedbbs_entry_missing_tth, {
	return bb_parse_entry("IBBL SI412 BDgeneral ID" BB_CID " TS100\n") == 0;
});

EXO_TEST(seedbbs_entry_missing_board, {
	return bb_parse_entry("IBBL TR" BB_TTH " SI412 ID" BB_CID " TS100\n") == 0;
});

EXO_TEST(seedbbs_entry_missing_timestamp, {
	return bb_parse_entry("IBBL TR" BB_TTH " SI412 BDgeneral ID" BB_CID "\n") == 0;
});

/* A live entry needs its size and the CID the hub accepted it from. */
EXO_TEST(seedbbs_entry_missing_size, {
	return bb_parse_entry("IBBL TR" BB_TTH " BDgeneral ID" BB_CID " TS100\n") == 0;
});

EXO_TEST(seedbbs_entry_missing_author, {
	return bb_parse_entry("IBBL TR" BB_TTH " SI412 BDgeneral TS100\n") == 0;
});

EXO_TEST(seedbbs_entry_short_tth_rejected, {
	return bb_parse_entry("IBBL TRAAAA SI412 BDgeneral ID" BB_CID " TS100\n") == 0;
});

EXO_TEST(seedbbs_entry_non_base32_tth_rejected, {
	return bb_parse_entry("IBBL TR1111111111111111111111111111111111111 SI412"
		" BDgeneral ID" BB_CID " TS100\n") == 0;
});

EXO_TEST(seedbbs_entry_non_numeric_timestamp, {
	return bb_parse_entry("IBBL TR" BB_TTH " SI412 BDgeneral ID" BB_CID " TSnow\n") == 0;
});

/*
 * A tombstone carries TR, BD, TS and RM1 and should carry nothing else -- the
 * subject and author of a withdrawn post are usually why it was withdrawn -- so
 * it is accepted on those alone.
 */
EXO_TEST(seedbbs_entry_tombstone, {
	int ok = bb_parse_entry("IBBL TR" BB_TTH " BDgeneral TS1786443100 RM1\n");
	if (ok)
		ok = bb_entry.removed == 1 && bb_entry.timestamp == 1786443100;
	if (ok)
		ok = strcmp(bb_entry.tth, BB_TTH) == 0 && bb_entry.size == 0;
	if (ok)
		ok = bb_entry.author_cid[0] == '\0' && bb_entry.subject[0] == '\0';
	return ok;
});

/* Nothing further is read out of a tombstone even when the hub sent it. */
EXO_TEST(seedbbs_entry_tombstone_ignores_extra_fields, {
	int ok = bb_parse_entry("IBBL TR" BB_TTH " BDgeneral TS100 RM1 SI999 ID" BB_CID
		" SJshould\\sbe\\signored\n");
	if (ok)
		ok = bb_entry.removed == 1 && bb_entry.size == 0;
	if (ok)
		ok = bb_entry.subject[0] == '\0' && bb_entry.author_cid[0] == '\0';
	return ok;
});

/* A tombstone still has to name a board and a time. */
EXO_TEST(seedbbs_entry_tombstone_missing_timestamp, {
	return bb_parse_entry("IBBL TR" BB_TTH " BDgeneral RM1\n") == 0;
});

/* ----------------------------------------------------------- search results */

EXO_TEST(seedbbs_result_full, {
	int ok = bb_parse_result("DRES BBBB AAAA FNTTH/" BB_TTH " SI412 SL2 TR" BB_TTH " TO9001\n");
	if (ok)
		ok = strcmp(bb_result.tth, BB_TTH) == 0 && bb_result.size == 412;
	if (ok)
		ok = strcmp(bb_result.token, "9001") == 0;
	if (ok)
		ok = bb_result.from == string_to_sid("BBBB");
	return ok;
});

/* A result naming no hash is of no use to a content-addressed cache. */
EXO_TEST(seedbbs_result_without_tth, {
	return bb_parse_result("DRES BBBB AAAA FNmovie.avi SI412 SL2 TO9001\n") == 0;
});

EXO_TEST(seedbbs_result_without_token, {
	int ok = bb_parse_result("DRES BBBB AAAA TR" BB_TTH " SI412\n");
	if (ok)
		ok = bb_result.token[0] == '\0';
	return ok;
});

EXO_TEST(seedbbs_result_without_size, {
	int ok = bb_parse_result("DRES BBBB AAAA TR" BB_TTH "\n");
	if (ok)
		ok = bb_result.size == 0;
	return ok;
});

EXO_TEST(seedbbs_result_bad_tth, {
	return bb_parse_result("DRES BBBB AAAA TRnope SI1\n") == 0;
});

/* ------------------------------------------------------- the board allowlist */

/* No list means no restriction: a descriptor arriving is permission enough. */
EXO_TEST(seedbbs_allowed_empty_list_allows_all, {
	return seed_bbs_board_allowed("general", NULL) == 1
		&& seed_bbs_board_allowed("general", "") == 1;
});

EXO_TEST(seedbbs_allowed_single, {
	return seed_bbs_board_allowed("general", "general") == 1;
});

EXO_TEST(seedbbs_allowed_not_listed, {
	return seed_bbs_board_allowed("general", "announce") == 0;
});

EXO_TEST(seedbbs_allowed_in_a_list, {
	return seed_bbs_board_allowed("dev.adc", "announce,dev.adc,general") == 1;
});

/* Whole names only: a prefix of a listed name is not a match. */
EXO_TEST(seedbbs_allowed_prefix_is_not_a_match, {
	return seed_bbs_board_allowed("gen", "general") == 0
		&& seed_bbs_board_allowed("general", "gen") == 0;
});

/* Board names are case sensitive, so the comparison is too. */
EXO_TEST(seedbbs_allowed_case_sensitive, {
	return seed_bbs_board_allowed("General", "general") == 0;
});

/* Space around an item is not part of the name. */
EXO_TEST(seedbbs_allowed_spaces_trimmed, {
	return seed_bbs_board_allowed("general", "announce, general , dev") == 1;
});

EXO_TEST(seedbbs_allowed_empty_board, {
	return seed_bbs_board_allowed("", "general") == 0
		&& seed_bbs_board_allowed(NULL, "general") == 0;
});

/* --------------------------------------------------------------- the backoff */

/* The first attempt waits the minimum, and it is never zero: a delay of zero
   would busy-loop on a hash nobody holds. */
EXO_TEST(seedbbs_retry_first, {
	return seed_bbs_retry_delay(0) == SEED_BBS_RETRY_MIN
		&& seed_bbs_retry_delay(1) == SEED_BBS_RETRY_MIN;
});

EXO_TEST(seedbbs_retry_doubles, {
	return seed_bbs_retry_delay(2) == SEED_BBS_RETRY_MIN * 2
		&& seed_bbs_retry_delay(3) == SEED_BBS_RETRY_MIN * 4;
});

EXO_TEST(seedbbs_retry_saturates, {
	unsigned int i;
	for (i = 0; i < 64; i++)
	{
		if (seed_bbs_retry_delay(i) > SEED_BBS_RETRY_MAX)
			return 0;
	}
	return seed_bbs_retry_delay(64) == SEED_BBS_RETRY_MAX;
});

EXO_TEST(seedbbs_retry_never_zero, {
	unsigned int i;
	for (i = 0; i < 64; i++)
	{
		if (seed_bbs_retry_delay(i) == 0)
			return 0;
	}
	return 1;
});

/* --------------------------------------------------------------- null safety */

EXO_TEST(seedbbs_parsers_reject_null, {
	return seed_hub_parse_bbs_board(NULL, &bb_board) == 0
		&& seed_hub_parse_bbs_entry(NULL, &bb_entry) == 0
		&& seed_hub_parse_result(NULL, &bb_result) == 0;
});

EXO_TEST(seedbbs_engine_events_survive_null, {
	/* Every event is safe on a NULL engine, which is what a caller that failed
	   to create one, or that runs with boards disabled, will hand them. */
	seed_bbs_on_logged_in(NULL);
	seed_bbs_on_disconnected(NULL);
	seed_bbs_on_board(NULL, NULL);
	seed_bbs_on_entry(NULL, NULL);
	seed_bbs_on_search_result(NULL, NULL);
	seed_bbs_on_download(NULL, NULL, SEED_OK, NULL);
	seed_bbs_tick(NULL, 0);
	seed_bbs_destroy(NULL);
	return 1;
});

EXO_TEST(seedbbs_create_rejects_null, {
	return seed_bbs_create(NULL, NULL, NULL, NULL) == NULL;
});

EXO_TEST(seedbbs_stats_of_null_is_zeroed, {
	struct seed_bbs_stats stats;
	memset(&stats, 0xAA, sizeof(stats));
	seed_bbs_get_stats(NULL, &stats);
	return stats.boards == 0 && stats.queued == 0 && stats.posts_fetched == 0;
});
