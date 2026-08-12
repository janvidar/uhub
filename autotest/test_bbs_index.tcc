#include "core/bbs_index.h"
#include "util/memory.h"

static struct bbs_index* bbs_idx = 0;

/* Three well-formed Tiger tree hash roots (39 base32 characters). */
#define TTH_A "KX3TQ7ZVN5PLQGKD3NDBK6ZTZG5PYQXSNMFYVJH"
#define TTH_B "7ZQGKD3NDBK6ZTZG5PYQXSNMFYVJH4TXAVN6PLQ"
#define TTH_C "VN6PLQ7ZQGKD3NDBK6ZTZG5PYQXSNMFYVJH4TXA"
#define CID_A "IPJJWEPPPLCA3PF2ZCRRYO4F2ZX2EV2JMW2KC3I"

/* Fill in the author-supplied half of an entry; the hub supplies the rest. */
static void bbs_entry_init(struct bbs_entry* e, const char* tth, const char* parent, const char* subject)
{
	memset(e, 0, sizeof(struct bbs_entry));
	strcpy(e->tth, tth);
	if (parent)
		strcpy(e->parent, parent);
	if (subject)
		strcpy(e->subject, subject);
	strcpy(e->cid, CID_A);
	strcpy(e->nick, "janvidar");
	e->size = 412;
}

static int bbs_add(const char* board, const char* tth, const char* parent, time_t now)
{
	struct bbs_entry e;
	bbs_entry_init(&e, tth, parent, "Subject");
	return bbs_index_append(bbs_idx, board, &e, now, 0) == bbs_index_ok;
}

/* Replay collector. */
static int bbs_seen = 0;
static struct bbs_entry bbs_last;
static struct bbs_entry bbs_first;
static int bbs_order_ok = 0;
static time_t bbs_prev_ts = 0;

static void bbs_collect(const struct bbs_entry* entry, void* ptr)
{
	(void) ptr;
	if (bbs_seen == 0)
	{
		bbs_first = *entry;
		bbs_order_ok = 1;
	}
	else if (entry->ts < bbs_prev_ts)
	{
		bbs_order_ok = 0;
	}
	bbs_prev_ts = entry->ts;
	bbs_last = *entry;
	bbs_seen++;
}

static int bbs_replay(const char* board, time_t from)
{
	bbs_seen = 0;
	bbs_order_ok = 0;
	bbs_prev_ts = 0;
	memset(&bbs_first, 0, sizeof(bbs_first));
	memset(&bbs_last, 0, sizeof(bbs_last));
	return bbs_index_replay(bbs_idx, board, from, &bbs_collect, 0);
}

EXO_TEST(bbs_index_setup, {
	bbs_idx = bbs_index_open(":memory:");
	return bbs_idx != 0;
});

/* -- hash validation --------------------------------------------------- */

EXO_TEST(bbs_index_tth_valid, { return bbs_tth_is_valid(TTH_A); });
EXO_TEST(bbs_index_tth_null, { return !bbs_tth_is_valid(0); });
EXO_TEST(bbs_index_tth_empty, { return !bbs_tth_is_valid(""); });
EXO_TEST(bbs_index_tth_short, { return !bbs_tth_is_valid("KX3TQ7ZVN5PLQGKD3NDBK6ZTZG5PYQXSNMFYVJ"); });
EXO_TEST(bbs_index_tth_long, { return !bbs_tth_is_valid(TTH_A "A"); });
EXO_TEST(bbs_index_tth_lowercase, { return !bbs_tth_is_valid("kx3tq7zvn5plqgkd3ndbk6ztzg5pyqxsnmfyvjh"); });
/* base32 has no 0, 1, 8 or 9. */
EXO_TEST(bbs_index_tth_digit_zero, { return !bbs_tth_is_valid("0X3TQ7ZVN5PLQGKD3NDBK6ZTZG5PYQXSNMFYVJH"); });
EXO_TEST(bbs_index_tth_digit_eight, { return !bbs_tth_is_valid("8X3TQ7ZVN5PLQGKD3NDBK6ZTZG5PYQXSNMFYVJH"); });

/* -- append and look up ------------------------------------------------ */

EXO_TEST(bbs_index_empty_board, {
	time_t newest = 1, oldest = 1;
	size_t count = 1;
	return bbs_index_stats(bbs_idx, "general", &newest, &oldest, &count) == 0
		&& newest == 0 && oldest == 0 && count == 0;
});

EXO_TEST(bbs_index_append_first, {
	struct bbs_entry e;
	bbs_entry_init(&e, TTH_A, 0, "Hub upgrade on Saturday");
	return bbs_index_append(bbs_idx, "general", &e, 1786439662, 0) == bbs_index_ok
		&& e.ts == 1786439662
		/* A post that starts a thread is its own thread root. */
		&& !strcmp(e.thread, TTH_A)
		&& e.removed == 0;
});

EXO_TEST(bbs_index_lookup_found, {
	struct bbs_entry e;
	return bbs_index_lookup(bbs_idx, "general", TTH_A, &e) == bbs_index_ok
		&& !strcmp(e.tth, TTH_A)
		&& !strcmp(e.cid, CID_A)
		&& !strcmp(e.nick, "janvidar")
		&& !strcmp(e.subject, "Hub upgrade on Saturday")
		&& e.parent[0] == 0
		&& e.size == 412
		&& e.ts == 1786439662;
});

EXO_TEST(bbs_index_lookup_missing, {
	return bbs_index_lookup(bbs_idx, "general", TTH_C, 0) == bbs_index_not_found;
});

/* A post is the same post on every hub, but an index entry belongs to one
   board on one hub. */
EXO_TEST(bbs_index_lookup_other_board, {
	return bbs_index_lookup(bbs_idx, "announcements", TTH_A, 0) == bbs_index_not_found;
});

EXO_TEST(bbs_index_append_duplicate, {
	struct bbs_entry e;
	bbs_entry_init(&e, TTH_A, 0, "Again");
	return bbs_index_append(bbs_idx, "general", &e, 1786439700, 0) == bbs_index_duplicate;
});

/* The same document may be indexed on a second board -- that is a relayed post,
   and it is the honest case. */
EXO_TEST(bbs_index_append_same_tth_other_board, {
	return bbs_add("announcements", TTH_A, 0, 1786439700);
});

/* -- threading --------------------------------------------------------- */

EXO_TEST(bbs_index_reply_inherits_thread, {
	struct bbs_entry e;
	bbs_entry_init(&e, TTH_B, TTH_A, "Re: Hub upgrade on Saturday");
	return bbs_index_append(bbs_idx, "general", &e, 1786442550, 0) == bbs_index_ok
		&& !strcmp(e.parent, TTH_A)
		&& !strcmp(e.thread, TTH_A);
});

/* A reply to a reply stays in the same thread: TH follows the root, not the
   parent. */
EXO_TEST(bbs_index_nested_reply_keeps_root, {
	struct bbs_entry e;
	bbs_entry_init(&e, TTH_C, TTH_B, "Re: Re: Hub upgrade");
	return bbs_index_append(bbs_idx, "general", &e, 1786442600, 0) == bbs_index_ok
		&& !strcmp(e.thread, TTH_A);
});

EXO_TEST(bbs_index_reply_unknown_parent, {
	struct bbs_entry e;
	bbs_entry_init(&e, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TTH_C, "Orphan");
	return bbs_index_append(bbs_idx, "announcements", &e, 1786442700, 0) == bbs_index_no_parent;
});

/* -- timestamps -------------------------------------------------------- */

/* A hub must assign a timestamp no lower than the highest already on the board.
   Where its clock has moved backwards it reuses the highest rather than a lower
   one, so nothing ever enters the index behind a cursor that has passed it. */
EXO_TEST(bbs_index_clock_moves_backwards, {
	struct bbs_entry e;
	bbs_entry_init(&e, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 0, "Back in time");
	return bbs_index_append(bbs_idx, "general", &e, 1000, 0) == bbs_index_ok
		&& e.ts == 1786442600;
});

/* Timestamps are not unique, and on a busy board that is ordinary: the hub must
   not perturb one to make it so. */
EXO_TEST(bbs_index_same_second_not_perturbed, {
	struct bbs_entry e;
	bbs_entry_init(&e, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", 0, "Same second");
	return bbs_index_append(bbs_idx, "general", &e, 1786442600, 0) == bbs_index_ok
		&& e.ts == 1786442600;
});

EXO_TEST(bbs_index_stats_after_appends, {
	time_t newest = 0, oldest = 0;
	size_t count = 0;
	return bbs_index_stats(bbs_idx, "general", &newest, &oldest, &count) == 0
		&& newest == 1786442600
		&& oldest == 1786439662
		&& count == 5;
});

/* -- replay ------------------------------------------------------------ */

EXO_TEST(bbs_index_replay_everything, {
	return bbs_replay("general", 0) == 5 && bbs_seen == 5 && bbs_order_ok;
});

EXO_TEST(bbs_index_replay_from_cursor, {
	/* Entries at 1786442550, 1786442600, 1786442600, 1786442600. */
	return bbs_replay("general", 1786442550) == 4 && bbs_order_ok;
});

/* Resuming from the highest timestamp seen re-delivers that second's entries;
   a client discards them by hash. Resuming from one second later would skip a
   post accepted in the same second, which is why clients must not do it. */
EXO_TEST(bbs_index_replay_resumption_window_overlaps, {
	int with = bbs_replay("general", 1786442600);
	int without = bbs_replay("general", 1786442601);
	return with == 3 && without == 0;
});

EXO_TEST(bbs_index_replay_future_cursor, {
	return bbs_replay("general", 2000000000) == 0;
});

EXO_TEST(bbs_index_replay_unknown_board, {
	return bbs_replay("nosuchboard", 0) == 0;
});

/* -- withdrawal -------------------------------------------------------- */

EXO_TEST(bbs_index_withdraw_missing, {
	return bbs_index_withdraw(bbs_idx, "general", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
	                          1786443100, 0) == bbs_index_not_found;
});

/* The tombstone keeps the hash and takes a *new* timestamp, which is what puts
   it at the head of the stream where a resuming client will see it. */
EXO_TEST(bbs_index_withdraw_tombstone, {
	struct bbs_entry tomb;
	return bbs_index_withdraw(bbs_idx, "general", TTH_A, 1786443100, &tomb) == bbs_index_ok
		&& !strcmp(tomb.tth, TTH_A)
		&& tomb.ts == 1786443100
		&& tomb.removed == 1
		/* and nothing else: the subject and author of a withdrawn post are
		   usually the reason it was withdrawn. */
		&& tomb.subject[0] == 0
		&& tomb.cid[0] == 0
		&& tomb.nick[0] == 0;
});

EXO_TEST(bbs_index_withdraw_marks_stored_entry, {
	struct bbs_entry e;
	return bbs_index_lookup(bbs_idx, "general", TTH_A, &e) == bbs_index_ok
		&& e.removed == 1
		&& e.ts == 1786443100;
});

/* NP excludes tombstones, but the entry stays in the index so that replay can
   still deliver the withdrawal. */
EXO_TEST(bbs_index_withdraw_excluded_from_count, {
	size_t count = 0;
	return bbs_index_stats(bbs_idx, "general", 0, 0, &count) == 0 && count == 4;
});

EXO_TEST(bbs_index_withdraw_replayed_as_tombstone, {
	return bbs_replay("general", 1786443100) == 1
		&& bbs_last.removed == 1
		&& !strcmp(bbs_last.tth, TTH_A);
});

/* Withdrawal is not deletion: a reply to a withdrawn post is a separate post
   and stays where it is. */
EXO_TEST(bbs_index_withdraw_keeps_replies, {
	struct bbs_entry e;
	return bbs_index_lookup(bbs_idx, "general", TTH_B, &e) == bbs_index_ok && e.removed == 0;
});

EXO_TEST(bbs_index_withdraw_twice, {
	struct bbs_entry tomb;
	return bbs_index_withdraw(bbs_idx, "general", TTH_A, 1786443200, &tomb) == bbs_index_ok
		&& tomb.ts == 1786443200;
});

/* -- pruning ----------------------------------------------------------- */

EXO_TEST(bbs_index_prune_setup, {
	int i;
	char tth[BBS_TTH_LEN + 1];
	struct bbs_entry e;
	for (i = 0; i < 10; i++)
	{
		memset(tth, 'A' + (i % 20), BBS_TTH_LEN);
		tth[BBS_TTH_LEN] = 0;
		bbs_entry_init(&e, tth, 0, "Prunable");
		if (bbs_index_append(bbs_idx, "prune", &e, 2000 + i, 0) != bbs_index_ok)
			return 0;
	}
	return bbs_replay("prune", 0) == 10;
});

EXO_TEST(bbs_index_prune_drops_oldest, {
	struct bbs_entry e;
	char tth[BBS_TTH_LEN + 1];
	memset(tth, 'Z', BBS_TTH_LEN);
	tth[BBS_TTH_LEN] = 0;
	bbs_entry_init(&e, tth, 0, "The eleventh");
	/* Retain five: the new entry plus the four newest already there. */
	return bbs_index_append(bbs_idx, "prune", &e, 2010, 5) == bbs_index_ok
		&& bbs_replay("prune", 0) == 5;
});

/* Once pruning has happened the board's oldest entry moves forward, and that is
   what OT reports -- so the hub never promises a replay it cannot deliver. */
EXO_TEST(bbs_index_prune_raises_oldest, {
	time_t oldest = 0;
	return bbs_index_stats(bbs_idx, "prune", 0, &oldest, 0) == 0 && oldest == 2006;
});

EXO_TEST(bbs_index_prune_zero_retains_everything, {
	struct bbs_entry e;
	char tth[BBS_TTH_LEN + 1];
	memset(tth, 'Y', BBS_TTH_LEN);
	tth[BBS_TTH_LEN] = 0;
	bbs_entry_init(&e, tth, 0, "Kept");
	return bbs_index_append(bbs_idx, "prune", &e, 2011, 0) == bbs_index_ok
		&& bbs_replay("prune", 0) == 6;
});

/* -- defensive --------------------------------------------------------- */

EXO_TEST(bbs_index_null_index, {
	struct bbs_entry e;
	bbs_entry_init(&e, TTH_A, 0, "nope");
	return bbs_index_append(0, "general", &e, 1, 0) == bbs_index_error
		&& bbs_index_lookup(0, "general", TTH_A, 0) == bbs_index_error
		&& bbs_index_withdraw(0, "general", TTH_A, 1, 0) == bbs_index_error
		&& bbs_index_replay(0, "general", 0, &bbs_collect, 0) == -1
		&& bbs_index_stats(0, "general", 0, 0, 0) == -1;
});

EXO_TEST(bbs_index_teardown, {
	bbs_index_close(bbs_idx);
	bbs_idx = 0;
	bbs_index_close(0); /* tolerates NULL */
	return 1;
});
