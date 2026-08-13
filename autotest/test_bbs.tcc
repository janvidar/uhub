#include "adc/adcconst.h"
#include "adc/message.h"
#include "core/bbs.h"
#include "core/bbs_index.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/usermanager.h"
#include "network/network.h"
#include "testutil_user.h"

/* BBS0 at the protocol level: the exact lines the hub puts on the wire, read
   back out of the send queue (see testutil_user.h). */

#define BBS_TTH_A "KX3TQ7ZVN5PLQGKD3NDBK6ZTZG5PYQXSNMFYVJH"
#define BBS_CID_A "IPJJWEPPPLCA3PF2ZCRRYO4F2ZX2EV2JMW2KC3I"

static struct hub_info* bh = 0;
static struct hub_user* bu_guest = 0;
static struct hub_user* bu_reg = 0;
static struct hub_user* bu_op = 0;

static struct bbs_board* bbs_add_board(const char* line)
{
	int error = 0;
	struct bbs_board* board = bbs_board_parse(line, &error);
	if (board)
		list_append(bh->bbs->boards, board);
	return board;
}

EXO_TEST(bbs_setup, {
	net_initialize();

	bh = (struct hub_info*) hub_malloc_zero(sizeof(struct hub_info));
	if (!bh)
		return 0;
	bh->config = (struct hub_config*) hub_malloc_zero(sizeof(struct hub_config));
	if (!bh->config)
		return 0;
	config_defaults(bh->config);
	bh->users = uman_init(0, 1);
	bh->write_queue = list_create();

	/* A handle built by hand rather than through bbs_initialize(), so the test
	   needs no files: an in-memory index and boards appended directly. */
	bh->bbs = (struct bbs_handle*) hub_malloc_zero(sizeof(struct bbs_handle));
	if (!bh->bbs)
		return 0;
	bh->bbs->boards = list_create();
	bh->bbs->index = bbs_index_open(":memory:");

	bu_guest = tu_user_create(bh, 1, "guest", BBS_CID_A, auth_cred_guest);
	bu_reg   = tu_user_create(bh, 2, "reg", "AN7ZMSLIEBL53OPTM7WXGSTXUS3XOY6KQS5LBGX", auth_cred_user);
	bu_op    = tu_user_create(bh, 3, "op", "BN7ZMSLIEBL53OPTM7WXGSTXUS3XOY6KQS5LBGX", auth_cred_operator);

	/* Everyone here speaks BBS0 unless a test says otherwise. */
	user_flag_set(bu_guest, feature_bbs);
	user_flag_set(bu_reg, feature_bbs);
	user_flag_set(bu_op, feature_bbs);

	return bh->bbs->index && bh->users && bh->write_queue
		&& bu_guest && bu_reg && bu_op;
});

EXO_TEST(bbs_setup_boards, {
	return bbs_add_board("board general title=\"General discussion\" description=\"Anything about this hub\"")
		&& bbs_add_board("board announcements title=\"Announcements\" post=operator max_size=65536")
		&& bbs_add_board("board members subscribe=reg")
		&& list_size(bh->bbs->boards) == 3;
});

EXO_TEST(bbs_is_enabled_when_index_open, {
	return bbs_is_enabled(bh);
});

EXO_TEST(bbs_is_enabled_false_without_handle, {
	struct bbs_handle* saved = bh->bbs;
	int enabled;
	bh->bbs = 0;
	enabled = bbs_is_enabled(bh);
	bh->bbs = saved;
	return !enabled && !bbs_is_enabled(0);
});

/* -- board descriptors -------------------------------------------------- */

/* A guest sees the two open boards and is never told the registered-only one
   exists. PE5 on general is subscribe (1) + reply (4); PE5 on announcements is
   the same, since only operators may start a thread there. */
EXO_TEST(bbs_descriptor_guest_sees_two_boards, {
	tu_queue_clear(bu_guest);
	bbs_send_board_list(bh, bu_guest);
	return tu_queue_count(bu_guest) == 2
		&& tu_queue_find(bu_guest, "IBBD BDgeneral ") == 0
		&& tu_queue_find(bu_guest, "IBBD BDannouncements ") == 1
		&& tu_queue_find(bu_guest, "IBBD BDmembers ") == -1;
});

/* The whole line, exactly. An empty board reports TS0, OT0 and NP0. */
EXO_TEST(bbs_descriptor_wire_format, {
	return tu_queue_has(bu_guest,
		"IBBD BDgeneral NIGeneral\\sdiscussion DEAnything\\sabout\\sthis\\shub"
		" PE5 MS262144 TS0 OT0 NP0\n");
});

EXO_TEST(bbs_descriptor_max_size_is_per_board, {
	return tu_queue_has(bu_guest,
		"IBBD BDannouncements NIAnnouncements PE5 MS65536 TS0 OT0 NP0\n");
});

EXO_TEST(bbs_descriptor_registered_user_sees_all_three, {
	tu_queue_clear(bu_reg);
	bbs_send_board_list(bh, bu_reg);
	return tu_queue_count(bu_reg) == 3
		&& tu_queue_find(bu_reg, "IBBD BDmembers ") == 2;
});

/* PE15 is 1+2+4+8: subscribe, post, reply and withdraw one's own. */
EXO_TEST(bbs_descriptor_registered_permissions, {
	return tu_queue_has(bu_reg,
		"IBBD BDgeneral NIGeneral\\sdiscussion DEAnything\\sabout\\sthis\\shub"
		" PE15 MS262144 TS0 OT0 NP0\n");
});

/* PE31 is every bit: an operator moderates as well as posts. */
EXO_TEST(bbs_descriptor_operator_permissions, {
	tu_queue_clear(bu_op);
	bbs_send_board_list(bh, bu_op);
	return tu_queue_has(bu_op,
		"IBBD BDgeneral NIGeneral\\sdiscussion DEAnything\\sabout\\sthis\\shub"
		" PE31 MS262144 TS0 OT0 NP0\n");
});

/* Splitting post from reply is the point of an announcements board: a
   registered user gets 1+4+8 = 13, with the posting bit withheld. */
EXO_TEST(bbs_descriptor_announcements_registered_cannot_post, {
	return tu_queue_has(bu_reg, "IBBD BDannouncements NIAnnouncements PE13 MS65536 TS0 OT0 NP0\n");
});

/* A client that never offered BBS0 receives no descriptor, whatever its
   permissions: the hub's announcement in SUP is what the exchange rests on. */
EXO_TEST(bbs_descriptor_not_sent_without_feature, {
	user_flag_unset(bu_op, feature_bbs);
	tu_queue_clear(bu_op);
	bbs_send_board_list(bh, bu_op);
	user_flag_set(bu_op, feature_bbs);
	return tu_queue_count(bu_op) == 0;
});

/* -- descriptor contents track the index -------------------------------- */

EXO_TEST(bbs_descriptor_reports_posts, {
	struct bbs_entry e;
	memset(&e, 0, sizeof(e));
	strcpy(e.tth, BBS_TTH_A);
	strcpy(e.cid, BBS_CID_A);
	strcpy(e.nick, "guest");
	strcpy(e.subject, "Hub upgrade on Saturday");
	e.size = 412;
	if (bbs_index_append(bh->bbs->index, "general", &e, 1786439662, 0) != bbs_index_ok)
		return 0;

	tu_queue_clear(bu_guest);
	bbs_send_board_list(bh, bu_guest);
	/* TS is the newest entry, OT the oldest the hub will replay -- here the
	   same entry, since the board keeps everything. */
	return tu_queue_has(bu_guest,
		"IBBD BDgeneral NIGeneral\\sdiscussion DEAnything\\sabout\\sthis\\shub"
		" PE5 MS262144 TS1786439662 OT1786439662 NP1\n");
});

/* A withdrawn post leaves the index entry in place, so it still bounds TS, but
   it stops counting towards NP. */
EXO_TEST(bbs_descriptor_excludes_tombstones_from_count, {
	if (bbs_index_withdraw(bh->bbs->index, "general", BBS_TTH_A, 1786443100, 0) != bbs_index_ok)
		return 0;
	tu_queue_clear(bu_guest);
	bbs_send_board_list(bh, bu_guest);
	return tu_queue_has(bu_guest,
		"IBBD BDgeneral NIGeneral\\sdiscussion DEAnything\\sabout\\sthis\\shub"
		" PE5 MS262144 TS1786443100 OT1786443100 NP0\n");
});

/* replay_days moves OT forward: the hub declares what it will replay rather
   than the age of its oldest entry. */
EXO_TEST(bbs_descriptor_replay_days_bounds_oldest, {
	struct bbs_board* board = bbs_add_board("board recent replay_days=1");
	time_t oldest;
	struct bbs_entry e;
	if (!board)
		return 0;
	memset(&e, 0, sizeof(e));
	strcpy(e.tth, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	strcpy(e.cid, BBS_CID_A);
	e.size = 1;
	/* An entry a week old on a board that replays one day. */
	if (bbs_index_append(bh->bbs->index, "recent", &e, 1786000000, 0) != bbs_index_ok)
		return 0;
	oldest = bbs_board_oldest_replay(bh->bbs, board, 1786500000);
	return oldest == 1786500000 - 86400;
});

/* With no age limit OT is simply the oldest entry held. */
EXO_TEST(bbs_descriptor_no_replay_limit_reports_oldest_entry, {
	struct bbs_board* board = bbs_board_find(bh->bbs, "general");
	return board && bbs_board_oldest_replay(bh->bbs, board, 1786500000) == 1786443100;
});

/* -- subscriptions (HBBL) ----------------------------------------------- */

/* Drive the handler the way the dispatch switch does: parse a real line, then
   call it. Everything the hub sends back lands in the user's send queue. */
static int bbs_hbbl(struct hub_user* user, const char* line)
{
	struct adc_message* cmd = adc_msg_parse(line, strlen(line));
	int ret;
	if (!cmd)
		return -2;
	tu_queue_clear(user);
	ret = bbs_handle_subscribe(bh, user, cmd);
	adc_msg_free(cmd);
	return ret;
}

/* Post to a board directly through the index, standing in for another user's
   HBBP until posting exists. */
static int bbs_seed(const char* board, const char* tth, const char* parent,
                    const char* subject, time_t ts)
{
	struct bbs_entry e;
	memset(&e, 0, sizeof(e));
	strcpy(e.tth, tth);
	if (parent)
		strcpy(e.parent, parent);
	if (subject)
		strcpy(e.subject, subject);
	strcpy(e.cid, BBS_CID_A);
	strcpy(e.nick, "janvidar");
	e.size = 412;
	return bbs_index_append(bh->bbs->index, board, &e, ts, 0) == bbs_index_ok;
}

#define BBS_TTH_B "7ZQGKD3NDBK6ZTZG5PYQXSNMFYVJH4TXAVN6PLQ"
#define BBS_TTH_C "VN6PLQ7ZQGKD3NDBK6ZTZG5PYQXSNMFYVJH4TXA"

EXO_TEST(bbs_subscribe_seed_board, {
	return bbs_seed("announcements", BBS_TTH_B, 0, "Hub upgrade on Saturday", 1786436000)
		&& bbs_seed("announcements", BBS_TTH_C, BBS_TTH_B, "Re: Hub upgrade on Saturday", 1786438120);
});

EXO_TEST(bbs_subscribe_replays_backlog, {
	return bbs_hbbl(bu_guest, "HBBL BDannouncements TS0\n") == 0
		&& tu_queue_count(bu_guest) == 2;
});

/* The entry, in full. TH names the thread root the hub derived; the reply's is
   its parent's hash, and nothing in a document names a thread. */
EXO_TEST(bbs_subscribe_entry_wire_format, {
	return tu_queue_has(bu_guest,
		"IBBL TR" BBS_TTH_B " SI412 BDannouncements ID" BBS_CID_A
		" NIjanvidar TH" BBS_TTH_B " SJHub\\supgrade\\son\\sSaturday TS1786436000\n");
});

EXO_TEST(bbs_subscribe_reply_carries_parent_and_thread, {
	return tu_queue_has(bu_guest,
		"IBBL TR" BBS_TTH_C " SI412 BDannouncements ID" BBS_CID_A
		" NIjanvidar PA" BBS_TTH_B " TH" BBS_TTH_B
		" SJRe:\\sHub\\supgrade\\son\\sSaturday TS1786438120\n");
});

EXO_TEST(bbs_subscribe_records_subscription, {
	struct bbs_board* board = bbs_board_find(bh->bbs, "announcements");
	struct bbs_subscription* sub = bbs_user_subscription(bu_guest, board);
	return sub && sub->cursor == 1786438120;
});

/* Resuming from the highest timestamp seen re-delivers that second. */
EXO_TEST(bbs_subscribe_resume_from_cursor, {
	return bbs_hbbl(bu_guest, "HBBL BDannouncements TS1786438120\n") == 0
		&& tu_queue_count(bu_guest) == 1;
});

/* A second HBBL replaces the first rather than adding to it. */
EXO_TEST(bbs_subscribe_replaces_not_adds, {
	struct bbs_board* board = bbs_board_find(bh->bbs, "announcements");
	return list_size(bu_guest->bbs_subs) == 1
		&& bbs_user_subscription(bu_guest, board) != 0;
});

EXO_TEST(bbs_subscribe_absent_ts_means_everything, {
	return bbs_hbbl(bu_guest, "HBBL BDannouncements\n") == 0
		&& tu_queue_count(bu_guest) == 2;
});

EXO_TEST(bbs_subscribe_cancel, {
	struct bbs_board* board = bbs_board_find(bh->bbs, "announcements");
	return bbs_hbbl(bu_guest, "HBBL BDannouncements RM1\n") == 0
		&& tu_queue_count(bu_guest) == 0
		&& bbs_user_subscription(bu_guest, board) == 0;
});

/* Cancelling something never subscribed to is not an error. */
EXO_TEST(bbs_subscribe_cancel_when_not_subscribed, {
	return bbs_hbbl(bu_guest, "HBBL BDannouncements RM1\n") == 0
		&& tu_queue_count(bu_guest) == 0;
});

/* -- single entry requests ---------------------------------------------- */

EXO_TEST(bbs_subscribe_single_entry, {
	return bbs_hbbl(bu_guest, "HBBL BDannouncements TR" BBS_TTH_B "\n") == 0
		&& tu_queue_count(bu_guest) == 1
		&& tu_queue_find(bu_guest, "IBBL TR" BBS_TTH_B " ") == 0;
});

/* A request carrying TR is a question, not a subscription. */
EXO_TEST(bbs_subscribe_single_entry_does_not_subscribe, {
	struct bbs_board* board = bbs_board_find(bh->bbs, "announcements");
	return bbs_user_subscription(bu_guest, board) == 0;
});

EXO_TEST(bbs_subscribe_single_entry_missing, {
	return bbs_hbbl(bu_guest, "HBBL BDannouncements TRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n") == -1
		&& tu_queue_has(bu_guest,
			"ISTA 176 No\\ssuch\\spost FCBBL TRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
});

EXO_TEST(bbs_subscribe_single_entry_bad_hash, {
	return bbs_hbbl(bu_guest, "HBBL BDannouncements TRnothash\n") == -1
		&& tu_queue_has(bu_guest, "ISTA 143 Invalid\\shash FCBBL FBTR\n");
});

/* -- refusals ----------------------------------------------------------- */

EXO_TEST(bbs_subscribe_missing_board, {
	return bbs_hbbl(bu_guest, "HBBL TS0\n") == -1
		&& tu_queue_has(bu_guest, "ISTA 143 Missing\\sboard\\sname FCBBL FMBD\n");
});

EXO_TEST(bbs_subscribe_unknown_board, {
	return bbs_hbbl(bu_guest, "HBBL BDgenrel TS0\n") == -1
		&& tu_queue_has(bu_guest, "ISTA 171 No\\ssuch\\sboard FCBBL BDgenrel\n");
});

/* A board the session cannot subscribe to is refused exactly as one that does
   not exist, so the refusal does not disclose it. */
EXO_TEST(bbs_subscribe_invisible_board_looks_missing, {
	return bbs_hbbl(bu_guest, "HBBL BDmembers TS0\n") == -1
		&& tu_queue_has(bu_guest, "ISTA 171 No\\ssuch\\sboard FCBBL BDmembers\n");
});

EXO_TEST(bbs_subscribe_visible_to_registered, {
	return bbs_hbbl(bu_reg, "HBBL BDmembers TS0\n") == 0
		&& tu_queue_count(bu_reg) == 0; /* the board is empty, but it exists */
});

EXO_TEST(bbs_subscribe_tr_and_ts_together, {
	return bbs_hbbl(bu_guest, "HBBL BDannouncements TS0 TR" BBS_TTH_B "\n") == -1
		&& tu_queue_has(bu_guest, "ISTA 140 TR\\sand\\sTS\\smust\\snot\\sboth\\sbe\\sgiven FCBBL\n");
});

EXO_TEST(bbs_subscribe_limit, {
	int i;
	char line[64];
	char name[32];
	/* One more board than the session is allowed to hold at once. */
	for (i = 0; i < bh->config->bbs_max_subscriptions + 1; i++)
	{
		snprintf(name, sizeof(name), "many%d", i);
		snprintf(line, sizeof(line), "board %s", name);
		if (!bbs_add_board(line))
			return 0;
	}
	for (i = 0; i < bh->config->bbs_max_subscriptions; i++)
	{
		snprintf(line, sizeof(line), "HBBL BDmany%d TS0\n", i);
		if (bbs_hbbl(bu_op, line) != 0)
			return 0;
	}
	snprintf(line, sizeof(line), "HBBL BDmany%d TS0\n", bh->config->bbs_max_subscriptions);
	return bbs_hbbl(bu_op, line) == -1
		&& tu_queue_find(bu_op, "ISTA 170 Too\\smany\\ssubscriptions FCBBL BDmany") == 0;
});

/* Re-subscribing to a board already held is not a new subscription and does not
   count against the limit. */
EXO_TEST(bbs_subscribe_resubscribe_within_limit, {
	return bbs_hbbl(bu_op, "HBBL BDmany0 TS0\n") == 0
		&& list_size(bu_op->bbs_subs) == (size_t) bh->config->bbs_max_subscriptions;
});

/* -- OT clamping -------------------------------------------------------- */

/* A cursor older than what the hub will replay is not refused: the request is
   treated as one from OT, so a client that has been away too long still gets
   everything the hub still holds. */
EXO_TEST(bbs_subscribe_setup_bounded_board, {
	return bbs_add_board("board bounded") != 0
		&& bbs_seed("bounded", "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", 0, "First", 5000)
		&& bbs_seed("bounded", "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", 0, "Second", 6000);
});

EXO_TEST(bbs_subscribe_ancient_cursor_is_served_not_refused, {
	return bbs_hbbl(bu_guest, "HBBL BDbounded TS1\n") == 0
		&& tu_queue_count(bu_guest) == 2;
});

/* The cursor ends up at the newest entry actually sent, so the next resume
   starts from there rather than from the value the client asked for. */
EXO_TEST(bbs_subscribe_cursor_follows_what_was_sent, {
	struct bbs_board* board = bbs_board_find(bh->bbs, "bounded");
	struct bbs_subscription* sub = bbs_user_subscription(bu_guest, board);
	return sub && sub->cursor == 6000;
});

/* A negative timestamp is not a way to ask for something before the beginning. */
EXO_TEST(bbs_subscribe_negative_ts, {
	return bbs_hbbl(bu_guest, "HBBL BDbounded TS-9999\n") == 0
		&& tu_queue_count(bu_guest) == 2;
});

/* -- lifecycle ---------------------------------------------------------- */

/* Cancelling a board's subscriptions walks the user manager, so a user has to
   be in it to be reached. */
EXO_TEST(bbs_subscribe_cancelled_when_board_goes, {
	struct bbs_board* board = bbs_board_find(bh->bbs, "many0");
	if (bbs_user_subscription(bu_op, board) == 0)
		return 0;
	uman_add(bh->users, bu_op);
	bbs_cancel_subscriptions(bh, board);
	uman_remove(bh->users, bu_op);
	return bbs_user_subscription(bu_op, board) == 0
		/* and only that board's */
		&& bbs_user_subscription(bu_op, bbs_board_find(bh->bbs, "many1")) != 0;
});

EXO_TEST(bbs_subscribe_unsubscribe_all, {
	bbs_user_unsubscribe_all(bu_op);
	return bu_op->bbs_subs == 0
		&& bbs_user_subscription(bu_op, bbs_board_find(bh->bbs, "many1")) == 0;
});

/* -- posting and withdrawal (HBBP) --------------------------------------- */

static int bbs_hbbp(struct hub_user* user, const char* line)
{
	struct adc_message* cmd = adc_msg_parse(line, strlen(line));
	int ret;
	if (!cmd)
		return -2;
	ret = bbs_handle_post(bh, user, cmd);
	adc_msg_free(cmd);
	return ret;
}

#define BBS_TTH_P "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP"
#define BBS_TTH_Q "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
#define BBS_TTH_R "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"

EXO_TEST(bbs_post_setup, {
	/* A board everyone can use, and two subscribers -- the poster is not one of
	   them, so that "the entry is the acknowledgement" is actually tested. */
	if (!bbs_add_board("board talk post=guest withdraw_own=guest"))
		return 0;
	bh->config->bbs_post_interval = 0; /* rate limiting has its own tests */
	uman_add(bh->users, bu_guest);
	uman_add(bh->users, bu_reg);
	tu_queue_clear(bu_guest);
	tu_queue_clear(bu_reg);
	return bbs_hbbl(bu_reg, "HBBL BDtalk TS0\n") == 0;
});

EXO_TEST(bbs_post_accepted, {
	tu_queue_clear(bu_guest);
	tu_queue_clear(bu_reg);
	return bbs_hbbp(bu_guest, "HBBP TR" BBS_TTH_P " SI412 BDtalk SJHub\\supgrade\\son\\sSaturday\n") == 0;
});

/* The author sees exactly what every other subscriber sees, and that is the
   acknowledgement -- there is no success status in BBS0. */
EXO_TEST(bbs_post_author_receives_the_entry, {
	char expect[512];
	struct bbs_entry e;
	if (bbs_index_lookup(bh->bbs->index, "talk", BBS_TTH_P, &e) != bbs_index_ok)
		return 0;
	/* The hub stamps the post with its own clock, so the expected line is built
	   around the timestamp the index actually assigned. */
	snprintf(expect, sizeof(expect),
		"IBBL TR" BBS_TTH_P " SI412 BDtalk ID" BBS_CID_A " NIguest TH" BBS_TTH_P
		" SJHub\\supgrade\\son\\sSaturday TS%lld\n", (long long) e.ts);
	return tu_queue_count(bu_guest) == 1 && tu_queue_has(bu_guest, expect);
});

EXO_TEST(bbs_post_subscriber_receives_the_entry, {
	return tu_queue_count(bu_reg) == 1
		&& tu_queue_find(bu_reg, "IBBL TR" BBS_TTH_P " ") == 0;
});

/* TH equals TR because the post starts a thread, and the hub worked that out
   from the absence of PA. */
EXO_TEST(bbs_post_thread_root_is_own_hash, {
	struct bbs_entry e;
	return bbs_index_lookup(bh->bbs->index, "talk", BBS_TTH_P, &e) == bbs_index_ok
		&& !strcmp(e.thread, BBS_TTH_P)
		&& e.parent[0] == 0;
});

/* The hub records the CID of the session it accepted the post from and the
   nick that session held -- both its own testimony. */
EXO_TEST(bbs_post_records_submitting_session, {
	struct bbs_entry e;
	return bbs_index_lookup(bh->bbs->index, "talk", BBS_TTH_P, &e) == bbs_index_ok
		&& !strcmp(e.cid, BBS_CID_A)
		&& !strcmp(e.nick, "guest");
});

/* ID, NI, TH and TS are the hub's to say: a client sending them has them
   discarded, not the command refused. */
EXO_TEST(bbs_post_discards_client_supplied_hub_fields, {
	struct bbs_entry e;
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_reg,
		"HBBP TR" BBS_TTH_Q " SI99 BDtalk SJMine IDLIEDABOUTTHISCIDAAAAAAAAAAAAAAAAAAAAAA"
		" NIimposter TH" BBS_TTH_P " TS12345\n") == 0
		&& bbs_index_lookup(bh->bbs->index, "talk", BBS_TTH_Q, &e) == bbs_index_ok
		&& !strcmp(e.nick, "reg")
		&& !strcmp(e.thread, BBS_TTH_Q)
		&& strcmp(e.cid, "LIEDABOUTTHISCIDAAAAAAAAAAAAAAAAAAAAAA") != 0
		&& e.ts != 12345;
});

EXO_TEST(bbs_post_reply_inherits_thread, {
	struct bbs_entry e;
	return bbs_hbbp(bu_guest, "HBBP TR" BBS_TTH_R " SI298 BDtalk PA" BBS_TTH_P
	                          " SJRe:\\sHub\\supgrade\\son\\sSaturday\n") == 0
		&& bbs_index_lookup(bh->bbs->index, "talk", BBS_TTH_R, &e) == bbs_index_ok
		&& !strcmp(e.thread, BBS_TTH_P);
});

/* -- refusals ------------------------------------------------------------ */

EXO_TEST(bbs_post_duplicate, {
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, "HBBP TR" BBS_TTH_P " SI412 BDtalk SJAgain\n") == -1
		&& tu_queue_has(bu_guest,
			"ISTA 170 Already\\sposted\\son\\sthis\\sboard FCBBP TR" BBS_TTH_P "\n");
});

EXO_TEST(bbs_post_unknown_parent, {
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, "HBBP TRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA SI1 BDtalk"
	                          " PABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n") == -1
		&& tu_queue_has(bu_guest,
			"ISTA 170 No\\ssuch\\spost\\sto\\sreply\\sto FCBBP PABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n");
});

EXO_TEST(bbs_post_missing_hash, {
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, "HBBP SI412 BDtalk\n") == -1
		&& tu_queue_has(bu_guest, "ISTA 143 Missing\\shash FCBBP FMTR\n");
});

EXO_TEST(bbs_post_invalid_hash, {
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, "HBBP TRnothash SI412 BDtalk\n") == -1
		&& tu_queue_has(bu_guest, "ISTA 143 Invalid\\shash FCBBP FBTR\n");
});

EXO_TEST(bbs_post_missing_size, {
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, "HBBP TRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA BDtalk\n") == -1
		&& tu_queue_has(bu_guest, "ISTA 143 Missing\\ssize FCBBP FMSI\n");
});

EXO_TEST(bbs_post_invalid_size, {
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, "HBBP TRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA SIbig BDtalk\n") == -1
		&& tu_queue_has(bu_guest, "ISTA 143 Invalid\\ssize FCBBP FBSI\n");
});

EXO_TEST(bbs_post_missing_board, {
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, "HBBP TRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA SI1\n") == -1
		&& tu_queue_has(bu_guest, "ISTA 143 Missing\\sboard\\sname FCBBP FMBD\n");
});

EXO_TEST(bbs_post_unknown_board, {
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, "HBBP TRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA SI1 BDgenrel\n") == -1
		&& tu_queue_has(bu_guest, "ISTA 171 No\\ssuch\\sboard FCBBP BDgenrel\n");
});

/* An operator may post to announcements, so this gets past the permission
   check and is refused on the board's MS instead. */
EXO_TEST(bbs_post_too_large, {
	tu_queue_clear(bu_op);
	return bbs_hbbp(bu_op, "HBBP TRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA SI70000 BDannouncements\n") == -1
		&& tu_queue_has(bu_op,
			"ISTA 172 Post\\sexceeds\\sthe\\ssize\\slimit\\sfor\\sthis\\sboard FCBBP MS65536\n");
});

/* Only operators may start a thread on the announcements board; a guest may
   still reply there. */
EXO_TEST(bbs_post_thread_denied, {
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, "HBBP TRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA SI1 BDannouncements\n") == -1
		&& tu_queue_has(bu_guest,
			"ISTA 125 Not\\spermitted\\sto\\sstart\\sa\\sthread\\son\\sthis\\sboard"
			" FCBBP TRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
});

EXO_TEST(bbs_post_reply_allowed_where_thread_is_not, {
	return bbs_hbbp(bu_guest, "HBBP TRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA SI1 BDannouncements"
	                          " PA" BBS_TTH_B "\n") == 0;
});

EXO_TEST(bbs_post_subject_too_long, {
	char line[BBS_MAX_SUBJECT + 128];
	char subject[BBS_MAX_SUBJECT + 2];
	memset(subject, 'x', sizeof(subject) - 1);
	subject[sizeof(subject) - 1] = 0;
	snprintf(line, sizeof(line), "HBBP TRCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC SI1 BDtalk SJ%s\n", subject);
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, line) == -1
		&& tu_queue_has(bu_guest, "ISTA 143 Invalid\\ssubject FCBBP FBSJ\n");
});

/* A composing client emits no newline within a subject, so one arriving here
   means the index copy would not match the document. */
EXO_TEST(bbs_post_subject_with_newline, {
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, "HBBP TRCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC SI1 BDtalk SJone\\ntwo\n") == -1
		&& tu_queue_has(bu_guest, "ISTA 143 Invalid\\ssubject FCBBP FBSJ\n");
});

/* -- rate limiting ------------------------------------------------------- */

EXO_TEST(bbs_post_rate_limited, {
	bh->config->bbs_post_interval = 60;
	bu_guest->bbs_last_post = net_get_time();
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, "HBBP TRCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC SI1 BDtalk\n") == -1
		&& tu_queue_has(bu_guest, "ISTA 175 Posting\\stoo\\sfast FCBBP TL60\n");
});

/* Bots and unrestricted operators are never rate-limited. */
EXO_TEST(bbs_post_rate_limit_skips_unrestricted, {
	bu_op->credentials = auth_cred_opubot;
	bu_op->bbs_last_post = net_get_time();
	return bbs_hbbp(bu_op, "HBBP TRCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC SI1 BDtalk\n") == 0;
});

EXO_TEST(bbs_post_rate_limit_disabled, {
	bh->config->bbs_post_interval = 0;
	bu_guest->bbs_last_post = net_get_time();
	return bbs_hbbp(bu_guest, "HBBP TRFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF SI1 BDtalk\n") == 0;
});

/* -- withdrawal ---------------------------------------------------------- */

EXO_TEST(bbs_withdraw_own_post, {
	tu_queue_clear(bu_guest);
	tu_queue_clear(bu_reg);
	return bbs_hbbp(bu_guest, "HBBP TR" BBS_TTH_P " BDtalk RM1\n") == 0;
});

/* A tombstone carries the hash, the board, the new timestamp and RM1, and
   nothing else. */
EXO_TEST(bbs_withdraw_tombstone_wire_format, {
	char expect[256];
	struct bbs_entry e;
	if (bbs_index_lookup(bh->bbs->index, "talk", BBS_TTH_P, &e) != bbs_index_ok)
		return 0;
	snprintf(expect, sizeof(expect), "IBBL TR" BBS_TTH_P " BDtalk TS%lld RM1\n", (long long) e.ts);
	return e.removed
		&& tu_queue_has(bu_reg, expect)
		&& tu_queue_has(bu_guest, expect);
});

/* Withdrawal is not deletion: replies to a withdrawn post are separate posts
   and stay where they are. */
EXO_TEST(bbs_withdraw_keeps_replies, {
	struct bbs_entry e;
	return bbs_index_lookup(bh->bbs->index, "talk", BBS_TTH_R, &e) == bbs_index_ok
		&& e.removed == 0;
});

/* withdraw_own goes by the CID the hub accepted the post from, never the nick. */
EXO_TEST(bbs_withdraw_someone_elses_denied, {
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, "HBBP TR" BBS_TTH_Q " BDtalk RM1\n") == -1
		&& tu_queue_has(bu_guest,
			"ISTA 125 Not\\spermitted\\sto\\swithdraw\\sthis\\spost FCBBP TR" BBS_TTH_Q "\n");
});

/* Permission 16 withdraws anything. */
EXO_TEST(bbs_withdraw_any_by_operator, {
	bu_op->credentials = auth_cred_operator;
	return bbs_hbbp(bu_op, "HBBP TR" BBS_TTH_Q " BDtalk RM1\n") == 0;
});

EXO_TEST(bbs_withdraw_missing_post, {
	tu_queue_clear(bu_guest);
	return bbs_hbbp(bu_guest, "HBBP TRZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ BDtalk RM1\n") == -1
		&& tu_queue_has(bu_guest,
			"ISTA 176 No\\ssuch\\spost FCBBP TRZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\n");
});

EXO_TEST(bbs_post_cleanup_usermanager, {
	uman_remove(bh->users, bu_guest);
	uman_remove(bh->users, bu_reg);
	return 1;
});

EXO_TEST(bbs_teardown, {
	tu_user_destroy(bu_guest);
	tu_user_destroy(bu_reg);
	tu_user_destroy(bu_op);
	bu_guest = bu_reg = bu_op = 0;
	bbs_shutdown(bh->bbs);
	bh->bbs = 0;
	uman_shutdown(bh->users);
	list_destroy(bh->write_queue);
	free_config(bh->config);
	hub_free(bh->config);
	hub_free(bh);
	bh = 0;
	return net_destroy() == 0;
});
