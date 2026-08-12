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

EXO_TEST(bbs_teardown, {
	tu_user_destroy(bu_guest);
	tu_user_destroy(bu_reg);
	tu_user_destroy(bu_op);
	bu_guest = bu_reg = bu_op = 0;
	bbs_shutdown(bh->bbs);
	bh->bbs = 0;
	uman_shutdown(bh->users);
	list_destroy(bh->write_queue);
	hub_free(bh->config);
	hub_free(bh);
	bh = 0;
	return net_destroy() == 0;
});
