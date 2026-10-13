#include "system.h"
#include "util/memory.h"
#include "adc/message.h"
#include "fuse/roster.h"

#define CID_A "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define CID_B "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

static struct fs_roster* roster = NULL;

/* SID "AAAB" is 1, "AAAC" is 2 -- see sid_to_string(). */
#define INF_A  "BINF AAAB ID" CID_A " NIalice DEhello SS1024 SL3 I4127.0.0.1\n"
#define INF_B  "BINF AAAC ID" CID_B " NIbob I4127.0.0.2\n"

static struct adc_message* parse(const char* line)
{
	return adc_msg_parse(line, strlen(line));
}

/* Feed one line into the roster and drop our reference to it. */
static enum fs_roster_result feed(const char* line, time_t now)
{
	enum fs_roster_result result;
	struct adc_message* msg = parse(line);
	if (!msg)
		return FS_ROSTER_REJECTED;

	result = fs_roster_update(roster, msg, now);
	adc_msg_free(msg);
	return result;
}

/*
 * Each test starts from one of these, so none depends on another. They tell
 * the roster's story a step at a time: alice joins, bob joins, alice's INF is
 * updated, alice reconnects on a new SID, and then leaves.
 */
static int r_fresh(void)
{
	fs_roster_destroy(roster);
	roster = fs_roster_create();
	return roster != NULL;
}

static int r_alice(void)     { return r_fresh() && feed(INF_A, 1000) == FS_ROSTER_ADDED; }
static int r_alice_bob(void) { return r_alice() && feed(INF_B, 1001) == FS_ROSTER_ADDED; }
static int r_merged(void)    { return r_alice_bob() && feed("BINF AAAB DEbusy\n", 2000) == FS_ROSTER_UPDATED; }
static int r_reused(void)    { return r_merged() && feed("BINF AAAE ID" CID_A " NIalice\n", 4000) == FS_ROSTER_ADDED; }
static int r_removed(void)   { return r_reused() && fs_roster_remove(roster, 4) == 1; }

EXO_TEARDOWN({
	fs_roster_destroy(roster);
	roster = NULL;
	return 1;
});

EXO_TEST(fuse_roster_create, {
	return r_fresh() && fs_roster_size(roster) == 0;
});

EXO_TEST(fuse_roster_add, { return r_fresh() && feed(INF_A, 1000) == FS_ROSTER_ADDED; });
EXO_TEST(fuse_roster_size_1, { return r_alice() && fs_roster_size(roster) == 1; });

EXO_TEST(fuse_roster_by_cid, {
	struct fs_roster_user* user;
	if (!r_alice())
		return 0;
	user = fs_roster_by_cid(roster, CID_A);
	return user && user->sid == 1 && user->since == 1000;
});

EXO_TEST(fuse_roster_by_sid, {
	struct fs_roster_user* user;
	if (!r_alice())
		return 0;
	user = fs_roster_by_sid(roster, 1);
	return user && strcmp(user->cid, CID_A) == 0;
});

EXO_TEST(fuse_roster_by_sid_missing, { return r_alice() && fs_roster_by_sid(roster, 4711) == NULL; });
EXO_TEST(fuse_roster_by_sid_zero, { return r_alice() && fs_roster_by_sid(roster, 0) == NULL; });
EXO_TEST(fuse_roster_by_cid_missing, { return r_alice() && fs_roster_by_cid(roster, CID_B) == NULL; });
EXO_TEST(fuse_roster_by_cid_null, { return r_alice() && fs_roster_by_cid(roster, NULL) == NULL; });

EXO_TEST(fuse_roster_nick, {
	char nick[64];
	struct fs_roster_user* user;
	if (!r_alice())
		return 0;
	user = fs_roster_by_cid(roster, CID_A);
	return fs_roster_nick(user, nick, sizeof(nick)) == 5 && strcmp(nick, "alice") == 0;
});

EXO_TEST(fuse_roster_by_nick, { return r_alice() && fs_roster_by_nick(roster, "alice") == fs_roster_by_cid(roster, CID_A); });

EXO_TEST(fuse_roster_by_nick_missing, { return r_alice() && fs_roster_by_nick(roster, "nobody") == NULL; });

EXO_TEST(fuse_roster_add_second, { return r_alice() && feed(INF_B, 1001) == FS_ROSTER_ADDED; });
EXO_TEST(fuse_roster_size_2, { return r_alice_bob() && fs_roster_size(roster) == 2; });

/* An INF update names only what changed; everything else must survive it. */
EXO_TEST(fuse_roster_merge, { return r_alice_bob() && feed("BINF AAAB DEbusy\n", 2000) == FS_ROSTER_UPDATED; });

EXO_TEST(fuse_roster_merge_replaced, {
	struct fs_roster_user* user;
	char* value;
	int ok;
	if (!r_merged())
		return 0;
	user = fs_roster_by_cid(roster, CID_A);
	value = adc_msg_get_named_argument(user->inf, "DE");
	ok = value && strcmp(value, "busy") == 0;
	hub_free(value);
	return ok;
});

EXO_TEST(fuse_roster_merge_kept_nick, {
	struct fs_roster_user* user;
	char* value;
	int ok;
	if (!r_merged())
		return 0;
	user = fs_roster_by_cid(roster, CID_A);
	value = adc_msg_get_named_argument(user->inf, "NI");
	ok = value && strcmp(value, "alice") == 0;
	hub_free(value);
	return ok;
});

EXO_TEST(fuse_roster_merge_kept_share, {
	struct fs_roster_user* user;
	char* value;
	int ok;
	if (!r_merged())
		return 0;
	user = fs_roster_by_cid(roster, CID_A);
	value = adc_msg_get_named_argument(user->inf, "SS");
	ok = value && strcmp(value, "1024") == 0;
	hub_free(value);
	return ok;
});

EXO_TEST(fuse_roster_merge_kept_since, {
	struct fs_roster_user* user;
	if (!r_merged())
		return 0;
	user = fs_roster_by_cid(roster, CID_A);
	return user->since == 1000;
});

EXO_TEST(fuse_roster_merge_no_new_user, { return r_merged() && fs_roster_size(roster) == 2; });

/* An INF with no source SID belongs to nobody. */
EXO_TEST(fuse_roster_no_sid, {
	struct adc_message* msg;
	enum fs_roster_result result;
	if (!r_fresh())
		return 0;
	msg = adc_msg_create("BINF ID" CID_A " NIx\n");
	result = fs_roster_update(roster, msg, 3000);
	adc_msg_free(msg);
	return result == FS_ROSTER_REJECTED;
});

/* A first INF with no CID has no path to live at. */
EXO_TEST(fuse_roster_no_cid, { return r_alice_bob() && feed("BINF AAAD NIcarol\n", 3000) == FS_ROSTER_REJECTED; });
EXO_TEST(fuse_roster_no_cid_not_added, {
	if (!r_alice_bob())
		return 0;
	feed("BINF AAAD NIcarol\n", 3000);
	return fs_roster_size(roster) == 2;
});

EXO_TEST(fuse_roster_bad_cid, { return r_fresh() && feed("BINF AAAD IDnope NIcarol\n", 3000) == FS_ROSTER_REJECTED; });

EXO_TEST(fuse_roster_null_message, { return r_fresh() && fs_roster_update(roster, NULL, 3000) == FS_ROSTER_REJECTED; });

/* Ordered by CID, which is what users/ lists. */
EXO_TEST(fuse_roster_iterate, {
	struct fs_roster_user* first;
	struct fs_roster_user* second;
	struct fs_roster_user* third;
	if (!r_merged())
		return 0;
	first = fs_roster_first(roster);
	second = fs_roster_next(roster);
	third = fs_roster_next(roster);
	return first && second && !third
		&& strcmp(first->cid, CID_A) == 0
		&& strcmp(second->cid, CID_B) == 0;
});

/* A CID that reappears on a new SID is the same person reconnecting; the stale
   entry must not keep the name. */
EXO_TEST(fuse_roster_cid_reused, { return r_merged() && feed("BINF AAAE ID" CID_A " NIalice\n", 4000) == FS_ROSTER_ADDED; });
EXO_TEST(fuse_roster_cid_reused_size, { return r_reused() && fs_roster_size(roster) == 2; });
EXO_TEST(fuse_roster_cid_reused_new_sid, {
	struct fs_roster_user* user;
	if (!r_reused())
		return 0;
	user = fs_roster_by_cid(roster, CID_A);
	return user && user->sid == 4 && user->since == 4000;
});
EXO_TEST(fuse_roster_cid_reused_old_sid_gone, { return r_reused() && fs_roster_by_sid(roster, 1) == NULL; });

EXO_TEST(fuse_roster_remove, { return r_reused() && fs_roster_remove(roster, 4) == 1; });
EXO_TEST(fuse_roster_remove_again, { return r_removed() && fs_roster_remove(roster, 4) == 0; });
EXO_TEST(fuse_roster_remove_size, { return r_removed() && fs_roster_size(roster) == 1; });
EXO_TEST(fuse_roster_remove_cid_gone, { return r_removed() && fs_roster_by_cid(roster, CID_A) == NULL; });

EXO_TEST(fuse_roster_clear, {
	if (!r_removed())
		return 0;
	fs_roster_clear(roster);
	return fs_roster_size(roster) == 0 && fs_roster_first(roster) == NULL;
});

EXO_TEST(fuse_roster_reuse_after_clear, {
	if (!r_removed())
		return 0;
	fs_roster_clear(roster);
	return feed(INF_A, 5000) == FS_ROSTER_ADDED && fs_roster_size(roster) == 1;
});

/*
 * A walk that stops at the first match must still leave the tree walkable and
 * destroyable. The iterator lives inside the tree and rb_tree_destroy()
 * refuses a stack that was left loaded, so an abandoned walk shows up as a
 * crash at unmount rather than here -- which is why this is a test.
 */
EXO_TEST(fuse_roster_walk_stopped_early_can_be_destroyed, {
	struct fs_roster* other = fs_roster_create();
	struct adc_message* msg;
	char line[256];
	char cid[MAX_CID_LEN + 1];
	int i;
	int ok;

	/*
	 * Enough users that the tree has depth, and a match that is not the
	 * leftmost one: stopping on the very first entry leaves nothing on the
	 * iterator's stack and would not reproduce anything.
	 */
	for (i = 0; i < 16; i++)
	{
		memset(cid, 'A' + i, MAX_CID_LEN);
		cid[MAX_CID_LEN] = '\0';

		snprintf(line, sizeof(line), "BINF AA%c%c ID%s NIuser%d\n",
			'A' + (i / 8), 'B' + (i % 8), cid, i);

		msg = parse(line);
		fs_roster_update(other, msg, 1000);
		adc_msg_free(msg);
	}

	ok = (fs_roster_size(other) == 16);

	/* Somewhere in the middle, so the walk is abandoned part-way down. */
	ok = ok && (fs_roster_by_nick(other, "user9") != NULL);

	/* The tree must still be walkable afterwards. */
	ok = ok && (fs_roster_first(other) != NULL);

	fs_roster_destroy(other);   /* aborts if a walk was left in progress */
	return ok;
});

EXO_TEST(fuse_roster_destroy, {
	fs_roster_destroy(fs_roster_create());
	return 1;
});

EXO_TEST(fuse_roster_destroy_null, {
	fs_roster_destroy(NULL);
	return 1;
});
