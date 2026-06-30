#include "core/user.h"
#include "core/usermanager.h"

#define MAX_USERS 64

static struct hub_user_manager* uman = 0;
static struct hub_user um_user[MAX_USERS];
static struct hub_user remote_user;

EXO_TEST(um_init_1, {
	sid_t s;
	uman = uman_init(0, 1);

	for (s = 0; s < MAX_USERS; s++)
	{
		memset(&um_user[s], 0, sizeof(struct hub_user));
		um_user[s].id.sid = s;
		snprintf(um_user[s].id.nick, sizeof(um_user[s].id.nick), "u%u", (unsigned) s);
		snprintf(um_user[s].id.cid,  sizeof(um_user[s].id.cid),  "cid%u", (unsigned) s);
	}
	return !!uman;
});

EXO_TEST(um_shutdown_1, {
	return uman_shutdown(0) == -1;
});

EXO_TEST(um_shutdown_2, {
	return uman_shutdown(uman) == 0;
});

EXO_TEST(um_init_2, {
	uman = uman_init(0, 1);
	return !!uman;
});

EXO_TEST(um_add_1, {
	return uman_add(uman, &um_user[0]) == 0;
});

EXO_TEST(um_size_1, {
	return uman->count == 1;
});


EXO_TEST(um_remove_1, {
	return uman_remove(uman, &um_user[0]) == 0;
});

EXO_TEST(um_size_2, {
	return uman->count == 0;
});


EXO_TEST(um_add_2, {
	int i;
	for (i = 0; i < MAX_USERS; i++)
	{
		if (uman_add(uman, &um_user[i]) != 0)
			return 0;
	}
	return 1;
});

EXO_TEST(um_size_3, {
	return uman->count == MAX_USERS;
});

/* Re-adding any user with the same nick/CID must fail and must not
   change the user count. Regression guard for the silent rb_tree
   duplicate-insert that previously corrupted the lookup maps. */
EXO_TEST(um_add_duplicate, {
	size_t before = uman->count;
	if (uman_add(uman, &um_user[0]) == 0)
		return 0;
	return uman->count == before;
});

EXO_TEST(um_remove_2, {
	int i;
	for (i = 0; i < MAX_USERS; i++)
	{
		if (uman_remove(uman, &um_user[i]) != 0)
			return 0;
	}
	return 1;
});












/* Remote users (federation): injected with a peer-assigned SID, appear in the
   maps/list/count and resolve via all lookups, then removed cleanly. */
EXO_TEST(um_remote_add, {
	memset(&remote_user, 0, sizeof(remote_user));
	remote_user.id.sid = 64; /* distinct from local um_user 0..63, in range */
	snprintf(remote_user.id.nick, sizeof(remote_user.id.nick), "remoteNick");
	snprintf(remote_user.id.cid, sizeof(remote_user.id.cid), "REMOTECID");
	remote_user.origin_link = (struct hub_link*) &remote_user; /* non-NULL marker */
	return uman_add_remote(uman, &remote_user) == 0;
});

EXO_TEST(um_remote_count, {
	return uman->count == 1;
});

EXO_TEST(um_remote_is_remote, {
	return user_is_remote(&remote_user) == 1 && user_is_remote(&um_user[0]) == 0;
});

EXO_TEST(um_remote_lookup_sid, {
	return uman_get_user_by_sid(uman, 64) == &remote_user;
});

EXO_TEST(um_remote_lookup_nick, {
	return uman_get_user_by_nick(uman, "remoteNick") == &remote_user;
});

EXO_TEST(um_remote_lookup_cid, {
	return uman_get_user_by_cid(uman, "REMOTECID") == &remote_user;
});

EXO_TEST(um_remote_add_dup_sid, {
	/* A second remote with the same SID must be rejected (collision). */
	static struct hub_user dup;
	memset(&dup, 0, sizeof(dup));
	dup.id.sid = 64;
	snprintf(dup.id.nick, sizeof(dup.id.nick), "otherNick");
	snprintf(dup.id.cid, sizeof(dup.id.cid), "OTHERCID");
	dup.origin_link = (struct hub_link*) &dup;
	return uman_add_remote(uman, &dup) == -1 && uman->count == 1;
});

EXO_TEST(um_remote_remove, {
	uman_remove_remote(uman, &remote_user);
	return uman_get_user_by_sid(uman, 64) == 0
	    && uman_get_user_by_nick(uman, "remoteNick") == 0
	    && uman_get_user_by_cid(uman, "REMOTECID") == 0
	    && uman->count == 0;
});

EXO_TEST(um_shutdown_4, {
	return uman_shutdown(uman) == 0;
});

/* SID partitioning: a federated node allocates local SIDs only from its
   disjoint window of the shared 1,048,576-SID space (window = MAX/node_count). */
EXO_TEST(um_partition_node0_window, {
	struct hub_user_manager* p = uman_init(0, 4); /* window [1, 262143] */
	struct hub_user u;
	sid_t s;
	int ok;
	if (!p) return 0;
	memset(&u, 0, sizeof(u));
	s = uman_get_free_sid(p, &u);
	ok = (s >= 1 && s <= 262143);
	uman_shutdown(p);
	return ok;
});

EXO_TEST(um_partition_node1_window, {
	struct hub_user_manager* p = uman_init(1, 4); /* window [262144, 524287] */
	struct hub_user u;
	sid_t s;
	int ok;
	if (!p) return 0;
	memset(&u, 0, sizeof(u));
	s = uman_get_free_sid(p, &u);
	ok = (s >= 262144 && s <= 524287);
	uman_shutdown(p);
	return ok;
});
