#include "system.h"
#include "util/memory.h"
#include "adc/sid.h"

static struct sid_pool* sid_pool = 0;

struct dummy_user
{
	sid_t sid;
};

static struct dummy_user* last = 0;
sid_t last_sid = 0;

EXO_TEST(sid_create_pool, {
	sid_pool = sid_pool_create(4);
	return sid_pool != 0;
});

EXO_TEST(sid_check_0a, {
	struct dummy_user* user = (struct dummy_user*) sid_lookup(sid_pool, 0);
	return user == 0;
});

EXO_TEST(sid_check_0b, {
	struct dummy_user* user = (struct dummy_user*) sid_lookup(sid_pool, 5);
	return user == 0;
});

EXO_TEST(sid_alloc_1, {
	struct dummy_user* user = hub_malloc_zero(sizeof(struct dummy_user));
	user->sid = sid_alloc(sid_pool, (struct hub_user*) user);
	last = user;
	last_sid = user->sid;
	return (user->sid > 0 && user->sid < 1048576);
});

EXO_TEST(sid_check_1a, {
	struct dummy_user* user = (struct dummy_user*) sid_lookup(sid_pool, last_sid);
	return last == user;
});

EXO_TEST(sid_check_1b, {
	struct dummy_user* user = (struct dummy_user*) sid_lookup(sid_pool, last_sid+1);
	return user == 0;
});

EXO_TEST(sid_alloc_2, {
	struct dummy_user* user = hub_malloc_zero(sizeof(struct dummy_user));
	user->sid = sid_alloc(sid_pool, (struct hub_user*) user);
	last_sid = user->sid;
	return (user->sid > 0 && user->sid < 1048576);
});

EXO_TEST(sid_check_2, {
	struct dummy_user* user = (struct dummy_user*) sid_lookup(sid_pool, last_sid);
	return last != user;
});

EXO_TEST(sid_alloc_3, {
	struct dummy_user* user = hub_malloc_zero(sizeof(struct dummy_user));
	user->sid = sid_alloc(sid_pool, (struct hub_user*) user);
	last_sid = user->sid;
	return (user->sid > 0 && user->sid < 1048576);
});

EXO_TEST(sid_check_3, {
	struct dummy_user* user = (struct dummy_user*) sid_lookup(sid_pool, last_sid);
	return last != user;
});

EXO_TEST(sid_alloc_4, {
	struct dummy_user* user = hub_malloc_zero(sizeof(struct dummy_user));
	user->sid = sid_alloc(sid_pool, (struct hub_user*) user);
	last_sid = user->sid;
	return (user->sid > 0 && user->sid < 1048576);
});

EXO_TEST(sid_check_4, {
	struct dummy_user* user = (struct dummy_user*) sid_lookup(sid_pool, last_sid);
	return last != user;
});

EXO_TEST(sid_alloc_5, {
	struct dummy_user user;
	sid_t sid;
	sid = sid_alloc(sid_pool, (struct hub_user*) &user);
	return sid == 0;
});

EXO_TEST(sid_check_6, {
	struct dummy_user* user = (struct dummy_user*) sid_lookup(sid_pool, 0);
	return user == 0;
});


EXO_TEST(sid_list_all_1, {
	sid_t s;
	size_t n = 0;
	int ok = 1;
	for (s = last->sid; s <= last_sid; s++)
	{
		struct dummy_user* user = (struct dummy_user*) sid_lookup(sid_pool, s);
		if (s != (user ? user->sid : -1))
		{
			ok = 0;
			break;
		}
		n++;
	}
	return ok && n == 4;
});

#define FREE_SID(N) \
	struct dummy_user* user = (struct dummy_user*) sid_lookup(sid_pool, N); \
	sid_free(sid_pool, N); \
	hub_free(user); \
	return sid_lookup(sid_pool, N) == NULL;

EXO_TEST(sid_remove_1, {
	FREE_SID(2);
});

EXO_TEST(sid_remove_2, {
	FREE_SID(1);
});

EXO_TEST(sid_remove_3, {
	FREE_SID(4);
});

EXO_TEST(sid_remove_4, {
	FREE_SID(3);
});

/*
 * sid_free() used to write pool->map[sid] = 0 without bounds-checking
 * sid. Confirm out-of-range and 0 sids are now no-ops, and that a
 * double-free doesn't underflow pool->count.
 */
EXO_TEST(sid_free_out_of_range, {
	sid_free(sid_pool, 999999); /* past pool->max (=5) */
	sid_free(sid_pool, 0);      /* reserved sid */
	return 1;
});

EXO_TEST(sid_free_double, {
	struct dummy_user* user = hub_malloc_zero(sizeof(struct dummy_user));
	sid_t s = sid_alloc(sid_pool, (struct hub_user*) user);
	sid_free(sid_pool, s);
	sid_free(sid_pool, s); /* double free must not corrupt count */
	hub_free(user);
	/* Allocate again -- if count was decremented twice, pool would
	 * miscount and refuse this alloc once full. */
	user = hub_malloc_zero(sizeof(struct dummy_user));
	s = sid_alloc(sid_pool, (struct hub_user*) user);
	sid_free(sid_pool, s);
	hub_free(user);
	return s != 0;
});

/*
 * sid_to_string() used to return a pointer into a single static
 * buffer, so two calls in the same expression aliased. Confirm
 * adjacent calls now return distinct, correct values.
 */
EXO_TEST(sid_to_string_no_alias, {
	const char* a = sid_to_string(1);
	const char* b = sid_to_string(2);
	return a != b && strcmp(a, "AAAB") == 0 && strcmp(b, "AAAC") == 0;
});

EXO_TEST(sid_destroy_pool, {
	sid_pool_destroy(sid_pool);
	sid_pool = 0;
	return sid_pool == 0;
});

/*
 * Partitioned pool (federation): a node owns a disjoint window [min, max]
 * inside a map that spans the whole shared SID space.
 */
static struct sid_pool* part_pool = 0;
static sid_t part_sids[256];

EXO_TEST(sid_range_create, {
	/* Node 1 of 4 over a 1024-SID space owns the window [256, 511]. */
	part_pool = sid_pool_create_range(1024, 256, 511);
	return part_pool != 0;
});

EXO_TEST(sid_range_alloc_in_window, {
	int i = 0;
	int ok = 1;
	for (i = 0; i < 256; i++)
	{
		struct dummy_user* u = hub_malloc_zero(sizeof(struct dummy_user));
		part_sids[i] = sid_alloc(part_pool, (struct hub_user*) u);
		u->sid = part_sids[i];
		if (part_sids[i] < 256 || part_sids[i] > 511)
			ok = 0;
	}
	return ok;
});

EXO_TEST(sid_range_window_exhausted, {
	struct dummy_user u;
	/* All 256 window slots are taken; the next local alloc must fail. */
	return sid_alloc(part_pool, (struct hub_user*) &u) == 0;
});

EXO_TEST(sid_range_lookup_bounds, {
	/* In-window allocated SID resolves; a slot outside the window is a valid
	   map index but empty (no remote user yet); past map_size returns NULL. */
	return sid_lookup(part_pool, 511) != 0
	    && sid_lookup(part_pool, 100) == 0
	    && sid_lookup(part_pool, 1024) == 0
	    && sid_lookup(part_pool, 0) == 0;
});

EXO_TEST(sid_range_free_and_reuse, {
	int i = 0;
	int ok = 1;
	for (i = 0; i < 256; i++)
	{
		struct dummy_user* u = (struct dummy_user*) sid_lookup(part_pool, part_sids[i]);
		sid_free(part_pool, part_sids[i]);
		hub_free(u);
		if (sid_lookup(part_pool, part_sids[i]) != 0)
			ok = 0;
	}
	/* Window empty again: allocation succeeds and stays in range. */
	struct dummy_user* u = hub_malloc_zero(sizeof(struct dummy_user));
	sid_t s = sid_alloc(part_pool, (struct hub_user*) u);
	ok = ok && (s >= 256 && s <= 511);
	sid_free(part_pool, s);
	hub_free(u);
	return ok;
});

/* sid_pool_insert: register a remote user at a peer-assigned SID outside the
   local window. part_pool window is [256,511]; insert at 100. */
EXO_TEST(sid_insert_remote, {
	struct dummy_user* u = hub_malloc_zero(sizeof(struct dummy_user));
	int ok;
	u->sid = 100;
	ok = sid_pool_insert(part_pool, 100, (struct hub_user*) u);
	return ok == 1 && (struct dummy_user*) sid_lookup(part_pool, 100) == u;
});

EXO_TEST(sid_insert_does_not_disturb_window, {
	/* A local allocation still comes from [256,511], not near the inserted slot. */
	struct dummy_user* u = hub_malloc_zero(sizeof(struct dummy_user));
	sid_t s = sid_alloc(part_pool, (struct hub_user*) u);
	int ok = (s >= 256 && s <= 511);
	sid_free(part_pool, s);
	hub_free(u);
	return ok;
});

EXO_TEST(sid_insert_rejects_taken, {
	struct dummy_user u;
	return sid_pool_insert(part_pool, 100, (struct hub_user*) &u) == 0;
});

EXO_TEST(sid_insert_rejects_out_of_range, {
	struct dummy_user u;
	int a = sid_pool_insert(part_pool, 0, (struct hub_user*) &u);
	int b = sid_pool_insert(part_pool, 1024, (struct hub_user*) &u);
	int c = sid_pool_insert(part_pool, 99999, (struct hub_user*) &u);
	return a == 0 && b == 0 && c == 0;
});

EXO_TEST(sid_insert_free, {
	struct dummy_user* u = (struct dummy_user*) sid_lookup(part_pool, 100);
	sid_free(part_pool, 100);
	hub_free(u);
	return sid_lookup(part_pool, 100) == NULL;
});

EXO_TEST(sid_range_destroy, {
	sid_pool_destroy(part_pool);
	part_pool = 0;
	return 1;
});
