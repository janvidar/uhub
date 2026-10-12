#include "system.h"
#include "util/memory.h"
#include "adc/sid.h"

/*
 * Every test builds the pool it needs, and frees the pool and its users again,
 * so each one runs alone or in any order.
 */

struct dummy_user
{
	sid_t sid;
};

/* A pool, and the users allocated into it so far. */
struct sid_fixture
{
	struct sid_pool* pool;
	struct dummy_user* users[260];
	int count;
};

static void fx_init(struct sid_fixture* fx, struct sid_pool* pool)
{
	memset(fx, 0, sizeof(*fx));
	fx->pool = pool;
}

/* Allocate a user into the pool; returns its SID, 0 when the pool is full. */
static sid_t fx_alloc(struct sid_fixture* fx)
{
	struct dummy_user* user = hub_malloc_zero(sizeof(struct dummy_user));
	user->sid = sid_alloc(fx->pool, (struct hub_user*) user);
	if (!user->sid)
	{
		hub_free(user);
		return 0;
	}
	fx->users[fx->count++] = user;
	return user->sid;
}

/* Free one user by SID, the way the hub does. */
static void fx_free(struct sid_fixture* fx, sid_t sid)
{
	int i;
	sid_free(fx->pool, sid);
	for (i = 0; i < fx->count; i++)
	{
		if (fx->users[i] && fx->users[i]->sid == sid)
		{
			hub_free(fx->users[i]);
			fx->users[i] = NULL;
		}
	}
}

static void fx_done(struct sid_fixture* fx)
{
	int i;
	for (i = 0; i < fx->count; i++)
		hub_free(fx->users[i]);
	sid_pool_destroy(fx->pool);
}

/* A pool of four, with `n` users in it. */
static void fx_pool4(struct sid_fixture* fx, int n)
{
	fx_init(fx, sid_pool_create(4));
	while (n--)
		fx_alloc(fx);
}

EXO_TEST(sid_create_pool, {
	struct sid_pool* pool = sid_pool_create(4);
	int ok = pool != 0;
	sid_pool_destroy(pool);
	return ok;
});

EXO_TEST(sid_check_0a, {
	struct sid_fixture fx;
	int ok;
	fx_pool4(&fx, 0);
	ok = sid_lookup(fx.pool, 0) == 0;
	fx_done(&fx);
	return ok;
});

EXO_TEST(sid_check_0b, {
	struct sid_fixture fx;
	int ok;
	fx_pool4(&fx, 0);
	ok = sid_lookup(fx.pool, 5) == 0;
	fx_done(&fx);
	return ok;
});

EXO_TEST(sid_alloc_1, {
	struct sid_fixture fx;
	sid_t sid;
	fx_pool4(&fx, 0);
	sid = fx_alloc(&fx);
	fx_done(&fx);
	return sid > 0 && sid < 1048576;
});

EXO_TEST(sid_check_1a, {
	struct sid_fixture fx;
	int ok;
	fx_pool4(&fx, 1);
	ok = (struct dummy_user*) sid_lookup(fx.pool, fx.users[0]->sid) == fx.users[0];
	fx_done(&fx);
	return ok;
});

EXO_TEST(sid_check_1b, {
	struct sid_fixture fx;
	int ok;
	fx_pool4(&fx, 1);
	ok = sid_lookup(fx.pool, fx.users[0]->sid + 1) == 0;
	fx_done(&fx);
	return ok;
});

/* Each further user gets a SID of its own: looking it up does not find the first. */
#define SID_ALLOC_N(N) \
	struct sid_fixture fx; \
	sid_t sid; \
	int ok; \
	fx_pool4(&fx, (N) - 1); \
	sid = fx_alloc(&fx); \
	ok = sid > 0 && sid < 1048576; \
	fx_done(&fx); \
	return ok;

#define SID_CHECK_N(N) \
	struct sid_fixture fx; \
	int ok; \
	fx_pool4(&fx, N); \
	ok = (struct dummy_user*) sid_lookup(fx.pool, fx.users[(N) - 1]->sid) == fx.users[(N) - 1] \
		&& fx.users[(N) - 1] != fx.users[0]; \
	fx_done(&fx); \
	return ok;

EXO_TEST(sid_alloc_2, { SID_ALLOC_N(2) });
EXO_TEST(sid_check_2, { SID_CHECK_N(2) });
EXO_TEST(sid_alloc_3, { SID_ALLOC_N(3) });
EXO_TEST(sid_check_3, { SID_CHECK_N(3) });
EXO_TEST(sid_alloc_4, { SID_ALLOC_N(4) });
EXO_TEST(sid_check_4, { SID_CHECK_N(4) });

/* The pool holds four: a fifth is refused. */
EXO_TEST(sid_alloc_5, {
	struct sid_fixture fx;
	struct dummy_user user;
	int ok;
	fx_pool4(&fx, 4);
	ok = sid_alloc(fx.pool, (struct hub_user*) &user) == 0;
	fx_done(&fx);
	return ok;
});

EXO_TEST(sid_check_6, {
	struct sid_fixture fx;
	int ok;
	fx_pool4(&fx, 4);
	ok = sid_lookup(fx.pool, 0) == 0;
	fx_done(&fx);
	return ok;
});

/* The four SIDs are consecutive, and each finds its own user. */
EXO_TEST(sid_list_all_1, {
	struct sid_fixture fx;
	sid_t s;
	size_t n = 0;
	int ok = 1;
	fx_pool4(&fx, 4);
	for (s = fx.users[0]->sid; s <= fx.users[3]->sid; s++)
	{
		struct dummy_user* user = (struct dummy_user*) sid_lookup(fx.pool, s);
		if (s != (user ? user->sid : (sid_t)-1))
		{
			ok = 0;
			break;
		}
		n++;
	}
	fx_done(&fx);
	return ok && n == 4;
});

#define FREE_SID(N) \
	struct sid_fixture fx; \
	int ok; \
	fx_pool4(&fx, 4); \
	fx_free(&fx, N); \
	ok = sid_lookup(fx.pool, N) == NULL; \
	fx_done(&fx); \
	return ok;

EXO_TEST(sid_remove_1, { FREE_SID(2) });
EXO_TEST(sid_remove_2, { FREE_SID(1) });
EXO_TEST(sid_remove_3, { FREE_SID(4) });
EXO_TEST(sid_remove_4, { FREE_SID(3) });

/*
 * sid_free() used to write pool->map[sid] = 0 without bounds-checking
 * sid. Confirm out-of-range and 0 sids are now no-ops, and that a
 * double-free doesn't underflow pool->count.
 */
EXO_TEST(sid_free_out_of_range, {
	struct sid_pool* pool = sid_pool_create(4);
	sid_free(pool, 999999); /* past pool->max (=5) */
	sid_free(pool, 0);      /* reserved sid */
	sid_pool_destroy(pool);
	return 1;
});

EXO_TEST(sid_free_double, {
	struct sid_pool* pool = sid_pool_create(4);
	struct dummy_user* user = hub_malloc_zero(sizeof(struct dummy_user));
	sid_t s = sid_alloc(pool, (struct hub_user*) user);
	sid_free(pool, s);
	sid_free(pool, s); /* double free must not corrupt count */
	hub_free(user);
	/* Allocate again -- if count was decremented twice, pool would
	 * miscount and refuse this alloc once full. */
	user = hub_malloc_zero(sizeof(struct dummy_user));
	s = sid_alloc(pool, (struct hub_user*) user);
	sid_free(pool, s);
	hub_free(user);
	sid_pool_destroy(pool);
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
	struct sid_fixture fx;
	fx_pool4(&fx, 4);
	fx_done(&fx);
	return 1;
});

/*
 * Partitioned pool (federation): a node owns a disjoint window [min, max]
 * inside a map that spans the whole shared SID space. Node 1 of 4 over a
 * 1024-SID space owns the window [256, 511].
 */
static void fx_part(struct sid_fixture* fx)
{
	fx_init(fx, sid_pool_create_range(1024, 256, 511));
}

/* The window, filled. */
static int fx_part_full(struct sid_fixture* fx)
{
	int i;
	int ok = 1;
	fx_part(fx);
	for (i = 0; i < 256; i++)
	{
		sid_t s = fx_alloc(fx);
		if (s < 256 || s > 511)
			ok = 0;
	}
	return ok;
}

EXO_TEST(sid_range_create, {
	struct sid_pool* pool = sid_pool_create_range(1024, 256, 511);
	int ok = pool != 0;
	sid_pool_destroy(pool);
	return ok;
});

EXO_TEST(sid_range_alloc_in_window, {
	struct sid_fixture fx;
	int ok = fx_part_full(&fx);
	fx_done(&fx);
	return ok;
});

EXO_TEST(sid_range_window_exhausted, {
	struct sid_fixture fx;
	struct dummy_user u;
	int ok;
	fx_part_full(&fx);
	/* All 256 window slots are taken; the next local alloc must fail. */
	ok = sid_alloc(fx.pool, (struct hub_user*) &u) == 0;
	fx_done(&fx);
	return ok;
});

EXO_TEST(sid_range_lookup_bounds, {
	struct sid_fixture fx;
	int ok;
	fx_part_full(&fx);
	/* In-window allocated SID resolves; a slot outside the window is a valid
	   map index but empty (no remote user yet); past map_size returns NULL. */
	ok = sid_lookup(fx.pool, 511) != 0
	    && sid_lookup(fx.pool, 100) == 0
	    && sid_lookup(fx.pool, 1024) == 0
	    && sid_lookup(fx.pool, 0) == 0;
	fx_done(&fx);
	return ok;
});

EXO_TEST(sid_range_free_and_reuse, {
	struct sid_fixture fx;
	int i;
	int ok = fx_part_full(&fx);
	for (i = 0; i < 256; i++)
	{
		sid_t s = fx.users[i]->sid;
		fx_free(&fx, s);
		if (sid_lookup(fx.pool, s) != 0)
			ok = 0;
	}
	/* Window empty again: allocation succeeds and stays in range. */
	{
		sid_t s = fx_alloc(&fx);
		ok = ok && (s >= 256 && s <= 511);
	}
	fx_done(&fx);
	return ok;
});

/* sid_pool_insert: register a remote user at a peer-assigned SID outside the
   local window. The window is [256,511]; insert at 100. */
static struct dummy_user* fx_insert_remote(struct sid_fixture* fx, sid_t sid)
{
	struct dummy_user* u = hub_malloc_zero(sizeof(struct dummy_user));
	u->sid = sid;
	if (!sid_pool_insert(fx->pool, sid, (struct hub_user*) u))
	{
		hub_free(u);
		return NULL;
	}
	fx->users[fx->count++] = u;
	return u;
}

EXO_TEST(sid_insert_remote, {
	struct sid_fixture fx;
	struct dummy_user* u;
	int ok;
	fx_part(&fx);
	u = fx_insert_remote(&fx, 100);
	ok = u && (struct dummy_user*) sid_lookup(fx.pool, 100) == u;
	fx_done(&fx);
	return ok;
});

EXO_TEST(sid_insert_does_not_disturb_window, {
	struct sid_fixture fx;
	sid_t s;
	fx_part(&fx);
	fx_insert_remote(&fx, 100);
	/* A local allocation still comes from [256,511], not near the inserted slot. */
	s = fx_alloc(&fx);
	fx_done(&fx);
	return s >= 256 && s <= 511;
});

EXO_TEST(sid_insert_rejects_taken, {
	struct sid_fixture fx;
	struct dummy_user u;
	int ok;
	fx_part(&fx);
	fx_insert_remote(&fx, 100);
	ok = sid_pool_insert(fx.pool, 100, (struct hub_user*) &u) == 0;
	fx_done(&fx);
	return ok;
});

EXO_TEST(sid_insert_rejects_out_of_range, {
	struct sid_fixture fx;
	struct dummy_user u;
	int a, b, c;
	fx_part(&fx);
	a = sid_pool_insert(fx.pool, 0, (struct hub_user*) &u);
	b = sid_pool_insert(fx.pool, 1024, (struct hub_user*) &u);
	c = sid_pool_insert(fx.pool, 99999, (struct hub_user*) &u);
	fx_done(&fx);
	return a == 0 && b == 0 && c == 0;
});

EXO_TEST(sid_insert_free, {
	struct sid_fixture fx;
	int ok;
	fx_part(&fx);
	fx_insert_remote(&fx, 100);
	fx_free(&fx, 100);
	ok = sid_lookup(fx.pool, 100) == NULL;
	fx_done(&fx);
	return ok;
});

EXO_TEST(sid_range_destroy, {
	struct sid_fixture fx;
	fx_part_full(&fx);
	fx_done(&fx);
	return 1;
});

/* Dynamic lease: a pending pool has an empty window until sid_pool_set_window()
   applies a leased range. */
static struct sid_pool* lease_pool_create(void)
{
	return sid_pool_create_range(1024, 1, 0); /* empty window */
}

EXO_TEST(sid_lease_create_empty, {
	struct sid_pool* pool = lease_pool_create();
	int ok = pool != 0;
	sid_pool_destroy(pool);
	return ok;
});

EXO_TEST(sid_lease_alloc_before_lease_fails, {
	struct sid_pool* pool = lease_pool_create();
	struct dummy_user u;
	int ok = sid_alloc(pool, (struct hub_user*) &u) == 0; /* no window yet */
	sid_pool_destroy(pool);
	return ok;
});

EXO_TEST(sid_lease_set_window, {
	struct sid_pool* pool = lease_pool_create();
	sid_pool_set_window(pool, 256, 511);
	sid_pool_destroy(pool);
	return 1;
});

EXO_TEST(sid_lease_alloc_after_lease, {
	struct sid_fixture fx;
	sid_t s;
	fx_init(&fx, lease_pool_create());
	sid_pool_set_window(fx.pool, 256, 511);
	s = fx_alloc(&fx);
	fx_done(&fx);
	return s >= 256 && s <= 511;
});

EXO_TEST(sid_lease_destroy, {
	sid_pool_destroy(lease_pool_create());
	return 1;
});
