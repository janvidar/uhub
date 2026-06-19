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
