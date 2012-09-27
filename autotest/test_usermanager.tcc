#include <uhub.h>

#define MAX_USERS 64

static struct hub_user_manager* uman = 0;
static struct hub_user um_user[MAX_USERS];

EXO_TEST(um_init_1, {
	sid_t s;
	uman = uman_init();
	
	for (s = 0; s < MAX_USERS; s++)
	{
		memset(&um_user[s], 0, sizeof(struct hub_user));
		um_user[s].id.sid = s;
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
	uman = uman_init();
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

EXO_TEST(um_remove_2, {
	int i;
	for (i = 0; i < MAX_USERS; i++)
	{
		if (uman_remove(uman, &um_user[i]) != 0)
			return 0;
	}
	return 1;
});












/* Last test */
EXO_TEST(um_shutdown_4, {
	return uman_shutdown(uman) == 0;
});
