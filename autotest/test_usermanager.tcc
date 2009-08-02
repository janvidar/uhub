#include <uhub.h>

#define MAX_USERS 64

static struct hub_info um_hub;
static struct hub_user um_user[MAX_USERS];

EXO_TEST(um_test_setup, {
	int i = 0;
	memset(&um_hub,  0, sizeof(um_hub));
	
	for (i = 0; i < MAX_USERS; i++)
	{
		memset(&um_user[i], 0, sizeof(struct hub_user));
		um_user[i].id.sid = i+1;
		um_user[i].net.connection.sd = -1;
	}
	return 1;
});

EXO_TEST(um_init_1, {
	return uman_init(0) != 0;
});

EXO_TEST(um_init_2, {
	return uman_init(&um_hub) == 0;
});

EXO_TEST(um_shutdown_1, {
	return uman_shutdown(0) == -1;
});

EXO_TEST(um_shutdown_2, {
	return uman_shutdown(&um_hub) == 0;
});

EXO_TEST(um_shutdown_3, {
	return uman_shutdown(&um_hub) == -1;
});

EXO_TEST(um_init_3, {
	return uman_init(&um_hub) == 0;
});

EXO_TEST(um_add_1, {
	return uman_add(&um_hub, &um_user[0]) == 0;
});

EXO_TEST(um_size_1, {
	return hub_get_user_count(&um_hub) == 1;
});


EXO_TEST(um_remove_1, {
	return uman_remove(&um_hub, &um_user[0]) == 0;
});

EXO_TEST(um_size_2, {
	return hub_get_user_count(&um_hub) == 0;
});


EXO_TEST(um_add_2, {
	int i;
	for (i = 0; i < MAX_USERS; i++)
	{
		if (uman_add(&um_hub, &um_user[i]) != 0)
			return 0;
	}
	return 1;
});

EXO_TEST(um_size_3, {
	return hub_get_user_count(&um_hub) == MAX_USERS;
});

EXO_TEST(um_add_3, {
	return uman_add(&um_hub, &um_user[5]) != 0;
});

EXO_TEST(um_remove_2, {
	int i;
	for (i = 0; i < MAX_USERS; i++)
	{
		if (uman_remove(&um_hub, &um_user[i]) != 0)
			return 0;
	}
	return 1;
});












/* Last test */
EXO_TEST(um_shutdown_4, {
	return uman_shutdown(&um_hub) == 0;
});
