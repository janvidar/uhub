#include <uhub.h>

struct adc_message* g_msg;

EXO_TEST(test_message_refc_1, {
	g_msg = adc_msg_create("IMSG Hello\\sWorld!");
	return g_msg != NULL;
});

EXO_TEST(test_message_refc_2, {
	return g_msg->references == 1;
});

EXO_TEST(test_message_refc_3, {
	adc_msg_incref(g_msg);
	return g_msg->references == 2;
});

EXO_TEST(test_message_refc_4, {
	adc_msg_incref(g_msg);
	return g_msg->references == 3;
});

EXO_TEST(test_message_refc_5, {
	adc_msg_free(g_msg);
	return g_msg->references == 2;
});

EXO_TEST(test_message_refc_6, {
	adc_msg_free(g_msg);
	return g_msg->references == 1;
});

EXO_TEST(test_message_refc_7, {
	adc_msg_free(g_msg);
	return 1;
});
