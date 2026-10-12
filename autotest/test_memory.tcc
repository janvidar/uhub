#include "adc/message.h"

/*
 * adc_message reference counting. Each test makes its own message and drops
 * every reference it took, so each one runs alone or in any order.
 */

static struct adc_message* refc_message(void)
{
	return adc_msg_create("IMSG Hello\\sWorld!");
}

EXO_TEST(test_message_refc_1, {
	struct adc_message* msg = refc_message();
	int ok = msg != NULL;
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(test_message_refc_2, {
	struct adc_message* msg = refc_message();
	int ok = msg->references == 1;
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(test_message_refc_3, {
	struct adc_message* msg = refc_message();
	int ok;
	adc_msg_incref(msg);
	ok = msg->references == 2;
	adc_msg_free(msg);
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(test_message_refc_4, {
	struct adc_message* msg = refc_message();
	int ok;
	adc_msg_incref(msg);
	adc_msg_incref(msg);
	ok = msg->references == 3;
	adc_msg_free(msg);
	adc_msg_free(msg);
	adc_msg_free(msg);
	return ok;
});

/* Each free drops one reference, and the message lives while any is left. */
EXO_TEST(test_message_refc_5, {
	struct adc_message* msg = refc_message();
	int ok;
	adc_msg_incref(msg);
	adc_msg_incref(msg);
	adc_msg_free(msg);
	ok = msg->references == 2;
	adc_msg_free(msg);
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(test_message_refc_6, {
	struct adc_message* msg = refc_message();
	int ok;
	adc_msg_incref(msg);
	adc_msg_free(msg);
	ok = msg->references == 1;
	adc_msg_free(msg);
	return ok;
});

/* The last free releases it. */
EXO_TEST(test_message_refc_7, {
	adc_msg_free(refc_message());
	return 1;
});
