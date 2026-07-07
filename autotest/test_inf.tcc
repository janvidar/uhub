#include "util/memory.h"
#include "adc/message.h"
#include "network/network.h"
#include "core/auth.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/usermanager.h"

#define USER_CID "GNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI"
#define USER_PID "3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y"
#define USER_NICK "Friend"
#define USER_SID "AAAB"

static struct hub_user* inf_user       = 0;
static struct hub_info* inf_hub    = 0;

extern int hub_handle_info_login(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd);
extern int hub_handle_info_common(struct hub_user* user, struct adc_message* cmd);

static void inf_create_hub()
{
	net_initialize();
	inf_hub = (struct hub_info*) hub_malloc_zero(sizeof(struct hub_info));
	
	inf_hub->users = uman_init(0, 1);
	inf_hub->acl = (struct acl_handle*) hub_malloc_zero(sizeof(struct acl_handle));
	inf_hub->config = (struct hub_config*) hub_malloc_zero(sizeof(struct hub_config));
	
	config_defaults(inf_hub->config);
	acl_initialize(inf_hub->config, inf_hub->acl);
}

static void inf_destroy_hub()
{
	uman_shutdown(inf_hub->users);
	acl_shutdown(inf_hub->acl);
	free_config(inf_hub->config);
	hub_free(inf_hub->acl);
	hub_free(inf_hub->config);
	hub_free(inf_hub);
	net_destroy();
}


static void inf_create_user()
{
	if (inf_user) return;
	inf_user = (struct hub_user*) hub_malloc_zero(sizeof(struct hub_user));
	inf_user->id.sid = 1;
	inf_user->limits.upload_slots = 1;
}

static void inf_destroy_user()
{
	if (!inf_user) return;
	/* Release the info message that hub_handle_info_login() attached via
	   user_set_info(); a plain hub_free() would leak it. */
	user_set_info(inf_user, 0);
	hub_free(inf_user);
	inf_user = 0;
}

EXO_TEST(inf_create_setup,
{
	inf_create_hub();
	inf_create_user();
	return (inf_user && inf_hub);
});


/* hub_handle_info_login() takes a reference on the message via user_set_info();
   we free our own reference here, and inf_destroy_user() releases the one held
   by inf_user at teardown. */
#define CHECK_INF(MSG, EXPECT) \
	do { \
		struct adc_message* msg = adc_msg_parse_verify(inf_user, MSG, strlen(MSG)); \
		int ok = hub_handle_info_login(inf_hub, inf_user, msg); \
		adc_msg_free(msg); \
		return ok == EXPECT; \
	} while(0)

EXO_TEST(inf_ok_1,  { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", 0); });

/* check CID abuse */
EXO_TEST(inf_cid_1, { CHECK_INF("BINF AAAB NIFriend PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_cid_missing); });
EXO_TEST(inf_cid_2, { CHECK_INF("BINF AAAB NIFriend IDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_cid_invalid); });
EXO_TEST(inf_cid_3, { CHECK_INF("BINF AAAB NIFriend IDaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_cid_invalid); });
EXO_TEST(inf_cid_4, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2R PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_cid_invalid); }); /* cid 1 byte short */
EXO_TEST(inf_cid_5, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RX PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_cid_invalid); }); /* cid 1 byte longer */
EXO_TEST(inf_cid_6, { CHECK_INF("BINF AAAB NIFriend IDA PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_cid_invalid); });
EXO_TEST(inf_cid_7, { CHECK_INF("BINF AAAB NIFriend IDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_cid_invalid); }); /* multi */
EXO_TEST(inf_cid_8, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y IDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", status_msg_inf_error_cid_invalid); });
EXO_TEST(inf_cid_9, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI\n", status_msg_inf_error_cid_invalid); });

/* equivalent to the pid versions */
EXO_TEST(inf_pid_1, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI\n", status_msg_inf_error_pid_missing); }); /* pid missing */
EXO_TEST(inf_pid_2, { CHECK_INF("BINF AAAB NIFriend ID3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y PDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", status_msg_inf_error_cid_invalid); }); /* variant of inf_cid_2 */
EXO_TEST(inf_pid_3, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PDaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", status_msg_inf_error_pid_invalid); }); /* pid invalid */
EXO_TEST(inf_pid_4, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7\n", status_msg_inf_error_pid_invalid); }); /* pid 1 byte short */
EXO_TEST(inf_pid_5, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7YX\n", status_msg_inf_error_pid_invalid); }); /* pid 1 byte longer */
EXO_TEST(inf_pid_6, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PDA\n", status_msg_inf_error_pid_invalid); }); /* very short pid */
EXO_TEST(inf_pid_7, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y PDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", status_msg_inf_error_pid_invalid); });
EXO_TEST(inf_pid_8, { CHECK_INF("BINF AAAB NIFriend PDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_pid_invalid); });
EXO_TEST(inf_pid_9, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_pid_invalid); });

/* check nickname abuse */
EXO_TEST(inf_nick_01, { CHECK_INF("BINF AAAB IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_nick_missing); });
EXO_TEST(inf_nick_02, { CHECK_INF("BINF AAAB NI IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_nick_short); });
EXO_TEST(inf_nick_03, { CHECK_INF("BINF AAAB NIa IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_nick_short); });
EXO_TEST(inf_nick_04, { CHECK_INF("BINF AAAB NIabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_nick_long); });
EXO_TEST(inf_nick_05, { CHECK_INF("BINF AAAB NI\\sabc IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_nick_spaces); });
EXO_TEST(inf_nick_06, { CHECK_INF("BINF AAAB NIa\\sc IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", 0); });
EXO_TEST(inf_nick_07, { CHECK_INF("BINF AAAB NIa\tc IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_nick_bad_chars); });
EXO_TEST(inf_nick_08, { CHECK_INF("BINF AAAB NIa\\nc IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_nick_bad_chars); });
EXO_TEST(inf_nick_09, { CHECK_INF("BINF AAAB NIabc NIdef IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n", status_msg_inf_error_nick_multiple); });
EXO_TEST(inf_nick_10, {
	const char* line = "BINF AAAB IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n";
	int ok;
	char nick[10];
	struct adc_message* msg;

	/* Invalid UTF-8 (0xf7 lead byte is out of range), with no ASCII control
	   bytes -- so it is rejected by the UTF-8 check, not the bad-characters
	   check (which now also rejects DEL, 0x7f). */
	nick[0] = 0xf7; nick[1] = 0x80; nick[2] = 0x80; nick[3] = 0x81; nick[4] = 0x98; nick[5] = 0x00;
	msg = adc_msg_parse_verify(inf_user, line, strlen(line));
	
	adc_msg_add_named_argument(msg, "NI", nick);
	ok = hub_handle_info_login(inf_hub, inf_user, msg);
	adc_msg_free(msg);
	if (ok != status_msg_inf_error_nick_not_utf8)
		printf("Expected %d, got %d\n", status_msg_inf_error_nick_not_utf8, ok);
	return ok == status_msg_inf_error_nick_not_utf8;
});

EXO_TEST(inf_nick_11, {
	const char* line = "BINF AAAB IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y\n";
	int ok;
	char nick[10];
	struct adc_message* msg;

	/* Valid UTF-8 but contains DEL (0x7f): must be rejected as a bad character. */
	nick[0] = 'a'; nick[1] = 'b'; nick[2] = 'c'; nick[3] = 0x7f; nick[4] = 0x00;
	msg = adc_msg_parse_verify(inf_user, line, strlen(line));

	adc_msg_add_named_argument(msg, "NI", nick);
	ok = hub_handle_info_login(inf_hub, inf_user, msg);
	adc_msg_free(msg);
	if (ok != status_msg_inf_error_nick_bad_chars)
		printf("Expected %d, got %d\n", status_msg_inf_error_nick_bad_chars, ok);
	return ok == status_msg_inf_error_nick_bad_chars;
});

/* check limits for slots and share */
EXO_TEST(inf_limits_1, { inf_hub->config->limit_min_slots = 1; CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y SL0\n", status_msg_user_slots_low); });
EXO_TEST(inf_limits_2, { inf_hub->config->limit_max_slots = 5; CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y SL99\n", status_msg_user_slots_high); });
EXO_TEST(inf_limits_3, { inf_hub->config->limit_min_share = 100; CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y SS104857599\n", status_msg_user_share_size_low); });
EXO_TEST(inf_limits_4, { inf_hub->config->limit_max_share = 500; CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y SS524288001\n", status_msg_user_share_size_high); });

/* setup for check limits for hubs */
EXO_TEST(inf_limit_hubs_setup,
{
	inf_hub->config->limit_min_slots = 0;
	inf_hub->config->limit_max_slots = 0;
	inf_hub->config->limit_max_share = 0;
	inf_hub->config->limit_min_share = 0;
	inf_hub->config->limit_max_hubs_user = 10;
	inf_hub->config->limit_max_hubs_reg  = 10;
	inf_hub->config->limit_max_hubs_op   = 10;
	inf_hub->config->limit_min_hubs_user = 2;
	inf_hub->config->limit_min_hubs_reg  = 2;
	inf_hub->config->limit_min_hubs_op   = 2;
	inf_hub->config->limit_max_hubs      = 25;
	
	return 1;
} );


EXO_TEST(inf_limit_hubs_1, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y HN15\n", status_msg_user_hub_limit_high); });
EXO_TEST(inf_limit_hubs_2, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y HN1\n", status_msg_user_hub_limit_low); });
EXO_TEST(inf_limit_hubs_3, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y HO15\n", status_msg_user_hub_limit_high); });
EXO_TEST(inf_limit_hubs_4, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y HO1\n", status_msg_user_hub_limit_low); });
EXO_TEST(inf_limit_hubs_5, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y HR15\n", status_msg_user_hub_limit_high); });
EXO_TEST(inf_limit_hubs_6, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y HR1\n", status_msg_user_hub_limit_low); });
EXO_TEST(inf_limit_hubs_7, { CHECK_INF("BINF AAAB NIFriend IDGNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI PD3A4545WFVGZLSGUXZLG7OS6ULQUVG3HM2T63I7Y HN15 HR15 HO15\n", status_msg_user_hub_limit_high); });


/*
 * ADC0 support-cast stripping. inf_user has no connection, which counts as
 * "not confirmed TLS", so hub_handle_info_common() must drop the ADC0 feature
 * token from the SU field. EXPECT is the resulting SU value, or NULL when the
 * SU argument is expected to be removed entirely.
 */
static int check_su_strip(const char* line, const char* expect_su)
{
	struct adc_message* msg = adc_msg_parse_verify(inf_user, line, strlen(line));
	char* su;
	int ok;

	if (!msg)
		return 0;

	hub_handle_info_common(inf_user, msg);
	su = adc_msg_get_named_argument(msg, "SU");

	if (expect_su == NULL)
		ok = (su == NULL);
	else
		ok = (su != NULL && strcmp(su, expect_su) == 0);

	if (!ok)
		printf("SU mismatch: got '%s', expected '%s'\n", su ? su : "(null)", expect_su ? expect_su : "(null)");

	hub_free(su);
	adc_msg_free(msg);
	user_clear_feature_cast_support(inf_user);
	return ok;
}

EXO_TEST(inf_su_adc0_only,  { return check_su_strip("BINF AAAB SUADC0\n", NULL); });
EXO_TEST(inf_su_adc0_first, { return check_su_strip("BINF AAAB SUADC0,TCP4,UDP4\n", "TCP4,UDP4"); });
EXO_TEST(inf_su_adc0_mid,   { return check_su_strip("BINF AAAB SUTCP4,ADC0,UDP4\n", "TCP4,UDP4"); });
EXO_TEST(inf_su_adc0_last,  { return check_su_strip("BINF AAAB SUTCP4,UDP4,ADC0\n", "TCP4,UDP4"); });
EXO_TEST(inf_su_no_adc0,    { return check_su_strip("BINF AAAB SUTCP4,UDP4\n", "TCP4,UDP4"); });
EXO_TEST(inf_su_adcs_kept,  { return check_su_strip("BINF AAAB SUADCS,TCP4\n", "ADCS,TCP4"); }); /* ADCS must not be confused with ADC0 */
EXO_TEST(inf_su_adcs_adc0,  { return check_su_strip("BINF AAAB SUADCS,ADC0,TCP4\n", "ADCS,TCP4"); });
EXO_TEST(inf_su_none,       { return check_su_strip("BINF AAAB NIFriend\n", NULL); }); /* no SU field at all */

EXO_TEST(inf_destroy_setup,
{
	inf_destroy_user();
	inf_destroy_hub();
	return 1;
});
