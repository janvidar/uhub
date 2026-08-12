#include "core/bbs.h"
#include "util/credentials.h"
#include "util/memory.h"

/* Parse one boards-file line; the board is left in bbs_b for the test to poke
   at, and freed by the next call. */
static struct bbs_board* bbs_b = 0;
static int bbs_b_error = 0;

static int bbs_parse(const char* line)
{
	bbs_board_free(bbs_b);
	bbs_b = bbs_board_parse(line, &bbs_b_error);
	return bbs_b != 0;
}

EXO_TEST(bbs_board_setup, {
	bbs_b = 0;
	bbs_b_error = 0;
	return 1;
});

/* -- board names ------------------------------------------------------- */

EXO_TEST(bbs_board_name_simple, { return bbs_board_name_is_valid("general"); });
EXO_TEST(bbs_board_name_dotted, { return bbs_board_name_is_valid("dev.adc"); });
EXO_TEST(bbs_board_name_punctuation, { return bbs_board_name_is_valid("a-b_c.9"); });
EXO_TEST(bbs_board_name_uppercase, { return bbs_board_name_is_valid("General"); });

/* "." and ".." are legal board names: the character set permits a dot, which is
   exactly why a client must never use a board name as a path component. */
EXO_TEST(bbs_board_name_dot, { return bbs_board_name_is_valid("."); });
EXO_TEST(bbs_board_name_dotdot, { return bbs_board_name_is_valid(".."); });

EXO_TEST(bbs_board_name_empty, { return !bbs_board_name_is_valid(""); });
EXO_TEST(bbs_board_name_null, { return !bbs_board_name_is_valid(0); });
EXO_TEST(bbs_board_name_space, { return !bbs_board_name_is_valid("two words"); });
EXO_TEST(bbs_board_name_slash, { return !bbs_board_name_is_valid("etc/passwd"); });
EXO_TEST(bbs_board_name_utf8, { return !bbs_board_name_is_valid("sm\xc3\xb8rg\xc3\xa5s"); });

EXO_TEST(bbs_board_name_max_length, {
	char name[BBS_MAX_BOARD_NAME + 1];
	memset(name, 'a', sizeof(name));
	name[BBS_MAX_BOARD_NAME] = 0;
	return bbs_board_name_is_valid(name);
});

EXO_TEST(bbs_board_name_too_long, {
	char name[BBS_MAX_BOARD_NAME + 2];
	memset(name, 'a', sizeof(name));
	name[BBS_MAX_BOARD_NAME + 1] = 0;
	return !bbs_board_name_is_valid(name);
});

/* -- parsing ----------------------------------------------------------- */

EXO_TEST(bbs_board_parse_minimal, {
	return bbs_parse("board general") && !strcmp(bbs_b->name, "general");
});

EXO_TEST(bbs_board_parse_defaults, {
	return bbs_parse("board general")
		&& bbs_b->max_size == 262144
		&& bbs_b->replay_days == 0
		&& bbs_b->title == 0
		&& bbs_b->description == 0;
});

/* A quoted value keeps its spaces: cfg_tokenize hands the whole thing over as
   one token, and the key/value split happens at the first '=' only. */
EXO_TEST(bbs_board_parse_quoted_title, {
	return bbs_parse("board general title=\"General discussion\"")
		&& bbs_b->title && !strcmp(bbs_b->title, "General discussion");
});

EXO_TEST(bbs_board_parse_quoted_description, {
	return bbs_parse("board general description=\"Anything about this hub\"")
		&& bbs_b->description && !strcmp(bbs_b->description, "Anything about this hub");
});

EXO_TEST(bbs_board_parse_numbers, {
	return bbs_parse("board general max_size=65536 replay_days=90")
		&& bbs_b->max_size == 65536
		&& bbs_b->replay_days == 90;
});

EXO_TEST(bbs_board_parse_comment_stripped, {
	return bbs_parse("board general max_size=1024 # the rest is a comment")
		&& bbs_b->max_size == 1024;
});

EXO_TEST(bbs_board_parse_blank_line, {
	return !bbs_parse("") && !bbs_b_error;
});

EXO_TEST(bbs_board_parse_comment_only, {
	return !bbs_parse("   # just a comment") && !bbs_b_error;
});

EXO_TEST(bbs_board_parse_missing_keyword, {
	return !bbs_parse("general title=x") && bbs_b_error;
});

EXO_TEST(bbs_board_parse_missing_name, {
	return !bbs_parse("board") && bbs_b_error;
});

EXO_TEST(bbs_board_parse_bad_name, {
	return !bbs_parse("board has space") && bbs_b_error;
});

EXO_TEST(bbs_board_parse_unknown_setting, {
	return !bbs_parse("board general colour=blue") && bbs_b_error;
});

EXO_TEST(bbs_board_parse_setting_without_value, {
	return !bbs_parse("board general title") && bbs_b_error;
});

EXO_TEST(bbs_board_parse_bad_credential, {
	return !bbs_parse("board general post=wizard") && bbs_b_error;
});

EXO_TEST(bbs_board_parse_bad_max_size, {
	return !bbs_parse("board general max_size=lots") && bbs_b_error;
});

EXO_TEST(bbs_board_parse_zero_max_size, {
	return !bbs_parse("board general max_size=0") && bbs_b_error;
});

EXO_TEST(bbs_board_parse_negative_replay_days, {
	return !bbs_parse("board general replay_days=-1") && bbs_b_error;
});

/* -- permissions ------------------------------------------------------- */

EXO_TEST(bbs_board_perm_defaults_guest, {
	/* subscribe (1) + reply (4) */
	return bbs_parse("board general")
		&& bbs_board_permissions(bbs_b, auth_cred_guest) == 5;
});

EXO_TEST(bbs_board_perm_defaults_user, {
	/* subscribe (1) + post (2) + reply (4) + withdraw_own (8) */
	return bbs_parse("board general")
		&& bbs_board_permissions(bbs_b, auth_cred_user) == 15;
});

EXO_TEST(bbs_board_perm_defaults_operator, {
	/* everything: 1 + 2 + 4 + 8 + 16 */
	return bbs_parse("board general")
		&& bbs_board_permissions(bbs_b, auth_cred_operator) == 31;
});

/* The announcements board from the BBS0 draft: anyone may read and reply, only
   operators may start a thread. PE5 for a guest. */
EXO_TEST(bbs_board_perm_announcements, {
	return bbs_parse("board announcements subscribe=guest post=operator reply=guest withdraw_own=none withdraw_any=operator")
		&& bbs_board_permissions(bbs_b, auth_cred_guest) == 5
		&& bbs_board_permissions(bbs_b, auth_cred_operator) == 23;
});

/* "none" means nobody, not "everybody". auth_cred_none is the *lowest*
   credential, so treating it as a threshold would grant the permission to all. */
EXO_TEST(bbs_board_perm_none_denies_admin, {
	return bbs_parse("board locked post=none")
		&& !(bbs_board_permissions(bbs_b, auth_cred_admin) & 2);
});

EXO_TEST(bbs_board_perm_never_alias, {
	return bbs_parse("board locked post=never")
		&& !(bbs_board_permissions(bbs_b, auth_cred_admin) & 2);
});

/* A board nobody may subscribe to is invisible to everyone, and invisible means
   no permissions at all -- not "everything except reading". */
EXO_TEST(bbs_board_perm_no_subscribe, {
	return bbs_parse("board hidden subscribe=none")
		&& bbs_board_permissions(bbs_b, auth_cred_admin) == 0;
});

/* Same rule one credential up: a guest cannot see a registered-only board, so
   the reply permission the defaults would otherwise grant is withheld too. */
EXO_TEST(bbs_board_perm_guest_denied_when_reg_required, {
	return bbs_parse("board members subscribe=reg")
		&& bbs_board_permissions(bbs_b, auth_cred_guest) == 0
		&& bbs_board_permissions(bbs_b, auth_cred_user) == 15;
});

EXO_TEST(bbs_board_perm_null_board, {
	return bbs_board_permissions(0, auth_cred_admin) == 0;
});

EXO_TEST(bbs_board_teardown, {
	bbs_board_free(bbs_b);
	bbs_b = 0;
	return 1;
});
