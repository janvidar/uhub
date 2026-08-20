#include "system.h"
#include "uhub_limits.h"
#include "util/memory.h"
#include "util/misc.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "tools/adcclient.h"
#include "seeder/hubconn.h"

#include <sys/stat.h>

/*
 * The seeder's hub connection: roster, wire parsing, reconnect backoff and the
 * DRES it answers searches with. Everything here is driven without a socket --
 * the parsing and bookkeeping are deliberately separate from the transport so
 * they can be.
 */

#define SH_TTH  "AN7ZMSLIEBL53OPTM7WXGSTXUS3XOY6KQS5LBGX"
#define SH_TTH2 "TESTTESTTESTTESTTESTTESTTESTTESTTESTTES"
#define SH_CID  "MUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define SH_CID2 "NUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

#define SH_PID_DIR "test_seedhub.tmp"

static struct seed_roster* sh_roster = NULL;
static char sh_pid_first[MAX_CID_LEN + 1];

static void sh_fill(struct seed_user* user, sid_t sid, const char* cid, const char* nick,
	const char* address, int ct)
{
	memset(user, 0, sizeof(*user));
	user->sid = sid;
	user->client_type = ct;
	if (cid)
		uhub_strlcpy(user->cid, cid, sizeof(user->cid));
	if (nick)
		uhub_strlcpy(user->nick, nick, sizeof(user->nick));
	if (address)
		uhub_strlcpy(user->address, address, sizeof(user->address));
}

/* Parse a wire line into a message the parsers can be pointed at. */
static struct adc_message* sh_msg(const char* line)
{
	return adc_msg_parse(line, strlen(line));
}

static void sh_rmtree(const char* path)
{
	char child[512];
	snprintf(child, sizeof(child), "%s/pid", path);
	unlink(child);
	rmdir(path);
}


/* -------------------------------------------------------------------------
 * Roster
 * ------------------------------------------------------------------------- */

EXO_TEST(seedhub_roster_create, {
	sh_roster = seed_roster_create();
	return sh_roster != NULL && seed_roster_size(sh_roster) == 0;
});

EXO_TEST(seedhub_roster_empty_lookup, {
	return seed_roster_get_sid(sh_roster, 1) == NULL
		&& seed_roster_get_cid(sh_roster, SH_CID) == NULL;
});

EXO_TEST(seedhub_roster_add, {
	struct seed_user user;
	sh_fill(&user, 4, SH_CID, "alice", "192.0.2.10", SEED_CT_REGISTERED);
	return seed_roster_update(sh_roster, &user) != NULL && seed_roster_size(sh_roster) == 1;
});

EXO_TEST(seedhub_roster_get_by_sid, {
	const struct seed_user* user = seed_roster_get_sid(sh_roster, 4);
	return user && user->sid == 4 && strcmp(user->nick, "alice") == 0
		&& strcmp(user->address, "192.0.2.10") == 0;
});

EXO_TEST(seedhub_roster_get_by_cid, {
	const struct seed_user* user = seed_roster_get_cid(sh_roster, SH_CID);
	return user && user->sid == 4 && strcmp(user->cid, SH_CID) == 0;
});

EXO_TEST(seedhub_roster_get_by_cid_unknown, {
	return seed_roster_get_cid(sh_roster, SH_CID2) == NULL
		&& seed_roster_get_cid(sh_roster, "") == NULL
		&& seed_roster_get_cid(sh_roster, NULL) == NULL;
});

/* A second BINF for a SID already in the roster is an update, not a duplicate. */
EXO_TEST(seedhub_roster_duplicate_sid, {
	struct seed_user user;
	sh_fill(&user, 4, SH_CID, "alice2", "192.0.2.11", SEED_CT_REGISTERED | SEED_CT_OPERATOR);
	return seed_roster_update(sh_roster, &user) != NULL && seed_roster_size(sh_roster) == 1;
});

EXO_TEST(seedhub_roster_update_applied, {
	const struct seed_user* user = seed_roster_get_sid(sh_roster, 4);
	return user && strcmp(user->nick, "alice2") == 0
		&& strcmp(user->address, "192.0.2.11") == 0
		&& seed_user_is_operator(user);
});

/* The CID index has to follow when a SID starts carrying a different CID. */
EXO_TEST(seedhub_roster_update_cid_reindexes, {
	struct seed_user user;
	sh_fill(&user, 4, SH_CID2, "alice2", "192.0.2.11", SEED_CT_REGISTERED);
	seed_roster_update(sh_roster, &user);
	return seed_roster_get_cid(sh_roster, SH_CID) == NULL
		&& seed_roster_get_cid(sh_roster, SH_CID2) != NULL
		&& seed_roster_size(sh_roster) == 1;
});

EXO_TEST(seedhub_roster_second_user, {
	struct seed_user user;
	sh_fill(&user, 9, SH_CID, "bob", "192.0.2.20", SEED_CT_BOT);
	seed_roster_update(sh_roster, &user);
	return seed_roster_size(sh_roster) == 2
		&& seed_roster_get_sid(sh_roster, 9) != NULL
		&& seed_roster_get_cid(sh_roster, SH_CID) != NULL;
});

EXO_TEST(seedhub_roster_no_cid_is_not_indexed, {
	struct seed_user user;
	sh_fill(&user, 11, "", "ghost", "", 0);
	seed_roster_update(sh_roster, &user);
	return seed_roster_size(sh_roster) == 3
		&& seed_roster_get_sid(sh_roster, 11) != NULL
		&& seed_roster_get_cid(sh_roster, "") == NULL;
});

EXO_TEST(seedhub_roster_remove, {
	int removed = seed_roster_remove(sh_roster, 9);
	return removed == 1 && seed_roster_size(sh_roster) == 2
		&& seed_roster_get_sid(sh_roster, 9) == NULL
		&& seed_roster_get_cid(sh_roster, SH_CID) == NULL;
});

EXO_TEST(seedhub_roster_remove_unknown, {
	return seed_roster_remove(sh_roster, 9) == 0 && seed_roster_size(sh_roster) == 2;
});

EXO_TEST(seedhub_roster_survivor_intact, {
	const struct seed_user* user = seed_roster_get_sid(sh_roster, 4);
	return user && strcmp(user->cid, SH_CID2) == 0
		&& seed_roster_get_cid(sh_roster, SH_CID2) == user;
});

EXO_TEST(seedhub_roster_clear, {
	seed_roster_clear(sh_roster);
	return seed_roster_size(sh_roster) == 0
		&& seed_roster_get_sid(sh_roster, 4) == NULL
		&& seed_roster_get_cid(sh_roster, SH_CID2) == NULL;
});

EXO_TEST(seedhub_roster_reuse_after_clear, {
	struct seed_user user;
	sh_fill(&user, 4, SH_CID, "alice", "192.0.2.10", 0);
	return seed_roster_update(sh_roster, &user) != NULL && seed_roster_size(sh_roster) == 1;
});

EXO_TEST(seedhub_roster_null_safe, {
	return seed_roster_update(sh_roster, NULL) == NULL
		&& seed_roster_update(NULL, NULL) == NULL
		&& seed_roster_get_sid(NULL, 1) == NULL
		&& seed_roster_remove(NULL, 1) == 0
		&& seed_roster_size(NULL) == 0;
});

EXO_TEST(seedhub_roster_destroy, {
	seed_roster_destroy(sh_roster);
	sh_roster = NULL;
	seed_roster_destroy(NULL);
	return 1;
});


/* -------------------------------------------------------------------------
 * CT (client type) bits
 * ------------------------------------------------------------------------- */

EXO_TEST(seedhub_ct_absent, {
	return ADC_client_parse_client_type(NULL) == 0
		&& ADC_client_parse_client_type("") == 0;
});

EXO_TEST(seedhub_ct_not_a_number, {
	return ADC_client_parse_client_type("op") == 0
		&& ADC_client_parse_client_type("4x") == 0
		&& ADC_client_parse_client_type("-4") == 0;
});

EXO_TEST(seedhub_ct_bot, {
	struct seed_user user;
	sh_fill(&user, 1, SH_CID, "b", "", ADC_client_parse_client_type("1"));
	return user.client_type == SEED_CT_BOT
		&& seed_user_is_bot(&user)
		&& !seed_user_is_operator(&user)
		&& !seed_user_is_registered(&user);
});

EXO_TEST(seedhub_ct_registered, {
	struct seed_user user;
	sh_fill(&user, 1, SH_CID, "r", "", ADC_client_parse_client_type("2"));
	return seed_user_is_registered(&user) && !seed_user_is_operator(&user);
});

EXO_TEST(seedhub_ct_operator, {
	struct seed_user user;
	sh_fill(&user, 1, SH_CID, "o", "", ADC_client_parse_client_type("4"));
	return seed_user_is_operator(&user) && !seed_user_is_bot(&user)
		&& !seed_user_is_hub(&user);
});

EXO_TEST(seedhub_ct_hub, {
	struct seed_user user;
	sh_fill(&user, 1, SH_CID, "h", "", ADC_client_parse_client_type("32"));
	return seed_user_is_hub(&user) && !seed_user_is_operator(&user);
});

/* CT is a mask: the hub's own bot is 1 + 4, and both bits must read back. */
EXO_TEST(seedhub_ct_hubbot_is_a_mask, {
	struct seed_user user;
	sh_fill(&user, 1, SH_CID, "hb", "", ADC_client_parse_client_type("5"));
	return seed_user_is_bot(&user) && seed_user_is_operator(&user)
		&& !seed_user_is_registered(&user);
});

EXO_TEST(seedhub_ct_none, {
	struct seed_user user;
	sh_fill(&user, 1, SH_CID, "guest", "", 0);
	return !seed_user_is_bot(&user) && !seed_user_is_operator(&user)
		&& !seed_user_is_registered(&user) && !seed_user_is_hub(&user);
});

EXO_TEST(seedhub_ct_predicates_null_safe, {
	return !seed_user_is_bot(NULL) && !seed_user_is_operator(NULL)
		&& !seed_user_is_registered(NULL) && !seed_user_is_hub(NULL);
});


/* -------------------------------------------------------------------------
 * Search parsing
 * ------------------------------------------------------------------------- */

EXO_TEST(seedhub_search_tth_and_token, {
	struct seed_search search;
	struct adc_message* msg = sh_msg("BSCH AAAB TR" SH_TTH " TOtoken42\n");
	int ok = msg && seed_hub_parse_search(msg, &search)
		&& strcmp(search.tth, SH_TTH) == 0
		&& strcmp(search.token, "token42") == 0;
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_search_without_token, {
	struct seed_search search;
	struct adc_message* msg = sh_msg("BSCH AAAB TR" SH_TTH "\n");
	int ok = msg && seed_hub_parse_search(msg, &search)
		&& strcmp(search.tth, SH_TTH) == 0
		&& search.token[0] == '\0';
	adc_msg_free(msg);
	return ok;
});

/* A substring search is not something a content-addressed cache can answer. */
EXO_TEST(seedhub_search_without_tth, {
	struct seed_search search;
	struct adc_message* msg = sh_msg("BSCH AAAB ANmovie TOtoken42\n");
	int ok = msg && !seed_hub_parse_search(msg, &search)
		&& search.tth[0] == '\0';
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_search_short_tth_rejected, {
	struct seed_search search;
	struct adc_message* msg = sh_msg("BSCH AAAB TRABCDEF TOtoken42\n");
	int ok = msg && !seed_hub_parse_search(msg, &search);
	adc_msg_free(msg);
	return ok;
});

/* Base32 is upper case; anything else is not a TTH we could look up. */
EXO_TEST(seedhub_search_non_base32_tth_rejected, {
	struct seed_search search;
	struct adc_message* msg = sh_msg("BSCH AAAB TRan7zmsliebl53optm7wxgstxus3xoy6kqs5lbgx\n");
	int ok = msg && !seed_hub_parse_search(msg, &search);
	adc_msg_free(msg);
	return ok;
});

/*
 * The exact wire form EiskaltDC++ sends: a TTH with a trailing escaped space.
 * This was rejected outright, so every search from that client went unanswered
 * -- the TTH was validated in its escaped form while the token beside it was
 * unescaped first.
 */
EXO_TEST(seedhub_search_tth_trailing_escaped_space, {
	struct seed_search search;
	struct adc_message* msg = sh_msg("BSCH AAAE TO228369373 TR" SH_TTH "\\s\n");
	int ok = msg && seed_hub_parse_search(msg, &search)
		&& strcmp(search.tth, SH_TTH) == 0
		&& strcmp(search.token, "228369373") == 0;
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_search_tth_leading_escaped_space, {
	struct seed_search search;
	struct adc_message* msg = sh_msg("BSCH AAAE TR\\s" SH_TTH "\n");
	int ok = msg && seed_hub_parse_search(msg, &search)
		&& strcmp(search.tth, SH_TTH) == 0;
	adc_msg_free(msg);
	return ok;
});

/* Trimming is forgiveness about surrounding blanks, not about the TTH itself:
   an embedded space still makes it something other than a TTH. */
EXO_TEST(seedhub_search_tth_embedded_space_rejected, {
	struct seed_search search;
	struct adc_message* msg = sh_msg("BSCH AAAE TRDFXOIUTHRBTBVKKKZ35I\\s65RLRZRWXNN7DYP4NHY\n");
	int ok = msg && !seed_hub_parse_search(msg, &search);
	adc_msg_free(msg);
	return ok;
});

/* A TTH that is only blanks is not a TTH, and trimming must not turn it into
   an empty string that then looks like a valid lookup. */
EXO_TEST(seedhub_search_tth_only_blanks_rejected, {
	struct seed_search search;
	struct adc_message* msg = sh_msg("BSCH AAAE TR\\s\\s\n");
	int ok = msg && !seed_hub_parse_search(msg, &search)
		&& search.tth[0] == '\0';
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_search_token_is_unescaped, {
	struct seed_search search;
	struct adc_message* msg = sh_msg("BSCH AAAB TR" SH_TTH " TOa\\sb\n");
	int ok = msg && seed_hub_parse_search(msg, &search)
		&& strcmp(search.token, "a b") == 0;
	adc_msg_free(msg);
	return ok;
});

/* An unusable token costs the token, not the answer. */
EXO_TEST(seedhub_search_overlong_token_dropped, {
	struct seed_search search;
	char line[512];
	struct adc_message* msg;
	int ok;

	memset(line, 0, sizeof(line));
	snprintf(line, sizeof(line), "BSCH AAAB TR" SH_TTH " TO%0*d\n", SEED_TOKEN_MAX + 4, 1);
	msg = sh_msg(line);
	ok = msg && seed_hub_parse_search(msg, &search)
		&& strcmp(search.tth, SH_TTH) == 0
		&& search.token[0] == '\0';
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_search_null_safe, {
	struct seed_search search;
	return seed_hub_parse_search(NULL, &search) == 0
		&& seed_hub_parse_search(NULL, NULL) == 0;
});


/* -------------------------------------------------------------------------
 * CTM / RCM parsing
 * ------------------------------------------------------------------------- */

EXO_TEST(seedhub_ctm_ok, {
	struct seed_connect req;
	struct adc_message* msg = sh_msg("DCTM AAAB AAAC ADCS/0.10 1512 tok123\n");
	int ok = msg && seed_hub_parse_ctm(msg, &req)
		&& strcmp(req.protocol, "ADCS/0.10") == 0
		&& req.port == 1512
		&& strcmp(req.token, "tok123") == 0;
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_ctm_port_zero_rejected, {
	struct seed_connect req;
	struct adc_message* msg = sh_msg("DCTM AAAB AAAC ADC/1.0 0 tok123\n");
	int ok = msg && !seed_hub_parse_ctm(msg, &req) && req.port == 0 && req.token[0] == '\0';
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_ctm_port_too_large_rejected, {
	struct seed_connect req;
	struct adc_message* msg = sh_msg("DCTM AAAB AAAC ADC/1.0 65536 tok123\n");
	int ok = msg && !seed_hub_parse_ctm(msg, &req);
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_ctm_port_not_a_number_rejected, {
	struct seed_connect req;
	struct adc_message* msg = sh_msg("DCTM AAAB AAAC ADC/1.0 1512x tok123\n");
	int ok = msg && !seed_hub_parse_ctm(msg, &req);
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_ctm_missing_token_rejected, {
	struct seed_connect req;
	struct adc_message* msg = sh_msg("DCTM AAAB AAAC ADC/1.0 1512\n");
	int ok = msg && !seed_hub_parse_ctm(msg, &req);
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_ctm_no_arguments_rejected, {
	struct seed_connect req;
	struct adc_message* msg = sh_msg("DCTM AAAB AAAC\n");
	int ok = msg && !seed_hub_parse_ctm(msg, &req);
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_ctm_overlong_token_rejected, {
	struct seed_connect req;
	char line[512];
	struct adc_message* msg;
	int ok;

	memset(line, 0, sizeof(line));
	snprintf(line, sizeof(line), "DCTM AAAB AAAC ADC/1.0 1512 %0*d\n", SEED_TOKEN_MAX + 4, 1);
	msg = sh_msg(line);
	ok = msg && !seed_hub_parse_ctm(msg, &req);
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_rcm_ok, {
	struct seed_connect req;
	struct adc_message* msg = sh_msg("DRCM AAAB AAAC ADCS/0.10 tok456\n");
	int ok = msg && seed_hub_parse_rcm(msg, &req)
		&& strcmp(req.protocol, "ADCS/0.10") == 0
		&& strcmp(req.token, "tok456") == 0
		&& req.port == 0;
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_rcm_missing_token_rejected, {
	struct seed_connect req;
	struct adc_message* msg = sh_msg("DRCM AAAB AAAC ADCS/0.10\n");
	int ok = msg && !seed_hub_parse_rcm(msg, &req);
	adc_msg_free(msg);
	return ok;
});

/* An RCM has no port field, so its third word is not one. */
EXO_TEST(seedhub_rcm_ignores_a_third_word, {
	struct seed_connect req;
	struct adc_message* msg = sh_msg("DRCM AAAB AAAC ADCS/0.10 tok456 1512\n");
	int ok = msg && seed_hub_parse_rcm(msg, &req)
		&& strcmp(req.token, "tok456") == 0 && req.port == 0;
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(seedhub_connect_null_safe, {
	struct seed_connect req;
	return seed_hub_parse_ctm(NULL, &req) == 0 && seed_hub_parse_rcm(NULL, NULL) == 0;
});


/* -------------------------------------------------------------------------
 * Reconnect backoff
 * ------------------------------------------------------------------------- */

EXO_TEST(seedhub_backoff_first_delay, {
	return seed_hub_backoff_next(0) == SEED_RECONNECT_MIN;
});

EXO_TEST(seedhub_backoff_doubles, {
	unsigned int d = seed_hub_backoff_next(0);
	return d == 1
		&& (d = seed_hub_backoff_next(d)) == 2
		&& (d = seed_hub_backoff_next(d)) == 4
		&& (d = seed_hub_backoff_next(d)) == 8
		&& (d = seed_hub_backoff_next(d)) == 16
		&& (d = seed_hub_backoff_next(d)) == 32;
});

EXO_TEST(seedhub_backoff_saturates, {
	return seed_hub_backoff_next(32) == SEED_RECONNECT_MAX
		&& seed_hub_backoff_next(SEED_RECONNECT_MAX) == SEED_RECONNECT_MAX
		&& seed_hub_backoff_next(1000) == SEED_RECONNECT_MAX;
});

/* Never 0: a zero delay would be a busy reconnect loop against a dead hub. */
EXO_TEST(seedhub_backoff_never_zero, {
	unsigned int d = 0;
	int i;
	for (i = 0; i < 20; i++)
	{
		d = seed_hub_backoff_next(d);
		if (d == 0 || d > SEED_RECONNECT_MAX)
			return 0;
	}
	return 1;
});

/* A successful login resets the delay, so the next outage starts at 1s again. */
EXO_TEST(seedhub_backoff_reset, {
	unsigned int grown = seed_hub_backoff_next(SEED_RECONNECT_MAX);
	/* A successful login sets the delay back to 0, which is where the first
	   delay is measured from. */
	return grown == SEED_RECONNECT_MAX && seed_hub_backoff_next(0) == SEED_RECONNECT_MIN;
});

/* One arm of the timer must stay inside the timeout wheel. */
EXO_TEST(seedhub_backoff_fits_the_timeout_wheel, {
	return SEED_RECONNECT_MAX < TIMEOUT_QUEUE_MAX;
});


/* -------------------------------------------------------------------------
 * DRES construction
 * ------------------------------------------------------------------------- */

EXO_TEST(seedhub_result_fields, {
	struct adc_message* res = seed_hub_build_result(4, 9, SH_TTH, 12345, "file.png", 3, "tok9");
	char* fn = res ? adc_msg_get_named_argument(res, "FN") : NULL;
	char* si = res ? adc_msg_get_named_argument(res, "SI") : NULL;
	char* sl = res ? adc_msg_get_named_argument(res, "SL") : NULL;
	char* tr = res ? adc_msg_get_named_argument(res, "TR") : NULL;
	char* to = res ? adc_msg_get_named_argument(res, "TO") : NULL;
	int ok = res && fn && si && sl && tr && to
		/* An absolute virtual path, not a bare name: ADC's FN is a path, and
		   clients take the name they show from after the last '/'. */
		&& strcmp(fn, "/seed/file.png") == 0
		&& strcmp(si, "12345") == 0
		&& strcmp(sl, "3") == 0
		&& strcmp(tr, SH_TTH) == 0
		&& strcmp(to, "tok9") == 0;
	hub_free(fn); hub_free(si); hub_free(sl); hub_free(tr); hub_free(to);
	adc_msg_free(res);
	return ok;
});

EXO_TEST(seedhub_result_header, {
	struct adc_message* res = seed_hub_build_result(4, 9, SH_TTH, 1, "a", 1, "");
	int ok = res && res->cmd == ADC_CMD_DRES && res->source == 4 && res->target == 9;
	adc_msg_free(res);
	return ok;
});

/* The name is user-supplied text going back on the wire; it must be escaped. */
EXO_TEST(seedhub_result_escapes_name, {
	struct adc_message* res = seed_hub_build_result(4, 9, SH_TTH, 1, "my file.png", 1, "");
	int ok = res && strstr(res->cache, "FN/seed/my\\sfile.png") != NULL;
	adc_msg_free(res);
	return ok;
});

EXO_TEST(seedhub_result_escapes_newline_in_name, {
	struct adc_message* res = seed_hub_build_result(4, 9, SH_TTH, 1, "a\nb", 1, "");
	int ok = res && strstr(res->cache, "FN/seed/a\\nb") != NULL && strchr(res->cache, '\n') == strrchr(res->cache, '\n');
	adc_msg_free(res);
	return ok;
});

EXO_TEST(seedhub_result_escapes_token, {
	struct adc_message* res = seed_hub_build_result(4, 9, SH_TTH, 1, "a", 1, "a b");
	int ok = res && strstr(res->cache, "TOa\\sb") != NULL;
	adc_msg_free(res);
	return ok;
});

/* No TO in the search means no TO in the answer, not an empty one. */
EXO_TEST(seedhub_result_without_token, {
	struct adc_message* empty = seed_hub_build_result(4, 9, SH_TTH, 1, "a", 1, "");
	struct adc_message* none  = seed_hub_build_result(4, 9, SH_TTH, 1, "a", 1, NULL);
	int ok = empty && none
		&& !adc_msg_has_named_argument(empty, "TO")
		&& !adc_msg_has_named_argument(none, "TO");
	adc_msg_free(empty);
	adc_msg_free(none);
	return ok;
});

EXO_TEST(seedhub_result_nameless_falls_back_to_tth, {
	struct adc_message* res = seed_hub_build_result(4, 9, SH_TTH, 1, "", 1, "");
	char* fn = res ? adc_msg_get_named_argument(res, "FN") : NULL;
	int ok = fn && strcmp(fn, "/" SEED_SHARE_DIR "/" SH_TTH) == 0;
	hub_free(fn);
	adc_msg_free(res);
	return ok;
});

/*
 * A name is one path component. It arrives from a magnet's "dn=", so it is
 * whatever a user typed, and the seeder has no directory structure to place it
 * in -- anything before a separator is dropped rather than published as a tree
 * that does not exist. Nothing is ever served by path: a download names its
 * file by TTH.
 */
EXO_TEST(seedhub_result_name_is_one_component, {
	struct adc_message* res = seed_hub_build_result(4, 9, SH_TTH, 1, "a/b/c.png", 1, "");
	char* fn = res ? adc_msg_get_named_argument(res, "FN") : NULL;
	int ok = fn && strcmp(fn, "/seed/c.png") == 0;
	hub_free(fn);
	adc_msg_free(res);
	return ok;
});

EXO_TEST(seedhub_result_name_strips_backslash_paths, {
	struct adc_message* res = seed_hub_build_result(4, 9, SH_TTH, 1, "..\\..\\secret.png", 1, "");
	char* fn = res ? adc_msg_get_named_argument(res, "FN") : NULL;
	int ok = fn && strcmp(fn, "/seed/secret.png") == 0;
	hub_free(fn);
	adc_msg_free(res);
	return ok;
});

/* A name that is nothing but separators leaves no component at all, and must
   still produce a well-formed FN rather than a bare "/" plus rubbish. */
EXO_TEST(seedhub_result_name_all_separators, {
	struct adc_message* res = seed_hub_build_result(4, 9, SH_TTH, 1, "///", 1, "");
	char* fn = res ? adc_msg_get_named_argument(res, "FN") : NULL;
	int ok = fn && strcmp(fn, "/seed/") == 0;
	hub_free(fn);
	adc_msg_free(res);
	return ok;
});

EXO_TEST(seedhub_result_slots_floor, {
	struct adc_message* res = seed_hub_build_result(4, 9, SH_TTH, 1, "a", 0, "");
	char* sl = res ? adc_msg_get_named_argument(res, "SL") : NULL;
	int ok = sl && strcmp(sl, "1") == 0;
	hub_free(sl);
	adc_msg_free(res);
	return ok;
});

EXO_TEST(seedhub_result_large_size, {
	struct adc_message* res = seed_hub_build_result(4, 9, SH_TTH2, 4294967296ULL, "big", 1, "");
	char* si = res ? adc_msg_get_named_argument(res, "SI") : NULL;
	int ok = si && strcmp(si, "4294967296") == 0;
	hub_free(si);
	adc_msg_free(res);
	return ok;
});

EXO_TEST(seedhub_result_bad_tth_refused, {
	return seed_hub_build_result(4, 9, "ABC", 1, "a", 1, "") == NULL
		&& seed_hub_build_result(4, 9, NULL, 1, "a", 1, "") == NULL;
});


/* -------------------------------------------------------------------------
 * The PID file: a stable identity across restarts
 * ------------------------------------------------------------------------- */

EXO_TEST(seedhub_pid_generated, {
	sh_rmtree(SH_PID_DIR);
	memset(sh_pid_first, 0, sizeof(sh_pid_first));
	return seed_hub_pid_load(SH_PID_DIR, sh_pid_first) == 1
		&& strlen(sh_pid_first) == MAX_CID_LEN;
});

/* The whole point: the same PID, hence the same CID, on the next start. */
EXO_TEST(seedhub_pid_is_stable, {
	char again[MAX_CID_LEN + 1];
	memset(again, 0, sizeof(again));
	return seed_hub_pid_load(SH_PID_DIR, again) == 1
		&& strcmp(again, sh_pid_first) == 0;
});

EXO_TEST(seedhub_pid_file_is_private, {
	struct stat st;
	char path[512];
	snprintf(path, sizeof(path), "%s/pid", SH_PID_DIR);
	return stat(path, &st) == 0 && (st.st_mode & 0777) == 0600;
});

/* A corrupt file is replaced rather than being handed to the transport. */
EXO_TEST(seedhub_pid_corrupt_is_regenerated, {
	char path[512];
	char again[MAX_CID_LEN + 1];
	FILE* file;

	snprintf(path, sizeof(path), "%s/pid", SH_PID_DIR);
	file = fopen(path, "w");
	if (!file)
		return 0;
	fprintf(file, "not-a-pid\n");
	fclose(file);

	memset(again, 0, sizeof(again));
	return seed_hub_pid_load(SH_PID_DIR, again) == 1
		&& strlen(again) == MAX_CID_LEN
		&& strcmp(again, sh_pid_first) != 0;
});

EXO_TEST(seedhub_pid_null_safe, {
	char pid[MAX_CID_LEN + 1];
	return seed_hub_pid_load(NULL, pid) == 0
		&& seed_hub_pid_load("", pid) == 0
		&& seed_hub_pid_load(SH_PID_DIR, NULL) == 0;
});

EXO_TEST(seedhub_pid_cleanup, {
	sh_rmtree(SH_PID_DIR);
	return 1;
});


/* -------------------------------------------------------------------------
 * The "?kp=" keyprint in the hub URL
 *
 * This is what authenticates the hub: without it the seeder's link is
 * encrypted but anyone able to intercept it can be the hub, and everything the
 * seeder trusts (operator authority, the peers it dials, the password
 * challenge it answers) comes down that link. Parsing only -- no handshake.
 * ------------------------------------------------------------------------- */

/* A valid SHA-256 keyprint: 52 base32 characters. */
#define SH_KP32 "7LTBHRI6DRARELTAMUCE3MXHGRZQRZHCIKYE4GHP4S3GV4LETMZQ"
#define SH_KP   "SHA256/" SH_KP32

/* Returns the parse result, and leaves the keyprint in sh_kp for inspection. */
static char sh_kp[ADC_KEYPRINT_MAX];

static int sh_parse_kp(const char* url)
{
	memset(sh_kp, 0x7f, sizeof(sh_kp));  /* poisoned: a "no keyprint" answer must still clear it */
	return ADC_client_parse_keyprint(url, sh_kp, sizeof(sh_kp));
}

EXO_TEST(seedhub_kp_present, {
	return sh_parse_kp("adcs://hub.example.org:1511/?kp=" SH_KP) == 1
		&& strcmp(sh_kp, SH_KP) == 0;
});

/* The path may be omitted, and other parameters may sit on either side of it. */
EXO_TEST(seedhub_kp_present_no_path, {
	return sh_parse_kp("adcs://hub.example.org:1511?kp=" SH_KP) == 1
		&& strcmp(sh_kp, SH_KP) == 0;
});

EXO_TEST(seedhub_kp_among_other_parameters, {
	return sh_parse_kp("adcs://hub.example.org:1511/?foo=bar&kp=" SH_KP "&baz=1") == 1
		&& strcmp(sh_kp, SH_KP) == 0;
});

/* Base32 is case-insensitive, so a keyprint pasted in lower case is usable. */
EXO_TEST(seedhub_kp_lowercase_accepted, {
	return sh_parse_kp("adcs://hub.example.org:1511/?kp=sha256/"
		"7ltbhri6drareltamuce3mxhgrzqrzhcikye4ghp4s3gv4letmzq") == 1;
});

/* --- absent -------------------------------------------------------------- */

EXO_TEST(seedhub_kp_absent, {
	return sh_parse_kp("adcs://hub.example.org:1511") == 0 && sh_kp[0] == '\0';
});

EXO_TEST(seedhub_kp_absent_with_path, {
	return sh_parse_kp("adcs://hub.example.org:1511/?foo=bar") == 0 && sh_kp[0] == '\0';
});

EXO_TEST(seedhub_kp_null_url, {
	return sh_parse_kp(NULL) == 0 && sh_kp[0] == '\0';
});

/* "kp=" has to be a parameter of its own: a hostname or a longer parameter
   name that merely ends in "kp" pins nothing. */
EXO_TEST(seedhub_kp_not_a_substring, {
	return sh_parse_kp("adcs://kp=host.example.org:1511") == 0
		&& sh_parse_kp("adcs://hub.example.org:1511/?xkp=" SH_KP) == 0;
});

/* --- refused ------------------------------------------------------------- */

/* An algorithm this build cannot compute must fail, not be quietly dropped:
   ignoring it would leave the link unauthenticated while looking pinned. */
EXO_TEST(seedhub_kp_unknown_algorithm, {
	return sh_parse_kp("adcs://hub.example.org:1511/?kp=SHA1/" SH_KP32) == -1
		&& sh_parse_kp("adcs://hub.example.org:1511/?kp=MD5/" SH_KP32) == -1
		&& sh_parse_kp("adcs://hub.example.org:1511/?kp=SHA512/" SH_KP32) == -1;
});

/* Not 52 base32 characters -- too short, too long, or empty -- is not a
   SHA-256 keyprint whatever else it may be. */
EXO_TEST(seedhub_kp_wrong_length, {
	return sh_parse_kp("adcs://hub.example.org:1511/?kp=SHA256/7LTBHRI6DRAR") == -1
		&& sh_parse_kp("adcs://hub.example.org:1511/?kp=SHA256/" SH_KP32 "A") == -1
		&& sh_parse_kp("adcs://hub.example.org:1511/?kp=SHA256/") == -1;
});

EXO_TEST(seedhub_kp_malformed, {
	return sh_parse_kp("adcs://hub.example.org:1511/?kp=") == -1          /* nothing at all */
		&& sh_parse_kp("adcs://hub.example.org:1511/?kp=" SH_KP32) == -1   /* no algorithm */
		&& sh_parse_kp("adcs://hub.example.org:1511/?kp=SHA256") == -1     /* no separator */
		&& sh_parse_kp("adcs://hub.example.org:1511/?kp=/" SH_KP32) == -1; /* empty algorithm */
});

/* '0', '1', '8' and '9' are not in the base32 alphabet. */
EXO_TEST(seedhub_kp_not_base32, {
	return sh_parse_kp("adcs://hub.example.org:1511/?kp=SHA256/"
		"0LTBHRI6DRARELTAMUCE3MXHGRZQRZHCIKYE4GHP4S3GV4LETMZQ") == -1
		&& sh_parse_kp("adcs://hub.example.org:1511/?kp=SHA256/"
		"7LTBHRI6DRARELTAMUCE3MXHGRZQRZHCIKYE4GHP4S3GV4LETMZ!") == -1;
});

/* Every outcome leaves the buffer NUL-terminated: a caller that ignores the
   return value must not read poison, and must not think it has a keyprint. */
EXO_TEST(seedhub_kp_clears_output_on_failure, {
	return sh_parse_kp("adcs://hub.example.org:1511/?kp=SHA1/" SH_KP32) == -1
		&& sh_kp[0] == '\0';
});

/* --- the address as a whole ---------------------------------------------- */

/* Never invoked by the cases below -- every one of them fails while parsing the
   address, before anything is connected -- but a NULL callback would be a trap
   if that ever stopped being true. */
static int sh_kp_cb(struct ADC_client* client, enum ADC_client_callback_type type,
	struct ADC_client_callback_data* data)
{
	(void) client; (void) type; (void) data;
	return 1;
}

/*
 * An address whose keyprint cannot be honoured is refused outright rather than
 * connected to unverified: an operator who wrote a keyprint down expects it to
 * be checked. No socket is touched -- each of these fails in the parser.
 */
EXO_TEST(seedhub_kp_bad_address_refused, {
	struct ADC_client* client = ADC_client_create("seedtest", "", NULL);
	int ok;

	if (!client)
		return 0;
	ADC_client_set_callback(client, sh_kp_cb);

	ok = ADC_client_connect(client, "adcs://hub.example.org:1511/?kp=SHA1/" SH_KP32) == 0
		/* nothing to verify a keyprint against on an unencrypted connection */
		&& ADC_client_connect(client, "adc://hub.example.org:411/?kp=" SH_KP) == 0
		&& ADC_client_connect(client, "adcs://hub.example.org:1511/?kp=SHA256/TOOSHORT") == 0
		&& strcmp(ADC_client_get_keyprint(client), "") == 0;

	ADC_client_destroy(client);
	return ok;
});

/* A buffer too small to hold the value is a failure, never a truncation: a
   truncated keyprint would never match and would look like an attack. */
EXO_TEST(seedhub_kp_small_buffer, {
	char small[16];
	memset(small, 0x7f, sizeof(small));
	return ADC_client_parse_keyprint("adcs://hub.example.org:1511/?kp=" SH_KP, small, sizeof(small)) == -1
		&& small[0] == '\0'
		&& ADC_client_parse_keyprint("adcs://x:1511/?kp=" SH_KP, NULL, 0) == -1;
});

/* --- SU advertisement ----------------------------------------------------- */

/*
 * SU is a claim other clients act on, so the interesting cases are the ones
 * where it is absent or would be wrong. A seeder that does not advertise TCP4
 * is taken for passive and never dialled, which silently disables the whole
 * point of the cache; one that advertises ADC0 without a certificate wins the
 * transfer and then hangs the peer on a handshake nothing answers.
 */

EXO_TEST(seedhub_support_defaults_to_none, {
	struct ADC_client* client = ADC_client_create("test", "test", NULL);
	int ok;

	/* A client that does not listen must not claim it does; uhub-admin and
	   adcrush share this transport and never accept a connection. */
	ok = (client != NULL) && strcmp(ADC_client_get_support(client), "") == 0;

	ADC_client_destroy(client);
	return ok;
});

EXO_TEST(seedhub_support_round_trip, {
	struct ADC_client* client = ADC_client_create("test", "test", NULL);
	int ok;

	ok = ADC_client_set_support(client, "TCP4,ADCS") == 1
		&& strcmp(ADC_client_get_support(client), "TCP4,ADCS") == 0;

	/* Cleared again, because a seeder that loses its certificate on a reload
	   must be able to stop claiming ADCS. */
	ok = ok && ADC_client_set_support(client, NULL) == 1
		&& strcmp(ADC_client_get_support(client), "") == 0;

	ok = ok && ADC_client_set_support(client, "TCP6") == 1
		&& ADC_client_set_support(client, "") == 1
		&& strcmp(ADC_client_get_support(client), "") == 0;

	ADC_client_destroy(client);
	return ok;
});

/* Refused, not truncated: "TCP4,AD" is a different claim from "TCP4,ADCS". */
EXO_TEST(seedhub_support_refuses_an_oversized_list, {
	struct ADC_client* client = ADC_client_create("test", "test", NULL);
	char big[ADC_SUPPORT_MAX + 8];
	char max[ADC_SUPPORT_MAX];
	int ok;

	memset(big, 'A', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';

	memset(max, 'B', sizeof(max) - 1);
	max[sizeof(max) - 1] = '\0';

	ok = ADC_client_set_support(client, "TCP4") == 1
		&& ADC_client_set_support(client, big) == 0
		/* the refused value left the previous one alone */
		&& strcmp(ADC_client_get_support(client), "TCP4") == 0
		/* exactly ADC_SUPPORT_MAX - 1 characters still fits */
		&& ADC_client_set_support(client, max) == 1
		&& strcmp(ADC_client_get_support(client), max) == 0;

	ok = ok && ADC_client_set_support(NULL, "TCP4") == 0;

	ADC_client_destroy(client);
	return ok;
});

/* The INF actually carries it -- the field is what the hub reads, not the
   value stashed on the client. */
EXO_TEST(seedhub_support_reaches_the_inf, {
	struct ADC_client* client = ADC_client_create("seedbot", "seed cache", NULL);
	struct adc_message* info;
	char* su;
	int ok;

	ADC_client_set_support(client, "TCP4,ADCS");
	info = ADC_client_build_info(client);
	if (!info)
	{
		ADC_client_destroy(client);
		return 0;
	}

	su = adc_msg_get_named_argument(info, ADC_INF_FLAG_SUPPORT);
	ok = su && strcmp(su, "TCP4,ADCS") == 0;
	hub_free(su);
	adc_msg_free(info);

	/* ...and no SU at all when nothing is claimed, rather than an empty one. */
	ADC_client_set_support(client, NULL);
	info = ADC_client_build_info(client);
	ok = ok && info && !adc_msg_has_named_argument(info, ADC_INF_FLAG_SUPPORT);
	adc_msg_free(info);

	ADC_client_destroy(client);
	return ok;
});
