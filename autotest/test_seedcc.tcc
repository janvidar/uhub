#include "system.h"

#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "network/backend.h"
#include "network/connection.h"
#include "network/ipcalc.h"
#include "network/network.h"
#include "network/timeout.h"
#include "seeder/cache.h"
#include "seeder/cc.h"
#include "seeder/grant.h"
#include "util/memory.h"
#include "util/tth.h"

/*
 * The seeder's ADC client-to-client transfer module (seeder/cc.c) and the grant
 * table it authorises with (seeder/grant.c).
 *
 * Two halves. The first drives the pure parts -- the line framer, the command
 * parser, the range check, the status formatter and the grant table -- directly:
 * they all run on attacker-controlled bytes arriving on a port that is reachable
 * before anything has been authenticated, so they are tested at that level.
 *
 * The second half drives the genuine state machine over a real socket, in both
 * directions, and compares the bytes that come back with the bytes that went in.
 * That is where the bugs in this feature have been: not in what a line means,
 * but in who is supposed to speak first.
 */

/* Well formed TTHs: exactly 39 characters from the base32 alphabet. */
#define SCC_TTH  "OZ4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXAI"
#define SCC_TTH2 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
/* A CID has the same shape as a TTH. */
#define SCC_CID  "CIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

#define SCC_DIR  "test_seedcc.tmp"
#define SCC_SIZE 4096
#define SCC_TOKEN "TESTTOKEN123456"

/* Seconds to wait for the seeder before declaring a test failed. */
#define SCC_DEADLINE 30

static struct seed_cc_request scc_req;

static int scc_parse(const char* line)
{
	memset(&scc_req, 0, sizeof(scc_req));
	return seed_cc_parse(line, strlen(line), &scc_req);
}

static int scc_parse_n(const char* line, size_t len)
{
	memset(&scc_req, 0, sizeof(scc_req));
	return seed_cc_parse(line, len, &scc_req);
}

static enum seed_cc_type scc_type(const char* line)
{
	scc_parse(line);
	return scc_req.type;
}

/* --- named identifiers, for a download asked for by name ------------------ */

/*
 * A file list has no hash until it has been received, so it is asked for by
 * name. The parser therefore understands both forms and says which one it saw:
 * a TTH lands in .tth and a name lands in .name, never both.
 */

/* A CGET is a peer asking us to serve, and we serve by hash: a name there is
   not a request we can answer, and never becomes one. */
EXO_TEST(seedcc_parse_get_refuses_a_name, {
	return scc_type("CGET file files.xml.bz2 0 -1\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_parse_snd_named_identifier, {
	return scc_type("CSND file files.xml.bz2 0 4096\n") == SEED_CC_SND
		&& strcmp(scc_req.name, "files.xml.bz2") == 0
		&& scc_req.tth[0] == '\0';
});

EXO_TEST(seedcc_parse_get_tth_leaves_name_empty, {
	return scc_type("CGET file TTH/" SCC_TTH " 0 -1\n") == SEED_CC_GET_FILE
		&& strcmp(scc_req.tth, SCC_TTH) == 0
		&& scc_req.name[0] == '\0';
});

/* A name is a name, not a path: a peer must not be able to spell a directory,
   let alone one above the share. */
EXO_TEST(seedcc_parse_named_rejects_path, {
	return scc_type("CSND file dir/files.xml.bz2 0 10\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_parse_named_rejects_traversal, {
	return scc_type("CSND file ../../etc/passwd 0 10\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_parse_named_rejects_absolute, {
	return scc_type("CSND file /etc/passwd 0 10\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_parse_named_rejects_oversized, {
	char line[256];
	char name[SEED_GRANT_FILENAME_MAX + 8];
	memset(name, 'a', sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	snprintf(line, sizeof(line), "CSND file %s 0 10\n", name);
	return scc_type(line) == SEED_CC_UNSUPPORTED;
});

/* A malformed TTH stays malformed: "TTH/" is a prefix the parser commits to,
   so a bad hash after it is not silently reinterpreted as a file name. */
EXO_TEST(seedcc_parse_named_does_not_rescue_a_bad_tth, {
	return scc_type("CSND file TTH/not-a-hash 0 10\n") == SEED_CC_UNSUPPORTED;
});

/* CGFI asks about content, which is addressed by hash and nothing else. */
EXO_TEST(seedcc_parse_gfi_refuses_a_name, {
	return scc_type("CGFI file files.xml.bz2\n") == SEED_CC_UNSUPPORTED;
});

/* --- grants for a named download ----------------------------------------- */

EXO_TEST(seedcc_grant_filelist, {
	struct seed_grants* grants = seed_grants_create();
	struct seed_grant grant;
	int ok = seed_grant_issue_filelist(grants, SCC_TOKEN, SCC_CID, "files.xml.bz2", 1000)
		&& seed_grant_is_download(grants, SCC_TOKEN, 1000, &grant)
		&& strcmp(grant.filename, "files.xml.bz2") == 0
		&& grant.tth[0] == '\0';
	seed_grants_destroy(grants);
	return ok;
});

EXO_TEST(seedcc_grant_filelist_refuses_a_path, {
	struct seed_grants* grants = seed_grants_create();
	int ok = !seed_grant_issue_filelist(grants, SCC_TOKEN, SCC_CID, "../etc/passwd", 1000);
	seed_grants_destroy(grants);
	return ok;
});

EXO_TEST(seedcc_grant_filelist_refuses_a_space, {
	struct seed_grants* grants = seed_grants_create();
	int ok = !seed_grant_issue_filelist(grants, SCC_TOKEN, SCC_CID, "two words", 1000);
	seed_grants_destroy(grants);
	return ok;
});

EXO_TEST(seedcc_grant_filelist_refuses_empty, {
	struct seed_grants* grants = seed_grants_create();
	int ok = !seed_grant_issue_filelist(grants, SCC_TOKEN, SCC_CID, "", 1000)
	      && !seed_grant_issue_filelist(grants, SCC_TOKEN, SCC_CID, NULL, 1000);
	seed_grants_destroy(grants);
	return ok;
});

/* An ordinary download grant still has to name a hash. */
EXO_TEST(seedcc_grant_download_still_requires_a_tth, {
	struct seed_grants* grants = seed_grants_create();
	int ok = !seed_grant_issue_download(grants, SCC_TOKEN, SCC_CID, NULL, 0, NULL, 1000)
	      && !seed_grant_issue_download(grants, SCC_TOKEN, SCC_CID, "nope", 0, NULL, 1000);
	seed_grants_destroy(grants);
	return ok;
});

/* --- the constants the protocol depends on ------------------------------- */

EXO_TEST(seedcc_tth_constants_are_well_formed, {
	return strlen(SCC_TTH) == SEED_TTH_STR_LEN &&
	       strlen(SCC_TTH2) == SEED_TTH_STR_LEN &&
	       strlen(SCC_CID) == SEED_CID_LEN;
});

/* --- CSUP ---------------------------------------------------------------- */

EXO_TEST(seedcc_sup_parses, {
	return scc_parse("CSUP ADBASE ADTIGR\n") == 1 && scc_req.type == SEED_CC_SUP;
});

EXO_TEST(seedcc_sup_reports_base_and_tigr, {
	scc_parse("CSUP ADBASE ADTIGR\n");
	return scc_req.have_base == 1 && scc_req.have_tigr == 1;
});

/* The order of the feature tokens is not significant. */
EXO_TEST(seedcc_sup_order_does_not_matter, {
	scc_parse("CSUP ADTIGR ADBASE\n");
	return scc_req.have_base == 1 && scc_req.have_tigr == 1;
});

/* Unknown features are ignored, not refused. */
EXO_TEST(seedcc_sup_extra_features_ignored, {
	scc_parse("CSUP ADBASE ADTIGR ADBZIP ADGFI\n");
	return scc_req.have_base == 1 && scc_req.have_tigr == 1;
});

/* The obsolete BAS0 spelling still means "base". */
EXO_TEST(seedcc_sup_bas0_is_base, {
	scc_parse("CSUP ADBAS0 ADTIGR\n");
	return scc_req.have_base == 1;
});

EXO_TEST(seedcc_sup_without_tigr, {
	scc_parse("CSUP ADBASE\n");
	return scc_req.have_base == 1 && scc_req.have_tigr == 0;
});

EXO_TEST(seedcc_sup_without_base, {
	scc_parse("CSUP ADTIGR\n");
	return scc_req.have_base == 0 && scc_req.have_tigr == 1;
});

/* Feature tokens are case sensitive, as ADC requires. */
EXO_TEST(seedcc_sup_lowercase_feature_ignored, {
	scc_parse("CSUP adbase adtigr\n");
	return scc_req.have_base == 0 && scc_req.have_tigr == 0;
});

/* An RM (remove) token is not an AD (add) token. */
EXO_TEST(seedcc_sup_rm_is_not_ad, {
	scc_parse("CSUP RMBASE RMTIGR\n");
	return scc_req.have_base == 0 && scc_req.have_tigr == 0;
});

/* --- CINF ---------------------------------------------------------------- */

EXO_TEST(seedcc_inf_parses, {
	return scc_parse("CINF ID" SCC_CID " TOtoken123\n") == 1 && scc_req.type == SEED_CC_INF;
});

EXO_TEST(seedcc_inf_extracts_cid, {
	scc_parse("CINF ID" SCC_CID " TOtoken123\n");
	return strcmp(scc_req.cid, SCC_CID) == 0;
});

EXO_TEST(seedcc_inf_extracts_token, {
	scc_parse("CINF ID" SCC_CID " TOtoken123\n");
	return strcmp(scc_req.token, "token123") == 0;
});

/* Named arguments are position independent. */
EXO_TEST(seedcc_inf_token_before_cid, {
	scc_parse("CINF TOtoken123 ID" SCC_CID "\n");
	return strcmp(scc_req.cid, SCC_CID) == 0 && strcmp(scc_req.token, "token123") == 0;
});

EXO_TEST(seedcc_inf_without_token, {
	scc_parse("CINF ID" SCC_CID "\n");
	return scc_req.type == SEED_CC_INF && scc_req.token[0] == '\0';
});

EXO_TEST(seedcc_inf_without_cid, {
	scc_parse("CINF TOtoken123\n");
	return scc_req.type == SEED_CC_INF && scc_req.cid[0] == '\0';
});

/* A CID that is not 39 base32 characters could never match a grant, so it is
   dropped rather than carried around as an unvalidated string. */
EXO_TEST(seedcc_inf_short_cid_rejected, {
	scc_parse("CINF IDABC TOtoken123\n");
	return scc_req.cid[0] == '\0';
});

EXO_TEST(seedcc_inf_lowercase_cid_rejected, {
	scc_parse("CINF IDcidaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa TOtok\n");
	return scc_req.cid[0] == '\0';
});

EXO_TEST(seedcc_inf_long_cid_rejected, {
	scc_parse("CINF ID" SCC_CID "A TOtok\n");
	return scc_req.cid[0] == '\0';
});

/* A token longer than the seeder will ever have issued is not remembered. */
EXO_TEST(seedcc_inf_oversized_token_rejected, {
	char line[256];
	char token[SEED_TOKEN_MAX + 8];
	memset(token, 'x', SEED_TOKEN_MAX + 1);
	token[SEED_TOKEN_MAX + 1] = '\0';
	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, token);
	scc_parse(line);
	return scc_req.token[0] == '\0';
});

EXO_TEST(seedcc_inf_max_length_token_kept, {
	char line[256];
	char token[SEED_TOKEN_MAX + 8];
	memset(token, 'x', SEED_TOKEN_MAX);
	token[SEED_TOKEN_MAX] = '\0';
	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, token);
	scc_parse(line);
	return strlen(scc_req.token) == SEED_TOKEN_MAX;
});

/* --- CGET file ----------------------------------------------------------- */

EXO_TEST(seedcc_get_file_parses, {
	return scc_parse("CGET file TTH/" SCC_TTH " 0 -1\n") == 1 && scc_req.type == SEED_CC_GET_FILE;
});

EXO_TEST(seedcc_get_file_extracts_tth, {
	scc_parse("CGET file TTH/" SCC_TTH " 0 -1\n");
	return strcmp(scc_req.tth, SCC_TTH) == 0;
});

EXO_TEST(seedcc_get_file_to_eof, {
	scc_parse("CGET file TTH/" SCC_TTH " 0 -1\n");
	return scc_req.start == 0 && scc_req.bytes == SEED_CC_TO_EOF;
});

EXO_TEST(seedcc_get_file_explicit_range, {
	scc_parse("CGET file TTH/" SCC_TTH " 100 200\n");
	return scc_req.start == 100 && scc_req.bytes == 200;
});

EXO_TEST(seedcc_get_file_zero_length, {
	scc_parse("CGET file TTH/" SCC_TTH " 0 0\n");
	return scc_req.type == SEED_CC_GET_FILE && scc_req.bytes == 0;
});

/* Trailing flags (ZL1 and friends) do not disturb the fields we read. */
EXO_TEST(seedcc_get_file_trailing_flag, {
	scc_parse("CGET file TTH/" SCC_TTH " 0 -1 ZL1\n");
	return scc_req.type == SEED_CC_GET_FILE && scc_req.bytes == SEED_CC_TO_EOF;
});

/* A different TTH comes back verbatim, so the extraction is not a fluke. */
EXO_TEST(seedcc_get_file_second_tth, {
	scc_parse("CGET file TTH/" SCC_TTH2 " 0 -1\n");
	return strcmp(scc_req.tth, SCC_TTH2) == 0;
});

/* --- malformed identifiers and ranges ------------------------------------ */

/* A command the seeder cannot serve is reported as unsupported (-> CSTA 140)
   and never as a parse failure, so the peer gets an answer rather than a
   hang-up. */
EXO_TEST(seedcc_get_no_namespace, {
	return scc_type("CGET file " SCC_TTH " 0 -1\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_get_wrong_namespace, {
	return scc_type("CGET file MD5/" SCC_TTH " 0 -1\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_get_short_tth, {
	return scc_type("CGET file TTH/OZ4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXA 0 -1\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_get_long_tth, {
	return scc_type("CGET file TTH/" SCC_TTH "A 0 -1\n") == SEED_CC_UNSUPPORTED;
});

/* '0', '1', '8' and '9' are outside the base32 alphabet. */
EXO_TEST(seedcc_get_tth_digit_zero, {
	return scc_type("CGET file TTH/0Z4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXAI 0 -1\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_get_tth_digit_nine, {
	return scc_type("CGET file TTH/OZ4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXA9 0 -1\n") == SEED_CC_UNSUPPORTED;
});

/* Lowercase is not the same TTH, and must not be folded into one. */
EXO_TEST(seedcc_get_lowercase_tth, {
	return scc_type("CGET file TTH/oz4v2gdgzlgxqkawxqbdit4km7hrfcwhmlpexai 0 -1\n") == SEED_CC_UNSUPPORTED;
});

/* A path traversal cannot survive the alphabet check -- which is what keeps the
   TTH safe to use as a file name component. */
EXO_TEST(seedcc_get_traversal, {
	return scc_type("CGET file TTH/../../../../../../../../etc/passwd 0 -1\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_get_missing_range, {
	return scc_type("CGET file TTH/" SCC_TTH "\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_get_missing_length, {
	return scc_type("CGET file TTH/" SCC_TTH " 0\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_get_non_numeric_start, {
	return scc_type("CGET file TTH/" SCC_TTH " abc -1\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_get_negative_start, {
	return scc_type("CGET file TTH/" SCC_TTH " -5 -1\n") == SEED_CC_UNSUPPORTED;
});

/* "-1" is the only negative length with a meaning. */
EXO_TEST(seedcc_get_negative_length, {
	return scc_type("CGET file TTH/" SCC_TTH " 0 -2\n") == SEED_CC_UNSUPPORTED;
});

/* An offset that cannot fit in 64 bits is refused rather than wrapped. */
EXO_TEST(seedcc_get_overflowing_start, {
	return scc_type("CGET file TTH/" SCC_TTH " 99999999999999999999999999 -1\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_get_overflowing_length, {
	return scc_type("CGET file TTH/" SCC_TTH " 0 99999999999999999999999999\n") == SEED_CC_UNSUPPORTED;
});

/* --- CGET tthl ----------------------------------------------------------- */

EXO_TEST(seedcc_get_tthl_recognised, {
	return scc_type("CGET tthl TTH/" SCC_TTH " 0 -1\n") == SEED_CC_GET_TTHL;
});

/*
 * Leaf hashes are deliberately not served, and the refusal must be recoverable
 * (1xx) and never fatal (2xx): a client that reads a fatal status aborts the
 * download, where a recoverable one makes it fall back to a plain file GET.
 */
EXO_TEST(seedcc_tthl_status_is_recoverable, {
	char buf[64];
	seed_cc_format_status(buf, sizeof(buf), SEED_CC_STATUS_NO_TTHL, "no");
	return strncmp(buf, "CSTA 1", 6) == 0;
});

EXO_TEST(seedcc_tthl_status_is_not_fatal, {
	char buf[64];
	seed_cc_format_status(buf, sizeof(buf), SEED_CC_STATUS_NO_TTHL, "no");
	return strncmp(buf, "CSTA 2", 6) != 0;
});

EXO_TEST(seedcc_tthl_status_code, {
	char buf[64];
	seed_cc_format_status(buf, sizeof(buf), SEED_CC_STATUS_NO_TTHL, "no");
	return strcmp(buf, "CSTA 151 no\n") == 0;
});

/* Every status the handler can emit is recoverable, for the same reason. */
EXO_TEST(seedcc_all_statuses_recoverable, {
	int codes[6];
	char buf[64];
	int i;
	codes[0] = SEED_CC_STATUS_BAD_COMMAND;
	codes[1] = SEED_CC_STATUS_UNAUTHORIZED;
	codes[2] = SEED_CC_STATUS_NO_FILE;
	codes[3] = SEED_CC_STATUS_NO_TTHL;
	codes[4] = SEED_CC_STATUS_BAD_RANGE;
	codes[5] = SEED_CC_STATUS_SLOTS_FULL;
	for (i = 0; i < 6; i++)
	{
		if (!seed_cc_format_status(buf, sizeof(buf), codes[i], "x"))
			return 0;
		if (strncmp(buf, "CSTA 1", 6) != 0)
			return 0;
	}
	return 1;
});

EXO_TEST(seedcc_status_terminated, {
	char buf[64];
	size_t n = seed_cc_format_status(buf, sizeof(buf), SEED_CC_STATUS_BAD_COMMAND, "x");
	return n > 0 && buf[n - 1] == '\n' && buf[n] == '\0';
});

/* A buffer too small produces nothing at all, never a half line. */
EXO_TEST(seedcc_status_tiny_buffer, {
	char buf[8];
	return seed_cc_format_status(buf, sizeof(buf), SEED_CC_STATUS_NO_FILE, "much too long") == 0 &&
	       buf[0] == '\0';
});

/* --- other commands ------------------------------------------------------- */

EXO_TEST(seedcc_get_list_unsupported, {
	return scc_type("CGET list / 0 -1\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_gfi_parses, {
	return scc_type("CGFI file TTH/" SCC_TTH "\n") == SEED_CC_GFI;
});

EXO_TEST(seedcc_gfi_extracts_tth, {
	scc_parse("CGFI file TTH/" SCC_TTH "\n");
	return strcmp(scc_req.tth, SCC_TTH) == 0;
});

EXO_TEST(seedcc_gfi_bad_tth, {
	return scc_type("CGFI file TTH/nope\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_gfi_list_unsupported, {
	return scc_type("CGFI list /\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_snd_parses, {
	return scc_type("CSND file TTH/" SCC_TTH " 0 4096\n") == SEED_CC_SND;
});

EXO_TEST(seedcc_snd_extracts_length, {
	scc_parse("CSND file TTH/" SCC_TTH " 0 4096\n");
	return scc_req.start == 0 && scc_req.bytes == 4096;
});

/* The seeder never asks for leaf hashes, so a CSND offering them is not
   expected. */
EXO_TEST(seedcc_snd_tthl_unsupported, {
	return scc_type("CSND tthl TTH/" SCC_TTH " 0 24\n") == SEED_CC_UNSUPPORTED;
});

EXO_TEST(seedcc_sta_parses, {
	return scc_type("CSTA 151 File\\snot\\savailable\n") == SEED_CC_STA;
});

EXO_TEST(seedcc_sta_extracts_code, {
	scc_parse("CSTA 151 File\\snot\\savailable\n");
	return scc_req.status == 151;
});

EXO_TEST(seedcc_unknown_command_is_unsupported, {
	return scc_type("CZZZ whatever\n") == SEED_CC_UNSUPPORTED;
});

/* --- context: only 'C' is accepted here ---------------------------------- */

/* Every hub context is rejected outright: a hub-side command arriving on a
   client connection is not something to answer, it is something to hang up on. */
EXO_TEST(seedcc_hub_context_hsup_rejected, {
	return scc_parse("HSUP ADBASE ADTIGR\n") == 0;
});

EXO_TEST(seedcc_hub_context_binf_rejected, {
	return scc_parse("BINF AAAB NInick\n") == 0;
});

EXO_TEST(seedcc_hub_context_isup_rejected, {
	return scc_parse("ISUP ADBASE\n") == 0;
});

EXO_TEST(seedcc_hub_context_dctm_rejected, {
	return scc_parse("DCTM AAAB AAAC ADC0 1511 tok\n") == 0;
});

EXO_TEST(seedcc_hub_context_leaves_type_invalid, {
	scc_parse("HSUP ADBASE ADTIGR\n");
	return scc_req.type == SEED_CC_INVALID;
});

/* --- malformed and hostile input ----------------------------------------- */

EXO_TEST(seedcc_null_pointer, {
	return seed_cc_parse(NULL, 10, &scc_req) == 0;
});

EXO_TEST(seedcc_zero_length, {
	return scc_parse_n("CSUP ADBASE\n", 0) == 0;
});

EXO_TEST(seedcc_too_short, {
	return scc_parse("CSU") == 0;
});

/* A command with no arguments at all is still a valid line. */
EXO_TEST(seedcc_bare_command, {
	return scc_parse("CSUP\n") == 1;
});

/* Not required to be terminated: the framer strips the terminator, and a line
   handed over without one still parses. */
EXO_TEST(seedcc_unterminated_line_parses, {
	return scc_parse("CSUP ADBASE ADTIGR") == 1 && scc_req.have_base == 1;
});

/* An embedded NUL is never legitimate, and never gets to confuse the parser. */
EXO_TEST(seedcc_embedded_nul_rejected, {
	char line[64];
	size_t n = strlen("CGET file TTH/" SCC_TTH " 0 -1\n");
	memcpy(line, "CGET file TTH/" SCC_TTH " 0 -1\n", n);
	line[6] = '\0';
	return scc_parse_n(line, n) == 0;
});

EXO_TEST(seedcc_trailing_nul_rejected, {
	char line[64];
	size_t n = strlen("CSUP ADBASE ADTIGR\n");
	memcpy(line, "CSUP ADBASE ADTIGR\n", n + 1);
	return scc_parse_n(line, n + 1) == 0;
});

/* Invalid UTF-8 and bad escapes are rejected by the shared ADC parser. */
EXO_TEST(seedcc_bad_escape_rejected, {
	return scc_parse("CSUP ADBASE\\q\n") == 0;
});

EXO_TEST(seedcc_control_character_rejected, {
	return scc_parse("CSUP ADBASE\x01\n") == 0;
});

/* A line longer than an ADC command is refused outright, never truncated into
   something that happens to parse. */
EXO_TEST(seedcc_over_long_line_rejected, {
	size_t n = SEED_CC_LINE_MAX + 1;
	char* line = (char*) hub_malloc(n + 1);
	int ok;
	if (!line) return 0;
	memcpy(line, "CGET file TTH/" SCC_TTH " 0 ", 14 + SEED_TTH_STR_LEN + 3);
	memset(line + 14 + SEED_TTH_STR_LEN + 3, '1', n - (14 + SEED_TTH_STR_LEN + 3) - 1);
	line[n - 1] = '\n';
	line[n] = '\0';
	ok = (scc_parse_n(line, n) == 0);
	hub_free(line);
	return ok;
});

EXO_TEST(seedcc_line_at_cap_accepted, {
	size_t n = SEED_CC_LINE_MAX;
	char* line = (char*) hub_malloc(n + 1);
	int ok;
	if (!line) return 0;
	memcpy(line, "CSUP ADBASE ADTIGR ADX", 22);
	memset(line + 22, 'X', n - 22 - 1);
	line[n - 1] = '\n';
	line[n] = '\0';
	ok = (scc_parse_n(line, n) == 1 && scc_req.have_base == 1);
	hub_free(line);
	return ok;
});

/* --- line framing --------------------------------------------------------- */

static size_t scc_used;

static int scc_take(const char* buf, size_t len)
{
	scc_used = 12345;
	return seed_cc_take_line(buf, len, &scc_used);
}

EXO_TEST(seedcc_frame_complete_line, {
	return scc_take("CSUP ADBASE\n", 12) == 1 && scc_used == 12;
});

EXO_TEST(seedcc_frame_stops_at_first_line, {
	return scc_take("CSUP\nCINF\n", 10) == 1 && scc_used == 5;
});

EXO_TEST(seedcc_frame_incomplete_line, {
	return scc_take("CSUP ADBASE", 11) == 0 && scc_used == 0;
});

EXO_TEST(seedcc_frame_empty_buffer, {
	return scc_take("", 0) == 0;
});

/* An empty line is a line: the framer does not judge the contents. */
EXO_TEST(seedcc_frame_bare_newline, {
	return scc_take("\n", 1) == 1 && scc_used == 1;
});

EXO_TEST(seedcc_frame_null_buffer, {
	return seed_cc_take_line(NULL, 10, &scc_used) == -1;
});

/* A NUL before the terminator kills the connection rather than being framed. */
EXO_TEST(seedcc_frame_embedded_nul, {
	return scc_take("CSUP\0BASE\n", 10) == -1;
});

/* ...and so does one in a still incomplete line, so it is caught early. */
EXO_TEST(seedcc_frame_embedded_nul_incomplete, {
	return scc_take("CSUP\0BASE", 9) == -1;
});

/* Once a whole command's worth of bytes has arrived with no terminator, no
   further byte can make it a valid line. */
EXO_TEST(seedcc_frame_no_terminator_at_cap, {
	char* buf = (char*) hub_malloc(SEED_CC_LINE_MAX);
	int ok;
	if (!buf) return 0;
	memset(buf, 'x', SEED_CC_LINE_MAX);
	ok = (scc_take(buf, SEED_CC_LINE_MAX) == -1);
	hub_free(buf);
	return ok;
});

EXO_TEST(seedcc_frame_terminator_at_cap_accepted, {
	char* buf = (char*) hub_malloc(SEED_CC_LINE_MAX);
	int ok;
	if (!buf) return 0;
	memset(buf, 'x', SEED_CC_LINE_MAX);
	buf[SEED_CC_LINE_MAX - 1] = '\n';
	ok = (scc_take(buf, SEED_CC_LINE_MAX) == 1 && scc_used == SEED_CC_LINE_MAX);
	hub_free(buf);
	return ok;
});

EXO_TEST(seedcc_frame_terminator_past_cap_rejected, {
	size_t n = SEED_CC_LINE_MAX + 1;
	char* buf = (char*) hub_malloc(n);
	int ok;
	if (!buf) return 0;
	memset(buf, 'x', n);
	buf[n - 1] = '\n';
	ok = (scc_take(buf, n) == -1);
	hub_free(buf);
	return ok;
});

/* --- ranges --------------------------------------------------------------- */

static uint64_t scc_len;

static int scc_range(uint64_t size, uint64_t start, int64_t bytes)
{
	scc_len = 12345;
	return seed_cc_range_ok(size, start, bytes, &scc_len);
}

EXO_TEST(seedcc_range_whole_file, {
	return scc_range(1000, 0, SEED_CC_TO_EOF) == 1 && scc_len == 1000;
});

EXO_TEST(seedcc_range_from_offset_to_eof, {
	return scc_range(1000, 100, SEED_CC_TO_EOF) == 1 && scc_len == 900;
});

EXO_TEST(seedcc_range_exact_length, {
	return scc_range(1000, 0, 1000) == 1 && scc_len == 1000;
});

EXO_TEST(seedcc_range_partial, {
	return scc_range(1000, 100, 200) == 1 && scc_len == 200;
});

EXO_TEST(seedcc_range_last_byte, {
	return scc_range(1000, 999, 1) == 1 && scc_len == 1;
});

/* Asking for nothing at the very end of the file is satisfiable, if pointless. */
EXO_TEST(seedcc_range_at_eof_is_empty, {
	return scc_range(1000, 1000, SEED_CC_TO_EOF) == 1 && scc_len == 0;
});

EXO_TEST(seedcc_range_empty_file, {
	return scc_range(0, 0, SEED_CC_TO_EOF) == 1 && scc_len == 0;
});

/* Beyond the end of the file is an error, never a short send: a truncated body
   is indistinguishable from a failed transfer to the peer. */
EXO_TEST(seedcc_range_start_past_eof, {
	return scc_range(1000, 1001, SEED_CC_TO_EOF) == 0 && scc_len == 0;
});

EXO_TEST(seedcc_range_length_past_eof, {
	return scc_range(1000, 0, 1001) == 0;
});

EXO_TEST(seedcc_range_offset_plus_length_past_eof, {
	return scc_range(1000, 500, 501) == 0;
});

EXO_TEST(seedcc_range_start_past_eof_of_empty_file, {
	return scc_range(0, 1, SEED_CC_TO_EOF) == 0;
});

EXO_TEST(seedcc_range_negative_length, {
	return scc_range(1000, 0, -2) == 0;
});

EXO_TEST(seedcc_range_huge_length, {
	return scc_range(1000, 0, INT64_MAX) == 0;
});

EXO_TEST(seedcc_range_null_out_param, {
	return seed_cc_range_ok(1000, 0, SEED_CC_TO_EOF, NULL) == 1;
});

/* --- what the seeder is willing to dial ----------------------------------- */

EXO_TEST(seedcc_protocol_plain_accepted, {
	int tls = 1;
	return seed_cc_protocol_ok("ADC/1.0", &tls) == 1 && tls == 0;
});

EXO_TEST(seedcc_protocol_tls_accepted, {
	int tls = 0;
	return seed_cc_protocol_ok("ADCS/0.10", &tls) == 1 && tls == 1;
});

EXO_TEST(seedcc_protocol_null_use_tls_is_allowed, {
	return seed_cc_protocol_ok("ADC/1.0", NULL) == 1;
});

EXO_TEST(seedcc_protocol_rejects_sup_feature_token, {
	/* "ADC0" is the SUP feature meaning "understands encrypted client
	   connections". It is not a protocol string and must never be taken as one
	   -- reading it as such silently dropped every real RCM. */
	return seed_cc_protocol_ok("ADC0", NULL) == 0;
});

EXO_TEST(seedcc_protocol_rejects_others, {
	if (seed_cc_protocol_ok("ADC/1.1", NULL)) return 0;
	if (seed_cc_protocol_ok("adc/1.0", NULL)) return 0;
	if (seed_cc_protocol_ok("", NULL)) return 0;
	if (seed_cc_protocol_ok(NULL, NULL)) return 0;
	return seed_cc_protocol_ok("NMDC", NULL) == 0;
});

/* Both ADCS revisions are the same thing on the wire: a TLS connection. Only
   the spelling differs, by which revision the peer knows about. */
EXO_TEST(seedcc_protocol_accepts_both_adcs_revisions, {
	int tls_a = 0;
	int tls_b = 0;
	return seed_cc_protocol_ok("ADCS/0.10", &tls_a) == 1 && tls_a == 1
		&& seed_cc_protocol_ok("ADCS/1.0", &tls_b) == 1 && tls_b == 1;
});

/* --- picking a protocol from the peer's SU -------------------------------- */

EXO_TEST(seedcc_support_has_whole_tokens, {
	if (!seed_cc_support_has("TCP4,ADCS", "ADCS")) return 0;
	if (!seed_cc_support_has("ADCS", "ADCS")) return 0;
	if (!seed_cc_support_has("ADCS,TCP4", "ADCS")) return 0;
	if (!seed_cc_support_has("TCP4,ADCS,UDP4", "ADCS")) return 0;
	return 1;
});

/* A token is four characters and comma delimited; it must not match inside a
   longer name, or a client claiming "ADCSX" would be read as claiming ADCS. */
EXO_TEST(seedcc_support_has_rejects_partial_matches, {
	if (seed_cc_support_has("ADCSX", "ADCS")) return 0;
	if (seed_cc_support_has("XADCS", "ADCS")) return 0;
	if (seed_cc_support_has("TCP4,ADCSX", "ADCS")) return 0;
	if (seed_cc_support_has("TCP4", "ADCS")) return 0;
	if (seed_cc_support_has("", "ADCS")) return 0;
	return seed_cc_support_has(NULL, "ADCS") == 0;
});

/* Only the NULL-ness of ssl_ctx is read, so a non-NULL sentinel stands in for
   a context the tests have no way to build. */
static int scc_tls_sentinel;

static struct seed_cc_policy scc_tls_policy(void)
{
	struct seed_cc_policy policy;
	memset(&policy, 0, sizeof(policy));
	policy.ssl_ctx = (struct ssl_context_handle*) (void*) &scc_tls_sentinel;
	return policy;
}

EXO_TEST(seedcc_protocol_for_peer_prefers_the_current_revision, {
	struct seed_cc_policy policy = scc_tls_policy();
	return strcmp(seed_cc_protocol_for_peer(&policy, "TCP4,ADCS", NULL), "ADCS/1.0") == 0;
});

/* A peer that only knows the pre-1.0 spelling is answered in its own terms: a
   revision it has never heard of is one it will not connect with. */
EXO_TEST(seedcc_protocol_for_peer_falls_back_to_the_old_revision, {
	struct seed_cc_policy policy = scc_tls_policy();
	return strcmp(seed_cc_protocol_for_peer(&policy, "TCP4,ADC0", NULL), "ADCS/0.10") == 0;
});

EXO_TEST(seedcc_protocol_for_peer_prefers_adcs_when_both_offered, {
	struct seed_cc_policy policy = scc_tls_policy();
	return strcmp(seed_cc_protocol_for_peer(&policy, "TCP4,ADCS,ADC0", NULL), "ADCS/1.0") == 0;
});

/* Neither token means the peer has not said it can do an encrypted transfer,
   and guessing costs the transfer when the guess is wrong. */
EXO_TEST(seedcc_protocol_for_peer_plain_without_a_claim, {
	struct seed_cc_policy policy = scc_tls_policy();
	if (strcmp(seed_cc_protocol_for_peer(&policy, "TCP4", NULL), "ADC/1.0") != 0) return 0;
	if (strcmp(seed_cc_protocol_for_peer(&policy, "", NULL), "ADC/1.0") != 0) return 0;
	return strcmp(seed_cc_protocol_for_peer(&policy, NULL, NULL), "ADC/1.0") == 0;
});

/*
 * A peer that claims ADCS or ADC0 gets TLS even when its own CTM or RCM asked
 * for plain ADC. Clients advertising either token expect every connection with
 * them to be encrypted -- QuickDC refuses the plaintext one it literally asked
 * for -- so the claim outranks the request.
 */
EXO_TEST(seedcc_protocol_for_peer_upgrades_a_plain_request, {
	struct seed_cc_policy policy = scc_tls_policy();
	if (strcmp(seed_cc_protocol_for_peer(&policy, "TCP4,ADCS", "ADC/1.0"), "ADCS/1.0") != 0) return 0;
	return strcmp(seed_cc_protocol_for_peer(&policy, "TCP4,ADC0", "ADC/1.0"), "ADCS/0.10") == 0;
});

/* The request still chooses the revision: a peer naming one has said which it
   speaks, and both are the same thing on the wire. */
EXO_TEST(seedcc_protocol_for_peer_keeps_the_requested_revision, {
	struct seed_cc_policy policy = scc_tls_policy();
	/* Claims the current token, asked for the old revision -- it gets the old. */
	if (strcmp(seed_cc_protocol_for_peer(&policy, "TCP4,ADCS", "ADCS/0.10"), "ADCS/0.10") != 0) return 0;
	/* ...and the reverse. */
	if (strcmp(seed_cc_protocol_for_peer(&policy, "TCP4,ADC0", "ADCS/1.0"), "ADCS/1.0") != 0) return 0;
	/* A request for TLS is honoured even from a peer that advertised no token,
	   since asking for it is itself a statement that it speaks it. */
	return strcmp(seed_cc_protocol_for_peer(&policy, "TCP4", "ADCS/1.0"), "ADCS/1.0") == 0;
});

/* No certificate here means no handshake to answer, whatever the peer claims. */
EXO_TEST(seedcc_protocol_for_peer_plain_without_a_certificate, {
	struct seed_cc_policy policy;
	memset(&policy, 0, sizeof(policy));
	if (strcmp(seed_cc_protocol_for_peer(&policy, "TCP4,ADCS", NULL), "ADC/1.0") != 0) return 0;
	/* Not even an explicit request for TLS can conjure a certificate. */
	if (strcmp(seed_cc_protocol_for_peer(&policy, "TCP4,ADCS", "ADCS/1.0"), "ADC/1.0") != 0) return 0;
	return strcmp(seed_cc_protocol_for_peer(NULL, "TCP4,ADCS", NULL), "ADC/1.0") == 0;
});

EXO_TEST(seedcc_port_rejects_privileged, {
	if (seed_cc_port_ok(0)) return 0;
	if (seed_cc_port_ok(22)) return 0;
	if (seed_cc_port_ok(80)) return 0;
	if (seed_cc_port_ok(443)) return 0;
	return seed_cc_port_ok(1023) == 0;
});

EXO_TEST(seedcc_port_accepts_unprivileged, {
	return seed_cc_port_ok(1024) && seed_cc_port_ok(41234) && seed_cc_port_ok(65535);
});

EXO_TEST(seedcc_may_dial_rejects_null, {
	return seed_cc_may_dial(NULL, NULL) == 0;
});

/* --- telling ADCS from plain ADC on the same port ------------------------- */

/*
 * seed_cc_probe_classify() is what makes one port serve both, so it is driven
 * here as the pure function it is: the handshake itself is the TLS layer's
 * business and is exercised end to end by test/seeder/e2e.sh instead.
 *
 * A genuine ClientHello prefix. Record header: content type 22 (handshake),
 * version 3.1, length; then handshake type 1 (client_hello), a 3 byte length,
 * and the client version 3.3 echoed at offset 9.
 */
static const char scc_client_hello[] =
	"\x16\x03\x01\x00\x9c"          /* record: handshake, TLS 1.0 framing, 156 bytes */
	"\x01\x00\x00\x98"              /* handshake: client_hello, 152 bytes */
	"\x03\x03"                      /* client version TLS 1.2 */
	"\x00\x01\x02\x03";             /* the first of the 32 random bytes */

EXO_TEST(seedcc_probe_detects_a_client_hello, {
	return seed_cc_probe_classify(scc_client_hello, sizeof(scc_client_hello) - 1) == SEED_CC_PROBE_TLS;
});

/* Exactly the 11 bytes the test needs, and no more. */
EXO_TEST(seedcc_probe_detects_a_client_hello_at_11_bytes, {
	return seed_cc_probe_classify(scc_client_hello, 11) == SEED_CC_PROBE_TLS;
});

/* An older client that frames its record as TLS 1.0 is still a ClientHello. */
EXO_TEST(seedcc_probe_detects_a_tls10_client_hello, {
	const char hello[] = "\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x01";
	return seed_cc_probe_classify(hello, sizeof(hello) - 1) == SEED_CC_PROBE_TLS;
});

/* The plain case: the first line of an ordinary client connection. */
EXO_TEST(seedcc_probe_detects_plain_adc, {
	const char* line = "CSUP ADBASE ADTIGR\n";
	return seed_cc_probe_classify(line, strlen(line)) == SEED_CC_PROBE_PLAIN;
});

/*
 * One byte is enough to rule TLS out, and it has to be: a peer whose whole
 * first line is shorter than the TLS test needs must not be left waiting for
 * bytes it is never going to send.
 */
EXO_TEST(seedcc_probe_decides_plain_on_one_byte, {
	return seed_cc_probe_classify("C", 1) == SEED_CC_PROBE_PLAIN;
});

/* Too few bytes to decide, when the first byte could still begin a record. */
EXO_TEST(seedcc_probe_wants_more_bytes, {
	if (seed_cc_probe_classify(scc_client_hello, 0) != SEED_CC_PROBE_MORE) return 0;
	if (seed_cc_probe_classify(scc_client_hello, 1) != SEED_CC_PROBE_MORE) return 0;
	if (seed_cc_probe_classify(scc_client_hello, 5) != SEED_CC_PROBE_MORE) return 0;
	return seed_cc_probe_classify(scc_client_hello, 10) == SEED_CC_PROBE_MORE;
});

EXO_TEST(seedcc_probe_handles_a_null_buffer, {
	return seed_cc_probe_classify(NULL, 12) == SEED_CC_PROBE_MORE;
});

/* Near misses: a handshake record that is not a ClientHello. */
EXO_TEST(seedcc_probe_rejects_near_misses, {
	char buf[16];

	/* A ServerHello (handshake type 2) arriving from a peer is not one. */
	memcpy(buf, scc_client_hello, 12);
	buf[5] = 2;
	if (seed_cc_probe_classify(buf, 12) != SEED_CC_PROBE_PLAIN) return 0;

	/* The version at offset 9 must echo the major version at offset 1. */
	memcpy(buf, scc_client_hello, 12);
	buf[9] = 2;
	if (seed_cc_probe_classify(buf, 12) != SEED_CC_PROBE_PLAIN) return 0;

	/* Major version 2 is not TLS. */
	memcpy(buf, scc_client_hello, 12);
	buf[1] = 2;
	buf[9] = 2;
	if (seed_cc_probe_classify(buf, 12) != SEED_CC_PROBE_PLAIN) return 0;

	/* Application data (23), not a handshake. */
	memcpy(buf, scc_client_hello, 12);
	buf[0] = 23;
	return seed_cc_probe_classify(buf, 12) == SEED_CC_PROBE_PLAIN;
});

/*
 * What the seeder puts in a CTM. Without a server context it can only be
 * reached in the clear; with one, ADCS -- which is what clients require.
 */
EXO_TEST(seedcc_offered_protocol_follows_the_context, {
	struct seed_cc_policy policy;
	memset(&policy, 0, sizeof(policy));

	if (strcmp(seed_cc_offered_protocol(NULL), "ADC/1.0") != 0) return 0;
	if (strcmp(seed_cc_offered_protocol(&policy), "ADC/1.0") != 0) return 0;

	/* Only the pointer is looked at, never dereferenced. */
	policy.ssl_ctx = (struct ssl_context_handle*) &policy;
	return strcmp(seed_cc_offered_protocol(&policy), "ADCS/0.10") == 0;
});

/* --- the grant table ------------------------------------------------------ */

static struct seed_grants* scc_grants = NULL;

EXO_TEST(seedcc_grants_setup, {
	scc_grants = seed_grants_create();
	return scc_grants != NULL && seed_grant_count(scc_grants) == 0;
});

EXO_TEST(seedcc_grant_unknown_token_refused, {
	return seed_grant_check(scc_grants, "nosuchtoken", SCC_CID, time(NULL), NULL) == 0;
});

EXO_TEST(seedcc_grant_empty_token_refused, {
	return seed_grant_check(scc_grants, "", SCC_CID, time(NULL), NULL) == 0;
});

EXO_TEST(seedcc_grant_null_table_refused, {
	return seed_grant_issue(NULL, "t", SCC_CID, NULL, time(NULL)) == 0 &&
	       seed_grant_check(NULL, "t", SCC_CID, time(NULL), NULL) == 0 &&
	       seed_grant_count(NULL) == 0;
});

EXO_TEST(seedcc_grant_accepts_its_own_cid, {
	if (!seed_grant_issue(scc_grants, "uptoken", SCC_CID, NULL, time(NULL))) return 0;
	return seed_grant_check(scc_grants, "uptoken", SCC_CID, time(NULL), NULL) == 1;
});

/* A grant is bound to the peer it was issued to: quoting someone else's token
   is exactly the attack the CID binding exists for. */
EXO_TEST(seedcc_grant_rejects_another_cid, {
	return seed_grant_check(scc_grants, "uptoken", SCC_TTH, time(NULL), NULL) == 0;
});

/* The token alone still identifies it, which is what the accepted path relies
   on before it has looked at the CID. */
EXO_TEST(seedcc_grant_null_cid_checks_the_token_only, {
	return seed_grant_check(scc_grants, "uptoken", NULL, time(NULL), NULL) == 1;
});

EXO_TEST(seedcc_grant_expired_refused, {
	time_t stale = time(NULL) - (SEED_GRANT_TTL + 1);
	if (!seed_grant_issue(scc_grants, "oldtoken", SCC_CID, NULL, stale)) return 0;
	return seed_grant_check(scc_grants, "oldtoken", SCC_CID, time(NULL), NULL) == 0;
});

/* A CID that is not 39 base32 characters is not one the seeder ever saw on the
   hub, so a grant is never recorded for it. */
EXO_TEST(seedcc_grant_refuses_a_malformed_cid, {
	return seed_grant_issue(scc_grants, "badcid", "short", NULL, time(NULL)) == 0 &&
	       seed_grant_issue(scc_grants, "badcid", "", NULL, time(NULL)) == 0 &&
	       seed_grant_issue(scc_grants, "badcid", NULL, NULL, time(NULL)) == 0;
});

EXO_TEST(seedcc_grant_refuses_an_oversized_token, {
	char token[SEED_TOKEN_MAX + 8];
	memset(token, 'x', SEED_TOKEN_MAX + 1);
	token[SEED_TOKEN_MAX + 1] = '\0';
	return seed_grant_issue(scc_grants, token, SCC_CID, NULL, time(NULL)) == 0;
});

/* An upload grant is not a licence for the seeder to download anything. */
EXO_TEST(seedcc_upload_grant_is_not_a_download_grant, {
	return seed_grant_is_download(scc_grants, "uptoken", time(NULL), NULL) == 0;
});

EXO_TEST(seedcc_download_grant_is_marked, {
	struct seed_grant dl;
	if (!seed_grant_issue_download(scc_grants, "dltoken", SCC_CID, SCC_TTH2, 4096, "wanted.png", time(NULL)))
		return 0;
	if (!seed_grant_is_download(scc_grants, "dltoken", time(NULL), &dl)) return 0;
	return strcmp(dl.tth, SCC_TTH2) == 0 && dl.size == 4096 &&
	       strcmp(dl.name, "wanted.png") == 0 && strcmp(dl.cid, SCC_CID) == 0;
});

/* It is still an ordinary grant, so the CID binding and the TTL apply to it. */
EXO_TEST(seedcc_download_grant_checks_cid, {
	return seed_grant_check(scc_grants, "dltoken", SCC_CID, time(NULL), NULL) == 1 &&
	       seed_grant_check(scc_grants, "dltoken", SCC_TTH, time(NULL), NULL) == 0;
});

EXO_TEST(seedcc_download_grant_expires, {
	time_t stale = time(NULL) - (SEED_GRANT_TTL + 1);
	if (!seed_grant_issue_download(scc_grants, "olddl", SCC_CID, SCC_TTH2, 0, NULL, stale)) return 0;
	return seed_grant_is_download(scc_grants, "olddl", time(NULL), NULL) == 0;
});

/* The seeder must know what it is fetching before it agrees to fetch anything. */
EXO_TEST(seedcc_download_grant_requires_a_tth, {
	return seed_grant_issue_download(scc_grants, "nottht", SCC_CID, NULL, 0, NULL, time(NULL)) == 0;
});

EXO_TEST(seedcc_download_grant_refuses_a_malformed_tth, {
	return seed_grant_issue_download(scc_grants, "badtth", SCC_CID, "nope", 0, NULL, time(NULL)) == 0;
});

EXO_TEST(seedcc_download_grant_released_once_used, {
	seed_grant_release(scc_grants, "dltoken");
	return seed_grant_check(scc_grants, "dltoken", SCC_CID, time(NULL), NULL) == 0 &&
	       seed_grant_is_download(scc_grants, "dltoken", time(NULL), NULL) == 0;
});

/* Re-issuing the same token replaces the grant rather than accumulating. */
EXO_TEST(seedcc_grant_reissue_replaces, {
	size_t before;
	if (!seed_grant_issue(scc_grants, "reissue", SCC_CID, NULL, time(NULL))) return 0;
	before = seed_grant_count(scc_grants);
	if (!seed_grant_issue(scc_grants, "reissue", SCC_CID, NULL, time(NULL))) return 0;
	if (seed_grant_count(scc_grants) != before) return 0;
	seed_grant_release(scc_grants, "reissue");
	return 1;
});

EXO_TEST(seedcc_grant_sweep_drops_expired, {
	seed_grant_sweep(scc_grants, time(NULL) + SEED_GRANT_TTL + 1);
	return seed_grant_count(scc_grants) == 0;
});

/* Tokens are minted, not guessed: a fresh one every time, in a shape that needs
   no ADC escaping. */
EXO_TEST(seedcc_grant_token_is_fresh, {
	char a[SEED_TOKEN_MAX + 1];
	char b[SEED_TOKEN_MAX + 1];
	size_t i;
	if (!seed_grant_make_token(a) || !seed_grant_make_token(b)) return 0;
	if (strlen(a) != 24 || strlen(b) != 24) return 0;
	if (strcmp(a, b) == 0) return 0;
	for (i = 0; i < 24; i++)
		if (a[i] == ' ' || a[i] == '\\' || a[i] == '\n') return 0;
	return 1;
});

/* --- a cache to serve out of ---------------------------------------------- */

static struct seed_cache* scc_cache = NULL;
static struct seed_cc_policy scc_policy;
static char scc_self_cid[SEED_CID_LEN + 1];

static uint8_t scc_data[SCC_SIZE];    /* what the cache holds and serves */
static uint8_t scc_dl_data[SCC_SIZE]; /* what a peer hands the seeder */
static char scc_tth[SEED_TTH_STR_LEN + 1];
static char scc_dl_tth[SEED_TTH_STR_LEN + 1];

/* Our end of the connection under test; we play the peer by hand. */
static int scc_fd = -1;
static char scc_buf[16384];
static size_t scc_buf_len = 0;

/*
 * net_backend_process() polls until the next scheduled timeout, and a client
 * connection sets a 30 second one. A test that is waiting for a reply the seeder
 * is never going to send would block there, so this keeps a one second event in
 * the queue and bounds every poll to it.
 */
static struct timeout_evt scc_tick;

static void scc_tick_cb(struct timeout_evt* t)
{
	timeout_queue_reschedule(net_backend_get_timeout_queue(), t, 1);
}

static void scc_rmtree(const char* path)
{
	DIR* dir = opendir(path);
	struct dirent* ent;

	if (!dir)
	{
		unlink(path);
		return;
	}
	while ((ent = readdir(dir)) != NULL)
	{
		char child[1024];
		struct stat st;
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;
		snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
		if (stat(child, &st) == 0 && S_ISDIR(st.st_mode))
			scc_rmtree(child);
		else
			unlink(child);
	}
	closedir(dir);
	rmdir(path);
}

/* A buffer that sniffs as image/png, so it passes the default allowlist. */
static void scc_make_png(uint8_t* buf, size_t len, uint32_t seed)
{
	static const uint8_t magic[8] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
	uint32_t x = seed ? seed : 1;
	size_t i;

	memcpy(buf, magic, (len < 8) ? len : 8);
	for (i = 8; i < len; i++)
	{
		x = (x * 1103515245u) + 12345u;
		buf[i] = (uint8_t) (x >> 16);
	}
}

static void scc_tth_of(const uint8_t* data, size_t len, char out[SEED_TTH_STR_LEN + 1])
{
	uint8_t root[TTH_SIZE];
	tth(data, len, root);
	tth_to_string(root, out);
}

/*
 * Pull whatever is available into scc_buf, pumping the reactor when the socket
 * has nothing yet. The seeder only acts inside net_backend_process(), so the
 * pumping is what makes it answer at all; the deadline means a state machine
 * that never replies fails the assertion instead of hanging the suite.
 */
static int scc_fill(size_t want)
{
	/*
	 * Generous on purpose. A working implementation returns as soon as the
	 * bytes arrive, so this bounds only the failure case -- and the suite runs
	 * on loaded machines, where a tight deadline turns a correct seeder into a
	 * flaky test.
	 */
	time_t deadline = time(NULL) + SCC_DEADLINE;

	while (scc_buf_len < want && time(NULL) < deadline)
	{
		ssize_t got;

		if (scc_buf_len >= sizeof(scc_buf))
			return 0;

		got = recv(scc_fd, scc_buf + scc_buf_len, sizeof(scc_buf) - scc_buf_len, MSG_DONTWAIT);
		if (got > 0)
		{
			scc_buf_len += (size_t) got;
			continue;
		}
		if (got == 0)
			return 0; /* peer closed */

		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			return 0;

		net_backend_process();
	}
	return scc_buf_len >= want;
}

static void scc_consume(size_t len)
{
	memmove(scc_buf, scc_buf + len, scc_buf_len - len);
	scc_buf_len -= len;
}

/** Read one newline-terminated protocol line into @p out (without the newline). */
static int scc_read_line(char* out, size_t size)
{
	int i;

	for (i = 0; i < 64; i++)
	{
		char* nl = (char*) memchr(scc_buf, '\n', scc_buf_len);
		if (nl)
		{
			size_t len = (size_t) (nl - scc_buf);
			if (len >= size)
				return 0;
			memcpy(out, scc_buf, len);
			out[len] = '\0';
			scc_consume(len + 1);
			return 1;
		}
		if (!scc_fill(scc_buf_len + 1))
			return 0;
	}
	return 0;
}

static int scc_send(const char* line)
{
	size_t len = strlen(line);
	return send(scc_fd, line, len, 0) == (ssize_t) len;
}

static int scc_send_bytes(const void* data, size_t len)
{
	return send(scc_fd, data, len, 0) == (ssize_t) len;
}

/* Hand one end of a socket pair to the seeder as an inbound client connection. */
static int scc_open_connection(void)
{
	int sv[2];
	struct net_connection* con;
	struct ip_addr_encap addr;

	scc_buf_len = 0;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return 0;

	net_set_nonblocking(sv[0], 1);
	net_set_nonblocking(sv[1], 1);

	memset(&addr, 0, sizeof(addr));
	ip_convert_to_binary("127.0.0.1", &addr);

	con = net_con_create();
	if (!con)
		return 0;
	net_con_initialize(con, sv[1], NULL, NULL, NET_EVENT_READ);

	if (!seed_cc_accept(&scc_policy, con, &addr))
		return 0;

	scc_fd = sv[0];
	return 1;
}

static void scc_close_connection(void)
{
	int i;

	if (scc_fd >= 0)
	{
		close(scc_fd);
		scc_fd = -1;
	}
	/*
	 * Pump until the seeder has actually finished tearing the connection down,
	 * rather than a fixed number of times and hoping. A connection that is still
	 * alive holds an upload slot, and with only max_concurrent_upload of them a
	 * few lingering ones make a later test fail with "slots full" -- which shows
	 * up as an unrelated test failing intermittently, somewhere else entirely.
	 */
	{
		time_t deadline = time(NULL) + SCC_DEADLINE;
		while (seed_cc_active_uploads() > 0 && time(NULL) < deadline)
			net_backend_process();
	}
	for (i = 0; i < 2; i++)
		net_backend_process();
	scc_buf_len = 0;
}

/* CSUP exchange plus the seeder's CINF, which it must send without being asked. */
static int scc_handshake(void)
{
	char line[512];

	if (!scc_send("CSUP ADBASE ADTIGR\n"))
		return 0;

	if (!scc_read_line(line, sizeof(line)))
		return 0;
	if (strncmp(line, "CSUP ", 5) != 0)
		return 0;

	if (!scc_read_line(line, sizeof(line)))
		return 0;
	return strncmp(line, "CINF ID", 7) == 0;
}

EXO_TEST(seedcc_setup, {
	struct seed_cache_config cfg;
	struct seed_ingest_request req;
	struct seed_ingest* job;
	enum seed_error err = SEED_OK;

	scc_rmtree(SCC_DIR);
	net_initialize();

	timeout_evt_initialize(&scc_tick, scc_tick_cb, NULL);
	timeout_queue_insert(net_backend_get_timeout_queue(), &scc_tick, 1);

	memset(scc_self_cid, 'S', SEED_CID_LEN);
	scc_self_cid[SEED_CID_LEN] = '\0';

	memset(&cfg, 0, sizeof(cfg));
	cfg.dir = SCC_DIR;
	cfg.max_bytes = 1024 * 1024;
	cfg.max_file_size = 1024 * 1024;
	cfg.max_entries = 16;
	cfg.entry_ttl = 0;
	cfg.max_concurrent_ingest = 4;

	scc_cache = seed_cache_open(&cfg);
	if (!scc_cache) return 0;

	memset(&scc_policy, 0, sizeof(scc_policy));
	scc_policy.cache = scc_cache;
	scc_policy.grants = scc_grants;
	scc_policy.cid = scc_self_cid;
	scc_policy.max_concurrent_upload = 4;

	scc_make_png(scc_data, SCC_SIZE, 11);
	scc_tth_of(scc_data, SCC_SIZE, scc_tth);
	scc_make_png(scc_dl_data, SCC_SIZE, 22);
	scc_tth_of(scc_dl_data, SCC_SIZE, scc_dl_tth);

	memset(&req, 0, sizeof(req));
	req.expect_tth = scc_tth;
	req.announced_size = SCC_SIZE;
	req.name = "served.png";
	req.origin_cid = SCC_CID;

	job = seed_ingest_begin(scc_cache, &req, &err);
	if (!job) return 0;
	if (seed_ingest_write(job, scc_data, SCC_SIZE) != 0) return 0;
	return seed_ingest_finish(job, NULL, &err) == 1;
});

EXO_TEST(seedcc_setup_cached_the_file, {
	return seed_cache_lookup(scc_cache, scc_tth, NULL) == 1 &&
	       seed_cache_lookup(scc_cache, scc_dl_tth, NULL) == 0;
});

/* --- per-peer ingest quota ------------------------------------------------ */

EXO_TEST(seedcc_quota_allows_when_unlimited, {
	scc_policy.ingest_interval = 300;
	scc_policy.ingest_per_user = 0;
	scc_policy.ingest_quota_kb = 0;
	return seed_cc_quota_allow(&scc_policy, SCC_CID, 4096, time(NULL)) == 1;
});

/* The cache already holds one file contributed by SCC_CID, which is what the
   window counts -- no side table to keep in sync with eviction. */
EXO_TEST(seedcc_quota_counts_cached_files, {
	scc_policy.ingest_per_user = 1;
	scc_policy.ingest_quota_kb = 0;
	return seed_cc_quota_allow(&scc_policy, SCC_CID, 4096, time(NULL)) == 0;
});

EXO_TEST(seedcc_quota_is_per_peer, {
	scc_policy.ingest_per_user = 1;
	return seed_cc_quota_allow(&scc_policy, SCC_TTH, 4096, time(NULL)) == 1;
});

EXO_TEST(seedcc_quota_allows_below_the_file_limit, {
	scc_policy.ingest_per_user = 2;
	return seed_cc_quota_allow(&scc_policy, SCC_CID, 4096, time(NULL)) == 1;
});

EXO_TEST(seedcc_quota_counts_bytes, {
	scc_policy.ingest_per_user = 0;
	scc_policy.ingest_quota_kb = 5; /* 5 KiB; 4 KiB is already cached */
	return seed_cc_quota_allow(&scc_policy, SCC_CID, 4096, time(NULL)) == 0;
});

EXO_TEST(seedcc_quota_allows_below_the_byte_limit, {
	scc_policy.ingest_quota_kb = 64;
	return seed_cc_quota_allow(&scc_policy, SCC_CID, 4096, time(NULL)) == 1;
});

/* An absurd request cannot wrap the byte accounting into an allow. */
EXO_TEST(seedcc_quota_refuses_absurd_size, {
	scc_policy.ingest_quota_kb = 64;
	return seed_cc_quota_allow(&scc_policy, SCC_CID, UINT64_MAX, time(NULL)) == 0;
});

/* Content cached before the window began no longer counts against whoever
   contributed it. */
EXO_TEST(seedcc_quota_window_expires, {
	scc_policy.ingest_per_user = 1;
	scc_policy.ingest_quota_kb = 0;
	scc_policy.ingest_interval = 300;
	return seed_cc_quota_allow(&scc_policy, SCC_CID, 4096, time(NULL) + 600) == 1;
});

EXO_TEST(seedcc_quota_needs_a_cid, {
	return seed_cc_quota_allow(&scc_policy, "", 4096, time(NULL)) == 0 &&
	       seed_cc_quota_allow(&scc_policy, NULL, 4096, time(NULL)) == 0;
});

EXO_TEST(seedcc_quota_without_a_policy, {
	return seed_cc_quota_allow(NULL, SCC_CID, 4096, time(NULL)) == 0;
});

/* --- asking a peer for content -------------------------------------------- */

EXO_TEST(seedcc_request_setup, {
	scc_policy.ingest_interval = 300;
	scc_policy.ingest_per_user = 0;
	scc_policy.ingest_quota_kb = 0;
	seed_grant_sweep(scc_grants, time(NULL) + SEED_GRANT_TTL + 1);
	return seed_grant_count(scc_grants) == 0;
});

EXO_TEST(seedcc_request_rejects_null_arguments, {
	char token[SEED_TOKEN_MAX + 1];
	return seed_cc_request_token(NULL, SCC_CID, scc_dl_tth, 0, NULL, token) == 0 &&
	       seed_cc_request_token(&scc_policy, NULL, scc_dl_tth, 0, NULL, token) == 0 &&
	       seed_cc_request_token(&scc_policy, SCC_CID, NULL, 0, NULL, token) == 0 &&
	       seed_cc_request_token(&scc_policy, SCC_CID, scc_dl_tth, 0, NULL, NULL) == 0;
});

EXO_TEST(seedcc_request_rejects_a_malformed_tth, {
	char token[SEED_TOKEN_MAX + 1];
	return seed_cc_request_token(&scc_policy, SCC_CID, "nope", 0, NULL, token) == 0;
});

/* Nothing to fetch into: with no cache the seeder does not ask anybody for
   anything. */
EXO_TEST(seedcc_request_without_a_cache, {
	char token[SEED_TOKEN_MAX + 1];
	struct seed_cache* cache = scc_policy.cache;
	int result;
	scc_policy.cache = NULL;
	result = seed_cc_request_token(&scc_policy, SCC_CID, scc_dl_tth, 4096, "x.png", token);
	scc_policy.cache = cache;
	return result == 0;
});

/* The request records exactly one live download grant, for exactly the content
   asked for. */
EXO_TEST(seedcc_request_issues_a_download_grant, {
	char token[SEED_TOKEN_MAX + 1];
	struct seed_grant grant;
	size_t before = seed_grant_count(scc_grants);

	if (seed_cc_request_token(&scc_policy, SCC_CID, scc_dl_tth, 4096, "wanted.png", token) != 1)
		return 0;
	if (seed_grant_count(scc_grants) != before + 1) return 0;
	if (!*token) return 0;
	if (!seed_grant_is_download(scc_grants, token, time(NULL), &grant)) return 0;
	if (strcmp(grant.tth, scc_dl_tth) != 0) return 0;
	if (strcmp(grant.cid, SCC_CID) != 0) return 0;
	if (strcmp(grant.name, "wanted.png") != 0) return 0;

	seed_grant_release(scc_grants, token);
	return seed_grant_count(scc_grants) == before;
});

/* Content the seeder already holds is never requested again. */
EXO_TEST(seedcc_request_skips_cached_content, {
	char token[SEED_TOKEN_MAX + 1];
	size_t before = seed_grant_count(scc_grants);
	int result = seed_cc_request_token(&scc_policy, SCC_CID, scc_tth, 4096, "served.png", token);
	return result == 0 && seed_grant_count(scc_grants) == before && token[0] == '\0';
});

/* An operator said no to this content: do not go and fetch it. */
EXO_TEST(seedcc_request_skips_blocked_content, {
	char token[SEED_TOKEN_MAX + 1];
	size_t before = seed_grant_count(scc_grants);
	int result;
	if (!seed_cache_block(scc_cache, scc_dl_tth, "operator", "test")) return 0;
	result = seed_cc_request_token(&scc_policy, SCC_CID, scc_dl_tth, 4096, "wanted.png", token);
	seed_cache_unblock(scc_cache, scc_dl_tth);
	return result == 0 && seed_grant_count(scc_grants) == before;
});

/* The quota gates the request, not just the transfer. */
EXO_TEST(seedcc_request_honours_the_quota, {
	char token[SEED_TOKEN_MAX + 1];
	int result;
	scc_policy.ingest_per_user = 1;
	result = seed_cc_request_token(&scc_policy, SCC_CID, scc_dl_tth, 4096, "x.png", token);
	scc_policy.ingest_per_user = 0;
	return result == 0;
});

/* --- serving over a real socket ------------------------------------------- */

/*
 * The whole point of the feature: a peer that holds a grant asks for a cached
 * file by TTH and gets exactly those bytes back.
 */
EXO_TEST(seedcc_serves_the_cached_bytes, {
	char line[512];
	char expect[128];
	uint8_t body[SCC_SIZE];

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue(scc_grants, SCC_TOKEN, SCC_CID, NULL, time(NULL))) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;

	snprintf(line, sizeof(line), "CGET file TTH/%s 0 -1\n", scc_tth);
	if (!scc_send(line)) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	snprintf(expect, sizeof(expect), "CSND file TTH/%s 0 %d", scc_tth, SCC_SIZE);
	if (strcmp(line, expect) != 0) return 0;

	if (!scc_fill(SCC_SIZE)) return 0;
	memcpy(body, scc_buf, SCC_SIZE);
	scc_consume(SCC_SIZE);

	scc_close_connection();
	return memcmp(body, scc_data, SCC_SIZE) == 0;
});

/*
 * The exact sequence EiskaltDC++ sends: an informational CSTA between the INF
 * and the CGET. Severity 0 means "carrying on", and treating any CSTA as "the
 * peer gave up" hung up on every download from that client before it had asked
 * for a file.
 */
EXO_TEST(seedcc_informational_status_does_not_end_the_connection, {
	char line[512];
	char expect[128];
	uint8_t body[SCC_SIZE];

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue(scc_grants, SCC_TOKEN, SCC_CID, NULL, time(NULL))) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;

	/* Empty description, and a referrer -- what Eiskalt actually sends. */
	if (!scc_send("CSTA 000  RFadc://192.0.2.1:1511\n")) return 0;

	snprintf(line, sizeof(line), "CGET file TTH/%s 0 -1\n", scc_tth);
	if (!scc_send(line)) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	snprintf(expect, sizeof(expect), "CSND file TTH/%s 0 %d", scc_tth, SCC_SIZE);
	if (strcmp(line, expect) != 0) return 0;

	if (!scc_fill(SCC_SIZE)) return 0;
	memcpy(body, scc_buf, SCC_SIZE);
	scc_consume(SCC_SIZE);

	scc_close_connection();
	return memcmp(body, scc_data, SCC_SIZE) == 0;
});

/* A recoverable status is still the peer telling us the thing we were waiting
   for is not coming, so it ends the connection as before. */
EXO_TEST(seedcc_recoverable_status_still_closes, {
	char line[512];
	int closed;

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue(scc_grants, SCC_TOKEN, SCC_CID, NULL, time(NULL))) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;
	if (!scc_send("CSTA 140 File\\snot\\savailable\n")) return 0;

	/* The seeder hangs up, so the CGET that follows is never answered. */
	snprintf(line, sizeof(line), "CGET file TTH/%s 0 -1\n", scc_tth);
	scc_send(line);

	closed = !scc_read_line(line, sizeof(line));

	scc_close_connection();
	return closed;
});

/* A partial request must be honoured at the right offset. */
EXO_TEST(seedcc_serves_a_range, {
	char line[512];
	char expect[128];
	uint8_t body[1024];

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue(scc_grants, SCC_TOKEN, SCC_CID, NULL, time(NULL))) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;

	snprintf(line, sizeof(line), "CGET file TTH/%s 1024 1024\n", scc_tth);
	if (!scc_send(line)) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	snprintf(expect, sizeof(expect), "CSND file TTH/%s 1024 1024", scc_tth);
	if (strcmp(line, expect) != 0) return 0;

	if (!scc_fill(sizeof(body))) return 0;
	memcpy(body, scc_buf, sizeof(body));
	scc_consume(sizeof(body));

	scc_close_connection();
	return memcmp(body, scc_data + 1024, sizeof(body)) == 0;
});

/* No grant, no data: the transfer port is reachable by anyone who can open a
   socket. */
EXO_TEST(seedcc_refuses_without_a_grant, {
	char line[512];
	int refused;

	if (!scc_open_connection()) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s TOBOGUSTOKEN\n", SCC_CID);
	if (!scc_send(line)) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	/* Recoverable status, never a fatal 2xx. */
	refused = (strncmp(line, "CSTA 1", 6) == 0);

	scc_close_connection();
	return refused;
});

/* Not even a CGET gets an answer without one. */
EXO_TEST(seedcc_serves_nothing_without_a_grant, {
	char line[512];
	int refused;

	if (!scc_open_connection()) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CGET file TTH/%s 0 -1\n", scc_tth);
	if (!scc_send(line)) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	refused = (strncmp(line, "CSTA 1", 6) == 0);

	scc_close_connection();
	return refused;
});

/* A grant belongs to the peer it was issued to. */
EXO_TEST(seedcc_refuses_another_cid, {
	char line[512];
	char other[SEED_CID_LEN + 1];
	int refused;

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue(scc_grants, SCC_TOKEN, SCC_CID, NULL, time(NULL))) return 0;
	if (!scc_handshake()) return 0;

	memset(other, 'C', SEED_CID_LEN);
	other[SEED_CID_LEN] = '\0';
	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", other, SCC_TOKEN);
	if (!scc_send(line)) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	refused = (strncmp(line, "CSTA 1", 6) == 0);

	scc_close_connection();
	seed_grant_release(scc_grants, SCC_TOKEN);
	return refused;
});

/* A token is single use, so a second connection cannot ride the same one. */
EXO_TEST(seedcc_token_is_single_use, {
	char line[512];
	int refused;

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue(scc_grants, SCC_TOKEN, SCC_CID, NULL, time(NULL))) return 0;
	if (!scc_handshake()) return 0;
	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;
	/* Let the seeder consume the CINF; it answers nothing until asked for a
	   file. */
	net_backend_process();
	net_backend_process();
	if (seed_grant_count(scc_grants) != 0) return 0;
	scc_close_connection();

	if (!scc_open_connection()) return 0;
	if (!scc_handshake()) return 0;
	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;
	if (!scc_read_line(line, sizeof(line))) return 0;
	refused = (strncmp(line, "CSTA 1", 6) == 0);

	scc_close_connection();
	return refused;
});

/* An expired grant is no grant. */
EXO_TEST(seedcc_expired_token_is_refused, {
	char line[512];
	int refused;

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue(scc_grants, SCC_TOKEN, SCC_CID, NULL,
		time(NULL) - (SEED_GRANT_TTL + 1))) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	refused = (strncmp(line, "CSTA 1", 6) == 0);

	scc_close_connection();
	seed_grant_release(scc_grants, SCC_TOKEN);
	return refused;
});

/* An unknown TTH is refused, and recoverably so. */
EXO_TEST(seedcc_unknown_tth_is_refused, {
	char line[512];
	int refused;

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue(scc_grants, SCC_TOKEN, SCC_CID, NULL, time(NULL))) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;
	if (!scc_send("CGET file TTH/" SCC_TTH2 " 0 -1\n")) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	refused = (strncmp(line, "CSTA 1", 6) == 0);

	scc_close_connection();
	return refused;
});

/* Leaf hashes are not kept, and saying so must not abort the download. */
EXO_TEST(seedcc_tthl_is_recoverable, {
	char line[512];
	int recoverable;

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue(scc_grants, SCC_TOKEN, SCC_CID, NULL, time(NULL))) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;
	snprintf(line, sizeof(line), "CGET tthl TTH/%s 0 -1\n", scc_tth);
	if (!scc_send(line)) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	recoverable = (strncmp(line, "CSTA 1", 6) == 0);

	scc_close_connection();
	return recoverable;
});

/* After a refusal the connection stays usable, so a client can fall back. */
EXO_TEST(seedcc_recovers_after_a_refusal, {
	char line[512];
	char expect[128];

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue(scc_grants, SCC_TOKEN, SCC_CID, NULL, time(NULL))) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;

	snprintf(line, sizeof(line), "CGET tthl TTH/%s 0 -1\n", scc_tth);
	if (!scc_send(line)) return 0;
	if (!scc_read_line(line, sizeof(line))) return 0;
	if (strncmp(line, "CSTA 1", 6) != 0) return 0;

	snprintf(line, sizeof(line), "CGET file TTH/%s 0 -1\n", scc_tth);
	if (!scc_send(line)) return 0;
	if (!scc_read_line(line, sizeof(line))) return 0;
	snprintf(expect, sizeof(expect), "CSND file TTH/%s 0 %d", scc_tth, SCC_SIZE);

	scc_close_connection();
	return strcmp(line, expect) == 0;
});

/* Metadata is answered from the cache, not from anything the peer said. */
EXO_TEST(seedcc_gfi_answers_from_the_cache, {
	char line[512];
	char expect[256];

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue(scc_grants, SCC_TOKEN, SCC_CID, NULL, time(NULL))) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;
	snprintf(line, sizeof(line), "CGFI file TTH/%s\n", scc_tth);
	if (!scc_send(line)) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	snprintf(expect, sizeof(expect), "CRES FNserved.png SI%d TRTTH/%s", SCC_SIZE, scc_tth);

	scc_close_connection();
	return strcmp(line, expect) == 0;
});

/* --- the download role: the seeder is the sink ---------------------------- */

/*
 * A download grant reverses the roles over the very same accepted connection:
 * the seeder sends the CGET and ingests what comes back. Nothing about that is
 * negotiable by the peer -- the TTH is the one named by the grant.
 */
EXO_TEST(seedcc_ingests_over_a_download_grant, {
	char line[512];
	char expect[128];
	time_t deadline;
	int done = 0;

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue_download(scc_grants, SCC_TOKEN, SCC_CID, scc_dl_tth,
		SCC_SIZE, "wanted.png", time(NULL))) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;

	/* The seeder asks, unprompted, for exactly what its own grant named. */
	if (!scc_read_line(line, sizeof(line))) return 0;
	snprintf(expect, sizeof(expect), "CGET file TTH/%s 0 -1", scc_dl_tth);
	if (strcmp(line, expect) != 0) return 0;

	snprintf(line, sizeof(line), "CSND file TTH/%s 0 %d\n", scc_dl_tth, SCC_SIZE);
	if (!scc_send(line)) return 0;
	if (!scc_send_bytes(scc_dl_data, SCC_SIZE)) return 0;

	deadline = time(NULL) + SCC_DEADLINE;
	while (!done && time(NULL) < deadline)
	{
		net_backend_process();
		done = seed_cache_lookup(scc_cache, scc_dl_tth, NULL);
	}

	scc_close_connection();
	return done;
});

/* Content that does not hash to what was asked for is not published. */
EXO_TEST(seedcc_refuses_a_mismatched_body, {
	char line[512];
	char expect[128];
	uint8_t junk[SCC_SIZE];
	int i;

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue_download(scc_grants, SCC_TOKEN, SCC_CID, SCC_TTH2,
		SCC_SIZE, "bogus.png", time(NULL))) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	snprintf(expect, sizeof(expect), "CGET file TTH/%s 0 -1", SCC_TTH2);
	if (strcmp(line, expect) != 0) return 0;

	scc_make_png(junk, SCC_SIZE, 33);
	snprintf(line, sizeof(line), "CSND file TTH/%s 0 %d\n", SCC_TTH2, SCC_SIZE);
	if (!scc_send(line)) return 0;
	if (!scc_send_bytes(junk, SCC_SIZE)) return 0;

	for (i = 0; i < 16; i++)
		net_backend_process();

	scc_close_connection();
	return seed_cache_lookup(scc_cache, SCC_TTH2, NULL) == 0;
});

/* The peer does not get to redirect the transfer onto something else. */
EXO_TEST(seedcc_refuses_a_substituted_csnd, {
	char line[512];
	char expect[128];
	int i;

	if (!scc_open_connection()) return 0;
	if (!seed_grant_issue_download(scc_grants, SCC_TOKEN, SCC_CID, SCC_TTH2,
		SCC_SIZE, "bogus.png", time(NULL))) return 0;
	if (!scc_handshake()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s TO%s\n", SCC_CID, SCC_TOKEN);
	if (!scc_send(line)) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	snprintf(expect, sizeof(expect), "CGET file TTH/%s 0 -1", SCC_TTH2);
	if (strcmp(line, expect) != 0) return 0;

	/* Offering the file the seeder already has, rather than the one it asked
	   for, must end the connection rather than start an ingest. */
	snprintf(line, sizeof(line), "CSND file TTH/%s 0 %d\n", scc_tth, SCC_SIZE);
	if (!scc_send(line)) return 0;
	if (!scc_send_bytes(scc_data, SCC_SIZE)) return 0;

	for (i = 0; i < 16; i++)
		net_backend_process();

	scc_close_connection();
	return seed_cache_lookup(scc_cache, SCC_TTH2, NULL) == 0;
});

/* -- active mode: the seeder dials us ---------------------------------------
 *
 * An active downloader sends a CTM asking the seeder to connect to it. The
 * ordering is the mirror of the accepted case: the seeder speaks first because
 * it is the connecting side, and it carries the token in its own CINF because it
 * is the side that received the connect request.
 */

static int scc_listen_fd = -1;
static uint16_t scc_listen_port = 0;
static struct ip_addr_encap scc_peer_addr;
static struct seed_cc_peer scc_peer;

static int scc_start_listener(void)
{
	struct sockaddr_in sa;
	socklen_t len = sizeof(sa);

	scc_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (scc_listen_fd < 0)
		return 0;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0; /* an ephemeral port, which is always above 1024 */

	if (bind(scc_listen_fd, (struct sockaddr*) &sa, sizeof(sa)) != 0)
		return 0;
	if (listen(scc_listen_fd, 4) != 0)
		return 0;
	if (getsockname(scc_listen_fd, (struct sockaddr*) &sa, &len) != 0)
		return 0;

	scc_listen_port = ntohs(sa.sin_port);
	net_set_nonblocking(scc_listen_fd, 1);
	return scc_listen_port >= 1024;
}

/*
 * Pump a few times and report whether the seeder stayed silent. Needed because
 * "we later received a CINF" would also hold if it had sent it too early; only
 * observing the silence in between actually pins the ordering.
 */
static int scc_stayed_quiet(void)
{
	int i;
	for (i = 0; i < 3; i++)
	{
		net_backend_process();
		if (scc_buf_len)
			return 0;
		if (recv(scc_fd, scc_buf, sizeof(scc_buf), MSG_DONTWAIT) > 0)
			return 0;
	}
	return 1;
}

/* Pump until the seeder's outbound connection lands on our listener. */
static int scc_accept_dial(void)
{
	/* The dial resolves through the DNS worker pool before it even connects,
	   which is exactly what a loaded machine makes slow. */
	time_t deadline = time(NULL) + SCC_DEADLINE;

	scc_buf_len = 0;

	while (time(NULL) < deadline)
	{
		int fd = accept(scc_listen_fd, NULL, NULL);
		if (fd >= 0)
		{
			net_set_nonblocking(fd, 1);
			scc_fd = fd;
			return 1;
		}
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			return 0;
		net_backend_process();
	}
	return 0;
}

EXO_TEST(seedcc_active_setup, {
	if (!scc_start_listener()) return 0;

	memset(&scc_peer_addr, 0, sizeof(scc_peer_addr));
	if (!ip_convert_to_binary("127.0.0.1", &scc_peer_addr)) return 0;

	memset(&scc_peer, 0, sizeof(scc_peer));
	scc_peer.cid = SCC_CID;
	scc_peer.addr = &scc_peer_addr;
	scc_peer.addr_is_client_supplied = 0;
	return seed_cc_may_dial(&scc_policy, &scc_peer) == 1;
});

/*
 * The whole active exchange. The assertions on ordering are the point: the
 * seeder must speak first, and must not send its CINF until it has seen ours.
 */
EXO_TEST(seedcc_active_speaks_first_and_serves, {
	char line[512];
	char expect[128];
	uint8_t body[SCC_SIZE];

	if (!seed_cc_connect_to_peer(&scc_policy, &scc_peer, "ADC/1.0", scc_listen_port, SCC_TOKEN))
		return 0;
	if (!scc_accept_dial()) return 0;

	/* The seeder connected, so the first line on the wire is its CSUP. */
	if (!scc_read_line(line, sizeof(line))) return 0;
	if (strncmp(line, "CSUP ", 5) != 0) return 0;

	if (!scc_send("CSUP ADBASE ADTIGR\n")) return 0;

	/*
	 * We are the side that was connected to, so our INF goes first, and the
	 * seeder must stay silent until it arrives. Asserting that silence is the
	 * point: simply reading a CINF later would pass just as well if it had sent
	 * one early, which is the mirror of the bug that broke the accepted
	 * direction.
	 */
	if (!scc_stayed_quiet()) return 0;

	snprintf(line, sizeof(line), "CINF ID%s\n", SCC_CID);
	if (!scc_send(line)) return 0;

	/* Now the seeder answers, and its INF carries the token from our CTM. */
	if (!scc_read_line(line, sizeof(line))) return 0;
	if (strncmp(line, "CINF ID", 7) != 0) return 0;
	if (!strstr(line, "TO" SCC_TOKEN)) return 0;

	snprintf(line, sizeof(line), "CGET file TTH/%s 0 -1\n", scc_tth);
	if (!scc_send(line)) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	snprintf(expect, sizeof(expect), "CSND file TTH/%s 0 %d", scc_tth, SCC_SIZE);
	if (strcmp(line, expect) != 0) return 0;

	if (!scc_fill(SCC_SIZE)) return 0;
	memcpy(body, scc_buf, SCC_SIZE);
	scc_consume(SCC_SIZE);

	scc_close_connection();
	return memcmp(body, scc_data, SCC_SIZE) == 0;
});

/* The peer that answers must be the one that asked us to connect. */
EXO_TEST(seedcc_active_refuses_unexpected_cid, {
	char line[512];
	char other[SEED_CID_LEN + 1];
	int refused;

	if (!seed_cc_connect_to_peer(&scc_policy, &scc_peer, "ADC/1.0", scc_listen_port, SCC_TOKEN))
		return 0;
	if (!scc_accept_dial()) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	if (strncmp(line, "CSUP ", 5) != 0) return 0;
	if (!scc_send("CSUP ADBASE ADTIGR\n")) return 0;

	memset(other, 'C', SEED_CID_LEN);
	other[SEED_CID_LEN] = '\0';
	snprintf(line, sizeof(line), "CINF ID%s\n", other);
	if (!scc_send(line)) return 0;

	if (!scc_read_line(line, sizeof(line))) return 0;
	refused = (strncmp(line, "CSTA 1", 6) == 0);

	scc_close_connection();
	return refused;
});

/* A dial is refused outright when even the hub's address for the peer is
   client-supplied. */
EXO_TEST(seedcc_active_refuses_a_client_supplied_address, {
	int refused;

	scc_peer.addr_is_client_supplied = 1;
	refused = (seed_cc_may_dial(&scc_policy, &scc_peer) == 0) &&
	          (seed_cc_connect_to_peer(&scc_policy, &scc_peer, "ADC/1.0", scc_listen_port, SCC_TOKEN) == 0);
	scc_peer.addr_is_client_supplied = 0;
	return refused;
});

EXO_TEST(seedcc_active_refuses_a_privileged_port, {
	return seed_cc_connect_to_peer(&scc_policy, &scc_peer, "ADC/1.0", 80, SCC_TOKEN) == 0;
});

EXO_TEST(seedcc_active_refuses_an_unknown_protocol, {
	return seed_cc_connect_to_peer(&scc_policy, &scc_peer, "ADC0", scc_listen_port, SCC_TOKEN) == 0 &&
	       seed_cc_connect_to_peer(&scc_policy, &scc_peer, "NMDC", scc_listen_port, SCC_TOKEN) == 0;
});

EXO_TEST(seedcc_active_refuses_without_a_token, {
	return seed_cc_connect_to_peer(&scc_policy, &scc_peer, "ADC/1.0", scc_listen_port, NULL) == 0 &&
	       seed_cc_connect_to_peer(&scc_policy, &scc_peer, "ADC/1.0", scc_listen_port, "") == 0;
});

/* A peer with no CID is not a peer we can identify, so it is not one we dial. */
EXO_TEST(seedcc_active_refuses_a_peer_without_a_cid, {
	struct seed_cc_peer bad = scc_peer;
	bad.cid = NULL;
	if (seed_cc_may_dial(&scc_policy, &bad)) return 0;
	bad.cid = "short";
	if (seed_cc_may_dial(&scc_policy, &bad)) return 0;
	bad = scc_peer;
	bad.addr = NULL;
	return seed_cc_may_dial(&scc_policy, &bad) == 0;
});

/* Without our own CID there is no CINF to send, so nothing is dialled or
   accepted. */
EXO_TEST(seedcc_refuses_without_our_own_cid, {
	struct seed_cc_policy broken = scc_policy;
	broken.cid = NULL;
	if (seed_cc_may_dial(&broken, &scc_peer)) return 0;
	broken.cid = "not-a-cid";
	return seed_cc_may_dial(&broken, &scc_peer) == 0;
});

EXO_TEST(seedcc_active_teardown, {
	if (scc_listen_fd >= 0)
	{
		close(scc_listen_fd);
		scc_listen_fd = -1;
	}
	return 1;
});

/* --- nothing left behind -------------------------------------------------- */

/* Nothing may be left pinned once the transfers are over. */
EXO_TEST(seedcc_releases_every_pin, {
	struct seed_cache_stats stats;
	seed_cache_get_stats(scc_cache, &stats);
	return stats.pinned == 0 && stats.entries >= 1;
});

/*
 * ...nor may an upload slot be. A dialled connection takes its slot when it
 * dials and the CGET must not take a second one, or the cap leaks a slot per
 * active transfer until the seeder refuses to serve anybody.
 */
EXO_TEST(seedcc_releases_every_upload_slot, {
	return seed_cc_active_uploads() == 0;
});

EXO_TEST(seedcc_no_ingest_left_running, {
	struct seed_cache_stats stats;
	seed_cache_get_stats(scc_cache, &stats);
	return stats.active_ingests == 0;
});

EXO_TEST(seedcc_cleanup, {
	scc_close_connection();
	timeout_queue_remove(net_backend_get_timeout_queue(), &scc_tick);
	seed_grants_destroy(scc_grants);
	scc_grants = NULL;
	seed_cache_close(scc_cache);
	scc_cache = NULL;
	net_destroy();
	scc_rmtree(SCC_DIR);
	return 1;
});
