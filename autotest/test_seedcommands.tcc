#include "system.h"

#include <dirent.h>
#include <sys/stat.h>

#include "seeder/cache.h"
#include "seeder/commands.h"
#include "util/memory.h"
#include "util/tth.h"

#define SXC_DIR "test_seedcommands.tmp"

/* The reply callback keeps every line, so a test can assert on the shape of the
   whole answer and not merely on the last line of it. */
#define SXC_MAX_LINES 64
#define SXC_LINE_MAX 1024

#define SXC_SID 42

static struct seed_cache* sxc_cache = NULL;
static struct seed_commands* sxc_cmds = NULL;
static struct seed_cache_config sxc_cfg;
static uint8_t sxc_data[64 * 1024];

static char sxc_lines[SXC_MAX_LINES][SXC_LINE_MAX];
static int sxc_count = 0;
static sid_t sxc_last_sid = 0;

static void sxc_rmtree(const char* path)
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
			sxc_rmtree(child);
		else
			unlink(child);
	}
	closedir(dir);
	rmdir(path);
}

static void sxc_reply(void* ptr, sid_t to, const char* text)
{
	(void) ptr;
	sxc_last_sid = to;
	if (sxc_count >= 0 && sxc_count < SXC_MAX_LINES)
		snprintf(sxc_lines[sxc_count], SXC_LINE_MAX, "%s", text);
	sxc_count++; /* keep counting past the cap, so an overflow is visible */
}

static void sxc_reset(void)
{
	memset(sxc_lines, 0, sizeof(sxc_lines));
	sxc_count = 0;
	sxc_last_sid = 0;
}

/** Run one command and return what seed_commands_handle() returned. */
static int sxc_run(int client_type, const char* text)
{
	sxc_reset();
	return seed_commands_handle(sxc_cmds, SXC_SID, client_type, text);
}

/** @return 1 if any reply line contains @p needle. */
static int sxc_has(const char* needle)
{
	int i;
	int lines = (sxc_count < SXC_MAX_LINES) ? sxc_count : SXC_MAX_LINES;

	for (i = 0; i < lines; i++)
		if (strstr(sxc_lines[i], needle))
			return 1;
	return 0;
}

/** @return 1 if no reply line carries a control character. */
static int sxc_lines_are_clean(void)
{
	int i;
	int lines = (sxc_count < SXC_MAX_LINES) ? sxc_count : SXC_MAX_LINES;

	for (i = 0; i < lines; i++)
	{
		const unsigned char* p = (const unsigned char*) sxc_lines[i];
		for (; *p; p++)
			if (*p < 0x20 || *p == 0x7f)
				return 0;
	}
	return 1;
}

/* A buffer that sniffs as image/png, so it passes the default allowlist. */
static void sxc_make_png(uint8_t* buf, size_t len, uint32_t seed)
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

static void sxc_tth(size_t len, uint32_t seed, char out[SEED_TTH_STR_LEN + 1])
{
	uint8_t root[TTH_SIZE];

	sxc_make_png(sxc_data, len, seed);
	tth(sxc_data, len, root);
	tth_to_string(root, out);
}

/** Ingest generated content. @return 1 when it is in the cache. */
static int sxc_ingest(size_t len, uint32_t seed, const char* cid, const char* name)
{
	struct seed_ingest_request req;
	struct seed_ingest* job;
	enum seed_error err = SEED_OK;
	char expect[SEED_TTH_STR_LEN + 1];

	sxc_tth(len, seed, expect);

	memset(&req, 0, sizeof(req));
	req.expect_tth = expect;
	req.announced_size = len;
	req.name = name;
	req.origin_cid = cid;
	req.origin_nick = "tester";
	req.origin_addr = "192.0.2.7";

	job = seed_ingest_begin(sxc_cache, &req, &err);
	if (!job)
		return 0;

	if (seed_ingest_write(job, sxc_data, len) != 0)
	{
		seed_ingest_abort(job, SEED_ERR_IO);
		return 0;
	}
	return seed_ingest_finish(job, NULL, &err);
}

static size_t sxc_entries(void)
{
	struct seed_cache_stats stats;
	seed_cache_get_stats(sxc_cache, &stats);
	return stats.entries;
}

/* CT bit patterns as they appear in a real INF. */
#define SXC_CT_GUEST      0
#define SXC_CT_BOT        1
#define SXC_CT_REGISTERED 2
#define SXC_CT_OPERATOR   4
#define SXC_CT_SUPER      12
#define SXC_CT_ADMIN      20
#define SXC_CT_HUB        32

EXO_TEST(seedcmd_setup, {
	sxc_rmtree(SXC_DIR);

	memset(&sxc_cfg, 0, sizeof(sxc_cfg));
	sxc_cfg.dir = SXC_DIR;
	sxc_cfg.max_bytes = 1024 * 1024;
	sxc_cfg.max_file_size = 128 * 1024;
	sxc_cfg.max_entries = 64;
	sxc_cfg.entry_ttl = 0;
	sxc_cfg.max_concurrent_ingest = 4;
	sxc_cfg.allowed_types = "image/png,image/jpeg";

	sxc_cache = seed_cache_open(&sxc_cfg);
	return sxc_cache != NULL;
});

EXO_TEST(seedcmd_create, {
	sxc_cmds = seed_commands_create(sxc_cache, sxc_reply, NULL);
	return sxc_cmds != NULL;
});

/* -- parsing --------------------------------------------------------------- */

EXO_TEST(seedcmd_parse_verb_and_args, {
	struct seed_command_line line;

	if (!seed_command_parse("list 10", &line)) return 0;
	if (strcmp(line.verb, "list") != 0) return 0;
	return strcmp(line.args, "10") == 0;
});

EXO_TEST(seedcmd_parse_no_args, {
	struct seed_command_line line;

	if (!seed_command_parse("stats", &line)) return 0;
	if (strcmp(line.verb, "stats") != 0) return 0;
	return line.args && line.args[0] == '\0';
});

EXO_TEST(seedcmd_parse_accepts_bang_prefix, {
	struct seed_command_line line;

	if (!seed_command_parse("!stats", &line)) return 0;
	if (strcmp(line.verb, "stats") != 0) return 0;

	if (!seed_command_parse("  !  list 5 ", &line)) return 0;
	if (strcmp(line.verb, "list") != 0) return 0;
	if (strncmp(line.args, "5", 1) != 0) return 0;

	if (!seed_command_parse("+gc", &line)) return 0;
	return strcmp(line.verb, "gc") == 0;
});

EXO_TEST(seedcmd_parse_folds_case, {
	struct seed_command_line line;

	if (!seed_command_parse("STATS", &line)) return 0;
	if (strcmp(line.verb, "stats") != 0) return 0;

	if (!seed_command_parse("!UnBlock ABC", &line)) return 0;
	if (strcmp(line.verb, "unblock") != 0) return 0;
	/* The arguments keep their case: a TTH is upper case base32. */
	return strcmp(line.args, "ABC") == 0;
});

EXO_TEST(seedcmd_parse_empty_is_not_a_command, {
	struct seed_command_line line;

	if (seed_command_parse("", &line)) return 0;
	if (seed_command_parse("   ", &line)) return 0;
	if (seed_command_parse("\t \t", &line)) return 0;
	if (seed_command_parse("!", &line)) return 0;
	if (seed_command_parse("  !  ", &line)) return 0;
	return seed_command_parse(NULL, &line) == 0;
});

EXO_TEST(seedcmd_parse_long_verb_does_not_truncate_into_a_real_one, {
	struct seed_command_line line;
	char text[128];
	size_t i;

	/* "stats" followed by a lot more must never come back as "stats". */
	memcpy(text, "stats", 5);
	for (i = 5; i < 100; i++)
		text[i] = 'x';
	text[100] = '\0';

	if (!seed_command_parse(text, &line)) return 0;
	if (strcmp(line.verb, "stats") == 0) return 0;
	return strlen(line.verb) <= SEED_COMMAND_VERB_MAX;
});

EXO_TEST(seedcmd_handle_ignores_empty_input, {
	if (sxc_run(SXC_CT_ADMIN, "") != 0) return 0;
	if (sxc_count != 0) return 0;
	if (sxc_run(SXC_CT_ADMIN, "    ") != 0) return 0;
	if (sxc_count != 0) return 0;
	if (sxc_run(SXC_CT_ADMIN, NULL) != 0) return 0;
	return sxc_count == 0;
});

/* -- authorisation --------------------------------------------------------- */

EXO_TEST(seedcmd_access_operator_commands, {
	/* Operator, super (8|4) and admin (16|4) all carry the operator bit. */
	if (seed_command_check_access("stats", SXC_CT_OPERATOR) != SEED_ACCESS_OK) return 0;
	if (seed_command_check_access("stats", SXC_CT_SUPER) != SEED_ACCESS_OK) return 0;
	if (seed_command_check_access("stats", SXC_CT_ADMIN) != SEED_ACCESS_OK) return 0;
	if (seed_command_check_access("list", SXC_CT_ADMIN) != SEED_ACCESS_OK) return 0;
	if (seed_command_check_access("purge", SXC_CT_SUPER) != SEED_ACCESS_OK) return 0;
	return 1;
});

EXO_TEST(seedcmd_access_refuses_the_unprivileged, {
	if (seed_command_check_access("stats", SXC_CT_GUEST) != SEED_ACCESS_DENIED) return 0;
	if (seed_command_check_access("stats", SXC_CT_REGISTERED) != SEED_ACCESS_DENIED) return 0;
	if (seed_command_check_access("stats", SXC_CT_BOT) != SEED_ACCESS_DENIED) return 0;
	/* The hub bit alone is not the operator bit. */
	return seed_command_check_access("stats", SXC_CT_HUB) == SEED_ACCESS_DENIED;
});

EXO_TEST(seedcmd_access_admin_only_commands, {
	if (seed_command_check_access("unblock", SXC_CT_ADMIN) != SEED_ACCESS_OK) return 0;
	if (seed_command_check_access("gc", SXC_CT_ADMIN) != SEED_ACCESS_OK) return 0;
	if (seed_command_check_access("unblock", SXC_CT_OPERATOR) != SEED_ACCESS_DENIED) return 0;
	if (seed_command_check_access("gc", SXC_CT_OPERATOR) != SEED_ACCESS_DENIED) return 0;
	/* A super user is 12: it has the operator bit, but not the admin one. */
	if (seed_command_check_access("unblock", SXC_CT_SUPER) != SEED_ACCESS_DENIED) return 0;
	return seed_command_check_access("gc", SXC_CT_SUPER) == SEED_ACCESS_DENIED;
});

EXO_TEST(seedcmd_access_help_is_open, {
	if (seed_command_check_access("help", SXC_CT_GUEST) != SEED_ACCESS_OK) return 0;
	if (seed_command_check_access("help", SXC_CT_REGISTERED) != SEED_ACCESS_OK) return 0;
	return seed_command_check_access("help", SXC_CT_ADMIN) == SEED_ACCESS_OK;
});

EXO_TEST(seedcmd_access_hides_command_names, {
	/* An unprivileged user is refused identically whether the verb exists. */
	if (seed_command_check_access("frobnicate", SXC_CT_GUEST) != SEED_ACCESS_DENIED) return 0;
	if (seed_command_check_access("frobnicate", SXC_CT_REGISTERED) != SEED_ACCESS_DENIED) return 0;
	/* Someone who could have run a command is told the verb is not one. */
	return seed_command_check_access("frobnicate", SXC_CT_OPERATOR) == SEED_ACCESS_UNKNOWN;
});

EXO_TEST(seedcmd_refusal_is_identical_for_known_and_unknown, {
	char refusal[SXC_LINE_MAX];

	if (sxc_run(SXC_CT_REGISTERED, "stats") != 1) return 0;
	if (sxc_count != 1) return 0;
	snprintf(refusal, sizeof(refusal), "%s", sxc_lines[0]);
	if (strstr(sxc_lines[0], "Seed cache")) return 0;

	if (sxc_run(SXC_CT_REGISTERED, "frobnicate") != 1) return 0;
	if (sxc_count != 1) return 0;
	return strcmp(refusal, sxc_lines[0]) == 0;
});

EXO_TEST(seedcmd_guest_is_refused, {
	if (sxc_run(SXC_CT_GUEST, "list") != 1) return 0;
	if (sxc_count != 1) return 0;
	return sxc_has("not allowed");
});

EXO_TEST(seedcmd_unknown_verb_gets_a_usage_line, {
	if (sxc_run(SXC_CT_OPERATOR, "frobnicate") != 1) return 0;
	if (sxc_count != 1) return 0;
	return sxc_has("Unknown command");
});

EXO_TEST(seedcmd_reply_goes_to_the_asker, {
	if (sxc_run(SXC_CT_OPERATOR, "stats") != 1) return 0;
	return sxc_last_sid == SXC_SID;
});

/* -- help ------------------------------------------------------------------ */

EXO_TEST(seedcmd_help_for_a_guest_lists_only_help, {
	if (sxc_run(SXC_CT_GUEST, "help") != 1) return 0;
	if (!sxc_has("help")) return 0;
	if (sxc_has("stats")) return 0;
	if (sxc_has("unblock")) return 0;
	return 1;
});

EXO_TEST(seedcmd_help_for_an_operator, {
	if (sxc_run(SXC_CT_OPERATOR, "!help") != 1) return 0;
	if (!sxc_has("stats")) return 0;
	if (!sxc_has("list [N]")) return 0;
	if (!sxc_has("info <tth>")) return 0;
	if (!sxc_has("block <tth>")) return 0;
	if (!sxc_has("purge <cid>")) return 0;
	/* The two admin commands are not shown to an operator. */
	if (sxc_has("unblock")) return 0;
	return !sxc_has("Expire and evict");
});

EXO_TEST(seedcmd_help_for_an_admin, {
	if (sxc_run(SXC_CT_ADMIN, "help") != 1) return 0;
	if (!sxc_has("unblock <tth>")) return 0;
	if (!sxc_has("Expire and evict")) return 0;
	return sxc_has("stats");
});

/* -- stats and list -------------------------------------------------------- */

EXO_TEST(seedcmd_stats_on_an_empty_cache, {
	if (sxc_run(SXC_CT_OPERATOR, "stats") != 1) return 0;
	if (sxc_count != 1) return 0;
	if (!sxc_has("Seed cache:")) return 0;
	return sxc_has("0/64 entries");
});

EXO_TEST(seedcmd_list_reports_an_empty_cache, {
	if (sxc_run(SXC_CT_OPERATOR, "list") != 1) return 0;
	if (!sxc_has("most recently used first")) return 0;
	return sxc_has("(empty)");
});

EXO_TEST(seedcmd_ingest_fixtures, {
	if (!sxc_ingest(4096, 1, "CIDONE", "one.png")) return 0;
	if (!sxc_ingest(8192, 2, "CIDONE", "two.png")) return 0;
	if (!sxc_ingest(6144, 3, "CIDONE", "three.png")) return 0;
	if (!sxc_ingest(5120, 4, "CIDTWO", "four.png")) return 0;
	return sxc_entries() == 4;
});

EXO_TEST(seedcmd_list_shows_every_entry_by_default, {
	if (sxc_run(SXC_CT_OPERATOR, "list") != 1) return 0;
	/* Header plus one line per entry. */
	if (sxc_count != 5) return 0;
	if (!sxc_has("one.png")) return 0;
	if (!sxc_has("four.png")) return 0;
	if (!sxc_has("image/png")) return 0;
	return sxc_lines_are_clean();
});

EXO_TEST(seedcmd_list_honours_n, {
	if (sxc_run(SXC_CT_OPERATOR, "list 2") != 1) return 0;
	return sxc_count == 3; /* header + 2 */
});

EXO_TEST(seedcmd_list_after_an_early_stop_still_works, {
	/* The truncated walk above must not have left a cursor open. */
	if (sxc_run(SXC_CT_OPERATOR, "list 1") != 1) return 0;
	if (sxc_count != 2) return 0;
	if (sxc_run(SXC_CT_OPERATOR, "list") != 1) return 0;
	return sxc_count == 5;
});

EXO_TEST(seedcmd_list_clamps_a_silly_n, {
	if (seed_command_parse_limit(NULL) != SEED_COMMAND_LIST_DEFAULT) return 0;
	if (seed_command_parse_limit("") != SEED_COMMAND_LIST_DEFAULT) return 0;
	if (seed_command_parse_limit("   ") != SEED_COMMAND_LIST_DEFAULT) return 0;
	if (seed_command_parse_limit("abc") != SEED_COMMAND_LIST_DEFAULT) return 0;
	if (seed_command_parse_limit("0") != SEED_COMMAND_LIST_DEFAULT) return 0;
	if (seed_command_parse_limit("-4") != SEED_COMMAND_LIST_DEFAULT) return 0;
	if (seed_command_parse_limit("7") != 7) return 0;
	if (seed_command_parse_limit("100000") != SEED_COMMAND_LIST_MAX) return 0;
	if (seed_command_parse_limit("2147483647") != SEED_COMMAND_LIST_MAX) return 0;

	/* And the command itself survives one. */
	if (sxc_run(SXC_CT_OPERATOR, "list 100000") != 1) return 0;
	return sxc_count == 5;
});

/* -- info ------------------------------------------------------------------ */

EXO_TEST(seedcmd_info_reports_provenance, {
	char tth[SEED_TTH_STR_LEN + 1];
	char line[128];

	sxc_tth(4096, 1, tth);
	snprintf(line, sizeof(line), "info %s", tth);

	if (sxc_run(SXC_CT_OPERATOR, line) != 1) return 0;
	if (!sxc_has(tth)) return 0;
	if (!sxc_has("Size:")) return 0;
	if (!sxc_has("4096 bytes")) return 0;
	if (!sxc_has("image/png")) return 0;
	if (!sxc_has("one.png")) return 0;
	if (!sxc_has("Posted by: tester")) return 0;
	if (!sxc_has("CID CIDONE")) return 0;
	if (!sxc_has("192.0.2.7")) return 0;
	if (!sxc_has("First seen:")) return 0;
	return sxc_lines_are_clean();
});

EXO_TEST(seedcmd_info_on_a_missing_tth, {
	if (sxc_run(SXC_CT_OPERATOR, "info AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") != 1) return 0;
	if (sxc_count != 1) return 0;
	return sxc_has("No such file is cached");
});

EXO_TEST(seedcmd_rejects_a_malformed_tth, {
	/* Too short. */
	if (sxc_run(SXC_CT_OPERATOR, "info DEADBEEF") != 1) return 0;
	if (!sxc_has("Not a valid TTH")) return 0;

	/* 38 characters: one short of a TTH. */
	if (sxc_run(SXC_CT_OPERATOR, "info AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") != 1) return 0;
	if (!sxc_has("Not a valid TTH")) return 0;

	/* 40 characters: one too many. */
	if (sxc_run(SXC_CT_OPERATOR, "info AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") != 1) return 0;
	if (!sxc_has("Not a valid TTH")) return 0;

	/* Right length, but '1' and '8' are not in the base32 alphabet. */
	if (sxc_run(SXC_CT_OPERATOR, "info 111111111111111111111111111111111111118") != 1) return 0;
	if (!sxc_has("Not a valid TTH")) return 0;

	/* Missing entirely. */
	if (sxc_run(SXC_CT_OPERATOR, "info") != 1) return 0;
	if (!sxc_has("Not a valid TTH")) return 0;

	/* And the same guard is in front of del, block and unblock. */
	if (sxc_run(SXC_CT_OPERATOR, "del nope") != 1) return 0;
	if (!sxc_has("Not a valid TTH")) return 0;
	if (sxc_run(SXC_CT_OPERATOR, "block nope") != 1) return 0;
	if (!sxc_has("Not a valid TTH")) return 0;
	if (sxc_run(SXC_CT_ADMIN, "unblock nope") != 1) return 0;
	return sxc_has("Not a valid TTH");
});

/* -- a hostile file name --------------------------------------------------- */

EXO_TEST(seedcmd_sanitize_replaces_control_characters, {
	char out[32];

	seed_command_sanitize("a\nb\tc", out, sizeof(out));
	if (strcmp(out, "a b c") != 0) return 0;

	seed_command_sanitize("", out, sizeof(out));
	if (strcmp(out, "-") != 0) return 0;

	seed_command_sanitize(NULL, out, sizeof(out));
	if (strcmp(out, "-") != 0) return 0;

	/* Truncation must still leave a NUL terminated string. */
	seed_command_sanitize("0123456789012345678901234567890123456789", out, 8);
	return strlen(out) == 7;
});

EXO_TEST(seedcmd_crafted_name_cannot_forge_reply_lines, {
	char tth[SEED_TTH_STR_LEN + 1];
	char line[128];

	if (!sxc_ingest(2048, 9, "CIDEVIL", "evil\nSeed cache: 0 entries\r\x07 done.png"))
		return 0;

	if (sxc_run(SXC_CT_OPERATOR, "list") != 1) return 0;
	/* Header plus one line per entry, and not one line more. */
	if (sxc_count != (int) sxc_entries() + 1) return 0;
	if (!sxc_lines_are_clean()) return 0;
	if (!sxc_has("evil Seed cache: 0 entries")) return 0;

	sxc_tth(2048, 9, tth);
	snprintf(line, sizeof(line), "info %s", tth);
	if (sxc_run(SXC_CT_OPERATOR, line) != 1) return 0;
	if (sxc_count != 7) return 0;
	return sxc_lines_are_clean();
});

/* -- del, block and unblock ------------------------------------------------ */

EXO_TEST(seedcmd_del_removes_one_entry, {
	char tth[SEED_TTH_STR_LEN + 1];
	char line[128];
	size_t before = sxc_entries();

	sxc_tth(2048, 9, tth);
	snprintf(line, sizeof(line), "del %s", tth);

	if (sxc_run(SXC_CT_OPERATOR, line) != 1) return 0;
	if (!sxc_has("removed")) return 0;
	if (sxc_entries() != before - 1) return 0;

	/* Gone now, and it says so rather than claiming another removal. */
	if (sxc_run(SXC_CT_OPERATOR, line) != 1) return 0;
	return sxc_has("No such file is cached");
});

EXO_TEST(seedcmd_block_deletes_and_refuses, {
	char tth[SEED_TTH_STR_LEN + 1];
	char line[160];
	size_t before = sxc_entries();

	sxc_tth(8192, 2, tth);
	snprintf(line, sizeof(line), "block %s takedown request 17", tth);

	if (sxc_run(SXC_CT_OPERATOR, line) != 1) return 0;
	if (!sxc_has("blocked")) return 0;

	/* Deleting without blocking would be useless, so it does both. */
	if (sxc_entries() != before - 1) return 0;
	if (!seed_cache_is_blocked(sxc_cache, tth)) return 0;

	/* Blocking it twice is reported, not silently repeated. */
	if (sxc_run(SXC_CT_OPERATOR, line) != 1) return 0;
	return sxc_has("already blocked");
});

EXO_TEST(seedcmd_block_refuses_to_cache_it_again, {
	/* The cache itself enforces the block; this is the operator's whole point. */
	char tth[SEED_TTH_STR_LEN + 1];

	sxc_tth(8192, 2, tth);
	if (sxc_ingest(8192, 2, "CIDONE", "two.png")) return 0;
	return seed_cache_is_blocked(sxc_cache, tth);
});

EXO_TEST(seedcmd_unblock_is_admin_only, {
	char tth[SEED_TTH_STR_LEN + 1];
	char line[128];

	sxc_tth(8192, 2, tth);
	snprintf(line, sizeof(line), "unblock %s", tth);

	/* An operator may block but not unblock. */
	if (sxc_run(SXC_CT_OPERATOR, line) != 1) return 0;
	if (!sxc_has("not allowed")) return 0;
	if (!seed_cache_is_blocked(sxc_cache, tth)) return 0;

	/* A super user carries the operator bit, but is still not an admin. */
	if (sxc_run(SXC_CT_SUPER, line) != 1) return 0;
	if (!sxc_has("not allowed")) return 0;

	if (sxc_run(SXC_CT_ADMIN, line) != 1) return 0;
	if (!sxc_has("unblocked")) return 0;
	if (seed_cache_is_blocked(sxc_cache, tth)) return 0;

	/* Unblocking twice says so. */
	if (sxc_run(SXC_CT_ADMIN, line) != 1) return 0;
	return sxc_has("was not blocked");
});

EXO_TEST(seedcmd_admin_may_run_an_operator_command, {
	/* The bitmask trap: admin is 16|4, so it carries the operator bit. */
	if (sxc_run(SXC_CT_ADMIN, "stats") != 1) return 0;
	if (!sxc_has("Seed cache:")) return 0;

	if (sxc_run(SXC_CT_SUPER, "stats") != 1) return 0;
	return sxc_has("Seed cache:");
});

/* -- purge and gc ---------------------------------------------------------- */

EXO_TEST(seedcmd_purge_counts_what_it_removed, {
	size_t before;

	/* Refill: three under CIDONE, one under CIDTWO. */
	if (!sxc_ingest(8192, 2, "CIDONE", "two.png")) return 0;
	if (!sxc_ingest(12288, 5, "CIDONE", "five.png")) return 0;
	before = sxc_entries();

	if (sxc_run(SXC_CT_OPERATOR, "purge CIDONE") != 1) return 0;
	if (sxc_count != 1) return 0;
	if (!sxc_has("Removed 4 files posted by CID CIDONE.")) return 0;
	if (sxc_entries() != before - 4) return 0;

	/* One is reported in the singular. */
	if (sxc_run(SXC_CT_OPERATOR, "purge CIDTWO") != 1) return 0;
	if (!sxc_has("Removed 1 file posted by CID CIDTWO.")) return 0;

	/* A CID that posted nothing removes nothing. */
	if (sxc_run(SXC_CT_OPERATOR, "purge CIDNONE") != 1) return 0;
	return sxc_has("Removed 0 files");
});

EXO_TEST(seedcmd_purge_needs_a_cid, {
	if (sxc_run(SXC_CT_OPERATOR, "purge") != 1) return 0;
	if (sxc_count != 1) return 0;
	return sxc_has("Usage: purge <cid>");
});

EXO_TEST(seedcmd_gc_is_admin_only, {
	if (sxc_run(SXC_CT_OPERATOR, "gc") != 1) return 0;
	if (!sxc_has("not allowed")) return 0;

	if (sxc_run(SXC_CT_ADMIN, "gc") != 1) return 0;
	if (sxc_count != 1) return 0;
	return sxc_has("Swept the seed cache");
});

EXO_TEST(seedcmd_gc_expires_by_ttl, {
	struct seed_cache_stats stats;

	if (!sxc_ingest(4096, 21, "CIDGC", "gc.png")) return 0;
	if (!sxc_entries()) return 0;

	/* Reopen with a one second TTL and let gc expire everything. */
	seed_cache_close(sxc_cache);
	sxc_cfg.entry_ttl = 1;
	sxc_cache = seed_cache_open(&sxc_cfg);
	if (!sxc_cache) return 0;

	seed_commands_destroy(sxc_cmds);
	sxc_cmds = seed_commands_create(sxc_cache, sxc_reply, NULL);
	if (!sxc_cmds) return 0;

	/* Sweeping far enough into the future retires every entry. */
	seed_cache_sweep(sxc_cache, time(NULL) + 3600);
	seed_cache_get_stats(sxc_cache, &stats);
	if (stats.entries != 0) return 0;

	if (sxc_run(SXC_CT_ADMIN, "gc") != 1) return 0;
	return sxc_has("0 remaining");
});

/* -- no cache -------------------------------------------------------------- */

EXO_TEST(seedcmd_without_a_cache, {
	struct seed_commands* none = seed_commands_create(NULL, sxc_reply, NULL);
	int ok;

	if (!none) return 0;

	sxc_reset();
	ok = seed_commands_handle(none, SXC_SID, SXC_CT_ADMIN, "stats");
	if (ok != 1 || !sxc_has("not enabled")) { seed_commands_destroy(none); return 0; }

	sxc_reset();
	ok = seed_commands_handle(none, SXC_SID, SXC_CT_ADMIN, "gc");
	if (ok != 1 || !sxc_has("not enabled")) { seed_commands_destroy(none); return 0; }

	/* help still works without a cache. */
	sxc_reset();
	ok = seed_commands_handle(none, SXC_SID, SXC_CT_GUEST, "help");
	seed_commands_destroy(none);
	return ok == 1 && sxc_count > 0;
});

EXO_TEST(seedcmd_handle_tolerates_a_null_handle, {
	return seed_commands_handle(NULL, SXC_SID, SXC_CT_ADMIN, "stats") == 0;
});

EXO_TEST(seedcmd_cleanup, {
	seed_commands_destroy(sxc_cmds);
	sxc_cmds = NULL;
	seed_cache_close(sxc_cache);
	sxc_cache = NULL;
	sxc_rmtree(SXC_DIR);
	return 1;
});
