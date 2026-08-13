#include "system.h"

#include <dirent.h>
#include <sys/stat.h>

#include "seeder/cache.h"
#include "seeder/embed.h"
#include "seeder/hubconn.h" /* SEED_CT_*: the bits seed_ingest_ct_permitted() reads */
#include "seeder/ingest.h"
#include "util/memory.h"
#include "util/tth.h"

/*
 * The seeder's ingest policy layer (seeder/ingest.c): the part that decides
 * what the daemon goes and fetches, as opposed to the parts that know how.
 *
 * Everything worth testing here is a decision, so every decision is behind a
 * pure function and is driven directly. Two of them touch a real (small) seed
 * cache -- there is no way to test "already held" or "an operator blocked it"
 * without a cache that holds and blocks -- but none of them touches a socket,
 * a hub connection or a grant table.
 */

#define SI_DIR "test_seedingest.tmp"

/* Well formed TTHs: exactly 39 characters from the base32 alphabet. */
#define SI_TTH1 "OZ4V2GDGZLGXQKAWXQBDIT4KM7HRFCWHMLPEXAI"
#define SI_TTH2 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define SI_TTH3 "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
#define SI_TTH4 "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
#define SI_TTH5 "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"

static struct seed_cache* si_cache = NULL;
static struct seed_embed  si_embeds[SEED_INGEST_MAX_PER_MESSAGE];
static struct seed_ingest_url si_urls[SEED_INGEST_MAX_PER_MESSAGE];
static uint8_t si_data[8192];

/* --- helpers -------------------------------------------------------------- */

static void si_rmtree(const char* path)
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
			si_rmtree(child);
		else
			unlink(child);
	}
	closedir(dir);
	rmdir(path);
}

/* A buffer that sniffs as image/png, so it passes the default allowlist. */
static void si_make_png(uint8_t* buf, size_t len)
{
	static const uint8_t magic[8] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
	uint32_t x = 1;
	size_t i;

	memcpy(buf, magic, (len < 8) ? len : 8);
	for (i = 8; i < len; i++)
	{
		x = (x * 1103515245u) + 12345u;
		buf[i] = (uint8_t) (x >> 16);
	}
}

/* Put si_data into the cache and report the TTH it landed under. */
static int si_ingest(char out[SEED_TTH_STR_LEN + 1])
{
	struct seed_ingest_request req;
	struct seed_ingest* job;
	enum seed_error err = SEED_OK;
	uint8_t root[TTH_SIZE];

	si_make_png(si_data, sizeof(si_data));
	tth(si_data, sizeof(si_data), root);
	tth_to_string(root, out);

	memset(&req, 0, sizeof(req));
	req.expect_tth = out;
	req.announced_size = sizeof(si_data);
	req.name = "shot.png";
	req.origin_cid = "CIDAAA";

	job = seed_ingest_begin(si_cache, &req, &err);
	if (!job)
		return 0;

	if (seed_ingest_write(job, si_data, sizeof(si_data)) != 0)
	{
		seed_ingest_abort(job, SEED_ERR_IO);
		return 0;
	}

	return seed_ingest_finish(job, NULL, &err);
}

/*
 * Build "![name](magnet:?xt=urn:tree:tiger:<tth>&xl=<size>)".
 *
 * The result rotates through several buffers so that a single expression may
 * name more than one magnet -- with one static buffer every argument of a
 * snprintf() would end up pointing at the same, last, string.
 */
static const char* si_magnet(const char* tth)
{
	static char bufs[8][256];
	static size_t next = 0;
	char* buf = bufs[next];

	next = (next + 1) % 8;
	snprintf(buf, sizeof(bufs[0]), "![shot.png](magnet:?xt=urn:tree:tiger:%s&xl=4096&dn=shot.png)", tth);
	return buf;
}

static size_t si_select(const char* text)
{
	memset(si_embeds, 0, sizeof(si_embeds));
	return seed_ingest_select(si_cache, text, si_embeds, SEED_INGEST_MAX_PER_MESSAGE);
}

static size_t si_scan_urls(const char* text)
{
	memset(si_urls, 0, sizeof(si_urls));
	return seed_ingest_scan_urls(text, si_urls, SEED_INGEST_MAX_PER_MESSAGE);
}

/* --- the constants the tests depend on ------------------------------------ */

EXO_TEST(seedingest_tth_constants_are_well_formed, {
	return strlen(SI_TTH1) == SEED_TTH_STR_LEN &&
	       strlen(SI_TTH2) == SEED_TTH_STR_LEN &&
	       strlen(SI_TTH3) == SEED_TTH_STR_LEN &&
	       strlen(SI_TTH4) == SEED_TTH_STR_LEN &&
	       strlen(SI_TTH5) == SEED_TTH_STR_LEN;
});

/* --- CT bits to seed_min_credentials -------------------------------------- */

/* "guest" is the floor: anyone who can post at all, CT bits or none. */
EXO_TEST(seedingest_cred_guest_accepts_anyone, {
	return seed_ingest_ct_permitted(0, "guest") == 1
		&& seed_ingest_ct_permitted(SEED_CT_REGISTERED, "guest") == 1
		&& seed_ingest_ct_permitted(SEED_CT_ADMIN | SEED_CT_OPERATOR, "guest") == 1;
});

EXO_TEST(seedingest_cred_user_refuses_unregistered, {
	return seed_ingest_ct_permitted(0, "user") == 0;
});

/* A bot is not a registered user; the bit says what it is, not what it may do. */
EXO_TEST(seedingest_cred_user_refuses_bare_bot, {
	return seed_ingest_ct_permitted(SEED_CT_BOT, "user") == 0;
});

EXO_TEST(seedingest_cred_user_accepts_registered, {
	return seed_ingest_ct_permitted(SEED_CT_REGISTERED, "user") == 1;
});

/* ...and everything above it, which in CT terms means any of the higher bits. */
EXO_TEST(seedingest_cred_user_accepts_higher, {
	return seed_ingest_ct_permitted(SEED_CT_OPERATOR, "user") == 1
		&& seed_ingest_ct_permitted(12, "user") == 1
		&& seed_ingest_ct_permitted(20, "user") == 1;
});

EXO_TEST(seedingest_cred_operator_refuses_registered, {
	return seed_ingest_ct_permitted(SEED_CT_REGISTERED, "operator") == 0;
});

EXO_TEST(seedingest_cred_operator_accepts_operator, {
	return seed_ingest_ct_permitted(SEED_CT_OPERATOR, "operator") == 1
		&& seed_ingest_ct_permitted(SEED_CT_REGISTERED | SEED_CT_OPERATOR, "operator") == 1;
});

/*
 * The mask cases this exists for. CT is a set of flags and not a rank: a super
 * user is 12 (8|4) and an admin is 20 (16|4), so both carry the operator bit
 * while neither is equal to it. An equality test would refuse an admin.
 */
EXO_TEST(seedingest_cred_operator_accepts_super_and_admin_masks, {
	return seed_ingest_ct_permitted(12, "operator") == 1
		&& seed_ingest_ct_permitted(20, "operator") == 1;
});

EXO_TEST(seedingest_cred_super_refuses_plain_operator, {
	return seed_ingest_ct_permitted(SEED_CT_OPERATOR, "super") == 0
		&& seed_ingest_ct_permitted(SEED_CT_REGISTERED, "super") == 0;
});

EXO_TEST(seedingest_cred_super_accepts_super, {
	return seed_ingest_ct_permitted(12, "super") == 1;
});

/* An admin (20) carries no super bit, but outranks a super user, so it passes. */
EXO_TEST(seedingest_cred_super_accepts_admin, {
	return seed_ingest_ct_permitted(20, "super") == 1;
});

EXO_TEST(seedingest_cred_admin_refuses_super, {
	return seed_ingest_ct_permitted(12, "admin") == 0
		&& seed_ingest_ct_permitted(SEED_CT_OPERATOR, "admin") == 0;
});

EXO_TEST(seedingest_cred_admin_accepts_admin, {
	return seed_ingest_ct_permitted(20, "admin") == 1
		&& seed_ingest_ct_permitted(SEED_CT_ADMIN, "admin") == 1;
});

/* Anything unrecognised, empty or unset falls back to "user". */
EXO_TEST(seedingest_cred_unknown_falls_back_to_user, {
	return seed_ingest_ct_permitted(0, "wizard") == 0
		&& seed_ingest_ct_permitted(SEED_CT_REGISTERED, "wizard") == 1
		&& seed_ingest_ct_permitted(0, "") == 0
		&& seed_ingest_ct_permitted(SEED_CT_REGISTERED, "") == 1
		&& seed_ingest_ct_permitted(0, NULL) == 0
		&& seed_ingest_ct_permitted(SEED_CT_REGISTERED, NULL) == 1;
});

/* The names are matched without regard to case, as the config parser is. */
EXO_TEST(seedingest_cred_names_are_case_insensitive, {
	return seed_ingest_ct_permitted(0, "GUEST") == 1
		&& seed_ingest_ct_permitted(SEED_CT_OPERATOR, "Operator") == 1;
});

/* --- selecting what to ask for -------------------------------------------- */

EXO_TEST(seedingest_setup, {
	struct seed_cache_config cfg;

	si_rmtree(SI_DIR);
	memset(&cfg, 0, sizeof(cfg));
	cfg.dir = SI_DIR;
	cfg.max_bytes = 1024 * 1024;
	cfg.max_file_size = 1024 * 1024;
	cfg.max_entries = 32;
	cfg.max_concurrent_ingest = 4;

	si_cache = seed_cache_open(&cfg);
	return si_cache != NULL;
});

/* Nothing to scan is not an error, it is just nothing. */
EXO_TEST(seedingest_select_no_embeds, {
	return si_select("hello, world") == 0
		&& si_select("") == 0;
});

EXO_TEST(seedingest_select_null_text_is_safe, {
	return seed_ingest_select(si_cache, NULL, si_embeds, SEED_INGEST_MAX_PER_MESSAGE) == 0;
});

EXO_TEST(seedingest_select_without_cache_selects_nothing, {
	return seed_ingest_select(NULL, si_magnet(SI_TTH1), si_embeds, SEED_INGEST_MAX_PER_MESSAGE) == 0;
});

EXO_TEST(seedingest_select_finds_one, {
	return si_select(si_magnet(SI_TTH1)) == 1
		&& strcmp(si_embeds[0].tth, SI_TTH1) == 0
		&& si_embeds[0].size == 4096
		&& strcmp(si_embeds[0].name, "shot.png") == 0;
});

/*
 * A magnet with no usable "xt" is not an embed at all. The scanner discards the
 * whole thing rather than emitting a partial entry, so a truncated or misspelt
 * topic produces no request instead of a request for nothing.
 */
EXO_TEST(seedingest_select_malformed_magnet, {
	return si_select("![x](magnet:?xt=urn:tree:tiger:TOOSHORT&xl=1)") == 0
		&& si_select("![x](magnet:?xt=urn:sha1:" SI_TTH1 ")") == 0
		&& si_select("![x](magnet:?xl=4096&dn=shot.png)") == 0
		&& si_select("![x](magnet:?xt=urn:tree:tiger:") == 0
		/* '1' and '8' are not in the base32 alphabet. */
		&& si_select("![x](magnet:?xt=urn:tree:tiger:1118AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)") == 0;
});

/* At most SEED_INGEST_MAX_PER_MESSAGE, however many were posted. */
EXO_TEST(seedingest_select_caps_per_message, {
	char text[2048];
	snprintf(text, sizeof(text), "%s %s %s %s %s",
		si_magnet(SI_TTH1), si_magnet(SI_TTH2), si_magnet(SI_TTH3),
		si_magnet(SI_TTH4), si_magnet(SI_TTH5));
	return si_select(text) == SEED_INGEST_MAX_PER_MESSAGE;
});

/* ...and a caller with less room than that gets no more than it asked for. */
EXO_TEST(seedingest_select_honours_a_smaller_max, {
	char text[2048];
	snprintf(text, sizeof(text), "%s %s %s", si_magnet(SI_TTH1), si_magnet(SI_TTH2), si_magnet(SI_TTH3));
	memset(si_embeds, 0, sizeof(si_embeds));
	return seed_ingest_select(si_cache, text, si_embeds, 1) == 1
		&& seed_ingest_select(si_cache, text, si_embeds, 0) == 0;
});

/* The same file posted twice in one line is asked for once. */
EXO_TEST(seedingest_select_deduplicates, {
	char text[1024];
	snprintf(text, sizeof(text), "%s and again %s", si_magnet(SI_TTH1), si_magnet(SI_TTH1));
	return si_select(text) == 1;
});

/* An operator said no: never ask for it again, and say so before looking it up. */
EXO_TEST(seedingest_select_skips_blocked, {
	char text[1024];

	if (!seed_cache_block(si_cache, SI_TTH2, "op", "dmca"))
		return 0;

	if (si_select(si_magnet(SI_TTH2)) != 0)
		return 0;

	/* The other embeds in the same message are unaffected. */
	snprintf(text, sizeof(text), "%s %s", si_magnet(SI_TTH2), si_magnet(SI_TTH3));
	return si_select(text) == 1 && strcmp(si_embeds[0].tth, SI_TTH3) == 0;
});

/* Already held: nothing to ask anyone for. */
EXO_TEST(seedingest_select_skips_cached, {
	char cached[SEED_TTH_STR_LEN + 1];
	char text[1024];

	if (!si_ingest(cached))
		return 0;
	if (!seed_cache_peek(si_cache, cached, NULL))
		return 0;

	if (si_select(si_magnet(cached)) != 0)
		return 0;

	snprintf(text, sizeof(text), "%s %s", si_magnet(cached), si_magnet(SI_TTH4));
	return si_select(text) == 1 && strcmp(si_embeds[0].tth, SI_TTH4) == 0;
});

/*
 * Scanning a message must not count as an access. seed_ingest_select() inspects
 * with peek(), so a file that is only ever talked about does not climb the LRU
 * and is not kept alive by chatter.
 */
EXO_TEST(seedingest_select_does_not_count_an_access, {
	char cached[SEED_TTH_STR_LEN + 1];
	struct seed_entry before;
	struct seed_entry after;

	if (!si_ingest(cached))
		return 0;
	if (!seed_cache_peek(si_cache, cached, &before))
		return 0;

	si_select(si_magnet(cached));

	return seed_cache_peek(si_cache, cached, &after) && after.hits == before.hits;
});

/* --- URL embeds ----------------------------------------------------------- */

EXO_TEST(seedingest_urls_none, {
	return si_scan_urls("hello, world") == 0
		&& si_scan_urls("") == 0
		&& seed_ingest_scan_urls(NULL, si_urls, SEED_INGEST_MAX_PER_MESSAGE) == 0;
});

EXO_TEST(seedingest_urls_image_embed, {
	return si_scan_urls("look: ![cat.png](https://cdn.example.org/cat.png) nice")  == 1
		&& strcmp(si_urls[0].url, "https://cdn.example.org/cat.png") == 0
		&& strcmp(si_urls[0].name, "cat.png") == 0;
});

/*
 * A plain link is a link to a page. Following it would make the seeder a
 * general purpose web fetcher aimed by whoever is typing.
 */
EXO_TEST(seedingest_urls_plain_link_is_not_mirrored, {
	return si_scan_urls("[docs](https://example.org/page.html)") == 0;
});

/* A magnet embed is not a URL embed, and vice versa. */
EXO_TEST(seedingest_urls_ignore_magnets, {
	return si_scan_urls(si_magnet(SI_TTH1)) == 0
		&& si_select("![cat.png](https://cdn.example.org/cat.png)") == 0;
});

EXO_TEST(seedingest_urls_capped, {
	return si_scan_urls(
		"![a](http://e.org/a.png) ![b](http://e.org/b.png) "
		"![c](http://e.org/c.png) ![d](http://e.org/d.png) "
		"![e](http://e.org/e.png)") == SEED_INGEST_MAX_PER_MESSAGE;
});

/*
 * Truncated constructs are legal input: the scanner is total, so each of these
 * either yields nothing or yields a string that is not a fetchable URL -- which
 * seed_url_parse() refuses in seeder/fetch.c. What must never happen is a read
 * past the end or a crash.
 */
EXO_TEST(seedingest_urls_truncated_is_safe, {
	return si_scan_urls("![a](htt") == 0             /* no anchor at all */
		&& si_scan_urls("![a](http") == 1            /* "http": parses to nothing */
		&& si_scan_urls("![a](http://") == 1
		&& si_scan_urls("](http://e.org/a.png)") == 0 /* no label */
		&& si_scan_urls("![](http://e.org/a.png)") == 1
		&& si_scan_urls("![a](httpx://e.org/a.png)") == 1;
});

/* --- the trigger's own guards --------------------------------------------- */

EXO_TEST(seedingest_trigger_requires_everything, {
	return seed_ingest_trigger_create(NULL, NULL, NULL, NULL) == NULL
		&& seed_ingest_trigger_create(si_cache, NULL, NULL, NULL) == NULL;
});

EXO_TEST(seedingest_trigger_destroy_accepts_null, {
	seed_ingest_trigger_destroy(NULL);
	return seed_ingest_active_fetches(NULL) == 0;
});

EXO_TEST(seedingest_on_chat_accepts_null, {
	return seed_ingest_on_chat(NULL, NULL, "![x](magnet:?xt=urn:tree:tiger:" SI_TTH1 ")") == 0;
});

EXO_TEST(seedingest_cleanup, {
	seed_cache_close(si_cache);
	si_cache = NULL;
	si_rmtree(SI_DIR);
	return 1;
});
