#include "system.h"
#include "util/memory.h"
#include "seeder/config.h"

/*
 * Exercises the uhub-seeder.conf parser in src/seeder/config.c through its
 * public entry point seed_config_read(), which returns 1 on success and 0 on
 * any error (parse error, unknown key, out-of-range value, missing required
 * key). Expected-failure tests log a fatal message on stderr; that is the
 * parser doing its job, not the test failing.
 */

static const char* sc_test_file = "test_seedconfig.tmp";

/* The two keys with no default; every otherwise-valid file needs them. */
static const char* sc_required =
	"seed_hub_url = adcs://hub.example.org:1511/\n"
	"seed_password = s3cret\n";

static int sc_write_file(const char* contents)
{
	FILE* fh = fopen(sc_test_file, "wb");
	if (!fh) return 0;
	fwrite(contents, 1, strlen(contents), fh);
	fclose(fh);
	return 1;
}

/* Parse exactly the given file contents. */
static int sc_read_raw(const char* contents, struct seed_config* cfg)
{
	if (!sc_write_file(contents))
	{
		seed_config_defaults(cfg); /* so the caller's free() is still valid */
		return -1;
	}
	return seed_config_read(sc_test_file, cfg);
}

/* Parse the given contents with the required keys prepended. */
static int sc_read(const char* contents, struct seed_config* cfg)
{
	size_t len = strlen(sc_required) + strlen(contents) + 1;
	char* buf = (char*) hub_malloc(len);
	int ret;

	if (!buf)
	{
		seed_config_defaults(cfg);
		return -1;
	}

	memcpy(buf, sc_required, strlen(sc_required));
	memcpy(buf + strlen(sc_required), contents, strlen(contents) + 1);

	ret = sc_read_raw(buf, cfg);
	hub_free(buf);
	return ret;
}

/* Parse (with required keys) and assert only success. */
static int sc_ok(const char* contents)
{
	struct seed_config cfg;
	int ret = sc_read(contents, &cfg);
	seed_config_free(&cfg);
	return ret == 1;
}

/* Parse (with required keys) and assert only failure. */
static int sc_fail(const char* contents)
{
	struct seed_config cfg;
	int ret = sc_read(contents, &cfg);
	seed_config_free(&cfg);
	return ret == 0;
}

/*
 * An integer key must accept both ends of its documented range and reject the
 * value just outside either end.
 */
static int sc_range(const char* key, int lo, int hi)
{
	char line[128];
	int ok = 1;

	snprintf(line, sizeof(line), "%s = %d\n", key, lo);
	ok = ok && sc_ok(line);

	snprintf(line, sizeof(line), "%s = %d\n", key, hi);
	ok = ok && sc_ok(line);

	snprintf(line, sizeof(line), "%s = %d\n", key, lo - 1);
	ok = ok && sc_fail(line);

	snprintf(line, sizeof(line), "%s = %d\n", key, hi + 1);
	ok = ok && sc_fail(line);

	return ok;
}

/* -------------------------------------------------------------------------
 * Defaults
 * ------------------------------------------------------------------------- */

EXO_TEST(seedconfig_defaults_hub, {
	struct seed_config cfg;
	seed_config_defaults(&cfg);
	int ok = strcmp(cfg.seed_nick, "[seed]cache") == 0
	      && strcmp(cfg.seed_description, "seed cache") == 0
	      /* required keys have no default */
	      && cfg.seed_hub_url && !*cfg.seed_hub_url
	      && cfg.seed_password && !*cfg.seed_password;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_defaults_client, {
	struct seed_config cfg;
	seed_config_defaults(&cfg);
	int ok = cfg.seed_client_port == 1512
	      && strcmp(cfg.seed_client_bind_addr, "any") == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_defaults_tls, {
	struct seed_config cfg;
	seed_config_defaults(&cfg);
	int ok = cfg.seed_tls_certificate && !*cfg.seed_tls_certificate
	      && cfg.seed_tls_private_key && !*cfg.seed_tls_private_key
	      && strcmp(cfg.seed_tls_version, "1.2") == 0
	      /* The hub's defaults, so an operator has one set of strings to learn. */
	      && strncmp(cfg.seed_tls_ciphersuite, "ECDH+AESGCM:", 12) == 0
	      && strcmp(cfg.seed_tls_ciphersuites,
			"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256") == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_defaults_cache, {
	struct seed_config cfg;
	seed_config_defaults(&cfg);
	int ok = strcmp(cfg.seed_cache_dir, "/var/lib/uhub/seed") == 0
	      && cfg.seed_cache_size == 256
	      && cfg.seed_max_file_size == 2
	      && cfg.seed_max_entries == 4096
	      && cfg.seed_entry_ttl == 2592000
	      && cfg.seed_max_concurrent_ingest == 4
	      && cfg.seed_max_concurrent_upload == 16
	      && strcmp(cfg.seed_allowed_types, "image/png,image/jpeg,image/gif,image/webp") == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_defaults_ingest, {
	struct seed_config cfg;
	seed_config_defaults(&cfg);
	int ok = strcmp(cfg.seed_min_credentials, "user") == 0
	      && cfg.seed_ingest_interval == 300
	      && cfg.seed_ingest_per_user == 5
	      && cfg.seed_ingest_quota_kb == 32768;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_defaults_url, {
	struct seed_config cfg;
	seed_config_defaults(&cfg);
	int ok = cfg.seed_url_mirror == 0
	      && strcmp(cfg.seed_url_allow_ports, "80,443") == 0
	      && cfg.seed_url_max_redirects == 2
	      && cfg.seed_url_timeout == 30
	      && cfg.seed_url_allow_private == 0
	      && cfg.seed_url_verify_tls == 1
	      && cfg.seed_url_allow_hosts && !*cfg.seed_url_allow_hosts
	      && cfg.seed_url_deny_hosts && !*cfg.seed_url_deny_hosts;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_defaults_http, {
	struct seed_config cfg;
	seed_config_defaults(&cfg);
	int ok = cfg.seed_http_enable == 0
	      && cfg.seed_http_port == 1513;
	seed_config_free(&cfg);
	return ok;
});

/* A file that only sets the required keys leaves every other default alone. */
EXO_TEST(seedconfig_defaults_kept, {
	struct seed_config cfg;
	int ok = sc_read("", &cfg) == 1
	      && strcmp(cfg.seed_nick, "[seed]cache") == 0
	      && cfg.seed_http_port == 1513;
	seed_config_free(&cfg);
	return ok;
});

/* seed_config_free() is idempotent and safe to call twice. */
EXO_TEST(seedconfig_free_idempotent, {
	struct seed_config cfg;
	seed_config_defaults(&cfg);
	seed_config_free(&cfg);
	seed_config_free(&cfg);
	return cfg.seed_nick == NULL;
});

/* -------------------------------------------------------------------------
 * Values are stored where they belong
 * ------------------------------------------------------------------------- */

EXO_TEST(seedconfig_required_stored, {
	struct seed_config cfg;
	int ok = sc_read("", &cfg) == 1
	      && strcmp(cfg.seed_hub_url, "adcs://hub.example.org:1511/") == 0
	      && strcmp(cfg.seed_password, "s3cret") == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_string_stored, {
	struct seed_config cfg;
	int ok = sc_read("seed_cache_dir = /srv/seed\n", &cfg) == 1
	      && strcmp(cfg.seed_cache_dir, "/srv/seed") == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_integer_stored, {
	struct seed_config cfg;
	int ok = sc_read("seed_client_port = 2048\n", &cfg) == 1
	      && cfg.seed_client_port == 2048;
	seed_config_free(&cfg);
	return ok;
});

/* Whitespace around key and value is stripped. */
EXO_TEST(seedconfig_whitespace, {
	struct seed_config cfg;
	int ok = sc_read("   seed_client_port   =   4096   \n", &cfg) == 1
	      && cfg.seed_client_port == 4096;
	seed_config_free(&cfg);
	return ok;
});

/* An unquoted multi-word value survives, with whitespace runs collapsed. */
EXO_TEST(seedconfig_multiword_value, {
	struct seed_config cfg;
	int ok = sc_read("seed_description = my   seed cache\n", &cfg) == 1
	      && strcmp(cfg.seed_description, "my seed cache") == 0;
	seed_config_free(&cfg);
	return ok;
});

/* A quoted value keeps its exact interior spacing. */
EXO_TEST(seedconfig_quoted_value, {
	struct seed_config cfg;
	int ok = sc_read("seed_description = \"  spaced  out  \"\n", &cfg) == 1
	      && strcmp(cfg.seed_description, "  spaced  out  ") == 0;
	seed_config_free(&cfg);
	return ok;
});

/* A last key wins over an earlier one. */
EXO_TEST(seedconfig_last_wins, {
	struct seed_config cfg;
	int ok = sc_read("seed_nick = first\nseed_nick = second\n", &cfg) == 1
	      && strcmp(cfg.seed_nick, "second") == 0;
	seed_config_free(&cfg);
	return ok;
});

/* -------------------------------------------------------------------------
 * Integer ranges
 * ------------------------------------------------------------------------- */

EXO_TEST(seedconfig_range_client_port,      { return sc_range("seed_client_port", 1024, 65535); });
EXO_TEST(seedconfig_range_cache_size,       { return sc_range("seed_cache_size", 1, 1048576); });
EXO_TEST(seedconfig_range_max_file_size,    { return sc_range("seed_max_file_size", 1, 1024); });
EXO_TEST(seedconfig_range_max_entries,      { return sc_range("seed_max_entries", 1, 1000000); });
EXO_TEST(seedconfig_range_entry_ttl,        { return sc_range("seed_entry_ttl", 0, 315360000); });
EXO_TEST(seedconfig_range_conc_ingest,      { return sc_range("seed_max_concurrent_ingest", 1, 64); });
EXO_TEST(seedconfig_range_conc_upload,      { return sc_range("seed_max_concurrent_upload", 1, 1024); });
EXO_TEST(seedconfig_range_ingest_interval,  { return sc_range("seed_ingest_interval", 1, 86400); });
EXO_TEST(seedconfig_range_ingest_per_user,  { return sc_range("seed_ingest_per_user", 0, 1000); });
EXO_TEST(seedconfig_range_ingest_quota_kb,  { return sc_range("seed_ingest_quota_kb", 0, 1048576); });
EXO_TEST(seedconfig_range_url_redirects,    { return sc_range("seed_url_max_redirects", 0, 5); });
EXO_TEST(seedconfig_range_url_timeout,      { return sc_range("seed_url_timeout", 1, 120); });
EXO_TEST(seedconfig_range_http_port,        { return sc_range("seed_http_port", 1024, 65535); });

/* Out of range is rejected, not clamped: the config does not silently mean
   something other than what it says. */
EXO_TEST(seedconfig_int_not_clamped, {
	struct seed_config cfg;
	int ok = sc_read("seed_client_port = 70000\n", &cfg) == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_int_not_a_number,   { return sc_fail("seed_client_port = banana\n"); });
EXO_TEST(seedconfig_int_trailing_junk,  { return sc_fail("seed_client_port = 1512x\n"); });
EXO_TEST(seedconfig_int_empty,          { return sc_fail("seed_client_port =\n"); });
EXO_TEST(seedconfig_int_overflow,       { return sc_fail("seed_entry_ttl = 99999999999999999999\n"); });
EXO_TEST(seedconfig_int_hex_rejected,   { return sc_fail("seed_http_port = 0x1234\n"); });

/* -------------------------------------------------------------------------
 * Booleans
 * ------------------------------------------------------------------------- */

EXO_TEST(seedconfig_bool_yes, {
	struct seed_config cfg;
	int ok = sc_read("seed_url_mirror = yes\n", &cfg) == 1 && cfg.seed_url_mirror == 1;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_bool_no, {
	struct seed_config cfg;
	int ok = sc_read("seed_url_verify_tls = no\n", &cfg) == 1 && cfg.seed_url_verify_tls == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_bool_one, {
	struct seed_config cfg;
	int ok = sc_read("seed_http_enable = 1\n", &cfg) == 1 && cfg.seed_http_enable == 1;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_bool_zero, {
	struct seed_config cfg;
	int ok = sc_read("seed_url_verify_tls = 0\n", &cfg) == 1 && cfg.seed_url_verify_tls == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_bool_on, {
	struct seed_config cfg;
	int ok = sc_read("seed_url_allow_private = on\n", &cfg) == 1 && cfg.seed_url_allow_private == 1;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_bool_off, {
	struct seed_config cfg;
	int ok = sc_read("seed_url_verify_tls = off\n", &cfg) == 1 && cfg.seed_url_verify_tls == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_bool_true, {
	struct seed_config cfg;
	int ok = sc_read("seed_url_mirror = true\n", &cfg) == 1 && cfg.seed_url_mirror == 1;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_bool_false, {
	struct seed_config cfg;
	int ok = sc_read("seed_url_verify_tls = false\n", &cfg) == 1 && cfg.seed_url_verify_tls == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_bool_invalid,    { return sc_fail("seed_url_mirror = maybe\n"); });
EXO_TEST(seedconfig_bool_empty,      { return sc_fail("seed_http_enable =\n"); });

/* -------------------------------------------------------------------------
 * Enumerated string
 * ------------------------------------------------------------------------- */

EXO_TEST(seedconfig_cred_guest,    { return sc_ok("seed_min_credentials = guest\n"); });
EXO_TEST(seedconfig_cred_user,     { return sc_ok("seed_min_credentials = user\n"); });
EXO_TEST(seedconfig_cred_operator, { return sc_ok("seed_min_credentials = operator\n"); });
EXO_TEST(seedconfig_cred_super,    { return sc_ok("seed_min_credentials = super\n"); });
EXO_TEST(seedconfig_cred_admin,    { return sc_ok("seed_min_credentials = admin\n"); });
EXO_TEST(seedconfig_cred_invalid,  { return sc_fail("seed_min_credentials = wizard\n"); });
/* A prefix of a legal value is not a legal value. */
EXO_TEST(seedconfig_cred_prefix,   { return sc_fail("seed_min_credentials = op\n"); });
EXO_TEST(seedconfig_cred_empty,    { return sc_fail("seed_min_credentials =\n"); });

/* -------------------------------------------------------------------------
 * TLS on the transfer port
 * ------------------------------------------------------------------------- */

EXO_TEST(seedconfig_tls_version_12,      { return sc_ok("seed_tls_version = 1.2\n"); });
EXO_TEST(seedconfig_tls_version_13,      { return sc_ok("seed_tls_version = 1.3\n"); });
/* The versions below 1.2 are gone from the hub, and are not selectable here. */
EXO_TEST(seedconfig_tls_version_10,      { return sc_fail("seed_tls_version = 1.0\n"); });
EXO_TEST(seedconfig_tls_version_11,      { return sc_fail("seed_tls_version = 1.1\n"); });
EXO_TEST(seedconfig_tls_version_junk,    { return sc_fail("seed_tls_version = tomorrow\n"); });
EXO_TEST(seedconfig_tls_version_empty,   { return sc_fail("seed_tls_version =\n"); });

/* The certificate and the key are stored where they belong. */
EXO_TEST(seedconfig_tls_pair_stored, {
	struct seed_config cfg;
	int ok = sc_read(
		"seed_tls_certificate = /etc/uhub/seeder.crt\n"
		"seed_tls_private_key = /etc/uhub/seeder.key\n", &cfg) == 1
	      && strcmp(cfg.seed_tls_certificate, "/etc/uhub/seeder.crt") == 0
	      && strcmp(cfg.seed_tls_private_key, "/etc/uhub/seeder.key") == 0;
	seed_config_free(&cfg);
	return ok;
});

/*
 * Either one alone is refused. Accepting it would bring the transfer port up
 * serving plain ADC while the operator believes it is serving ADCS -- and the
 * grant tokens and the file contents would go out in the clear.
 */
EXO_TEST(seedconfig_tls_certificate_without_key, {
	return sc_fail("seed_tls_certificate = /etc/uhub/seeder.crt\n");
});

EXO_TEST(seedconfig_tls_key_without_certificate, {
	return sc_fail("seed_tls_private_key = /etc/uhub/seeder.key\n");
});

/* An explicitly empty half is as absent as a missing one. */
EXO_TEST(seedconfig_tls_empty_key, {
	return sc_fail("seed_tls_certificate = /etc/uhub/seeder.crt\nseed_tls_private_key =\n");
});

/* Neither is required: a seeder with no certificate still starts (and warns). */
EXO_TEST(seedconfig_tls_neither, { return sc_ok("seed_tls_version = 1.3\n"); });

EXO_TEST(seedconfig_tls_ciphersuite_stored, {
	struct seed_config cfg;
	int ok = sc_read(
		"seed_tls_ciphersuite = \"ECDHE-RSA-AES128-GCM-SHA256:!aNULL\"\n"
		"seed_tls_ciphersuites = \"TLS_AES_128_GCM_SHA256\"\n", &cfg) == 1
	      && strcmp(cfg.seed_tls_ciphersuite, "ECDHE-RSA-AES128-GCM-SHA256:!aNULL") == 0
	      && strcmp(cfg.seed_tls_ciphersuites, "TLS_AES_128_GCM_SHA256") == 0;
	seed_config_free(&cfg);
	return ok;
});

/* The hub's names, not the hub's file: uhub.conf keys stay unknown here. */
EXO_TEST(seedconfig_tls_hub_key_rejected, { return sc_fail("tls_certificate = /etc/uhub/x.crt\n"); });

/* -------------------------------------------------------------------------
 * Unknown and missing keys
 * ------------------------------------------------------------------------- */

EXO_TEST(seedconfig_unknown_key,   { return sc_fail("seed_bogus_key = 1\n"); });
/* Not even a hub key: this is not uhub.conf. */
EXO_TEST(seedconfig_hub_key,       { return sc_fail("hub_name = My Hub\n"); });
/* Near misses are rejected too, rather than being quietly ignored. */
EXO_TEST(seedconfig_typo_key,      { return sc_fail("seed_cachedir = /srv/seed\n"); });
EXO_TEST(seedconfig_no_equals,     { return sc_fail("this line has no equals sign\n"); });
EXO_TEST(seedconfig_empty_key,     { return sc_fail("   = 5\n"); });

EXO_TEST(seedconfig_missing_hub_url, {
	struct seed_config cfg;
	int ok = sc_read_raw("seed_password = s3cret\n", &cfg) == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_missing_password, {
	struct seed_config cfg;
	int ok = sc_read_raw("seed_hub_url = adcs://hub.example.org:1511/\n", &cfg) == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_missing_both, {
	struct seed_config cfg;
	int ok = sc_read_raw("seed_nick = lonely\n", &cfg) == 0;
	seed_config_free(&cfg);
	return ok;
});

/* Present but empty is as good as missing for a required key. */
EXO_TEST(seedconfig_required_empty, {
	struct seed_config cfg;
	int ok = sc_read_raw("seed_hub_url = adcs://hub/\nseed_password =\n", &cfg) == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_empty_file, {
	struct seed_config cfg;
	int ok = sc_read_raw("", &cfg) == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_missing_file, {
	struct seed_config cfg;
	int ok = seed_config_read("test_seedconfig_does_not_exist.tmp", &cfg) == 0;
	seed_config_free(&cfg);
	return ok;
});

/* -------------------------------------------------------------------------
 * Lexical corners
 * ------------------------------------------------------------------------- */

/* A quote inside a quoted value, escaped with a backslash. */
EXO_TEST(seedconfig_embedded_quote, {
	struct seed_config cfg;
	int ok = sc_read("seed_description = \"say \\\"hi\\\" now\"\n", &cfg) == 1
	      && strcmp(cfg.seed_description, "say \"hi\" now") == 0;
	seed_config_free(&cfg);
	return ok;
});

/* A '#' inside quotes is data, not the start of a comment. */
EXO_TEST(seedconfig_hash_in_quotes, {
	struct seed_config cfg;
	int ok = sc_read("seed_description = \"tag #1\"\n", &cfg) == 1
	      && strcmp(cfg.seed_description, "tag #1") == 0;
	seed_config_free(&cfg);
	return ok;
});

/* A 4 KiB value is carried through intact. */
EXO_TEST(seedconfig_long_value, {
	struct seed_config cfg;
	const size_t big = 4096;
	char* line = (char*) hub_malloc(big + 64);
	int ok;

	if (!line)
		return 0;

	memcpy(line, "seed_url_deny_hosts = ", 22);
	memset(line + 22, 'a', big);
	line[22 + big] = '\n';
	line[23 + big] = '\0';

	ok = sc_read(line, &cfg) == 1
	  && strlen(cfg.seed_url_deny_hosts) == big;
	hub_free(line);
	seed_config_free(&cfg);
	return ok;
});

/* Comments, both whole-line and trailing, and blank lines. */
EXO_TEST(seedconfig_comments, {
	struct seed_config cfg;
	int ok = sc_read(
		"# a whole line comment\n"
		"\n"
		"   \n"
		"   # an indented comment\n"
		"seed_client_port = 3000 # trailing comment\n"
		"\n"
		"seed_nick = bot # another\n", &cfg) == 1
	      && cfg.seed_client_port == 3000
	      && strcmp(cfg.seed_nick, "bot") == 0;
	seed_config_free(&cfg);
	return ok;
});

/* A comment containing an '=' is still a comment. */
EXO_TEST(seedconfig_comment_with_equals, { return sc_ok("# seed_client_port = 1\n"); });

/* CRLF line endings, including a blank CRLF line and a trailing comment. */
EXO_TEST(seedconfig_crlf, {
	struct seed_config cfg;
	int ok = sc_read_raw(
		"# seeder config\r\n"
		"\r\n"
		"seed_hub_url = adcs://hub.example.org:1511/\r\n"
		"seed_password = s3cret\r\n"
		"seed_nick = crlf-bot\r\n"
		"seed_client_port = 5000 # trailing\r\n", &cfg) == 1
	      && strcmp(cfg.seed_nick, "crlf-bot") == 0
	      && strcmp(cfg.seed_password, "s3cret") == 0
	      && cfg.seed_client_port == 5000;
	seed_config_free(&cfg);
	return ok;
});

/* A file whose last line has no terminating newline is still applied. */
EXO_TEST(seedconfig_no_trailing_newline, {
	struct seed_config cfg;
	int ok = sc_read("seed_nick = tail", &cfg) == 1
	      && strcmp(cfg.seed_nick, "tail") == 0;
	seed_config_free(&cfg);
	return ok;
});

EXO_TEST(seedconfig_cleanup, { unlink(sc_test_file); return 1; });
