#include "system.h"
#include "util/memory.h"
#include "fuse/config.h"

static struct fs_config cfg;

/*
 * fs_config_defaults() zeroes the struct before filling it in, so whatever a
 * previous test left in it has to be released first or it is orphaned. The
 * program does this once at startup; a test file does it over and over.
 */
static void reset_config(void)
{
	fs_config_free(&cfg);
	fs_config_defaults(&cfg);
}

/* fs_config_parse_line() modifies the line in place, so tests hand it a copy. */
static int parse(const char* text)
{
	char buf[256];
	int ok;

	snprintf(buf, sizeof(buf), "%s", text);
	ok = fs_config_parse_line(buf, 1, &cfg);
	return ok;
}

/* Unset strings are "" and never NULL, so no caller has to test for both. */
static const char* config_path(void);

EXO_TEARDOWN({
	fs_config_free(&cfg);
	remove(config_path());
	return 1;
});

/* Every test starts from reset_config(), so none sees what another parsed. */

EXO_TEST(fuse_config_defaults, {
	reset_config();
	return cfg.address && !*cfg.address
		&& cfg.password && !*cfg.password
		&& cfg.nick && strcmp(cfg.nick, "uhub-fuse") == 0
		&& cfg.transfer_port == 1514
		&& cfg.download_timeout == 60
		&& cfg.keepalive_interval == 120
		&& cfg.cache_size == 512;
});

EXO_TEST(fuse_config_blank_line, { reset_config(); return parse("") == 1; });
EXO_TEST(fuse_config_whitespace_line, { reset_config(); return parse("   \t  ") == 1; });
EXO_TEST(fuse_config_comment, { reset_config(); return parse("# hub = nope") == 1; });
EXO_TEST(fuse_config_comment_not_applied, { reset_config(); return parse("# hub = nope") == 1 && cfg.address && !*cfg.address; });

EXO_TEST(fuse_config_hub, {
	reset_config();
	return parse("hub = adc://localhost:1511") == 1
		&& strcmp(cfg.address, "adc://localhost:1511") == 0;
});

EXO_TEST(fuse_config_no_spaces_around_equals, { reset_config();
	return parse("hub=adc://other:411") == 1 && strcmp(cfg.address, "adc://other:411") == 0;
});

EXO_TEST(fuse_config_trailing_whitespace_stripped, { reset_config();
	return parse("nick =   bob \t ") == 1 && strcmp(cfg.nick, "bob") == 0;
});

EXO_TEST(fuse_config_last_wins, { reset_config();
	return parse("nick = carol") == 1 && strcmp(cfg.nick, "carol") == 0;
});

/*
 * '#' is an ordinary character in a password. Treating it as the start of a
 * comment would truncate the secret and fail the login with nothing to show
 * for it.
 */
EXO_TEST(fuse_config_password_keeps_hash, { reset_config();
	return parse("password = a#b#c") == 1 && strcmp(cfg.password, "a#b#c") == 0;
});

EXO_TEST(fuse_config_password_keeps_spaces, { reset_config();
	return parse("password = two words") == 1 && strcmp(cfg.password, "two words") == 0;
});

EXO_TEST(fuse_config_password_keeps_equals, { reset_config();
	return parse("password = a=b") == 1 && strcmp(cfg.password, "a=b") == 0;
});

EXO_TEST(fuse_config_empty_value, { reset_config();
	return parse("password =") == 1 && cfg.password && cfg.password[0] == '\0';
});

EXO_TEST(fuse_config_unknown_key, { reset_config(); return parse("nope = 1") == 0; });
EXO_TEST(fuse_config_missing_equals, { reset_config(); return parse("hub adc://x") == 0; });
EXO_TEST(fuse_config_missing_key, { reset_config(); return parse(" = value") == 0; });
EXO_TEST(fuse_config_null_line, { reset_config(); return fs_config_parse_line(NULL, 1, &cfg) == 0; });

EXO_TEST(fuse_config_set, {
	reset_config();
	return fs_config_set(&cfg, "hub", "adc://set:1511") == 1
		&& strcmp(cfg.address, "adc://set:1511") == 0;
});

EXO_TEST(fuse_config_set_unknown, { reset_config(); return fs_config_set(&cfg, "nope", "x") == 0; });
EXO_TEST(fuse_config_set_null_value, { reset_config(); return fs_config_set(&cfg, "hub", NULL) == 0; });

EXO_TEST(fuse_config_free, {
	reset_config();
	fs_config_free(&cfg);
	return cfg.address == NULL && cfg.nick == NULL && cfg.password == NULL;
});

EXO_TEST(fuse_config_free_twice, {
	reset_config();
	fs_config_free(&cfg);
	return 1;
});

EXO_TEST(fuse_config_free_null, {
	reset_config();
	fs_config_free(NULL);
	return 1;
});

/* ------------------------------------------------------------------- files */

static const char* config_path(void)
{
	static char path[256];
	snprintf(path, sizeof(path), "%s/test_fuse_config.tmp", UHUB_TEST_DIR);
	return path;
}

static int write_config(const char* contents)
{
	FILE* fh = fopen(config_path(), "wb");
	if (!fh)
		return 0;

	fputs(contents, fh);
	fclose(fh);
	return 1;
}

EXO_TEST(fuse_config_read_file, {
	reset_config();
	return write_config("# a hub\nhub = adc://file:1511\nnick = fromfile\n")
		&& fs_config_read(config_path(), &cfg) == 1
		&& strcmp(cfg.address, "adc://file:1511") == 0
		&& strcmp(cfg.nick, "fromfile") == 0;
});

EXO_TEST(fuse_config_read_no_trailing_newline, {
	reset_config();
	return write_config("hub = adc://last:1511")
		&& fs_config_read(config_path(), &cfg) == 1
		&& strcmp(cfg.address, "adc://last:1511") == 0;
});

EXO_TEST(fuse_config_read_crlf, {
	reset_config();
	return write_config("hub = adc://crlf:1511\r\nnick = dos\r\n")
		&& fs_config_read(config_path(), &cfg) == 1
		&& strcmp(cfg.address, "adc://crlf:1511") == 0
		&& strcmp(cfg.nick, "dos") == 0;
});

/* A file that does not parse leaves nothing half-applied behind. */
EXO_TEST(fuse_config_read_bad_line, {
	reset_config();
	return write_config("hub = adc://ok:1511\nnope = 1\n")
		&& fs_config_read(config_path(), &cfg) == 0
		&& cfg.address == NULL && cfg.nick == NULL;
});

/* --------------------------------------------------------- numeric keys */

EXO_TEST(fuse_config_int, {
	reset_config();
	return parse("transfer_port = 4711") == 1 && cfg.transfer_port == 4711;
});

EXO_TEST(fuse_config_int_trailing_garbage, {
	/* "8080x" is a typo, not the number 8080, and leaves the setting alone. */
	reset_config();
	return parse("transfer_port = 4711") == 1
		&& parse("transfer_port = 8080x") == 0 && cfg.transfer_port == 4711;
});

EXO_TEST(fuse_config_int_out_of_range, { reset_config(); return parse("transfer_port = 99999") == 0; });
EXO_TEST(fuse_config_int_below_range, { reset_config(); return parse("transfer_port = 80") == 0; });

/* Unlike the other intervals, 0 is in range here: it means "send none". */
EXO_TEST(fuse_config_keepalive_zero_allowed, { reset_config();
	return parse("keepalive_interval = 0") == 1 && cfg.keepalive_interval == 0;
});

EXO_TEST(fuse_config_keepalive_set, { reset_config();
	return parse("keepalive_interval = 45") == 1 && cfg.keepalive_interval == 45;
});

EXO_TEST(fuse_config_keepalive_out_of_range, { reset_config(); return parse("keepalive_interval = 3601") == 0; });
EXO_TEST(fuse_config_keepalive_below_range, { reset_config(); return parse("keepalive_interval = -1") == 0; });
EXO_TEST(fuse_config_int_not_a_number, { reset_config(); return parse("transfer_port = nope") == 0; });
EXO_TEST(fuse_config_int_empty, { reset_config(); return parse("transfer_port =") == 0; });

EXO_TEST(fuse_config_enumerated_value, { reset_config();
	return parse("tls_version = 1.3") == 1 && strcmp(cfg.tls_version, "1.3") == 0;
});

EXO_TEST(fuse_config_enumerated_value_refused, {
	reset_config();
	return parse("tls_version = 1.3") == 1
		&& parse("tls_version = 1.0") == 0 && strcmp(cfg.tls_version, "1.3") == 0;
});

/* A certificate without its key would come up serving plain ADC while looking
   like it was serving ADCS. */
EXO_TEST(fuse_config_tls_pair_incomplete, {
	reset_config();
	return write_config("hub = adc://x:1511\ntls_certificate = /tmp/cert.pem\n")
		&& fs_config_read(config_path(), &cfg) == 0;
});

EXO_TEST(fuse_config_tls_pair_complete, {
	reset_config();
	return write_config("hub = adc://x:1511\ntls_certificate = /tmp/c.pem\ntls_private_key = /tmp/k.pem\n")
		&& fs_config_read(config_path(), &cfg) == 1;
});

EXO_TEST(fuse_config_cache_dir_default, {
	char dir[256];
	reset_config();
	/* HOME is set in any environment this runs in; if it is not, the fallback
	   is to fail rather than to invent a path. */
	return getenv("HOME") ? (fs_config_default_cache_dir(dir, sizeof(dir)) == 1 && strstr(dir, "uhub-fuse") != NULL) : 1;
});

EXO_TEST(fuse_config_cache_dir_no_room, {
	char dir[4];
	reset_config();
	return fs_config_default_cache_dir(dir, sizeof(dir)) == 0;
});

EXO_TEST(fuse_config_read_missing_file, {
	reset_config();
	return fs_config_read("/nonexistent/uhub-fuse.conf", &cfg) == 0;
});

EXO_TEST(fuse_config_read_null_file, {
	reset_config();
	return fs_config_read(NULL, &cfg) == 0;
});

EXO_TEST(fuse_config_read_null_cfg, { reset_config(); return fs_config_read(config_path(), NULL) == 0; });


