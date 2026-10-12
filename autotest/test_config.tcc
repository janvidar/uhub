#include "network/network.h"
#include "core/config.h"

/*
 * Exercises config_parse_line() (the uhub.conf line parser in src/core/config.c)
 * through its public entry point read_config(), which reads a file and applies
 * each "key = value" line via the generated apply_config(). The parsed result is
 * inspected on the struct hub_config it fills in.
 */

static const char* cfg_test_file = "test_config.tmp";

static int cfg_write_file(const char* contents)
{
	FILE* fh = fopen(cfg_test_file, "w");
	if (!fh) return 0;
	fwrite(contents, 1, strlen(contents), fh);
	fclose(fh);
	return 1;
}

/* Parse a snippet into a fresh config; returns read_config's result code. */
static int cfg_read(const char* contents, struct hub_config* config)
{
	if (!cfg_write_file(contents))
		return -99;
	return read_config(cfg_test_file, config, 0);
}

/* Parse a snippet and assert only the result code, freeing the config. */
static int cfg_expect(const char* contents, int expect)
{
	struct hub_config config;
	int ret = cfg_read(contents, &config);
	free_config(&config);
	return ret == expect;
}

EXO_TEST(cfg_setup, { net_initialize(); return 1; });

/* String, integer and boolean directives are stored on the right fields. */
EXO_TEST(cfg_string, {
	struct hub_config config;
	int ok = cfg_read("hub_name = My Hub\n", &config) == 0
	         && strcmp(config.hub_name, "My Hub") == 0;
	free_config(&config);
	return ok;
});

EXO_TEST(cfg_integer, {
	struct hub_config config;
	int ok = cfg_read("max_users = 1234\n", &config) == 0
	         && config.max_users == 1234;
	free_config(&config);
	return ok;
});

EXO_TEST(cfg_boolean_on, {
	struct hub_config config;
	int ok = cfg_read("registered_users_only = yes\n", &config) == 0
	         && config.registered_users_only == 1;
	free_config(&config);
	return ok;
});

EXO_TEST(cfg_boolean_off, {
	struct hub_config config;
	int ok = cfg_read("registered_users_only = off\n", &config) == 0
	         && config.registered_users_only == 0;
	free_config(&config);
	return ok;
});

/* Chat timestamps (the TS flag) are on unless the hub turns them off. */
EXO_TEST(cfg_chat_timestamps_default, {
	struct hub_config config;
	int ok = cfg_read("hub_name = Timestamped\n", &config) == 0
	         && config.chat_timestamps == 1;
	free_config(&config);
	return ok;
});

EXO_TEST(cfg_chat_timestamps_off, {
	struct hub_config config;
	int ok = cfg_read("chat_timestamps = no\n", &config) == 0
	         && config.chat_timestamps == 0;
	free_config(&config);
	return ok;
});

/* Surrounding whitespace around key and value is stripped. */
EXO_TEST(cfg_whitespace, {
	struct hub_config config;
	int ok = cfg_read("   max_users   =   55  \n", &config) == 0
	         && config.max_users == 55;
	free_config(&config);
	return ok;
});

/* Double and single quotes around a value are stripped. */
EXO_TEST(cfg_quotes_double, {
	struct hub_config config;
	int ok = cfg_read("hub_name = \"Quoted Hub\"\n", &config) == 0
	         && strcmp(config.hub_name, "Quoted Hub") == 0;
	free_config(&config);
	return ok;
});

EXO_TEST(cfg_quotes_single, {
	struct hub_config config;
	int ok = cfg_read("hub_name = 'Quoted Hub'\n", &config) == 0
	         && strcmp(config.hub_name, "Quoted Hub") == 0;
	free_config(&config);
	return ok;
});

/* Comments and blank lines are ignored; defaults survive untouched keys. */
EXO_TEST(cfg_comment, {
	struct hub_config config;
	int ok = cfg_read("# a comment\n\nmax_users = 7 # trailing comment\n", &config) == 0
	         && config.max_users == 7;
	free_config(&config);
	return ok;
});

EXO_TEST(cfg_defaults_kept, {
	struct hub_config config;
	/* hub_name not set in this file -> keeps its compiled-in default. */
	int ok = cfg_read("max_users = 9\n", &config) == 0
	         && strcmp(config.hub_name, "uhub") == 0;
	free_config(&config);
	return ok;
});

/* A line with no '=' is silently ignored (returns 0, not an error). */
EXO_TEST(cfg_no_equals_ignored, { return cfg_expect("this line has no equals sign\n", 0); });

/* Error paths: read_config returns -1. */
EXO_TEST(cfg_err_unknown_key,  { return cfg_expect("no_such_directive = 1\n", -1); });
EXO_TEST(cfg_err_int_range,    { return cfg_expect("server_port = 99999\n", -1); }); /* max is 65535 */
EXO_TEST(cfg_err_int_garbage,  { return cfg_expect("max_users = notanumber\n", -1); });
EXO_TEST(cfg_err_bad_boolean,  { return cfg_expect("registered_users_only = maybe\n", -1); });
EXO_TEST(cfg_err_empty_value,  { return cfg_expect("max_users = \n", -1); }); /* key present, value missing */

/* Missing file: error unless allow_missing is set. */
EXO_TEST(cfg_missing_strict, {
	struct hub_config config;
	int ret = read_config("test_config_does_not_exist.tmp", &config, 0);
	free_config(&config);
	return ret == -1;
});

EXO_TEST(cfg_missing_allowed, {
	struct hub_config config;
	int ret = read_config("test_config_does_not_exist.tmp", &config, 1);
	int ok = ret == 0 && strcmp(config.hub_name, "uhub") == 0; /* defaults applied */
	free_config(&config);
	return ok;
});

/* limit_min_search: parsed onto its field, defaults off, range-checked (0..255). */
EXO_TEST(cfg_min_search, {
	struct hub_config config;
	int ok = cfg_read("limit_min_search = 3\n", &config) == 0
	         && config.limit_min_search == 3;
	free_config(&config);
	return ok;
});

EXO_TEST(cfg_min_search_default, {
	struct hub_config config;
	int ok = cfg_read("max_users = 9\n", &config) == 0
	         && config.limit_min_search == 0;
	free_config(&config);
	return ok;
});

EXO_TEST(cfg_min_search_range, { return cfg_expect("limit_min_search = 256\n", -1); }); /* max is 255 */

/*
 * String value validation: options carrying a <check regexp=...> in config.xml
 * are matched against an anchored POSIX ERE in apply_string(). A value that
 * matches is stored; one that does not makes read_config() return -1.
 * (On Windows the validator is a no-op, but the suite is POSIX-only.)
 */

/* redirect_addr requires an adc:// / adcs:// / dchub:// URL. */
EXO_TEST(cfg_re_redirect_ok, {
	struct hub_config config;
	int ok = cfg_read("redirect_addr = adcs://example.com:1511\n", &config) == 0
	         && strcmp(config.redirect_addr, "adcs://example.com:1511") == 0;
	free_config(&config);
	return ok;
});

EXO_TEST(cfg_re_redirect_adc,   { return cfg_expect("redirect_addr = adc://example.com\n", 0); });
EXO_TEST(cfg_re_redirect_dchub, { return cfg_expect("redirect_addr = dchub://example.com\n", 0); });
EXO_TEST(cfg_re_redirect_bad,   { return cfg_expect("redirect_addr = http://example.com\n", -1); });

/* Anchoring: a valid URL preceded by junk must still be rejected. */
EXO_TEST(cfg_re_redirect_anchor, { return cfg_expect("redirect_addr = junk adcs://example.com\n", -1); });

/* server_alt_ports is a comma-separated list of numbers. */
EXO_TEST(cfg_re_altports_ok, {
	struct hub_config config;
	int ok = cfg_read("server_alt_ports = 1295,1512,53990\n", &config) == 0
	         && strcmp(config.server_alt_ports, "1295,1512,53990") == 0;
	free_config(&config);
	return ok;
});

EXO_TEST(cfg_re_altports_bad, { return cfg_expect("server_alt_ports = 1295,abc\n", -1); });

/* Anchoring: a trailing/leading non-digit run must not match a digit substring. */
EXO_TEST(cfg_re_altports_anchor, { return cfg_expect("server_alt_ports = abc123\n", -1); });

/* server_bind_addr accepts an address, "any" or "loopback". */
EXO_TEST(cfg_re_bind_ok,   { return cfg_expect("server_bind_addr = 192.168.0.1\n", 0); });
EXO_TEST(cfg_re_bind_word, { return cfg_expect("server_bind_addr = loopback\n", 0); });
EXO_TEST(cfg_re_bind_bad,  { return cfg_expect("server_bind_addr = not!an!addr\n", -1); });

/* hbri_address6: hex digits, colons and dots only. */
EXO_TEST(cfg_re_hbri6_ok,  { return cfg_expect("hbri_address6 = 2001:db8::10\n", 0); });
EXO_TEST(cfg_re_hbri6_bad, { return cfg_expect("hbri_address6 = zzz!!\n", -1); });

/* An explicitly quoted empty value sets a string option to the empty string.
   A key with nothing after the '=' at all is still an error (cfg_err_empty_value
   above). Together with the patterns below this is what makes the output of
   "uhub -s" -- which writes every empty string option as key = "" -- parse back
   in as a configuration file. */
EXO_TEST(cfg_quoted_empty_value, {
	struct hub_config config;
	int ok = cfg_read("hub_name = \"\"\n", &config) == 0
	         && config.hub_name[0] == '\0';
	free_config(&config);
	return ok;
});

/* These three default to the empty string, so their own validation pattern has
   to accept it -- otherwise dumping and re-reading the defaults fails. */
EXO_TEST(cfg_empty_alt_ports,    { return cfg_expect("server_alt_ports = \"\"\n", 0); });
EXO_TEST(cfg_empty_redirect,     { return cfg_expect("redirect_addr = \"\"\n", 0); });
EXO_TEST(cfg_empty_tls_redirect, { return cfg_expect("tls_require_redirect_addr = \"\"\n", 0); });

EXO_TEST(cfg_empty_http_redirect, { return cfg_expect("http_redirect_addr = \"\"\n", 0); });

/* The redirect address ends up in an HTTP header and an HTML attribute, so it
   may not carry what would break out of those. */
EXO_TEST(cfg_http_redirect_ok,       { return cfg_expect("http_redirect_addr = https://www.example.com/hub\n", 0); });
EXO_TEST(cfg_http_redirect_scheme,   { return cfg_expect("http_redirect_addr = javascript:alert(1)\n", -1); });
EXO_TEST(cfg_http_redirect_quote,    { return cfg_expect("http_redirect_addr = \"https://example.com/\\\"x\"\n", -1); });

/* An empty value does not disable validation for a non-empty value. */
EXO_TEST(cfg_alt_ports_still_checked, { return cfg_expect("server_alt_ports = not,ports\n", -1); });
EXO_TEST(cfg_redirect_still_checked,  { return cfg_expect("redirect_addr = ftp://elsewhere\n", -1); });

/* An unchecked string option (no regexp) accepts arbitrary text. */
EXO_TEST(cfg_re_unchecked, {
	struct hub_config config;
	int ok = cfg_read("hub_name = weird @!$%^&* name\n", &config) == 0
	         && strcmp(config.hub_name, "weird @!$%^&* name") == 0;
	free_config(&config);
	return ok;
});

/*
 * The msg_* status strings can also be kept in their own file, named by the
 * file_messages option and read by read_messages(). It shares the line parser
 * with read_config() but applies through apply_message_config(), which knows
 * only the message options.
 */

static const char* msg_test_file = "test_messages.tmp";

/* Apply a messages snippet on top of a default config. */
static int msg_read(const char* contents, struct hub_config* config)
{
	FILE* fh = fopen(msg_test_file, "w");
	if (!fh) return -99;
	fwrite(contents, 1, strlen(contents), fh);
	fclose(fh);

	if (read_config("test_config_does_not_exist.tmp", config, 1) == -1)
		return -99;
	return read_messages(msg_test_file, config);
}

EXO_TEST(msg_applies_value, {
	struct hub_config config;
	int ok = msg_read("msg_hub_full = No room at the inn\n", &config) == 0
	         && strcmp(config.msg_hub_full, "No room at the inn") == 0;
	free_config(&config);
	return ok;
});

/* Anything that is not a status message belongs in uhub.conf, not here. */
EXO_TEST(msg_rejects_non_message_key, {
	struct hub_config config;
	int ret = msg_read("server_port = 1234\n", &config);
	free_config(&config);
	return ret == -1;
});

EXO_TEST(msg_rejects_unknown_key, {
	struct hub_config config;
	int ret = msg_read("msg_no_such_message = hello\n", &config);
	free_config(&config);
	return ret == -1;
});

/* Comments and blank lines are handled by the shared line parser. */
EXO_TEST(msg_ignores_comments, {
	struct hub_config config;
	int ok = msg_read("# a comment\n\nmsg_hub_disabled = Closed\n", &config) == 0
	         && strcmp(config.msg_hub_disabled, "Closed") == 0;
	free_config(&config);
	return ok;
});

/* Values read from the messages file are applied last, so they win over the
   same key set in the main configuration file. */
EXO_TEST(msg_overrides_main_config, {
	struct hub_config config;
	int ok;
	if (!cfg_write_file("msg_hub_full = from uhub.conf\n"))
		return 0;
	if (read_config(cfg_test_file, &config, 0) != 0)
		return 0;
	ok = strcmp(config.msg_hub_full, "from uhub.conf") == 0;

	{
		FILE* fh = fopen(msg_test_file, "w");
		if (!fh) { free_config(&config); return 0; }
		fwrite("msg_hub_full = from messages.conf\n", 1, 34, fh);
		fclose(fh);
	}
	ok = ok && read_messages(msg_test_file, &config) == 0
	        && strcmp(config.msg_hub_full, "from messages.conf") == 0;
	free_config(&config);
	return ok;
});

/* A missing messages file is not an error: the configured messages stand. */
EXO_TEST(msg_missing_file_tolerated, {
	struct hub_config config;
	int ok;
	if (read_config("test_config_does_not_exist.tmp", &config, 1) == -1)
		return 0;
	ok = read_messages("test_messages_does_not_exist.tmp", &config) == 0
	     && strcmp(config.msg_hub_full, "Hub is full") == 0;
	free_config(&config);
	return ok;
});

EXO_TEST(cfg_teardown, { remove(cfg_test_file); remove(msg_test_file); net_destroy(); return 1; });
