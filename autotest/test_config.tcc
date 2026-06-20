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

EXO_TEST(cfg_teardown, { remove(cfg_test_file); net_destroy(); return 1; });
