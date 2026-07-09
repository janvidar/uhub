#include "util/list.h"
#include "util/memory.h"
#include "network/network.h"
#include "core/auth.h"
#include "core/config.h"
#include "plugin_api/types.h"

/*
 * Exercises acl_parse_line() (the ACL config line parser in src/core/auth.c).
 * It is static, so it is driven through its public entry point acl_initialize(),
 * which reads the file named by config->file_acl and parses it line by line.
 * The parsed result is then inspected through the acl_is_* query helpers and by
 * walking handle->users for the credentialed entries.
 */

static struct hub_config acl_config;
static struct acl_handle acl_acl;

static const char* acl_test_file = "test_auth_acl.tmp";

static int acl_write_file(const char* contents)
{
	FILE* fh = fopen(acl_test_file, "w");
	if (!fh) return 0;
	fwrite(contents, 1, strlen(contents), fh);
	fclose(fh);
	return 1;
}

/* Parse a single snippet through a throwaway handle and return acl_initialize's
   result code (0 on success, -1 on parse error). */
static int acl_parse_expect(const char* contents, int expect)
{
	struct hub_config cfg;
	struct acl_handle handle;
	int ret;

	if (!acl_write_file(contents))
		return 0;

	memset(&cfg, 0, sizeof(cfg));
	config_defaults(&cfg);
	hub_free(cfg.file_acl);
	cfg.file_acl = hub_strdup(acl_test_file);

	ret = acl_initialize(&cfg, &handle);
	acl_shutdown(&handle);
	free_config(&cfg);
	return ret == expect;
}

EXO_TEST(acl_setup,
{
	const char* acl =
		"# comment line, must be ignored\n"
		"\n"
		"user_admin admin1:secret\n" /* obsolete: registered users live in an auth plugin now; ignored non-fatally */
		"deny_nick badnick\n"
		"ban_nick evil\n"
		"ban_cid GNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI\n"
		"deny_ip 10.0.0.0/8\n";

	net_initialize();
	memset(&acl_config, 0, sizeof(acl_config));
	config_defaults(&acl_config);
	if (!acl_write_file(acl)) return 0;
	hub_free(acl_config.file_acl);
	acl_config.file_acl = hub_strdup(acl_test_file);
	/* NAT override now comes from the hub config, not the acl file's nat_ip. */
	hub_free(acl_config.nat_override);
	acl_config.nat_override = hub_strdup("192.168.0.0/16");
	return acl_initialize(&acl_config, &acl_acl) == 0;
});

/* deny_nick / ban_nick / ban_cid query helpers. */
EXO_TEST(acl_deny_nick,      { return acl_is_user_denied(&acl_acl, "badnick") == 1; });
EXO_TEST(acl_deny_nick_neg,  { return acl_is_user_denied(&acl_acl, "goodnick") == 0; });
EXO_TEST(acl_ban_nick,       { return acl_is_user_banned(&acl_acl, "evil") == 1; });
EXO_TEST(acl_ban_nick_case,  { return acl_is_user_banned(&acl_acl, "EVIL") == 1; }); /* case-insensitive */
EXO_TEST(acl_ban_nick_neg,   { return acl_is_user_banned(&acl_acl, "saint") == 0; });
EXO_TEST(acl_ban_cid,        { return acl_is_cid_banned(&acl_acl, "GNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI") == 1; });
EXO_TEST(acl_ban_cid_neg,    { return acl_is_cid_banned(&acl_acl, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == 0; });

/* deny_ip ranges (from the acl file) and nat_override ranges (from hub config). */
EXO_TEST(acl_deny_ip_in,     { return acl_is_ip_banned(&acl_acl, "10.1.2.3") == 1; });
EXO_TEST(acl_deny_ip_edge,   { return acl_is_ip_banned(&acl_acl, "10.255.255.255") == 1; });
EXO_TEST(acl_deny_ip_out,    { return acl_is_ip_banned(&acl_acl, "11.0.0.1") == 0; });
EXO_TEST(acl_nat_override_in,  { return acl_is_ip_nat_override(&acl_acl, "192.168.5.5") == 1; });
EXO_TEST(acl_nat_override_out, { return acl_is_ip_nat_override(&acl_acl, "10.1.2.3") == 0; });

/* Runtime ban add/remove round-trips (acl_user_ban_* / acl_user_unban_*). These
   mutate the shared handle, so they run after the ban-query assertions above. */
EXO_TEST(acl_unban_nick_add,    { return acl_user_ban_nick(&acl_acl, "tempnick") == 0 && acl_is_user_banned(&acl_acl, "tempnick") == 1; });
EXO_TEST(acl_unban_nick_remove, { return acl_user_unban_nick(&acl_acl, "tempnick") == 0 && acl_is_user_banned(&acl_acl, "tempnick") == 0; });
EXO_TEST(acl_unban_nick_again,  { return acl_user_unban_nick(&acl_acl, "tempnick") == -1; }); /* already gone */
EXO_TEST(acl_unban_nick_case,   { return acl_user_ban_nick(&acl_acl, "MixedCase") == 0 && acl_user_unban_nick(&acl_acl, "mixedcase") == 0 && acl_is_user_banned(&acl_acl, "MixedCase") == 0; });
EXO_TEST(acl_unban_nick_missing,{ return acl_user_unban_nick(&acl_acl, "neverbanned") == -1; });

EXO_TEST(acl_unban_cid_add,     { return acl_user_ban_cid(&acl_acl, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == 0 && acl_is_cid_banned(&acl_acl, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == 1; });
EXO_TEST(acl_unban_cid_remove,  { return acl_user_unban_cid(&acl_acl, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == 0 && acl_is_cid_banned(&acl_acl, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == 0; });

/* Lift the deny_ip 10.0.0.0/8 range added at setup (runs after the deny_ip tests). */
EXO_TEST(acl_unban_ip_remove,   { return acl_user_unban_ip(&acl_acl, "10.0.0.0/8") == 0 && acl_is_ip_banned(&acl_acl, "10.1.2.3") == 0; });
EXO_TEST(acl_unban_ip_again,    { return acl_user_unban_ip(&acl_acl, "10.0.0.0/8") == -1; }); /* already gone */
EXO_TEST(acl_unban_ip_badaddr,  { return acl_user_unban_ip(&acl_acl, "not-an-ip") == -1; });

/* Parser acceptance/rejection of whole lines. */
EXO_TEST(acl_ok_comment,     { return acl_parse_expect("# nothing here\n", 0); });
EXO_TEST(acl_ok_blank,       { return acl_parse_expect("   \n\t\n", 0); });
EXO_TEST(acl_err_unknown,    { return acl_parse_expect("frobnicate foo\n", -1); });
EXO_TEST(acl_err_prefix,     { return acl_parse_expect("user_adminx bar\n", -1); }); /* keyword must be a whole token */
EXO_TEST(acl_err_no_arg,     { return acl_parse_expect("ban_nick\n", -1); });         /* live keyword present, argument missing */
EXO_TEST(acl_err_bad_ip,     { return acl_parse_expect("deny_ip not-an-ip\n", -1); }); /* malformed address */

/* Obsolete keywords: recognised, warned about, ignored (non-fatal) so old files load. */
EXO_TEST(acl_ok_nat_ip_obs,  { return acl_parse_expect("nat_ip 10.0.0.0/8\n", 0); });
EXO_TEST(acl_ok_user_obs,    { return acl_parse_expect("user_admin admin:secret\n", 0); });
EXO_TEST(acl_ok_useropo_obs, { return acl_parse_expect("user_op op1\n", 0); });
EXO_TEST(acl_ok_link_obs,    { return acl_parse_expect("link peerhub\n", 0); });
EXO_TEST(acl_ok_bot_obs,     { return acl_parse_expect("bot mybot\n", 0); });
EXO_TEST(acl_ok_user_noarg,  { return acl_parse_expect("user_admin\n", 0); });         /* obsolete even without an argument */

EXO_TEST(acl_teardown,
{
	acl_shutdown(&acl_acl);
	free_config(&acl_config);
	remove(acl_test_file);
	net_destroy();
	return 1;
});
