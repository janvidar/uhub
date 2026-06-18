#include <uhub.h>

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

/* Look up a credentialed user by nick in the parsed users list. */
static struct auth_info* acl_find_user(struct acl_handle* handle, const char* nick)
{
	struct auth_info* info;
	LIST_FOREACH(struct auth_info*, info, handle->users,
	{
		if (strcmp(info->nickname, nick) == 0)
			return info;
	});
	return NULL;
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
		"user_admin admin1:secret\n"
		"user_super super1\n"
		"user_op op1\n"
		"user_reg reg1:pass1\n"
		"link linkuser\n"
		"bot bot1\n"
		"ubot ubot1\n"
		"opbot opbot1\n"
		"opubot opubot1\n"
		"deny_nick badnick\n"
		"ban_nick evil\n"
		"ban_cid GNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI\n"
		"deny_ip 10.0.0.0/8\n"
		"nat_ip 192.168.0.0/16\n";

	net_initialize();
	memset(&acl_config, 0, sizeof(acl_config));
	config_defaults(&acl_config);
	if (!acl_write_file(acl)) return 0;
	hub_free(acl_config.file_acl);
	acl_config.file_acl = hub_strdup(acl_test_file);
	return acl_initialize(&acl_config, &acl_acl) == 0;
});

/* Credentialed users: nick, credentials, and optional password. */
EXO_TEST(acl_admin_cred,  { struct auth_info* u = acl_find_user(&acl_acl, "admin1"); return u && u->credentials == auth_cred_admin; });
EXO_TEST(acl_admin_pass,  { struct auth_info* u = acl_find_user(&acl_acl, "admin1"); return u && strcmp(u->password, "secret") == 0; });
EXO_TEST(acl_super_cred,  { struct auth_info* u = acl_find_user(&acl_acl, "super1"); return u && u->credentials == auth_cred_super; });
EXO_TEST(acl_op_cred,     { struct auth_info* u = acl_find_user(&acl_acl, "op1"); return u && u->credentials == auth_cred_operator; });
EXO_TEST(acl_op_nopass,   { struct auth_info* u = acl_find_user(&acl_acl, "op1"); return u && u->password[0] == '\0'; });
EXO_TEST(acl_reg_cred,    { struct auth_info* u = acl_find_user(&acl_acl, "reg1"); return u && u->credentials == auth_cred_user && strcmp(u->password, "pass1") == 0; });
EXO_TEST(acl_link_cred,   { struct auth_info* u = acl_find_user(&acl_acl, "linkuser"); return u && u->credentials == auth_cred_link; });
EXO_TEST(acl_bot_cred,    { struct auth_info* u = acl_find_user(&acl_acl, "bot1"); return u && u->credentials == auth_cred_bot; });
EXO_TEST(acl_ubot_cred,   { struct auth_info* u = acl_find_user(&acl_acl, "ubot1"); return u && u->credentials == auth_cred_ubot; });
EXO_TEST(acl_opbot_cred,  { struct auth_info* u = acl_find_user(&acl_acl, "opbot1"); return u && u->credentials == auth_cred_opbot; });
EXO_TEST(acl_opubot_cred, { struct auth_info* u = acl_find_user(&acl_acl, "opubot1"); return u && u->credentials == auth_cred_opubot; });
EXO_TEST(acl_unknown_user, { return acl_find_user(&acl_acl, "nobody") == NULL; });

/* The bot/ubot/opbot/opubot keywords share the "user_" prefix logic for the
   ':' password split only for user_* entries; a bare bot nick keeps no pass. */
EXO_TEST(acl_bot_nopass,  { struct auth_info* u = acl_find_user(&acl_acl, "bot1"); return u && u->password[0] == '\0'; });

/* deny_nick / ban_nick / ban_cid query helpers. */
EXO_TEST(acl_deny_nick,      { return acl_is_user_denied(&acl_acl, "badnick") == 1; });
EXO_TEST(acl_deny_nick_neg,  { return acl_is_user_denied(&acl_acl, "goodnick") == 0; });
EXO_TEST(acl_ban_nick,       { return acl_is_user_banned(&acl_acl, "evil") == 1; });
EXO_TEST(acl_ban_nick_case,  { return acl_is_user_banned(&acl_acl, "EVIL") == 1; }); /* case-insensitive */
EXO_TEST(acl_ban_nick_neg,   { return acl_is_user_banned(&acl_acl, "saint") == 0; });
EXO_TEST(acl_ban_cid,        { return acl_is_cid_banned(&acl_acl, "GNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI") == 1; });
EXO_TEST(acl_ban_cid_neg,    { return acl_is_cid_banned(&acl_acl, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == 0; });

/* deny_ip / nat_ip ranges. */
EXO_TEST(acl_deny_ip_in,     { return acl_is_ip_banned(&acl_acl, "10.1.2.3") == 1; });
EXO_TEST(acl_deny_ip_edge,   { return acl_is_ip_banned(&acl_acl, "10.255.255.255") == 1; });
EXO_TEST(acl_deny_ip_out,    { return acl_is_ip_banned(&acl_acl, "11.0.0.1") == 0; });
EXO_TEST(acl_nat_ip_in,      { return acl_is_ip_nat_override(&acl_acl, "192.168.5.5") == 1; });
EXO_TEST(acl_nat_ip_out,     { return acl_is_ip_nat_override(&acl_acl, "10.1.2.3") == 0; });

/* Parser acceptance/rejection of whole lines. */
EXO_TEST(acl_ok_comment,     { return acl_parse_expect("# nothing here\n", 0); });
EXO_TEST(acl_ok_blank,       { return acl_parse_expect("   \n\t\n", 0); });
EXO_TEST(acl_err_unknown,    { return acl_parse_expect("frobnicate foo\n", -1); });
EXO_TEST(acl_err_prefix,     { return acl_parse_expect("user_adminx bar\n", -1); }); /* keyword must be a whole token */
EXO_TEST(acl_err_no_arg,     { return acl_parse_expect("user_admin\n", -1); });       /* keyword present, argument missing */
EXO_TEST(acl_err_bad_ip,     { return acl_parse_expect("deny_ip not-an-ip\n", -1); }); /* malformed address */

EXO_TEST(acl_teardown,
{
	acl_shutdown(&acl_acl);
	free_config(&acl_config);
	remove(acl_test_file);
	net_destroy();
	return 1;
});
