#include "util/memory.h"
#include "core/commands.h"
#include "core/hub.h"
#include "core/usermanager.h"

static struct hub_info* hub = NULL;
static struct hub_command* cmd = NULL;
static struct hub_user user;
static struct command_base* cbase = NULL;
static struct command_handle* c_test1 = NULL;
static struct command_handle* c_test2 = NULL;
static struct command_handle* c_test3 = NULL;
static struct command_handle* c_test4 = NULL;
static struct command_handle* c_test5 = NULL;
static struct command_handle* c_test6 = NULL;
static struct command_handle* c_test7 = NULL;

/* Whether `user` is currently in hub->users; see as(). */
static int user_in_hub = 0;

// for results:
static int result = 0;

static int test_handler(struct command_base* cbase, struct hub_user* user, struct hub_command* hcmd)
{
	(void) cbase; (void) user; (void) hcmd;
	printf("test_handler\n");
	result = 1;
	return 0;
}

static struct command_handle* create_handler(const char* prefix, const char* args, enum auth_credentials cred)
{
	struct command_handle* c = hub_malloc_zero(sizeof(struct command_handle));
	c->prefix = prefix;
	c->length = strlen(prefix);
	c->args = args;
	c->cred = cred;
	c->handler = test_handler;
	c->description = "A handler added by autotest.";
	c->origin = "exotic test";
	c->ptr = &c->ptr;
	return c;
}


#define ADD_TEST(var, prefix, args, cred) \
	var = create_handler(prefix, args, cred); \
	if (!command_add(cbase, var, NULL)) \
		return 0;

#define DEL_TEST(var) \
		if (var) \
		{ \
			if (!command_del(cbase, var)) \
				return 0; \
			hub_free(var); \
			var = NULL; \
		}

/*
 * A hub with a command base and user manager, the user "tester", and the test
 * commands test1..test7. Each test says, through as(), what credentials the
 * user has and whether it is in the hub, so none depends on another.
 */
EXO_SETUP({
	hub = hub_malloc_zero(sizeof(struct hub_info));
	cbase = command_initialize(hub);
	hub->commands = cbase;
	hub->users = uman_init(0, 1);
	if (!cbase || !hub || !hub->users)
		return 0;

	memset(&user, 0, sizeof(user));
	user.id.sid = 1;
	strcpy(user.id.nick, "tester");
	strcpy(user.id.cid, "3AGHMAASJA2RFNM22AA6753V7B7DYEPNTIWHBAY");
	user.credentials = auth_cred_guest;

	ADD_TEST(c_test1, "test1", "", auth_cred_guest);
	ADD_TEST(c_test2, "test2", "", auth_cred_operator);
	ADD_TEST(c_test3, "test3", "N?N?N", auth_cred_guest);
	ADD_TEST(c_test4, "test4", "u", auth_cred_guest);
	ADD_TEST(c_test5, "test5", "i", auth_cred_guest);
	ADD_TEST(c_test6, "test6", "?c", auth_cred_guest);
	ADD_TEST(c_test7, "test7", "C", auth_cred_guest);
	return 1;
});

EXO_TEARDOWN({
	command_free(cmd);
	cmd = NULL;

	if (user_in_hub)
		uman_remove(hub->users, &user);
	user_in_hub = 0;

	DEL_TEST(c_test1);
	DEL_TEST(c_test2);
	DEL_TEST(c_test3);
	DEL_TEST(c_test4);
	DEL_TEST(c_test5);
	DEL_TEST(c_test6);
	DEL_TEST(c_test7);

	uman_shutdown(hub->users);
	command_shutdown(hub->commands);
	hub_free(hub);
	return 1;
});

/* The user's credentials, and whether it is in the hub (a 'u' or 'i' argument
   only resolves a user who is). */
static void as(enum auth_credentials cred, int in_hub)
{
	user.credentials = cred;
	if (in_hub && !user_in_hub)
		user_in_hub = uman_add(hub->users, &user) == 0;
	else if (!in_hub && user_in_hub)
	{
		uman_remove(hub->users, &user);
		user_in_hub = 0;
	}
}

extern void command_destroy(struct hub_command* cmd);

static int verify(const char* str, enum command_parse_status expected)
{
	struct hub_command* cmd = command_parse(cbase, hub, &user, str);
	enum command_parse_status status = cmd->status;
	command_free(cmd);
	return status == expected;
}

static struct hub_command_arg_data* verify_argument(struct hub_command* cmd, enum hub_command_arg_type type)
{
	return  hub_command_arg_next(cmd, type);
}

static int verify_arg_integer(struct hub_command* cmd, int expected)
{
	struct hub_command_arg_data* data = verify_argument(cmd, type_integer);
	return data->data.integer == expected;
}

static int verify_arg_user(struct hub_command* cmd, struct hub_user* expected)
{
	struct hub_command_arg_data* data = verify_argument(cmd, type_user);
	return data->data.user == expected;
}

static int verify_arg_cred(struct hub_command* cmd, enum auth_credentials cred)
{
	struct hub_command_arg_data* data = verify_argument(cmd, type_credentials);
	return data->data.credentials == cred;
}


EXO_TEST(command_access_1, { as(auth_cred_guest, 1); return verify("!test1", cmd_status_ok); });
EXO_TEST(command_access_2, { as(auth_cred_guest, 1); return verify("!test2", cmd_status_access_error); });
EXO_TEST(command_access_3, { as(auth_cred_operator, 1); return verify("!test2", cmd_status_ok); });

EXO_TEST(command_syntax_1, { as(auth_cred_guest, 1); return verify("", cmd_status_syntax_error); });
EXO_TEST(command_syntax_2, { as(auth_cred_guest, 1); return verify("!", cmd_status_syntax_error); });

EXO_TEST(command_missing_args_1, { as(auth_cred_guest, 1); return verify("!test3", cmd_status_missing_args); });
EXO_TEST(command_missing_args_2, { as(auth_cred_guest, 1); return verify("!test3 12345", cmd_status_ok); });
EXO_TEST(command_missing_args_3, { as(auth_cred_guest, 1); return verify("!test3 1 2 345", cmd_status_ok); });
EXO_TEST(command_number_1, { as(auth_cred_guest, 1); return verify("!test3 abc", cmd_status_arg_number); });
EXO_TEST(command_number_2, { as(auth_cred_guest, 1); return verify("!test3 -", cmd_status_arg_number); });
EXO_TEST(command_number_3, { as(auth_cred_guest, 1); return verify("!test3 -12", cmd_status_ok); });

EXO_TEST(command_user_1, { as(auth_cred_guest, 0); return verify("!test4 tester", cmd_status_arg_nick); });
EXO_TEST(command_user_2, { as(auth_cred_guest, 0); return verify("!test5 3AGHMAASJA2RFNM22AA6753V7B7DYEPNTIWHBAY", cmd_status_arg_cid); });
EXO_TEST(command_user_3, { as(auth_cred_guest, 0); user_in_hub = uman_add(hub->users, &user) == 0; return user_in_hub; });
EXO_TEST(command_user_4, { as(auth_cred_guest, 1); return verify("!test4 tester", cmd_status_ok); });
EXO_TEST(command_user_5, { as(auth_cred_guest, 1); return verify("!test5 3AGHMAASJA2RFNM22AA6753V7B7DYEPNTIWHBAY", cmd_status_ok); });

EXO_TEST(command_command_1, { as(auth_cred_guest, 1); return verify("!test6 test1", cmd_status_ok); });
EXO_TEST(command_command_2, { as(auth_cred_guest, 1); return verify("!test6 test2", cmd_status_ok); });
EXO_TEST(command_command_3, { as(auth_cred_guest, 1); return verify("!test6 test3", cmd_status_ok); });
EXO_TEST(command_command_4, { as(auth_cred_guest, 1); return verify("!test6 test4", cmd_status_ok); });
EXO_TEST(command_command_5, { as(auth_cred_guest, 1); return verify("!test6 test5", cmd_status_ok); });
EXO_TEST(command_command_6, { as(auth_cred_guest, 1); return verify("!test6 test6", cmd_status_ok); });
EXO_TEST(command_command_7, { as(auth_cred_guest, 1); return verify("!test6 fail", cmd_status_arg_command); });
EXO_TEST(command_command_8, { as(auth_cred_guest, 1); return verify("!test6", cmd_status_ok); });

EXO_TEST(command_cred_1, { as(auth_cred_guest, 1); return verify("!test7 guest", cmd_status_ok); });
EXO_TEST(command_cred_2, { as(auth_cred_guest, 1); return verify("!test7 user", cmd_status_ok); });
EXO_TEST(command_cred_3, { as(auth_cred_guest, 1); return verify("!test7 operator", cmd_status_ok); });
EXO_TEST(command_cred_4, { as(auth_cred_guest, 1); return verify("!test7 super", cmd_status_ok); });
EXO_TEST(command_cred_5, { as(auth_cred_guest, 1); return verify("!test7 admin", cmd_status_ok); });
EXO_TEST(command_cred_6, { as(auth_cred_guest, 1); return verify("!test7 nobody", cmd_status_arg_cred); });
EXO_TEST(command_cred_7, { as(auth_cred_guest, 1); return verify("!test7 bot", cmd_status_ok); });
EXO_TEST(command_cred_8, { as(auth_cred_guest, 1); return verify("!test7 link", cmd_status_ok); });


#if 0
	cmd_status_arg_cred,       /** <<< "A credentials argument is not valid ('C')" */
};
#endif

// command not found
EXO_TEST(command_parse_3, { as(auth_cred_guest, 1); return verify("!fail", cmd_status_not_found); });

// built-in command
EXO_TEST(command_parse_4, { as(auth_cred_guest, 1); return verify("!help", cmd_status_ok); });


#define SETUP_COMMAND(string) \
	do { \
		if (cmd) command_free(cmd); \
		cmd = command_parse(cbase, hub, &user, string); \
	} while(0)

EXO_TEST(command_argument_integer_1, {
	as(auth_cred_guest, 1); SETUP_COMMAND("!test3");
	return verify_argument(cmd, type_integer) == NULL;
});

EXO_TEST(command_argument_integer_2, {
	as(auth_cred_guest, 1); SETUP_COMMAND("!test3 10 42");
	return verify_arg_integer(cmd, 10) && verify_arg_integer(cmd, 42) && verify_argument(cmd, type_integer) == NULL;
});

EXO_TEST(command_argument_integer_3, {
	as(auth_cred_guest, 1); SETUP_COMMAND("!test3 10 42 6784");
	return verify_arg_integer(cmd, 10) && verify_arg_integer(cmd, 42) && verify_arg_integer(cmd, 6784);
});

EXO_TEST(command_argument_user_1, {
	as(auth_cred_guest, 1); SETUP_COMMAND("!test4 tester");
	return verify_arg_user(cmd, &user) ;
});

EXO_TEST(command_argument_cid_1, {
	as(auth_cred_guest, 1); SETUP_COMMAND("!test5 3AGHMAASJA2RFNM22AA6753V7B7DYEPNTIWHBAY");
	return verify_arg_user(cmd, &user) ;
});

EXO_TEST(command_argument_cred_1, {
	as(auth_cred_guest, 1); SETUP_COMMAND("!test7 admin");
	return verify_arg_cred(cmd, auth_cred_admin);;
});

EXO_TEST(command_argument_cred_2, {
	as(auth_cred_guest, 1); SETUP_COMMAND("!test7 op");
	return verify_arg_cred(cmd, auth_cred_operator);;
});

EXO_TEST(command_argument_cred_3, {
	as(auth_cred_guest, 1); SETUP_COMMAND("!test7 operator");
	return verify_arg_cred(cmd, auth_cred_operator);
});

EXO_TEST(command_argument_cred_4, {
	as(auth_cred_guest, 1); SETUP_COMMAND("!test7 super");
	return verify_arg_cred(cmd, auth_cred_super);
});

EXO_TEST(command_argument_cred_5, {
	as(auth_cred_guest, 1); SETUP_COMMAND("!test7 guest");
	return verify_arg_cred(cmd, auth_cred_guest);
});

EXO_TEST(command_argument_cred_6, {
	as(auth_cred_guest, 1); SETUP_COMMAND("!test7 user");
	return verify_arg_cred(cmd, auth_cred_user);
});

#undef SETUP_COMMAND

/* !redirect: registration, access level and argument parsing. */
EXO_TEST(command_redirect_parse_ok,      { as(auth_cred_operator, 1); return verify("!redirect tester adc://host.example:411", cmd_status_ok); });
EXO_TEST(command_redirect_missing_addr,  { as(auth_cred_operator, 1); return verify("!redirect tester", cmd_status_missing_args); });
EXO_TEST(command_redirect_unknown_nick,  { as(auth_cred_operator, 1); return verify("!redirect nosuchuser adc://host:411", cmd_status_arg_nick); });
EXO_TEST(command_redirect_access,        { as(auth_cred_guest, 1); return verify("!redirect tester adc://host:411", cmd_status_access_error); });

/* !redirect: address validation (command_redirect_valid_address). */
EXO_TEST(command_redirect_addr_adc,          { return command_redirect_valid_address("adc://host.example:411") == 1; });
EXO_TEST(command_redirect_addr_adcs,         { return command_redirect_valid_address("adcs://host.example:412") == 1; });
EXO_TEST(command_redirect_addr_dchub,        { return command_redirect_valid_address("dchub://old.example:411") == 1; });
EXO_TEST(command_redirect_addr_ipv6,         { return command_redirect_valid_address("adc://[::1]:411") == 1; });
EXO_TEST(command_redirect_addr_ipv4_maxport, { return command_redirect_valid_address("adc://1.2.3.4:65535") == 1; });
EXO_TEST(command_redirect_addr_bad_scheme,   { return command_redirect_valid_address("http://host:411") == 0; });
EXO_TEST(command_redirect_addr_no_scheme,    { return command_redirect_valid_address("host:411") == 0; });
EXO_TEST(command_redirect_addr_no_port,      { return command_redirect_valid_address("adc://host") == 0; });
EXO_TEST(command_redirect_addr_empty_host,   { return command_redirect_valid_address("adc://:411") == 0; });
EXO_TEST(command_redirect_addr_port_zero,    { return command_redirect_valid_address("adc://host:0") == 0; });
EXO_TEST(command_redirect_addr_port_high,    { return command_redirect_valid_address("adc://host:99999") == 0; });
EXO_TEST(command_redirect_addr_port_nan,     { return command_redirect_valid_address("adc://host:abc") == 0; });
EXO_TEST(command_redirect_addr_space,        { return command_redirect_valid_address("adc://ho st:411") == 0; });
EXO_TEST(command_redirect_addr_plain,        { return command_redirect_valid_address("justtext") == 0; });
EXO_TEST(command_redirect_addr_empty,        { return command_redirect_valid_address("") == 0; });

/* !kick takes "u?+m": a user, then an optional reason that keeps its spaces. */
static int kick_spec_parse(const char* line, const char* expected_reason)
{
	struct command_handle* h = create_handler("kickspec", "u?+m", auth_cred_guest);
	struct hub_command* parsed;
	struct hub_command_arg_data* reason;
	int ok;

	if (!command_add(cbase, h, NULL))
		return 0;
	parsed = command_parse(cbase, hub, &user, line);
	ok = parsed->status == cmd_status_ok && verify_arg_user(parsed, &user);
	reason = hub_command_arg_next(parsed, type_string);
	if (expected_reason)
		ok = ok && reason && !strcmp(reason->data.string, expected_reason);
	else
		ok = ok && !reason;
	command_free(parsed);
	command_del(cbase, h);
	hub_free(h);
	return ok;
}

EXO_TEST(command_kick_spec_no_reason,   { as(auth_cred_guest, 1); return kick_spec_parse("!kickspec tester", NULL); });
EXO_TEST(command_kick_spec_reason,      { as(auth_cred_guest, 1); return kick_spec_parse("!kickspec tester spamming", "spamming"); });
EXO_TEST(command_kick_spec_long_reason, { as(auth_cred_guest, 1); return kick_spec_parse("!kickspec tester spamming the main chat", "spamming the main chat"); });



