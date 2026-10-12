#include "system.h"
#include "plugin_api/handle.h"
#include "plugin_api/command_api.h"

/*
 * Unit tests for the mod_users plugin.
 *
 * The plugin comes in through autotest/mod_users_shim.c. It only ever talks to
 * the hub through plugin->hub, so the tests wire that table to a small fake:
 * an in-memory account store standing in for the storage plugin, and a handful
 * of connected users. Every test starts from mu_reset(), so they do not depend
 * on one another.
 *
 * The rule under test above all: an operator can only manage accounts below
 * their own level and hand out levels below it.
 */

extern int mod_users_register(struct plugin_handle* plugin, const char* config);
extern int mod_users_unregister(struct plugin_handle* plugin);

static struct plugin_handle mu_plugin;

/* ---- the fake account store ---------------------------------------------- */

#define MU_MAX_ACCOUNTS 8

static struct auth_info mu_accounts[MU_MAX_ACCOUNTS];
static int mu_account_count;
static int mu_can_list;

static struct auth_info* mu_find_account(const char* nick)
{
	int i;
	for (i = 0; i < mu_account_count; i++)
		if (strcasecmp(mu_accounts[i].nickname, nick) == 0)
			return &mu_accounts[i];
	return NULL;
}

static void mu_add_account(const char* nick, const char* pass, enum auth_credentials cred)
{
	struct auth_info* a = &mu_accounts[mu_account_count++];
	memset(a, 0, sizeof(*a));
	snprintf(a->nickname, sizeof(a->nickname), "%s", nick);
	snprintf(a->password, sizeof(a->password), "%s", pass);
	a->credentials = cred;
}

static int mu_auth_get_user(struct plugin_handle* p, const char* nick, struct auth_info* out)
{
	struct auth_info* a = mu_find_account(nick);
	(void) p;
	if (!a)
		return 0;
	memcpy(out, a, sizeof(*out));
	return 1;
}

static int mu_auth_register_user(struct plugin_handle* p, struct auth_info* user)
{
	(void) p;
	if (mu_find_account(user->nickname) || mu_account_count == MU_MAX_ACCOUNTS)
		return 0;
	memcpy(&mu_accounts[mu_account_count++], user, sizeof(*user));
	return 1;
}

static int mu_auth_update_user(struct plugin_handle* p, struct auth_info* user)
{
	struct auth_info* a = mu_find_account(user->nickname);
	(void) p;
	if (!a)
		return 0;
	memcpy(a->password, user->password, sizeof(a->password));
	a->credentials = user->credentials;
	return 1;
}

static int mu_auth_delete_user(struct plugin_handle* p, struct auth_info* user)
{
	struct auth_info* a = mu_find_account(user->nickname);
	(void) p;
	if (!a)
		return 0;
	*a = mu_accounts[--mu_account_count];
	return 1;
}

static int mu_auth_list_users(struct plugin_handle* p, auth_list_users_callback callback, void* ptr)
{
	int i;
	(void) p;
	if (!mu_can_list)
		return -1;
	for (i = 0; i < mu_account_count; i++)
	{
		/* What the hub does on the way through: no passwords. */
		struct auth_info copy = mu_accounts[i];
		memset(copy.password, 0, sizeof(copy.password));
		callback(&copy, ptr);
	}
	return mu_account_count;
}

/* ---- connected users ------------------------------------------------------ */

struct mu_user
{
	char nick[MAX_NICK_LEN+1];
	enum auth_credentials cred;
	int online;
	int disconnected;
	char sent[8192];       /* the last message the plugin sent this user */
};

static struct mu_user mu_admin;   /* "Admin", admin  */
static struct mu_user mu_super;   /* "Super", super  */
static struct mu_user mu_op;      /* "Oper", operator */
static struct mu_user mu_bob;     /* "Bob", user     */
static struct mu_user mu_guest;   /* "Carol", guest, no account */

static struct mu_user* mu_users[] = { &mu_admin, &mu_super, &mu_op, &mu_bob, &mu_guest };

static struct plugin_user* mu_as_puser(struct mu_user* u) { return (struct plugin_user*) u; }
static struct mu_user* mu_as_user(struct plugin_user* u) { return (struct mu_user*) u; }

static const char* mu_get_nick(struct plugin_handle* p, struct plugin_user* u)
{
	(void) p; return u ? mu_as_user(u)->nick : "";
}

static enum auth_credentials mu_get_credentials(struct plugin_handle* p, struct plugin_user* u)
{
	(void) p; return u ? mu_as_user(u)->cred : auth_cred_none;
}

static struct plugin_user* mu_get_user_by_nick(struct plugin_handle* p, const char* nick)
{
	size_t i;
	(void) p;
	for (i = 0; i < sizeof(mu_users) / sizeof(mu_users[0]); i++)
		if (mu_users[i]->online && strcasecmp(mu_users[i]->nick, nick) == 0)
			return mu_as_puser(mu_users[i]);
	return NULL;
}

static int mu_send_message(struct plugin_handle* p, struct plugin_user* u, const char* message)
{
	(void) p;
	snprintf(mu_as_user(u)->sent, sizeof(mu_as_user(u)->sent), "%s", message ? message : "");
	return 1;
}

static int mu_user_disconnect(struct plugin_handle* p, struct plugin_user* u)
{
	(void) p;
	mu_as_user(u)->disconnected = 1;
	return 0;
}

/* ---- commands ------------------------------------------------------------- */

#define MU_MAX_COMMANDS 8

static struct plugin_command_handle* mu_commands[MU_MAX_COMMANDS];
static int mu_command_count;

static int mu_command_add(struct plugin_handle* p, struct plugin_command_handle* c)
{
	(void) p;
	if (mu_command_count < MU_MAX_COMMANDS)
		mu_commands[mu_command_count++] = c;
	return 1;
}

static int mu_command_del(struct plugin_handle* p, struct plugin_command_handle* c)
{
	(void) p; (void) c; return 1;
}

static struct plugin_command_handle* mu_command(const char* prefix)
{
	int i;
	for (i = 0; i < mu_command_count; i++)
		if (!strcmp(mu_commands[i]->prefix, prefix))
			return mu_commands[i];
	return NULL;
}

/* The arguments of the command being run, already parsed as the hub would. */
static struct plugin_command_arg_data mu_args[4];
static int mu_arg_count;
static int mu_arg_next;

static struct plugin_command_arg_data* mu_command_arg_next(struct plugin_handle* p, struct plugin_command* c, enum plugin_command_arg_type t)
{
	(void) p; (void) c;
	if (mu_arg_next >= mu_arg_count || mu_args[mu_arg_next].type != t)
		return NULL;
	return &mu_args[mu_arg_next++];
}

static void mu_arg_string(const char* s)
{
	mu_args[mu_arg_count].type = plugin_cmd_arg_type_string;
	mu_args[mu_arg_count].data.string = (char*) s;
	mu_arg_count++;
}

static void mu_arg_cred(enum auth_credentials cred)
{
	mu_args[mu_arg_count].type = plugin_cmd_arg_type_credentials;
	mu_args[mu_arg_count].data.credentials = cred;
	mu_arg_count++;
}

/* Run a command as `who` with the arguments queued by mu_arg_*(). Returns
   what the plugin replied to `who`. */
static const char* mu_run(struct mu_user* who, const char* prefix)
{
	struct plugin_command cmd;
	struct plugin_command_handle* handle = mu_command(prefix);

	memset(&cmd, 0, sizeof(cmd));
	cmd.prefix = prefix;
	mu_arg_next = 0;
	who->sent[0] = '\0';
	if (handle)
		handle->handler(&mu_plugin, mu_as_puser(who), &cmd);
	mu_arg_count = 0;
	return who->sent;
}

static void mu_user_init(struct mu_user* u, const char* nick, enum auth_credentials cred)
{
	memset(u, 0, sizeof(*u));
	snprintf(u->nick, sizeof(u->nick), "%s", nick);
	u->cred = cred;
	u->online = 1;
}

static int mu_reset(void)
{
	if (mu_plugin.ptr)
		mod_users_unregister(&mu_plugin);

	mu_account_count = 0;
	mu_add_account("Admin", "a", auth_cred_admin);
	mu_add_account("Super", "s", auth_cred_super);
	mu_add_account("Oper", "o", auth_cred_operator);
	mu_add_account("Bob", "b", auth_cred_user);
	mu_can_list = 1;

	mu_user_init(&mu_admin, "Admin", auth_cred_admin);
	mu_user_init(&mu_super, "Super", auth_cred_super);
	mu_user_init(&mu_op, "Oper", auth_cred_operator);
	mu_user_init(&mu_bob, "Bob", auth_cred_user);
	mu_user_init(&mu_guest, "Carol", auth_cred_guest);

	mu_command_count = 0;
	mu_arg_count = 0;

	memset(&mu_plugin, 0, sizeof(mu_plugin));
	mu_plugin.hub.send_message = mu_send_message;
	mu_plugin.hub.user_disconnect = mu_user_disconnect;
	mu_plugin.hub.auth_get_user = mu_auth_get_user;
	mu_plugin.hub.auth_register_user = mu_auth_register_user;
	mu_plugin.hub.auth_update_user = mu_auth_update_user;
	mu_plugin.hub.auth_delete_user = mu_auth_delete_user;
	mu_plugin.hub.auth_list_users = mu_auth_list_users;
	mu_plugin.hub.command_add = mu_command_add;
	mu_plugin.hub.command_del = mu_command_del;
	mu_plugin.hub.command_arg_next = mu_command_arg_next;
	mu_plugin.hub.get_user_nick = mu_get_nick;
	mu_plugin.hub.get_user_credentials = mu_get_credentials;
	mu_plugin.hub.get_user_by_nick = mu_get_user_by_nick;

	return mod_users_register(&mu_plugin, "") == 0;
}

/* ---- registration --------------------------------------------------------- */

EXO_TEST(mu_registers_operator_commands, {
	const char* names[] = { "useradd", "userdel", "usermod", "userpass", "userlist" };
	size_t i;
	if (!mu_reset() || mu_command_count != 5)
		return 0;
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
	{
		struct plugin_command_handle* c = mu_command(names[i]);
		if (!c || c->cred != auth_cred_operator)
			return 0;
	}
	return 1;
});

/* ---- !useradd ------------------------------------------------------------- */

EXO_TEST(mu_useradd_defaults_to_user, {
	struct auth_info* a;
	if (!mu_reset())
		return 0;
	mu_arg_string("Dave");
	mu_arg_string("secret");
	if (!strstr(mu_run(&mu_op, "useradd"), "Registered \"Dave\" as user"))
		return 0;
	a = mu_find_account("Dave");
	return a && a->credentials == auth_cred_user && !strcmp(a->password, "secret");
});

EXO_TEST(mu_useradd_level_below_own, {
	struct auth_info* a;
	if (!mu_reset())
		return 0;
	mu_arg_string("Dave");
	mu_arg_string("secret");
	mu_arg_cred(auth_cred_operator);
	mu_run(&mu_super, "useradd");
	a = mu_find_account("Dave");
	return a && a->credentials == auth_cred_operator;
});

/* Not even an equal: a second operator account is a second vote. */
EXO_TEST(mu_useradd_refuses_own_level, {
	if (!mu_reset())
		return 0;
	mu_arg_string("Dave");
	mu_arg_string("secret");
	mu_arg_cred(auth_cred_operator);
	return strstr(mu_run(&mu_op, "useradd"), "below your own") != NULL
		&& !mu_find_account("Dave");
});

EXO_TEST(mu_useradd_refuses_higher_level, {
	if (!mu_reset())
		return 0;
	mu_arg_string("Dave");
	mu_arg_string("secret");
	mu_arg_cred(auth_cred_admin);
	mu_run(&mu_op, "useradd");
	return !mu_find_account("Dave");
});

EXO_TEST(mu_useradd_refuses_guest_level, {
	if (!mu_reset())
		return 0;
	mu_arg_string("Dave");
	mu_arg_string("secret");
	mu_arg_cred(auth_cred_guest);
	return strstr(mu_run(&mu_admin, "useradd"), "cannot have the level") != NULL
		&& !mu_find_account("Dave");
});

/* Taken regardless of case, the way the storage plugins match nicks. */
EXO_TEST(mu_useradd_refuses_existing, {
	if (!mu_reset())
		return 0;
	mu_arg_string("bob");
	mu_arg_string("secret");
	return strstr(mu_run(&mu_op, "useradd"), "already registered") != NULL
		&& mu_account_count == 4;
});

EXO_TEST(mu_useradd_refuses_long_password, {
	char pass[MAX_PASS_LEN + 2];
	if (!mu_reset())
		return 0;
	memset(pass, 'x', sizeof(pass) - 1);
	pass[sizeof(pass) - 1] = '\0';
	mu_arg_string("Dave");
	mu_arg_string(pass);
	mu_run(&mu_op, "useradd");
	return !mu_find_account("Dave");
});

/* A guest already on the nick hears about it, and stays connected. */
EXO_TEST(mu_useradd_tells_guest_on_nick, {
	if (!mu_reset())
		return 0;
	mu_arg_string("carol");
	mu_arg_string("secret");
	mu_run(&mu_op, "useradd");
	return mu_find_account("carol")
		&& strstr(mu_guest.sent, "account has been created") != NULL
		&& !mu_guest.disconnected;
});

/* ---- !userdel ------------------------------------------------------------- */

/* The session outlives the account unless the user is put out. */
EXO_TEST(mu_userdel_disconnects_logged_in_user, {
	if (!mu_reset())
		return 0;
	mu_arg_string("Bob");
	if (!strstr(mu_run(&mu_op, "userdel"), "disconnected"))
		return 0;
	return !mu_find_account("Bob")
		&& mu_bob.disconnected
		&& strstr(mu_bob.sent, "deleted by Oper") != NULL;
});

EXO_TEST(mu_userdel_offline_user, {
	if (!mu_reset())
		return 0;
	mu_bob.online = 0;
	mu_arg_string("Bob");
	return strstr(mu_run(&mu_op, "userdel"), "Deleted \"Bob\".") != NULL
		&& !mu_find_account("Bob");
});

EXO_TEST(mu_userdel_refuses_equal, {
	if (!mu_reset())
		return 0;
	mu_add_account("Oper2", "x", auth_cred_operator);
	mu_arg_string("Oper2");
	mu_run(&mu_op, "userdel");
	return mu_find_account("Oper2") != NULL;
});

EXO_TEST(mu_userdel_refuses_higher, {
	if (!mu_reset())
		return 0;
	mu_arg_string("Admin");
	return strstr(mu_run(&mu_op, "userdel"), "below your own level") != NULL
		&& mu_find_account("Admin") && !mu_admin.disconnected;
});

/* Not even an admin, and not by changing the case of their own nick. */
EXO_TEST(mu_userdel_refuses_self, {
	if (!mu_reset())
		return 0;
	mu_arg_string("ADMIN");
	return strstr(mu_run(&mu_admin, "userdel"), "your own account") != NULL
		&& mu_find_account("Admin") != NULL;
});

EXO_TEST(mu_userdel_unknown, {
	if (!mu_reset())
		return 0;
	mu_arg_string("Nobody");
	return strstr(mu_run(&mu_op, "userdel"), "No account named") != NULL
		&& mu_account_count == 4;
});

/* ---- !usermod ------------------------------------------------------------- */

EXO_TEST(mu_usermod_promote_keeps_session, {
	struct auth_info* a;
	if (!mu_reset())
		return 0;
	mu_arg_string("Bob");
	mu_arg_cred(auth_cred_operator);
	if (!strstr(mu_run(&mu_super, "usermod"), "takes effect when they reconnect"))
		return 0;
	a = mu_find_account("Bob");
	return a && a->credentials == auth_cred_operator
		&& !strcmp(a->password, "b")
		&& !mu_bob.disconnected
		&& strstr(mu_bob.sent, "promoted to operator") != NULL;
});

/* A demoted operator must not keep operator powers for the rest of the session. */
EXO_TEST(mu_usermod_demote_disconnects, {
	struct auth_info* a;
	if (!mu_reset())
		return 0;
	mu_arg_string("Oper");
	mu_arg_cred(auth_cred_user);
	mu_run(&mu_super, "usermod");
	a = mu_find_account("Oper");
	return a && a->credentials == auth_cred_user && mu_op.disconnected;
});

EXO_TEST(mu_usermod_refuses_promotion_to_own_level, {
	if (!mu_reset())
		return 0;
	mu_arg_string("Bob");
	mu_arg_cred(auth_cred_operator);
	mu_run(&mu_op, "usermod");
	return mu_find_account("Bob")->credentials == auth_cred_user;
});

EXO_TEST(mu_usermod_refuses_self, {
	if (!mu_reset())
		return 0;
	mu_arg_string("Super");
	mu_arg_cred(auth_cred_operator);
	mu_run(&mu_super, "usermod");
	return mu_find_account("Super")->credentials == auth_cred_super;
});

EXO_TEST(mu_usermod_same_level, {
	if (!mu_reset())
		return 0;
	mu_arg_string("Bob");
	mu_arg_cred(auth_cred_user);
	return strstr(mu_run(&mu_op, "usermod"), "already user") != NULL;
});

/* ---- !userpass ------------------------------------------------------------ */

EXO_TEST(mu_userpass_changes_password_only, {
	struct auth_info* a;
	if (!mu_reset())
		return 0;
	mu_arg_string("Bob");
	mu_arg_string("newpass");
	mu_run(&mu_op, "userpass");
	a = mu_find_account("Bob");
	return a && !strcmp(a->password, "newpass")
		&& a->credentials == auth_cred_user
		&& strstr(mu_bob.sent, "password has been changed") != NULL
		&& !mu_bob.disconnected;
});

EXO_TEST(mu_userpass_refuses_higher, {
	if (!mu_reset())
		return 0;
	mu_arg_string("Admin");
	mu_arg_string("newpass");
	mu_run(&mu_op, "userpass");
	return !strcmp(mu_find_account("Admin")->password, "a");
});

/* ---- !userlist ------------------------------------------------------------ */

/* Highest level first, and never a password. */
EXO_TEST(mu_userlist_all, {
	const char* out;
	const char* admin;
	const char* bob;
	if (!mu_reset())
		return 0;
	out = mu_run(&mu_op, "userlist");
	admin = strstr(out, "Admin");
	bob = strstr(out, "Bob");
	return strstr(out, "4 accounts") != NULL
		&& admin && bob && admin < bob;
});

EXO_TEST(mu_userlist_pattern, {
	const char* out;
	if (!mu_reset())
		return 0;
	mu_arg_string("PER");
	out = mu_run(&mu_op, "userlist");
	return strstr(out, "2 accounts matching") != NULL
		&& strstr(out, "Oper") && strstr(out, "Super")
		&& !strstr(out, "Bob");
});

EXO_TEST(mu_userlist_no_match, {
	if (!mu_reset())
		return 0;
	mu_arg_string("zzz");
	return strstr(mu_run(&mu_op, "userlist"), "No accounts match") != NULL;
});

EXO_TEST(mu_userlist_storage_cannot_list, {
	if (!mu_reset())
		return 0;
	mu_can_list = 0;
	return strstr(mu_run(&mu_op, "userlist"), "can list") != NULL;
});

EXO_TEST(mu_teardown, {
	return mod_users_unregister(&mu_plugin) == 0 && mu_plugin.ptr == NULL;
});
