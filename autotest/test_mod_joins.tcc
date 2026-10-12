#include "system.h"
#include "plugin_api/handle.h"

/*
 * Unit tests for mod_joins, through autotest/mod_joins_shim.c, against a fake
 * hub: send_chat records what would have gone out.
 */

extern int mod_joins_register(struct plugin_handle* plugin, const char* config);
extern int mod_joins_unregister(struct plugin_handle* plugin);

static struct plugin_handle mj_plugin;

struct mj_user
{
	char nick[MAX_NICK_LEN+1];
	enum auth_credentials cred;
};

static struct mj_user mj_alice;

static struct plugin_user* mj_as_puser(struct mj_user* u) { return (struct plugin_user*) u; }

static const char* mj_get_nick(struct plugin_handle* p, struct plugin_user* u)
{
	(void) p; return ((struct mj_user*) u)->nick;
}

static enum auth_credentials mj_get_credentials(struct plugin_handle* p, struct plugin_user* u)
{
	(void) p; return ((struct mj_user*) u)->cred;
}

/* The last send_chat call. */
static char mj_sent[2048];
static int mj_sends;
static enum auth_credentials mj_low;
static enum auth_credentials mj_high;

static int mj_send_chat(struct plugin_handle* p, enum auth_credentials low, enum auth_credentials high, const char* message)
{
	(void) p;
	snprintf(mj_sent, sizeof(mj_sent), "%s", message);
	mj_low = low;
	mj_high = high;
	mj_sends++;
	return 1;
}

static int mj_start(const char* config)
{
	if (mj_plugin.ptr)
		mod_joins_unregister(&mj_plugin);
	memset(&mj_plugin, 0, sizeof(mj_plugin));
	mj_plugin.hub.get_user_nick = mj_get_nick;
	mj_plugin.hub.get_user_credentials = mj_get_credentials;
	mj_plugin.hub.send_chat = mj_send_chat;

	memset(&mj_alice, 0, sizeof(mj_alice));
	strcpy(mj_alice.nick, "Alice");
	mj_alice.cred = auth_cred_user;

	mj_sent[0] = '\0';
	mj_sends = 0;
	return mod_joins_register(&mj_plugin, config) == 0;
}

static void mj_login(void)  { mj_plugin.funcs.on_user_login(&mj_plugin, mj_as_puser(&mj_alice)); }
static void mj_logout(const char* reason) { mj_plugin.funcs.on_user_logout(&mj_plugin, mj_as_puser(&mj_alice), reason); }

/* Write a message file for the join= / leave= parameters. */
#define MJ_FILE "test_mod_joins.txt"
static int mj_write_file(const char* text)
{
	FILE* fp = fopen(MJ_FILE, "wb");
	if (!fp)
		return 0;
	fputs(text, fp);
	fclose(fp);
	return 1;
}

/* ---- defaults ------------------------------------------------------------- */

/* No parameters: both messages, to everybody. */
EXO_TEST(mj_default_join, {
	if (!mj_start(""))
		return 0;
	mj_login();
	return mj_sends == 1 && !strcmp(mj_sent, "*** Alice joined.")
		&& mj_low == auth_cred_guest && mj_high == auth_cred_admin;
});

EXO_TEST(mj_default_leave, {
	if (!mj_start(""))
		return 0;
	mj_login();
	mj_logout("disconnected");
	return mj_sends == 2 && !strcmp(mj_sent, "*** Alice left.");
});

/* ---- parameters ----------------------------------------------------------- */

EXO_TEST(mj_min_notify, {
	if (!mj_start("min_notify=op"))
		return 0;
	mj_login();
	return mj_low == auth_cred_operator && mj_high == auth_cred_admin;
});

EXO_TEST(mj_bad_min_notify, {
	return !mj_start("min_notify=everyone") && mj_plugin.error_msg != NULL;
});

EXO_TEST(mj_unknown_parameter, {
	return !mj_start("colour=blue") && mj_plugin.error_msg != NULL;
});

EXO_TEST(mj_missing_file, {
	return !mj_start("join=/nonexistent/uhub/join.txt") && mj_plugin.error_msg != NULL;
});

/* join=none keeps quiet on the way in, and still announces the way out. */
EXO_TEST(mj_join_none, {
	if (!mj_start("join=none"))
		return 0;
	mj_login();
	if (mj_sends != 0)
		return 0;
	mj_logout("kicked");
	return mj_sends == 1 && !strcmp(mj_sent, "*** Alice left.");
});

EXO_TEST(mj_leave_none, {
	if (!mj_start("leave=none"))
		return 0;
	mj_login();
	mj_logout("kicked");
	return mj_sends == 1;
});

/* The file's trailing newline is not part of the message. */
EXO_TEST(mj_message_from_file, {
	int ok;
	char config[64];
	if (!mj_write_file("Bye %n (%r)\n"))
		return 0;
	snprintf(config, sizeof(config), "leave=%s", MJ_FILE);
	ok = mj_start(config);
	remove(MJ_FILE);
	if (!ok)
		return 0;
	mj_login();
	mj_logout("timeout");
	return !strcmp(mj_sent, "Bye Alice (timeout)");
});

/* ---- formatting ----------------------------------------------------------- */

static const char* mj_format_join(const char* text)
{
	char config[64];
	if (!mj_write_file(text))
		return "";
	snprintf(config, sizeof(config), "join=%s", MJ_FILE);
	if (!mj_start(config))
	{
		remove(MJ_FILE);
		return "";
	}
	remove(MJ_FILE);
	mj_login();
	return mj_sent;
}

EXO_TEST(mj_format_credentials, {
	return !strcmp(mj_format_join("%n is %c"), "Alice is user");
});

/* %r means nothing on the way in. */
EXO_TEST(mj_format_reason_on_join, {
	return !strcmp(mj_format_join("[%r]"), "[]");
});

EXO_TEST(mj_format_percent, {
	return !strcmp(mj_format_join("100%% %n"), "100% Alice");
});

EXO_TEST(mj_format_unknown_code, {
	return !strcmp(mj_format_join("%x%n"), "%xAlice");
});

/* A "%" at the very end must not run past the end of the string. */
EXO_TEST(mj_format_trailing_percent, {
	return !strcmp(mj_format_join("%n %"), "Alice %");
});

EXO_TEST(mj_format_time, {
	const char* out = mj_format_join("%H:%M:%S");
	return strlen(out) == 8 && out[2] == ':' && out[5] == ':';
});

EXO_TEST(mj_teardown, {
	return mod_joins_unregister(&mj_plugin) == 0 && mj_plugin.ptr == NULL;
});
