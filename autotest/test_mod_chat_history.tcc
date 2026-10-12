#include "system.h"
#include "plugin_api/handle.h"
#include "plugin_api/command_api.h"

/*
 * Unit tests for the mod_chat_history plugin.
 *
 * The plugin is compiled into the test binary through
 * autotest/mod_chat_history_shim.c, which renames its entry points so they do
 * not collide with mod_auth_sqlite's -- see the note there. The tests call
 * plugin_register() under those renamed names and drive the plugin entirely
 * through the public plugin API: the command handlers are captured as the
 * plugin registers them, so nothing here depends on the plugin's private
 * state layout.
 *
 * What is worth covering:
 *  - the ":memory:" default, i.e. that the plugin loads with no parameters at
 *    all. That is the configuration the hub's built-in default plugin set uses,
 *    where nothing supplies a database path.
 *  - the round trip from on_user_chat_message to !history, since a row is now
 *    heap allocated per field rather than living in one fixed-size struct.
 *  - the clamping of the user-supplied line count, which bounds how much a
 *    guest can make the hub allocate with one command.
 */

extern int mod_chat_history_register(struct plugin_handle* plugin, const char* config);
extern int mod_chat_history_unregister(struct plugin_handle* plugin);

#define MCH_DB "test_mod_chat_history.db"

static struct plugin_handle mch_plugin;

/* Whatever the plugin last sent to a user. */
static char mch_sent[16384];

/* Captured as the plugin registers them, so the tests can invoke them. */
static struct plugin_command_handle* mch_cmd_history;
static struct plugin_command_handle* mch_cmd_cleanup;

/* struct plugin_user is opaque, so the plugin gets a handle to this stand-in
   and reads it back through the accessors wired up in mch_wire(). */
struct mch_user
{
	char nick[MAX_NICK_LEN+1];
};

static struct mch_user mch_alice = { "Alice" };

static struct plugin_user* mch_as_puser(struct mch_user* u) { return (struct plugin_user*) u; }

static const char* mch_get_nick(struct plugin_handle* p, struct plugin_user* u)
{
	(void) p; return u ? ((struct mch_user*) u)->nick : "";
}

static int mch_send_message(struct plugin_handle* p, struct plugin_user* u, const char* message)
{
	(void) p; (void) u;
	snprintf(mch_sent, sizeof(mch_sent), "%s", message ? message : "");
	return 1;
}

static int mch_command_add(struct plugin_handle* p, struct plugin_command_handle* c)
{
	(void) p;
	if (!c || !c->prefix)
		return 0;
	if (!strcmp(c->prefix, "history"))
		mch_cmd_history = c;
	else if (!strcmp(c->prefix, "historycleanup"))
		mch_cmd_cleanup = c;
	return 1;
}

static int mch_command_del(struct plugin_handle* p, struct plugin_command_handle* c)
{
	(void) p; (void) c; return 1;
}

/* What the next command_arg_next() call hands back, or NULL for "the user gave
   no count", which selects history_default. */
static struct plugin_command_arg_data* mch_next_arg;

static struct plugin_command_arg_data* mch_command_arg_next(struct plugin_handle* p, struct plugin_command* c, enum plugin_command_arg_type t)
{
	(void) p; (void) c; (void) t;
	struct plugin_command_arg_data* arg = mch_next_arg;
	mch_next_arg = NULL;
	return arg;
}

static void mch_wire(struct plugin_handle* plugin)
{
	memset(plugin, 0, sizeof(*plugin));
	plugin->hub.get_user_nick = mch_get_nick;
	plugin->hub.send_message = mch_send_message;
	plugin->hub.command_add = mch_command_add;
	plugin->hub.command_del = mch_command_del;
	plugin->hub.command_arg_next = mch_command_arg_next;
}

/* Register a fresh instance of the plugin into mch_plugin, tearing down any
   instance a previous test left there -- mch_wire() zeroes the handle, so an
   instance not unregistered first can no longer be reached, let alone freed. */
static int mch_start(const char* config)
{
	if (mch_plugin.ptr)
		mod_chat_history_unregister(&mch_plugin);
	mch_cmd_history = NULL;
	mch_cmd_cleanup = NULL;
	mch_wire(&mch_plugin);
	return mod_chat_history_register(&mch_plugin, config) == 0
		&& mch_cmd_history != NULL;
}

static void mch_say(const char* message)
{
	mch_plugin.funcs.on_user_chat_message(&mch_plugin, mch_as_puser(&mch_alice), message, 0);
}

/* Invoke !history. have_count selects between "!history <count>" and a bare
   "!history", which falls back to history_default. */
static int mch_history(int count, int have_count)
{
	struct plugin_command cmd;
	static struct plugin_command_arg_data arg;

	memset(&cmd, 0, sizeof(cmd));
	cmd.prefix = "history";

	if (have_count)
	{
		arg.type = plugin_cmd_arg_type_integer;
		arg.data.integer = count;
		mch_next_arg = &arg;
	}
	else
	{
		mch_next_arg = NULL;
	}

	mch_sent[0] = '\0';
	return mch_cmd_history->handler(&mch_plugin, mch_as_puser(&mch_alice), &cmd) == 0;
}

/* Number of "<nick> message" lines in the last captured message. */
static int mch_sent_lines(void)
{
	int lines = 0;
	const char* p;
	for (p = mch_sent; *p; p++)
		if (*p == '<')
			lines++;
	return lines;
}

EXO_TEARDOWN({
	if (mch_plugin.ptr)
		mod_chat_history_unregister(&mch_plugin);
	remove(MCH_DB);
	return 1;
});

/* No parameters at all: the plugin must come up on an in-memory database, and
   register both of its commands. This is how the built-in default plugin set
   loads it. */
EXO_TEST(mch_setup_defaults, {
	return mch_start("") && mch_cmd_cleanup != NULL;
});

/* !history is available to guests; !historycleanup must not be. */
EXO_TEST(mch_command_credentials, {
	if (!mch_start(""))
		return 0;
	return mch_cmd_history->cred == auth_cred_guest
		&& mch_cmd_cleanup->cred == auth_cred_admin;
});

EXO_TEST(mch_empty_history, {
	if (!mch_start("") || !mch_history(0, 0))
		return 0;
	return strstr(mch_sent, "No messages found") != NULL;
});

EXO_TEST(mch_add_and_read_back, {
	if (!mch_start(""))
		return 0;
	mch_say("hello");
	if (!mch_history(0, 0))
		return 0;
	return strstr(mch_sent, "Alice") != NULL && strstr(mch_sent, "hello") != NULL;
});

/* Messages come back oldest first, so a reader sees the conversation in order. */
EXO_TEST(mch_ordering, {
	const char* first;
	const char* second;
	if (!mch_start(""))
		return 0;
	mch_say("hello");
	mch_say("second");
	if (!mch_history(0, 0))
		return 0;
	first = strstr(mch_sent, "hello");
	second = strstr(mch_sent, "second");
	return first && second && first < second;
});

/* An explicit count limits how many lines come back. */
EXO_TEST(mch_explicit_count, {
	if (!mch_start(""))
		return 0;
	mch_say("hello");
	mch_say("second");
	if (!mch_history(1, 1))
		return 0;
	return mch_sent_lines() == 1;
});

/* "!history -1" would be "no limit" to SQLite's LIMIT clause, so a negative
   count must clamp to zero rather than dumping the whole table. */
EXO_TEST(mch_negative_count_clamped, {
	if (!mch_start(""))
		return 0;
	mch_say("hello");
	if (!mch_history(-1, 1))
		return 0;
	return strstr(mch_sent, "No messages found") != NULL;
});

/* A count above history_max is clamped to it, bounding one command's cost. */
EXO_TEST(mch_excessive_count_clamped, {
	if (!mch_start("history_max=1"))
		return 0;
	mch_say("one");
	mch_say("two");
	if (!mch_history(1000000, 1))
		return 0;
	return mch_sent_lines() == 1;
});

/* A message far longer than a chat line survives the round trip: a row is heap
   allocated per field now, not copied into a fixed-size struct member. */
EXO_TEST(mch_long_message, {
	char big[4096];
	memset(big, 'x', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	if (!mch_start(""))
		return 0;
	mch_say(big);
	if (!mch_history(1, 1))
		return 0;
	return strstr(mch_sent, big) != NULL;
});

/* !historycleanup empties the history. */
EXO_TEST(mch_cleanup_empties_history, {
	struct plugin_command cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.prefix = "historycleanup";

	if (!mch_start(""))
		return 0;
	mch_say("forget me");
	mch_sent[0] = '\0';
	if (mch_cmd_cleanup->handler(&mch_plugin, mch_as_puser(&mch_alice), &cmd) != 0)
		return 0;
	if (!mch_history(0, 0))
		return 0;
	return strstr(mch_sent, "No messages found") != NULL;
});

EXO_TEST(mch_teardown_defaults, {
	if (!mch_start(""))
		return 0;
	return mod_chat_history_unregister(&mch_plugin) == 0;
});

/* An unknown parameter must fail the load rather than being ignored. */
EXO_TEST(mch_rejects_unknown_parameter, {
	struct plugin_handle p;
	mch_wire(&p);
	return mod_chat_history_register(&p, "no_such_option=1") == -1;
});

/* With file=, the history outlives the plugin instance. This is what the
   separate mod_chat_history_sqlite plugin used to be for. */
EXO_TEST(mch_persists_across_reload, {
	struct plugin_handle p;
	char cfg[256];

	remove(MCH_DB);
	snprintf(cfg, sizeof(cfg), "file=%s", MCH_DB);

	mch_wire(&p);
	if (mod_chat_history_register(&p, cfg) != 0)
		return 0;
	p.funcs.on_user_chat_message(&p, mch_as_puser(&mch_alice), "durable", 0);
	if (mod_chat_history_unregister(&p) != 0)
		return 0;

	/* Reopen the same database through a fresh plugin instance. */
	if (!mch_start(cfg))
		return 0;
	if (!mch_history(0, 0))
		return 0;
	return strstr(mch_sent, "durable") != NULL;
});

/* An in-memory instance starts empty: a file-backed one with history in it
   does not leak into it -- ":memory:" really is per-instance storage. */
EXO_TEST(mch_memory_is_not_shared, {
	struct plugin_handle p;
	char cfg[256];

	remove(MCH_DB);
	snprintf(cfg, sizeof(cfg), "file=%s", MCH_DB);
	mch_wire(&p);
	if (mod_chat_history_register(&p, cfg) != 0)
		return 0;
	p.funcs.on_user_chat_message(&p, mch_as_puser(&mch_alice), "durable", 0);
	mod_chat_history_unregister(&p);

	if (!mch_start(""))
		return 0;
	if (!mch_history(0, 0))
		return 0;
	return strstr(mch_sent, "No messages found") != NULL;
});

/* history_connect controls what a user is sent on login. */
EXO_TEST(mch_login_sends_history, {
	if (!mch_start("history_connect=5"))
		return 0;
	mch_say("welcome back");
	mch_sent[0] = '\0';
	mch_plugin.funcs.on_user_login(&mch_plugin, mch_as_puser(&mch_alice));
	return strstr(mch_sent, "Chat history") != NULL && strstr(mch_sent, "welcome back") != NULL;
});

/* history_connect = 0 means "send nothing on login". */
EXO_TEST(mch_login_silent_when_disabled, {
	if (!mch_start("history_connect=0"))
		return 0;
	mch_say("unseen");
	mch_sent[0] = '\0';
	mch_plugin.funcs.on_user_login(&mch_plugin, mch_as_puser(&mch_alice));
	return mch_sent[0] == '\0';
});
