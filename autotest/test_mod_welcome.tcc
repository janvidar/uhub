#include "system.h"
#include "plugin_api/handle.h"

/*
 * Unit tests for mod_welcome's message codes, through
 * autotest/mod_welcome_shim.c: register it with a motd file, log a user in,
 * and look at what was sent.
 *
 * The case that mattered: a "%" as the very last character used to step the
 * formatter past the end of the string, so it went on reading whatever memory
 * followed. ASan catches that read; without it the motd may just come out
 * with junk on the end.
 */

extern int mod_welcome_register(struct plugin_handle* plugin, const char* config);
extern int mod_welcome_unregister(struct plugin_handle* plugin);

#define MW_FILE "test_mod_welcome_motd.txt"

static struct plugin_handle mw_plugin;
static char mw_sent[1024];
static char mw_nick[] = "Alice";

static const char* mw_get_nick(struct plugin_handle* p, struct plugin_user* u)
{
	(void) p; (void) u; return mw_nick;
}

static enum auth_credentials mw_get_credentials(struct plugin_handle* p, struct plugin_user* u)
{
	(void) p; (void) u; return auth_cred_user;
}

static int mw_send_message(struct plugin_handle* p, struct plugin_user* u, const char* message)
{
	(void) p; (void) u;
	snprintf(mw_sent, sizeof(mw_sent), "%s", message);
	return 1;
}

static int mw_command(struct plugin_handle* p, struct plugin_command_handle* c)
{
	(void) p; (void) c; return 1;
}

/* What the motd `text` comes out as when a user logs in. */
static const char* mw_motd(const char* text)
{
	FILE* fp = fopen(MW_FILE, "wb");
	char config[64];
	int ok;

	mw_sent[0] = '\0';
	if (!fp)
		return "";
	fputs(text, fp);
	fclose(fp);

	memset(&mw_plugin, 0, sizeof(mw_plugin));
	mw_plugin.hub.get_user_nick = mw_get_nick;
	mw_plugin.hub.get_user_credentials = mw_get_credentials;
	mw_plugin.hub.send_message = mw_send_message;
	mw_plugin.hub.command_add = mw_command;
	mw_plugin.hub.command_del = mw_command;

	snprintf(config, sizeof(config), "motd=%s", MW_FILE);
	ok = mod_welcome_register(&mw_plugin, config) == 0;
	remove(MW_FILE);
	if (!ok)
		return "";
	mw_plugin.funcs.on_user_login(&mw_plugin, NULL);
	mod_welcome_unregister(&mw_plugin);
	return mw_sent;
}

EXO_TEST(mw_motd_plain, {
	return !strcmp(mw_motd("Welcome!"), "Welcome!");
});

EXO_TEST(mw_motd_nick, {
	return !strcmp(mw_motd("Welcome, %n."), "Welcome, Alice.");
});

EXO_TEST(mw_motd_percent, {
	return !strcmp(mw_motd("100%% %c"), "100% user");
});

EXO_TEST(mw_motd_trailing_percent, {
	return !strcmp(mw_motd("Up 100%"), "Up 100%");
});

EXO_TEST(mw_motd_only_percent, {
	return !strcmp(mw_motd("%"), "%");
});
