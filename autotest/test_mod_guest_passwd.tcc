#include "system.h"
#include "util/list.h"
#include "core/hub.h"
#include "core/plugininvoke.h"
#include "core/pluginloader.h"
#include "plugin_api/handle.h"

/*
 * Unit tests for mod_guest_passwd, and for the rule in plugin_auth_get_user
 * that makes it safe to load: a real account beats a guest-level record, and a
 * guest-level record beats a plugin refusing the nick, whatever order the
 * plugins were loaded in.
 *
 * The plugin comes in through autotest/mod_guest_passwd_shim.c. For the order
 * tests a hub is put together with nothing but a plugin list, holding the real
 * plugin next to fake storage plugins.
 */

extern int mod_guest_passwd_register(struct plugin_handle* plugin, const char* config);
extern int mod_guest_passwd_unregister(struct plugin_handle* plugin);

static int mgp_register(struct plugin_handle* plugin, const char* config)
{
	memset(plugin, 0, sizeof(*plugin));
	return mod_guest_passwd_register(plugin, config);
}

/* ---- configuration -------------------------------------------------------- */

EXO_TEST(mgp_requires_password, {
	struct plugin_handle p;
	return mgp_register(&p, "") == -1 && p.error_msg && strstr(p.error_msg, "password=");
});

EXO_TEST(mgp_rejects_unknown_parameter, {
	struct plugin_handle p;
	return mgp_register(&p, "password=x colour=blue") == -1 && p.error_msg != NULL;
});

/* A password no client could send back would lock every guest out. */
EXO_TEST(mgp_rejects_long_password, {
	struct plugin_handle p;
	char config[MAX_PASS_LEN + 32];
	char* end;
	strcpy(config, "password=");
	end = config + strlen(config);
	memset(end, 'x', MAX_PASS_LEN + 1);
	end[MAX_PASS_LEN + 1] = '\0';
	return mgp_register(&p, config) == -1 && p.error_msg != NULL;
});

EXO_TEST(mgp_accepts_max_length_password, {
	struct plugin_handle p;
	char config[MAX_PASS_LEN + 32];
	char* end;
	int ok;
	strcpy(config, "password=");
	end = config + strlen(config);
	memset(end, 'x', MAX_PASS_LEN);
	end[MAX_PASS_LEN] = '\0';
	ok = mgp_register(&p, config) == 0;
	mod_guest_passwd_unregister(&p);
	return ok;
});

/* Every nick: a guest, who must give the shared password. */
EXO_TEST(mgp_answers_every_nick_as_guest, {
	struct plugin_handle p;
	struct auth_info info;
	int ok;
	if (mgp_register(&p, "password=letmein") != 0)
		return 0;
	ok = p.funcs.auth_get_user(&p, "anybody", &info) == st_allow
		&& !strcmp(info.nickname, "anybody")
		&& !strcmp(info.password, "letmein")
		&& info.credentials == auth_cred_guest;
	mod_guest_passwd_unregister(&p);
	return ok && p.ptr == NULL;
});

/* ---- plugin order --------------------------------------------------------- */

/* Holds one account, "Boss", and answers nothing else. */
static plugin_st mgp_accounts_get_user(struct plugin_handle* p, const char* nick, struct auth_info* info)
{
	(void) p;
	memset(info, 0, sizeof(*info));
	if (strcasecmp(nick, "Boss") != 0)
		return st_default;
	strcpy(info->nickname, "Boss");
	strcpy(info->password, "bosspass");
	info->credentials = auth_cred_admin;
	return st_allow;
}

/* Refuses every nick it does not know, the way mod_auth_simple does in
   exclusive mode. */
static plugin_st mgp_refuse_get_user(struct plugin_handle* p, const char* nick, struct auth_info* info)
{
	(void) p; (void) nick;
	memset(info, 0, sizeof(*info));
	return st_deny;
}

static struct plugin_handle mgp_guest;
static struct plugin_handle mgp_accounts;
static struct plugin_handle mgp_refuse;

/* A hub with just a plugin list, holding the given handles in order. */
static int mgp_lookup(struct plugin_handle** order, size_t count, const char* nick, struct auth_info* info)
{
	struct hub_info hub;
	struct uhub_plugins plugins;
	plugin_st status;
	size_t i;

	memset(&hub, 0, sizeof(hub));
	memset(&plugins, 0, sizeof(plugins));
	plugins.loaded = list_create();
	for (i = 0; i < count; i++)
		list_append(plugins.loaded, order[i]);
	hub.plugins = &plugins;

	status = plugin_auth_get_user(&hub, nick, info);

	list_clear(plugins.loaded, NULL);
	list_destroy(plugins.loaded);
	return (int) status;
}

/* The real plugin and the fake storage plugins the order tests line up. */
EXO_SETUP({
	memset(&mgp_accounts, 0, sizeof(mgp_accounts));
	mgp_accounts.funcs.auth_get_user = mgp_accounts_get_user;
	memset(&mgp_refuse, 0, sizeof(mgp_refuse));
	mgp_refuse.funcs.auth_get_user = mgp_refuse_get_user;
	return mgp_register(&mgp_guest, "password=letmein") == 0;
});

/* Listed first, the guest password must not shadow a registered account. */
EXO_TEST(mgp_account_beats_guest_listed_first, {
	struct plugin_handle* order[] = { &mgp_guest, &mgp_accounts };
	struct auth_info info;
	return mgp_lookup(order, 2, "boss", &info) == st_allow
		&& info.credentials == auth_cred_admin
		&& !strcmp(info.password, "bosspass");
});

EXO_TEST(mgp_account_beats_guest_listed_last, {
	struct plugin_handle* order[] = { &mgp_accounts, &mgp_guest };
	struct auth_info info;
	return mgp_lookup(order, 2, "Boss", &info) == st_allow
		&& info.credentials == auth_cred_admin;
});

/* No account: the guest record, even though the account plugin ran after it
   and cleared the buffer. */
EXO_TEST(mgp_guest_without_account, {
	struct plugin_handle* order[] = { &mgp_guest, &mgp_accounts };
	struct auth_info info;
	return mgp_lookup(order, 2, "stranger", &info) == st_allow
		&& info.credentials == auth_cred_guest
		&& !strcmp(info.password, "letmein")
		&& !strcmp(info.nickname, "stranger");
});

/* A refusal must not let a guest past the password. */
EXO_TEST(mgp_guest_beats_refusal, {
	struct plugin_handle* order[] = { &mgp_refuse, &mgp_guest };
	struct auth_info info;
	return mgp_lookup(order, 2, "stranger", &info) == st_allow
		&& info.credentials == auth_cred_guest;
});

/* Without a guest record the refusal still comes through. */
EXO_TEST(mgp_refusal_without_guest, {
	struct plugin_handle* order[] = { &mgp_accounts, &mgp_refuse };
	struct auth_info info;
	return mgp_lookup(order, 2, "stranger", &info) == st_deny;
});

EXO_TEST(mgp_no_answer, {
	struct plugin_handle* order[] = { &mgp_accounts };
	struct auth_info info;
	return mgp_lookup(order, 1, "stranger", &info) == st_default;
});

EXO_TEARDOWN({
	mod_guest_passwd_unregister(&mgp_guest);
	return 1;
});
