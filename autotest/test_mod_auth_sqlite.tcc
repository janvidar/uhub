#include "system.h"
#include "plugin_api/handle.h"
#include <sqlite3.h>

/*
 * Unit tests for the mod_auth_sqlite plugin's authentication functions.
 *
 * The plugin is compiled into the test binary (see CMakeLists.txt), so its
 * entry point plugin_register() -- normally dlsym'd by the plugin loader --
 * is called directly to populate the funcs table, which the tests then drive
 * against a throwaway SQLite database. This covers the credential round-trip
 * (register -> get -> update -> delete) and, in particular, the case-insensitive
 * nick lookup (report L-8): a guest logging in as "boss" must resolve to a
 * registered "Boss" so it is challenged for a password rather than admitted.
 */

/* mod_auth_sqlite entry points (not declared in any shared header). */
extern int plugin_register(struct plugin_handle* plugin, const char* config);
extern int plugin_unregister(struct plugin_handle* plugin);

#define MAS_DB "test_mod_auth_sqlite.db"

static struct plugin_handle mas_plugin;

static struct auth_info mas_info(const char* nick, const char* pass, enum auth_credentials cred)
{
	struct auth_info a;
	memset(&a, 0, sizeof(a));
	snprintf(a.nickname, sizeof(a.nickname), "%s", nick);
	snprintf(a.password, sizeof(a.password), "%s", pass);
	a.credentials = cred;
	return a;
}

EXO_TEST(mas_setup, {
	sqlite3* db = 0;
	int rc;
	char cfg[256];

	remove(MAS_DB);
	if (sqlite3_open(MAS_DB, &db) != SQLITE_OK)
		return 0;
	/* The plugin opens the database but does not create the schema. */
	rc = sqlite3_exec(db, "CREATE TABLE users (nickname TEXT, password TEXT, credentials TEXT);", 0, 0, 0);
	sqlite3_close(db);
	if (rc != SQLITE_OK)
		return 0;

	memset(&mas_plugin, 0, sizeof(mas_plugin));
	snprintf(cfg, sizeof(cfg), "file=%s", MAS_DB);
	return plugin_register(&mas_plugin, cfg) == 0
		&& mas_plugin.funcs.auth_get_user
		&& mas_plugin.funcs.auth_register_user
		&& mas_plugin.funcs.auth_update_user
		&& mas_plugin.funcs.auth_delete_user;
});

EXO_TEST(mas_register, {
	struct auth_info a = mas_info("Boss", "secret", auth_cred_user);
	return mas_plugin.funcs.auth_register_user(&mas_plugin, &a) == st_allow;
});

EXO_TEST(mas_get_exact, {
	struct auth_info a;
	memset(&a, 0, sizeof(a));
	if (mas_plugin.funcs.auth_get_user(&mas_plugin, "Boss", &a) != st_allow)
		return 0;
	return a.credentials == auth_cred_user
		&& !strcmp(a.nickname, "Boss")
		&& !strcmp(a.password, "secret");
});

/* L-8: a lowercase variant resolves to the registered account and returns its
   canonical stored case. */
EXO_TEST(mas_get_case_lower, {
	struct auth_info a;
	memset(&a, 0, sizeof(a));
	if (mas_plugin.funcs.auth_get_user(&mas_plugin, "boss", &a) != st_allow)
		return 0;
	return a.credentials == auth_cred_user && !strcmp(a.nickname, "Boss");
});

EXO_TEST(mas_get_case_upper, {
	struct auth_info a;
	memset(&a, 0, sizeof(a));
	return mas_plugin.funcs.auth_get_user(&mas_plugin, "BOSS", &a) == st_allow;
});

EXO_TEST(mas_get_missing, {
	struct auth_info a;
	memset(&a, 0, sizeof(a));
	return mas_plugin.funcs.auth_get_user(&mas_plugin, "stranger", &a) == st_default;
});

EXO_TEST(mas_update, {
	struct auth_info a = mas_info("Boss", "newpass", auth_cred_operator);
	struct auth_info got;
	memset(&got, 0, sizeof(got));
	if (mas_plugin.funcs.auth_update_user(&mas_plugin, &a) != st_allow)
		return 0;
	if (mas_plugin.funcs.auth_get_user(&mas_plugin, "Boss", &got) != st_allow)
		return 0;
	return got.credentials == auth_cred_operator && !strcmp(got.password, "newpass");
});

/* Characterization: auth_delete_user in mod_auth_sqlite is currently a stub --
   it returns st_default but does NOT remove the row (deletion is unimplemented;
   the plugin exposes no command that calls it). This test documents that and
   will trip if real deletion is ever added, prompting an update. */
EXO_TEST(mas_delete_is_noop, {
	struct auth_info a = mas_info("Boss", "", auth_cred_user);
	struct auth_info got;
	memset(&got, 0, sizeof(got));
	if (mas_plugin.funcs.auth_delete_user(&mas_plugin, &a) != st_default)
		return 0;
	/* The account is still present afterwards. */
	return mas_plugin.funcs.auth_get_user(&mas_plugin, "Boss", &got) == st_allow;
});

EXO_TEST(mas_teardown, {
	int rc = plugin_unregister(&mas_plugin);
	remove(MAS_DB);
	return rc == 0;
});
