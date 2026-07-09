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
	/* The plugin opens the database but does not create the schema; mirror the
	   one uhub-passwd creates, including the case-insensitive UNIQUE nick. */
	rc = sqlite3_exec(db, "CREATE TABLE users (nickname CHAR COLLATE NOCASE NOT NULL UNIQUE, password TEXT, credentials TEXT);", 0, 0, 0);
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

/* The case-insensitive UNIQUE constraint rejects a nick that collides with an
   existing registration only by case (registering "boss" when "Boss" exists). */
EXO_TEST(mas_register_dup_case_rejected, {
	struct auth_info a = mas_info("boss", "other", auth_cred_user);
	struct auth_info got;
	memset(&got, 0, sizeof(got));
	if (mas_plugin.funcs.auth_register_user(&mas_plugin, &a) != st_deny)
		return 0;
	/* The original registration is intact and unchanged. */
	if (mas_plugin.funcs.auth_get_user(&mas_plugin, "Boss", &got) != st_allow)
		return 0;
	return !strcmp(got.nickname, "Boss") && !strcmp(got.password, "secret");
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

/* Update matches the nick case-insensitively (a lowercase "boss" updates the
   registered "Boss"), consistent with the get_user lookup. */
EXO_TEST(mas_update_case_insensitive, {
	struct auth_info a = mas_info("boss", "newpass", auth_cred_operator);
	struct auth_info got;
	memset(&got, 0, sizeof(got));
	if (mas_plugin.funcs.auth_update_user(&mas_plugin, &a) != st_allow)
		return 0;
	if (mas_plugin.funcs.auth_get_user(&mas_plugin, "Boss", &got) != st_allow)
		return 0;
	return got.credentials == auth_cred_operator && !strcmp(got.password, "newpass");
});

/* auth_delete_user removes the registered account (returns st_allow), matching
   the nick case-insensitively -- deleting "boss" removes "Boss" -- so a
   subsequent lookup misses. */
EXO_TEST(mas_delete_case_insensitive, {
	struct auth_info a = mas_info("boss", "", auth_cred_user);
	struct auth_info got;
	memset(&got, 0, sizeof(got));
	if (mas_plugin.funcs.auth_delete_user(&mas_plugin, &a) != st_allow)
		return 0;
	/* The account is gone afterwards (looked up by its registered case). */
	return mas_plugin.funcs.auth_get_user(&mas_plugin, "Boss", &got) == st_default;
});

/* A legacy database whose schema lacks the case-insensitive constraint gains
   it from the index the plugin creates at startup: after registering "Boss",
   the case-variant "boss" is rejected. */
EXO_TEST(mas_defensive_index_upgrades_legacy_db, {
	const char* db2 = "test_mod_auth_sqlite_legacy.db";
	struct plugin_handle p;
	struct auth_info a;
	sqlite3* db = 0;
	char cfg[256];
	int ok;

	remove(db2);
	if (sqlite3_open(db2, &db) != SQLITE_OK)
		return 0;
	/* Old-style schema: plain columns, no case-insensitive uniqueness. */
	if (sqlite3_exec(db, "CREATE TABLE users (nickname TEXT, password TEXT, credentials TEXT);", 0, 0, 0) != SQLITE_OK)
	{
		sqlite3_close(db);
		remove(db2);
		return 0;
	}
	sqlite3_close(db);

	memset(&p, 0, sizeof(p));
	snprintf(cfg, sizeof(cfg), "file=%s", db2);
	if (plugin_register(&p, cfg) != 0)
	{
		remove(db2);
		return 0;
	}

	a = mas_info("Boss", "secret", auth_cred_user);
	ok = (p.funcs.auth_register_user(&p, &a) == st_allow);
	a = mas_info("boss", "other", auth_cred_user);
	ok = ok && (p.funcs.auth_register_user(&p, &a) == st_deny);

	plugin_unregister(&p);
	remove(db2);
	return ok;
});

/* A legacy database that already holds case-duplicate rows must not stop the
   plugin from loading: the index cannot be created (a warning is logged), but
   plugin_register still succeeds. */
EXO_TEST(mas_defensive_index_tolerates_existing_dups, {
	const char* db3 = "test_mod_auth_sqlite_dups.db";
	struct plugin_handle p;
	sqlite3* db = 0;
	char cfg[256];
	int rc;

	remove(db3);
	if (sqlite3_open(db3, &db) != SQLITE_OK)
		return 0;
	rc = sqlite3_exec(db,
		"CREATE TABLE users (nickname TEXT, password TEXT, credentials TEXT);"
		"INSERT INTO users VALUES ('Boss','a','user');"
		"INSERT INTO users VALUES ('boss','b','user');", 0, 0, 0);
	sqlite3_close(db);
	if (rc != SQLITE_OK)
	{
		remove(db3);
		return 0;
	}

	memset(&p, 0, sizeof(p));
	snprintf(cfg, sizeof(cfg), "file=%s", db3);
	rc = plugin_register(&p, cfg);
	if (rc == 0)
		plugin_unregister(&p);
	remove(db3);
	return rc == 0;
});

/* --- Ban storage (auth_ban_add / auth_ban_del / auth_is_banned) --- */

static struct ban_info mas_ban(const char* cid, const char* nick)
{
	struct ban_info b;
	memset(&b, 0, sizeof(b));
	if (cid && *cid)  { b.flags |= ban_cid;      snprintf(b.cid, sizeof(b.cid), "%s", cid); }
	if (nick && *nick){ b.flags |= ban_nickname; snprintf(b.nickname, sizeof(b.nickname), "%s", nick); }
	return b;
}

static struct plugin_user mas_puser(const char* cid, const char* nick)
{
	struct plugin_user u;
	memset(&u, 0, sizeof(u));
	snprintf(u.cid, sizeof(u.cid), "%s", cid);
	snprintf(u.nick, sizeof(u.nick), "%s", nick);
	return u;
}

#define MAS_CID "3AGHMAASJA2RFNM22AA6753V7B7DYEPNTIWHBAY"

EXO_TEST(mas_ban_funcs, {
	return mas_plugin.funcs.auth_ban_add
		&& mas_plugin.funcs.auth_ban_del
		&& mas_plugin.funcs.auth_is_banned;
});

EXO_TEST(mas_ban_add, {
	struct ban_info b = mas_ban(MAS_CID, "Eviluser");
	return mas_plugin.funcs.auth_ban_add(&mas_plugin, &b) == st_allow;
});

/* A user matching the banned CID (any nick) is banned. */
EXO_TEST(mas_banned_by_cid, {
	struct plugin_user u = mas_puser(MAS_CID, "SomeOtherNick");
	return mas_plugin.funcs.auth_is_banned(&mas_plugin, &u) == st_deny;
});

/* A user matching the banned nick (any CID), case-insensitively, is banned. */
EXO_TEST(mas_banned_by_nick, {
	struct plugin_user u = mas_puser("CLEANCID000000000000000000000000000000A", "eviluser");
	return mas_plugin.funcs.auth_is_banned(&mas_plugin, &u) == st_deny;
});

/* An unrelated user is not banned. */
EXO_TEST(mas_not_banned, {
	struct plugin_user u = mas_puser("CLEANCID000000000000000000000000000000A", "innocent");
	return mas_plugin.funcs.auth_is_banned(&mas_plugin, &u) == st_default;
});

/* Unban by nick (hub offers the target as both fields) removes the record. */
EXO_TEST(mas_ban_del, {
	struct ban_info b = mas_ban("Eviluser", "Eviluser");
	struct plugin_user u = mas_puser(MAS_CID, "Eviluser");
	if (mas_plugin.funcs.auth_ban_del(&mas_plugin, &b) != st_allow)
		return 0;
	return mas_plugin.funcs.auth_is_banned(&mas_plugin, &u) == st_default;
});

/* Deleting a ban that does not exist reports "no opinion" (st_default). */
EXO_TEST(mas_ban_del_missing, {
	struct ban_info b = mas_ban("nope", "nope");
	return mas_plugin.funcs.auth_ban_del(&mas_plugin, &b) == st_default;
});

/* Timed bans: a future expiry is enforced; a past expiry is treated as lifted. */
static struct ban_info mas_ban_exp(const char* cid, const char* nick, time_t expiry)
{
	struct ban_info b = mas_ban(cid, nick);
	b.expiry = expiry;
	return b;
}
EXO_TEST(mas_timed_future_add, {
	struct ban_info b = mas_ban_exp("TIMEDCID000000000000000000000000000000A", "timeduser", 2000000000);
	return mas_plugin.funcs.auth_ban_add(&mas_plugin, &b) == st_allow;
});
EXO_TEST(mas_timed_future_hit, {
	struct plugin_user u = mas_puser("TIMEDCID000000000000000000000000000000A", "whoever");
	return mas_plugin.funcs.auth_is_banned(&mas_plugin, &u) == st_deny;
});
EXO_TEST(mas_timed_past_add, {
	struct ban_info b = mas_ban_exp("EXPIREDCID00000000000000000000000000000A", "expireduser", 1);
	return mas_plugin.funcs.auth_ban_add(&mas_plugin, &b) == st_allow;
});
EXO_TEST(mas_timed_past_miss, {
	struct plugin_user u = mas_puser("EXPIREDCID00000000000000000000000000000A", "whoever");
	return mas_plugin.funcs.auth_is_banned(&mas_plugin, &u) == st_default;
});

EXO_TEST(mas_teardown, {
	int rc = plugin_unregister(&mas_plugin);
	remove(MAS_DB);
	return rc == 0;
});
