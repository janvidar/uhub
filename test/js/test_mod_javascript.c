/*
 * Standalone test for the mod_javascript QuickJS host (built only when
 * JAVASCRIPT_SUPPORT / -Djavascript is on). It dlopen()s mod_javascript.so,
 * stubs the hub service table, loads the shipped example scripts plus a couple
 * of inline fixtures, fires callbacks and asserts the observable behaviour --
 * including the per-callback watchdog and the "user reference invalidated after
 * its callback" guarantee.
 *
 * Usage: test_mod_javascript <mod_javascript.so> <js-script-dir>
 */
#include "plugin_api/handle.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- recording hub-func stubs ------------------------------------------ */

static char g_last_message[1024];
static char g_last_status[1024];
static int  g_status_count;
static int  g_disconnect_count;

static void reset_recorders(void)
{
	g_last_message[0] = '\0';
	g_last_status[0] = '\0';
	g_status_count = 0;
	g_disconnect_count = 0;
}

static int stub_send_message(struct plugin_handle* p, struct plugin_user* u, const char* m)
{
	(void) p; (void) u;
	snprintf(g_last_message, sizeof(g_last_message), "%s", m);
	return 1;
}
static int stub_send_status(struct plugin_handle* p, struct plugin_user* u, int code, const char* m)
{
	(void) p; (void) u; (void) code;
	snprintf(g_last_status, sizeof(g_last_status), "%s", m);
	g_status_count++;
	return 1;
}
static int stub_broadcast(struct plugin_handle* p, const char* m)
{
	(void) p;
	snprintf(g_last_message, sizeof(g_last_message), "%s", m);
	return 1;
}
static int stub_disconnect(struct plugin_handle* p, struct plugin_user* u)
{
	(void) p; (void) u;
	g_disconnect_count++;
	return 0;
}
static int stub_ban(struct plugin_handle* p, struct plugin_user* u, int secs, const char* r)
{
	(void) p; (void) u; (void) secs; (void) r;
	return 0;
}
/* Stable id == the user's SID here, so scripts keying a Map by user.id get a
   distinct key per test user. */
static uint64_t stub_conn_id(struct plugin_handle* p, struct plugin_user* u)
{
	(void) p;
	return (uint64_t) u->sid;
}
static size_t stub_usercount(struct plugin_handle* p) { (void) p; return 3; }

static void wire_hub_funcs(struct plugin_handle* h)
{
	memset(h, 0, sizeof(*h));
	h->hub.send_message = stub_send_message;
	h->hub.send_status_message = stub_send_status;
	h->hub.send_broadcast_message = stub_broadcast;
	h->hub.user_disconnect = stub_disconnect;
	h->hub.ban_user = stub_ban;
	h->hub.get_user_connection_id = stub_conn_id;
	h->hub.get_usercount = stub_usercount;
}

/* ---- harness ------------------------------------------------------------ */

static int (*p_register)(struct plugin_handle*, const char*);
static int (*p_unregister)(struct plugin_handle*);

static int failures = 0;
#define CHECK(cond, name) do { \
	if (cond) printf("  PASS %s\n", name); \
	else { printf("  FAIL %s\n", name); failures++; } } while (0)

static struct plugin_user make_user(const char* nick, sid_t sid, enum auth_credentials cred)
{
	struct plugin_user u;
	memset(&u, 0, sizeof(u));
	snprintf(u.nick, sizeof(u.nick), "%s", nick);
	snprintf(u.cid, sizeof(u.cid), "CID%u", (unsigned) sid);
	u.sid = sid;
	u.credentials = cred;
	return u;
}

static int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Write text to a temp file and return a malloc'd path (caller frees + unlinks). */
static char* write_temp_script(const char* text)
{
	char* path = malloc(64);
	FILE* f;
	static int n = 0;
	snprintf(path, 64, "test_js_fixture_%d.js", n++);
	f = fopen(path, "wb");
	if (!f) { free(path); return NULL; }
	fwrite(text, 1, strlen(text), f);
	fclose(f);
	return path;
}

/* ---- tests -------------------------------------------------------------- */

static void test_welcome(const char* dir)
{
	struct plugin_handle h;
	struct plugin_user user = make_user("Alice", 1, auth_cred_user);
	char cfg[512];
	printf("welcome.js:\n");
	wire_hub_funcs(&h);
	snprintf(cfg, sizeof(cfg), "script=%s/welcome.js motd=Hi_%%n", dir);
	if (p_register(&h, cfg) != 0) { CHECK(0, "register welcome.js"); return; }
	reset_recorders();
	h.funcs.on_user_login(&h, &user);
	CHECK(strcmp(g_last_message, "Hi_Alice") == 0, "onUserLogin substitutes %n from config motd");
	p_unregister(&h);
}

static void test_chat_only(const char* dir)
{
	struct plugin_handle h;
	struct plugin_user user = make_user("Bob", 2, auth_cred_user);
	struct plugin_user op = make_user("Op", 3, auth_cred_operator);
	char cfg[512];
	printf("chat_only.js:\n");
	wire_hub_funcs(&h);
	snprintf(cfg, sizeof(cfg), "script=%s/chat_only.js", dir);
	if (p_register(&h, cfg) != 0) { CHECK(0, "register chat_only.js"); return; }

	reset_recorders();
	CHECK(h.funcs.on_search(&h, &user, "TOfoo") == st_deny, "onSearch denies a normal user");
	CHECK(g_status_count == 1, "first denied search warns once");
	h.funcs.on_search(&h, &user, "TObar");
	CHECK(g_status_count == 1, "second denied search does NOT warn again");
	CHECK(h.funcs.on_p2p_connect(&h, &op, &op) == st_allow, "operator is exempt (st_allow)");
	p_unregister(&h);
}

static void test_flood(const char* dir)
{
	struct plugin_handle h;
	struct plugin_user user = make_user("Carol", 4, auth_cred_user);
	char cfg[512];
	printf("flood.js:\n");
	wire_hub_funcs(&h);
	snprintf(cfg, sizeof(cfg), "script=%s/flood.js grace=2", dir);
	if (p_register(&h, cfg) != 0) { CHECK(0, "register flood.js"); return; }

	reset_recorders();
	CHECK(h.funcs.on_flood_detected(&h, &user, flood_type_chat) == st_default, "1st strike -> st_default (hub warns)");
	CHECK(g_disconnect_count == 0, "no disconnect on 1st strike");
	CHECK(h.funcs.on_flood_detected(&h, &user, flood_type_chat) == st_deny, "2nd strike (grace) -> st_deny");
	CHECK(g_disconnect_count == 1, "user disconnected at grace limit");
	p_unregister(&h);
}

static void test_watchdog(const char* dir)
{
	struct plugin_handle h;
	struct plugin_user user = make_user("Spin", 5, auth_cred_user);
	char* script;
	char cfg[512];
	int64_t t0, dt;
	(void) dir;
	printf("watchdog:\n");
	script = write_temp_script("uhub.onSearch(function(u){ while(true){} });\n");
	if (!script) { CHECK(0, "write watchdog fixture"); return; }
	wire_hub_funcs(&h);
	snprintf(cfg, sizeof(cfg), "script=%s time_limit=150", script);
	if (p_register(&h, cfg) != 0) { CHECK(0, "register watchdog fixture"); remove(script); free(script); return; }
	t0 = now_ms();
	h.funcs.on_search(&h, &user, "spin");
	dt = now_ms() - t0;
	printf("  (interrupted after %lldms)\n", (long long) dt);
	CHECK(dt < 2000, "runaway callback interrupted by watchdog (<2s)");
	p_unregister(&h);
	remove(script);
	free(script);
}

static void test_lifetime(const char* dir)
{
	struct plugin_handle h;
	struct plugin_user user = make_user("Dave", 6, auth_cred_user);
	char* script;
	char cfg[512];
	const char* src =
		"var stashed = null;\n"
		"uhub.onUserLogin(function(u){ stashed = u; u.sendMessage('live'); });\n"
		"uhub.onChatMsg(function(from, msg){\n"
		"  try { stashed.sendMessage('stale'); return uhub.DENY; }\n"
		"  catch (e) { uhub.log('expected: ' + e); return uhub.ALLOW; }\n"
		"});\n";
	(void) dir;
	printf("lifetime (invalidation after callback):\n");
	script = write_temp_script(src);
	if (!script) { CHECK(0, "write lifetime fixture"); return; }
	wire_hub_funcs(&h);
	snprintf(cfg, sizeof(cfg), "script=%s", script);
	if (p_register(&h, cfg) != 0) { CHECK(0, "register lifetime fixture"); remove(script); free(script); return; }

	reset_recorders();
	h.funcs.on_user_login(&h, &user);          /* stashes the user, sends "live" */
	CHECK(strcmp(g_last_message, "live") == 0, "live user reference works during its callback");

	reset_recorders();
	/* The chat handler touches the stashed (now-invalidated) user; it must throw,
	   so the stale sendMessage never reaches the stub and the handler returns
	   ALLOW from the catch block (not DENY from the try). */
	{
		plugin_st st = h.funcs.on_chat_msg(&h, &user, "hi");
		CHECK(g_last_message[0] == '\0', "stale user reference does NOT reach the hub");
		CHECK(st == st_allow, "using a stale user throws (caught) instead of denying");
	}
	p_unregister(&h);
	remove(script);
	free(script);
}

/* dir=<dir> loads every *.js in the directory; the three example scripts must
   coexist (welcome's login message AND chat_only's search deny both fire). */
static void test_dir_load(const char* dir)
{
	struct plugin_handle h;
	struct plugin_user user = make_user("Erin", 7, auth_cred_user);
	char cfg[512];
	printf("dir= load:\n");
	wire_hub_funcs(&h);
	snprintf(cfg, sizeof(cfg), "dir=%s motd=Hi_%%n", dir);
	if (p_register(&h, cfg) != 0) { CHECK(0, "register dir="); return; }
	reset_recorders();
	h.funcs.on_user_login(&h, &user);
	CHECK(strcmp(g_last_message, "Hi_Erin") == 0, "welcome.js loaded from dir= (login message)");
	CHECK(h.funcs.on_search(&h, &user, "TOx") == st_deny, "chat_only.js loaded from dir= (search denied)");
	p_unregister(&h);
}

/* config=<file> lists scripts with per-script options that override globals. */
static void test_config_list(const char* dir)
{
	struct plugin_handle h;
	struct plugin_user user = make_user("Frank", 8, auth_cred_user);
	char* listfile;
	char listbody[600];
	char cfg[512];
	printf("config= list:\n");
	snprintf(listbody, sizeof(listbody),
		"# scripts\n%s/welcome.js motd=FromList_%%n\n", dir);
	listfile = write_temp_script(listbody);
	if (!listfile) { CHECK(0, "write list file"); return; }
	wire_hub_funcs(&h);
	snprintf(cfg, sizeof(cfg), "config=%s motd=Global_%%n", listfile);
	if (p_register(&h, cfg) != 0) { CHECK(0, "register config="); remove(listfile); free(listfile); return; }
	reset_recorders();
	h.funcs.on_user_login(&h, &user);
	CHECK(strcmp(g_last_message, "FromList_Frank") == 0, "per-script config overrides global (config= list)");
	p_unregister(&h);
	remove(listfile);
	free(listfile);
}

int main(int argc, char** argv)
{
	void* lib;
	if (argc < 3) { fprintf(stderr, "usage: %s <mod_javascript.so> <js-dir>\n", argv[0]); return 2; }
	lib = dlopen(argv[1], RTLD_NOW);
	if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
	p_register = dlsym(lib, "plugin_register");
	p_unregister = dlsym(lib, "plugin_unregister");
	if (!p_register || !p_unregister) { fprintf(stderr, "missing plugin symbols\n"); return 2; }

	test_welcome(argv[2]);
	test_chat_only(argv[2]);
	test_flood(argv[2]);
	test_dir_load(argv[2]);
	test_config_list(argv[2]);
	test_watchdog(argv[2]);
	test_lifetime(argv[2]);

	printf("%s\n", failures ? "FAILURES" : "ALL PASS");
	dlclose(lib);
	return failures ? 1 : 0;
}
