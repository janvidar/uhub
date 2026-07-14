/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

/*
 * mod_javascript - host QuickJS scripts as uhub plugins.
 *
 * Each configured "script=<file.js>" is evaluated in its own QuickJS context
 * (isolated globals, shared runtime). A script registers handlers on the global
 * `uhub` object (uhub.onChatMsg(fn), uhub.onUserLogin(fn), ...) and calls hub
 * services (uhub.sendMessage, uhub.broadcast, user.disconnect(), ...). The
 * plugin registers every C hook once and, when the hub fires one, marshals the
 * arguments and invokes each script's handler, mapping the JS return value to a
 * plugin_st verdict.
 *
 * Safety model: scripts get ONLY the `uhub` API -- no std/os modules, so no
 * ambient filesystem/network/process access. A per-callback wall-clock watchdog
 * (JS_SetInterruptHandler) stops a runaway script from wedging the single hub
 * thread, and the runtime has memory and stack caps. A `user` object handed to
 * a handler is invalidated when that handler returns, so a script that stashes
 * it and touches it later gets a clean exception rather than a stale pointer.
 */

#include "plugin_api/handle.h"
#include "plugin_api/command_api.h"
#include "util/memory.h"
#include "util/list.h"
#include "util/config_token.h"
#include "util/log.h"

#include <time.h>
#include <sys/stat.h>
#ifndef WIN32
#include <dirent.h>
#endif

#include "quickjs.h"

#define DEFAULT_MEMORY_LIMIT (64 * 1024 * 1024)   /* bytes */
#define DEFAULT_STACK_LIMIT  (1 * 1024 * 1024)    /* bytes */
#define DEFAULT_TIME_LIMIT   1000                 /* ms per callback */
#define MAX_SCRIPT_SIZE      (4 * 1024 * 1024)    /* refuse absurd script files */

static JSClassID js_user_class_id; /* 0 until first registered */

struct js_plugin
{
	JSRuntime* rt;
	struct linked_list* scripts;   /* struct js_script* */
	struct plugin_handle* handle;
	int time_limit_ms;             /* per-callback watchdog budget */
	int64_t deadline_ms;           /* absolute deadline while a callback runs; 0 = disarmed */
};

struct js_script
{
	JSContext* ctx;
	char* filename;
	struct js_plugin* owner;

	/* Registered handlers, JS_UNDEFINED when unset. */
	JSValue on_user_login;
	JSValue on_user_logout;
	JSValue on_chat_msg;
	JSValue on_private_msg;
	JSValue on_search;
	JSValue on_search_result;
	JSValue on_p2p_connect;
	JSValue on_p2p_revconnect;
	JSValue on_check_ip_late;
	JSValue on_change_nick;
	JSValue on_flood_detected;
	JSValue on_hub_started;
	JSValue on_hub_shutdown;
};

/* Opaque behind a JS `user` object. `user` is only valid during the callback it
   was created for; `valid` is cleared afterwards so later access throws. */
struct js_user
{
	struct plugin_handle* plugin;
	struct plugin_user* user;
	int valid;
};

/* ---- time / watchdog ---------------------------------------------------- */

static int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int js_interrupt_handler(JSRuntime* rt, void* opaque)
{
	struct js_plugin* jp = (struct js_plugin*) opaque;
	(void) rt;
	if (jp->deadline_ms && now_ms() > jp->deadline_ms)
		return 1; /* interrupt: raises an uncatchable InternalError */
	return 0;
}

static void js_arm_watchdog(struct js_plugin* jp)
{
	jp->deadline_ms = now_ms() + jp->time_limit_ms;
}

static void js_disarm_watchdog(struct js_plugin* jp)
{
	jp->deadline_ms = 0;
}

/* ---- value <-> verdict -------------------------------------------------- */

static plugin_st js_to_status(JSContext* ctx, JSValueConst v)
{
	if (JS_IsUndefined(v) || JS_IsNull(v))
		return st_default;
	if (JS_IsBool(v))
		return JS_ToBool(ctx, v) ? st_allow : st_deny;
	{
		int32_t n = 0;
		if (JS_ToInt32(ctx, &n, v) == 0)
			return n < 0 ? st_deny : (n > 0 ? st_allow : st_default);
	}
	return st_default;
}

static void js_report_exception(struct js_script* s)
{
	JSValue exc = JS_GetException(s->ctx);
	const char* msg = JS_ToCString(s->ctx, exc);
	LOG_ERROR("mod_javascript: %s: uncaught exception: %s", s->filename, msg ? msg : "(unknown)");
	if (msg)
		JS_FreeCString(s->ctx, msg);
	JS_FreeValue(s->ctx, exc);
}

/* ---- user object -------------------------------------------------------- */

static void js_user_finalizer(JSRuntime* rt, JSValue val)
{
	struct js_user* u = (struct js_user*) JS_GetOpaque(val, js_user_class_id);
	(void) rt;
	if (u)
		free(u); /* allocated with plain malloc below; see js_make_user */
}

static JSClassDef js_user_class = {
	"User",
	.finalizer = js_user_finalizer,
};

/* Returns the live plugin_user for `this`, or throws and returns NULL if the
   reference has been invalidated (used after its callback returned). */
static struct js_user* js_user_live(JSContext* ctx, JSValueConst this_val)
{
	struct js_user* u = (struct js_user*) JS_GetOpaque(this_val, js_user_class_id);
	if (!u || !u->valid || !u->user)
	{
		JS_ThrowTypeError(ctx, "user reference is no longer valid (used outside its callback)");
		return NULL;
	}
	return u;
}

static JSValue js_user_send_message(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
{
	struct js_user* u = js_user_live(ctx, this_val);
	const char* text;
	if (!u)
		return JS_EXCEPTION;
	if (argc < 1)
		return JS_ThrowTypeError(ctx, "sendMessage(text) requires a string");
	text = JS_ToCString(ctx, argv[0]);
	if (!text)
		return JS_EXCEPTION;
	u->plugin->hub.send_message(u->plugin, u->user, text);
	JS_FreeCString(ctx, text);
	return JS_UNDEFINED;
}

static JSValue js_user_send_status(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
{
	struct js_user* u = js_user_live(ctx, this_val);
	int32_t code = 0;
	const char* text;
	if (!u)
		return JS_EXCEPTION;
	if (argc < 2)
		return JS_ThrowTypeError(ctx, "sendStatus(code, text) requires two arguments");
	if (JS_ToInt32(ctx, &code, argv[0]))
		return JS_EXCEPTION;
	text = JS_ToCString(ctx, argv[1]);
	if (!text)
		return JS_EXCEPTION;
	u->plugin->hub.send_status_message(u->plugin, u->user, code, text);
	JS_FreeCString(ctx, text);
	return JS_UNDEFINED;
}

static JSValue js_user_disconnect(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
{
	struct js_user* u = js_user_live(ctx, this_val);
	(void) argc; (void) argv;
	if (!u)
		return JS_EXCEPTION;
	u->plugin->hub.user_disconnect(u->plugin, u->user);
	return JS_UNDEFINED;
}

static JSValue js_user_ban(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
{
	struct js_user* u = js_user_live(ctx, this_val);
	int32_t seconds = 0;
	const char* reason = NULL;
	if (!u)
		return JS_EXCEPTION;
	if (argc >= 1 && JS_ToInt32(ctx, &seconds, argv[0]))
		return JS_EXCEPTION;
	if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1]))
	{
		reason = JS_ToCString(ctx, argv[1]);
		if (!reason)
			return JS_EXCEPTION;
	}
	u->plugin->hub.ban_user(u->plugin, u->user, seconds, reason);
	if (reason)
		JS_FreeCString(ctx, reason);
	return JS_UNDEFINED;
}

static const JSCFunctionListEntry js_user_proto_funcs[] = {
	JS_CFUNC_DEF("sendMessage", 1, js_user_send_message),
	JS_CFUNC_DEF("sendStatus", 2, js_user_send_status),
	JS_CFUNC_DEF("disconnect", 0, js_user_disconnect),
	JS_CFUNC_DEF("ban", 2, js_user_ban),
};

static JSValue js_make_user(struct js_script* s, struct plugin_user* user)
{
	JSContext* ctx = s->ctx;
	JSValue obj = JS_NewObjectClass(ctx, js_user_class_id);
	struct js_user* u;
	if (JS_IsException(obj))
		return obj;

	u = (struct js_user*) malloc(sizeof(struct js_user));
	if (!u)
	{
		JS_FreeValue(ctx, obj);
		return JS_ThrowOutOfMemory(ctx);
	}
	u->plugin = s->owner->handle;
	u->user = user;
	u->valid = 1;
	JS_SetOpaque(obj, u);

	/* Snapshot the scalar identity fields as plain (read-only-ish) properties;
	   they remain readable even after the reference is invalidated. */
	JS_SetPropertyStr(ctx, obj, "nick", JS_NewString(ctx, user->nick));
	JS_SetPropertyStr(ctx, obj, "cid", JS_NewString(ctx, user->cid));
	JS_SetPropertyStr(ctx, obj, "userAgent", JS_NewString(ctx, user->user_agent));
	JS_SetPropertyStr(ctx, obj, "credentials", JS_NewString(ctx, auth_cred_to_string(user->credentials)));
	JS_SetPropertyStr(ctx, obj, "sid", JS_NewInt32(ctx, (int32_t) user->sid));
	JS_SetPropertyStr(ctx, obj, "id",
		JS_NewInt64(ctx, (int64_t) s->owner->handle->hub.get_user_connection_id(s->owner->handle, user)));
	return obj;
}

static void js_invalidate_user(JSContext* ctx, JSValue obj)
{
	struct js_user* u = (struct js_user*) JS_GetOpaque(obj, js_user_class_id);
	if (u)
	{
		u->valid = 0;
		u->user = NULL;
	}
	JS_FreeValue(ctx, obj);
}

/* ---- uhub global services ----------------------------------------------- */

static struct js_script* script_from_ctx(JSContext* ctx)
{
	return (struct js_script*) JS_GetContextOpaque(ctx);
}

/* Store the handler passed to an uhub.onXxx() registrar into *slot. */
static JSValue register_handler(JSContext* ctx, int argc, JSValueConst* argv, JSValue* slot)
{
	if (argc < 1 || !JS_IsFunction(ctx, argv[0]))
		return JS_ThrowTypeError(ctx, "handler must be a function");
	if (!JS_IsUndefined(*slot))
		JS_FreeValue(ctx, *slot);
	*slot = JS_DupValue(ctx, argv[0]);
	return JS_UNDEFINED;
}

#define DEFINE_REGISTRAR(FN, FIELD) \
	static JSValue FN(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) \
	{ \
		struct js_script* s = script_from_ctx(ctx); \
		(void) this_val; \
		return register_handler(ctx, argc, argv, &s->FIELD); \
	}

DEFINE_REGISTRAR(js_on_user_login,     on_user_login)
DEFINE_REGISTRAR(js_on_user_logout,    on_user_logout)
DEFINE_REGISTRAR(js_on_chat_msg,       on_chat_msg)
DEFINE_REGISTRAR(js_on_private_msg,    on_private_msg)
DEFINE_REGISTRAR(js_on_search,         on_search)
DEFINE_REGISTRAR(js_on_search_result,  on_search_result)
DEFINE_REGISTRAR(js_on_p2p_connect,    on_p2p_connect)
DEFINE_REGISTRAR(js_on_p2p_revconnect, on_p2p_revconnect)
DEFINE_REGISTRAR(js_on_check_ip_late,  on_check_ip_late)
DEFINE_REGISTRAR(js_on_change_nick,    on_change_nick)
DEFINE_REGISTRAR(js_on_flood_detected, on_flood_detected)
DEFINE_REGISTRAR(js_on_hub_started,    on_hub_started)
DEFINE_REGISTRAR(js_on_hub_shutdown,   on_hub_shutdown)

static JSValue js_uhub_broadcast(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
{
	struct js_script* s = script_from_ctx(ctx);
	const char* text;
	(void) this_val;
	if (argc < 1)
		return JS_ThrowTypeError(ctx, "broadcast(text) requires a string");
	text = JS_ToCString(ctx, argv[0]);
	if (!text)
		return JS_EXCEPTION;
	s->owner->handle->hub.send_broadcast_message(s->owner->handle, text);
	JS_FreeCString(ctx, text);
	return JS_UNDEFINED;
}

static JSValue js_uhub_get_user_count(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
{
	struct js_script* s = script_from_ctx(ctx);
	(void) this_val; (void) argc; (void) argv;
	return JS_NewInt64(ctx, (int64_t) s->owner->handle->hub.get_usercount(s->owner->handle));
}

static JSValue js_uhub_log(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
{
	struct js_script* s = script_from_ctx(ctx);
	const char* text;
	(void) this_val;
	if (argc < 1)
		return JS_UNDEFINED;
	text = JS_ToCString(ctx, argv[0]);
	if (!text)
		return JS_EXCEPTION;
	LOG_INFO("mod_javascript: %s: %s", s->filename, text);
	JS_FreeCString(ctx, text);
	return JS_UNDEFINED;
}

static const JSCFunctionListEntry js_uhub_funcs[] = {
	JS_CFUNC_DEF("onUserLogin", 1, js_on_user_login),
	JS_CFUNC_DEF("onUserLogout", 1, js_on_user_logout),
	JS_CFUNC_DEF("onChatMsg", 1, js_on_chat_msg),
	JS_CFUNC_DEF("onPrivateMsg", 1, js_on_private_msg),
	JS_CFUNC_DEF("onSearch", 1, js_on_search),
	JS_CFUNC_DEF("onSearchResult", 1, js_on_search_result),
	JS_CFUNC_DEF("onP2PConnect", 1, js_on_p2p_connect),
	JS_CFUNC_DEF("onP2PRevConnect", 1, js_on_p2p_revconnect),
	JS_CFUNC_DEF("onCheckIpLate", 1, js_on_check_ip_late),
	JS_CFUNC_DEF("onChangeNick", 1, js_on_change_nick),
	JS_CFUNC_DEF("onFloodDetected", 1, js_on_flood_detected),
	JS_CFUNC_DEF("onHubStarted", 1, js_on_hub_started),
	JS_CFUNC_DEF("onHubShutdown", 1, js_on_hub_shutdown),
	JS_CFUNC_DEF("broadcast", 1, js_uhub_broadcast),
	JS_CFUNC_DEF("getUserCount", 0, js_uhub_get_user_count),
	JS_CFUNC_DEF("log", 1, js_uhub_log),
	JS_PROP_INT32_DEF("DEFAULT", st_default, JS_PROP_ENUMERABLE),
	JS_PROP_INT32_DEF("ALLOW", st_allow, JS_PROP_ENUMERABLE),
	JS_PROP_INT32_DEF("DENY", st_deny, JS_PROP_ENUMERABLE),
};

/* ---- dispatch helpers --------------------------------------------------- */

static plugin_st js_invoke_status(struct js_script* s, JSValue cb, int argc, JSValue* argv)
{
	plugin_st st = st_default;
	JSValue r;
	if (JS_IsUndefined(cb))
		return st_default;
	js_arm_watchdog(s->owner);
	r = JS_Call(s->ctx, cb, JS_UNDEFINED, argc, (JSValueConst*) argv);
	js_disarm_watchdog(s->owner);
	if (JS_IsException(r))
		js_report_exception(s);
	else
		st = js_to_status(s->ctx, r);
	JS_FreeValue(s->ctx, r);
	return st;
}

/* ---- C callbacks fired by the hub --------------------------------------- */

#define FOREACH_SCRIPT(JP, IT) \
	struct js_script* IT; struct node* IT##_cur; \
	LIST_FOREACH_SAFE(struct js_script*, IT, (JP)->scripts, IT##_cur, )

static struct js_plugin* jp_of(struct plugin_handle* plugin)
{
	return (struct js_plugin*) plugin->ptr;
}

static void cb_user_login(struct plugin_handle* plugin, struct plugin_user* user)
{
	struct js_plugin* jp = jp_of(plugin);
	struct js_script* s;
	struct node* cur;
	LIST_FOREACH_SAFE(struct js_script*, s, jp->scripts, cur,
	{
		if (!JS_IsUndefined(s->on_user_login))
		{
			JSValue ju = js_make_user(s, user);
			js_invoke_status(s, s->on_user_login, 1, &ju);
			js_invalidate_user(s->ctx, ju);
		}
	});
}

static void cb_user_logout(struct plugin_handle* plugin, struct plugin_user* user, const char* reason)
{
	struct js_plugin* jp = jp_of(plugin);
	struct js_script* s;
	struct node* cur;
	LIST_FOREACH_SAFE(struct js_script*, s, jp->scripts, cur,
	{
		if (!JS_IsUndefined(s->on_user_logout))
		{
			JSValue args[2];
			args[0] = js_make_user(s, user);
			args[1] = JS_NewString(s->ctx, reason ? reason : "");
			js_invoke_status(s, s->on_user_logout, 2, args);
			js_invalidate_user(s->ctx, args[0]);
			JS_FreeValue(s->ctx, args[1]);
		}
	});
}

static plugin_st cb_chat_msg(struct plugin_handle* plugin, struct plugin_user* from, const char* message)
{
	struct js_plugin* jp = jp_of(plugin);
	struct js_script* s;
	struct node* cur;
	LIST_FOREACH_SAFE(struct js_script*, s, jp->scripts, cur,
	{
		if (!JS_IsUndefined(s->on_chat_msg))
		{
			JSValue args[2];
			plugin_st st;
			args[0] = js_make_user(s, from);
			args[1] = JS_NewString(s->ctx, message);
			st = js_invoke_status(s, s->on_chat_msg, 2, args);
			js_invalidate_user(s->ctx, args[0]);
			JS_FreeValue(s->ctx, args[1]);
			if (st != st_default)
				return st;
		}
	});
	return st_default;
}

static plugin_st cb_private_msg(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to, const char* message)
{
	struct js_plugin* jp = jp_of(plugin);
	struct js_script* s;
	struct node* cur;
	LIST_FOREACH_SAFE(struct js_script*, s, jp->scripts, cur,
	{
		if (!JS_IsUndefined(s->on_private_msg))
		{
			JSValue args[3];
			plugin_st st;
			args[0] = js_make_user(s, from);
			args[1] = js_make_user(s, to);
			args[2] = JS_NewString(s->ctx, message);
			st = js_invoke_status(s, s->on_private_msg, 3, args);
			js_invalidate_user(s->ctx, args[0]);
			js_invalidate_user(s->ctx, args[1]);
			JS_FreeValue(s->ctx, args[2]);
			if (st != st_default)
				return st;
		}
	});
	return st_default;
}

/* on_search / on_p2p_connect share the (user, string?) shape via a helper. */
static plugin_st dispatch_user_data(struct js_plugin* jp, size_t cb_offset,
	struct plugin_user* user, const char* data)
{
	struct js_script* s;
	struct node* cur;
	LIST_FOREACH_SAFE(struct js_script*, s, jp->scripts, cur,
	{
		JSValue cb = *(JSValue*) ((char*) s + cb_offset);
		if (!JS_IsUndefined(cb))
		{
			JSValue args[2];
			plugin_st st;
			int argc = 1;
			args[0] = js_make_user(s, user);
			if (data)
				args[argc++] = JS_NewString(s->ctx, data);
			st = js_invoke_status(s, cb, argc, args);
			js_invalidate_user(s->ctx, args[0]);
			if (data)
				JS_FreeValue(s->ctx, args[1]);
			if (st != st_default)
				return st;
		}
	});
	return st_default;
}

static plugin_st cb_search(struct plugin_handle* plugin, struct plugin_user* from, const char* data)
{
	return dispatch_user_data(jp_of(plugin), offsetof(struct js_script, on_search), from, data);
}

static plugin_st cb_p2p_connect(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to)
{
	(void) to;
	return dispatch_user_data(jp_of(plugin), offsetof(struct js_script, on_p2p_connect), from, NULL);
}

static plugin_st cb_p2p_revconnect(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to)
{
	(void) to;
	return dispatch_user_data(jp_of(plugin), offsetof(struct js_script, on_p2p_revconnect), from, NULL);
}

static plugin_st cb_search_result(struct plugin_handle* plugin, struct plugin_user* from, struct plugin_user* to, const char* data)
{
	struct js_plugin* jp = jp_of(plugin);
	struct js_script* s;
	struct node* cur;
	(void) to;
	LIST_FOREACH_SAFE(struct js_script*, s, jp->scripts, cur,
	{
		if (!JS_IsUndefined(s->on_search_result))
		{
			JSValue args[2];
			plugin_st st;
			args[0] = js_make_user(s, from);
			args[1] = JS_NewString(s->ctx, data);
			st = js_invoke_status(s, s->on_search_result, 2, args);
			js_invalidate_user(s->ctx, args[0]);
			JS_FreeValue(s->ctx, args[1]);
			if (st != st_default)
				return st;
		}
	});
	return st_default;
}

static plugin_st cb_check_ip_late(struct plugin_handle* plugin, struct plugin_user* user, struct ip_addr_encap* addr)
{
	(void) addr;
	return dispatch_user_data(jp_of(plugin), offsetof(struct js_script, on_check_ip_late), user, NULL);
}

static plugin_st cb_change_nick(struct plugin_handle* plugin, struct plugin_user* user, const char* new_nick)
{
	return dispatch_user_data(jp_of(plugin), offsetof(struct js_script, on_change_nick), user, new_nick);
}

static const char* flood_type_name(enum plugin_flood_type type)
{
	switch (type)
	{
		case flood_type_chat:    return "chat";
		case flood_type_connect: return "connect";
		case flood_type_search:  return "search";
		case flood_type_update:  return "update";
		case flood_type_extras:  return "protocol";
	}
	return "unknown";
}

static plugin_st cb_flood_detected(struct plugin_handle* plugin, struct plugin_user* user, enum plugin_flood_type type)
{
	struct js_plugin* jp = jp_of(plugin);
	struct js_script* s;
	struct node* cur;
	LIST_FOREACH_SAFE(struct js_script*, s, jp->scripts, cur,
	{
		if (!JS_IsUndefined(s->on_flood_detected))
		{
			JSValue args[2];
			plugin_st st;
			args[0] = js_make_user(s, user);
			args[1] = JS_NewString(s->ctx, flood_type_name(type));
			st = js_invoke_status(s, s->on_flood_detected, 2, args);
			js_invalidate_user(s->ctx, args[0]);
			JS_FreeValue(s->ctx, args[1]);
			if (st != st_default)
				return st;
		}
	});
	return st_default;
}

static void cb_hub_lifecycle(struct js_plugin* jp, int started)
{
	struct js_script* s;
	struct node* cur;
	LIST_FOREACH_SAFE(struct js_script*, s, jp->scripts, cur,
	{
		JSValue cb = started ? s->on_hub_started : s->on_hub_shutdown;
		if (!JS_IsUndefined(cb))
			js_invoke_status(s, cb, 0, NULL);
	});
}

static void cb_hub_started(struct plugin_handle* plugin, struct plugin_hub_info* info)
{
	(void) info;
	cb_hub_lifecycle(jp_of(plugin), 1);
}

static void cb_hub_shutdown(struct plugin_handle* plugin, struct plugin_hub_info* info)
{
	(void) info;
	cb_hub_lifecycle(jp_of(plugin), 0);
}

/* ---- script loading ----------------------------------------------------- */

/* Reject scripts that are group/world-writable or not regular files, mirroring
   the .so integrity check in the plugin loader: a writable script is a
   code-execution vector into the hub process. */
static int script_path_is_safe(const char* path, struct plugin_handle* plugin)
{
	struct stat st;
	if (stat(path, &st) != 0)
	{
		plugin->error_msg = "Unable to stat script file";
		return 0;
	}
	if (!S_ISREG(st.st_mode))
	{
		plugin->error_msg = "Script is not a regular file";
		return 0;
	}
	if (st.st_mode & (S_IWGRP | S_IWOTH))
	{
		plugin->error_msg = "Script is group- or world-writable";
		return 0;
	}
	return 1;
}

static char* read_file(const char* path, size_t* out_len)
{
	FILE* f = fopen(path, "rb");
	long size;
	char* buf;
	size_t got;
	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 || size > MAX_SCRIPT_SIZE)
	{
		fclose(f);
		return NULL;
	}
	rewind(f);
	buf = (char*) hub_malloc((size_t) size + 1);
	if (!buf)
	{
		fclose(f);
		return NULL;
	}
	got = fread(buf, 1, (size_t) size, f);
	fclose(f);
	buf[got] = '\0';
	if (out_len)
		*out_len = got;
	return buf;
}

static void script_init_handlers(struct js_script* s)
{
	s->on_user_login = s->on_user_logout = s->on_chat_msg = s->on_private_msg =
		s->on_search = s->on_search_result = s->on_p2p_connect = s->on_p2p_revconnect =
		s->on_check_ip_late = s->on_change_nick = s->on_flood_detected =
		s->on_hub_started = s->on_hub_shutdown = JS_UNDEFINED;
}

static void script_free_handlers(struct js_script* s)
{
	JSValue all[] = {
		s->on_user_login, s->on_user_logout, s->on_chat_msg, s->on_private_msg,
		s->on_search, s->on_search_result, s->on_p2p_connect, s->on_p2p_revconnect,
		s->on_check_ip_late, s->on_change_nick, s->on_flood_detected,
		s->on_hub_started, s->on_hub_shutdown,
	};
	size_t i;
	for (i = 0; i < sizeof(all) / sizeof(all[0]); i++)
		JS_FreeValue(s->ctx, all[i]);
}

static void apply_config_kv(JSContext* ctx, JSValue config, struct linked_list* kv)
{
	struct cfg_settings* s;
	struct node* cur;
	if (!kv)
		return;
	LIST_FOREACH_SAFE(struct cfg_settings*, s, kv, cur,
	{
		JS_SetPropertyStr(ctx, config, cfg_settings_get_key(s),
			JS_NewString(ctx, cfg_settings_get_value(s)));
	});
}

/* Build the per-context `uhub` global and the User prototype. uhub.config is the
   plugin-line options shared by all scripts (global_kv), overlaid with this
   script's own options (extra_kv, from a config-file line) which take priority. */
static int script_setup_globals(struct js_script* s, struct linked_list* global_kv, struct linked_list* extra_kv)
{
	JSContext* ctx = s->ctx;
	JSValue global, uhub, proto, config;

	/* User prototype (methods live here; instances are JS_NewObjectClass). */
	proto = JS_NewObject(ctx);
	JS_SetPropertyFunctionList(ctx, proto, js_user_proto_funcs,
		(int) (sizeof(js_user_proto_funcs) / sizeof(js_user_proto_funcs[0])));
	JS_SetClassProto(ctx, js_user_class_id, proto);

	global = JS_GetGlobalObject(ctx);

	uhub = JS_NewObject(ctx);
	JS_SetPropertyFunctionList(ctx, uhub, js_uhub_funcs,
		(int) (sizeof(js_uhub_funcs) / sizeof(js_uhub_funcs[0])));

	config = JS_NewObject(ctx);
	apply_config_kv(ctx, config, global_kv);
	apply_config_kv(ctx, config, extra_kv);
	JS_SetPropertyStr(ctx, uhub, "config", config);

	JS_SetPropertyStr(ctx, global, "uhub", uhub);
	JS_FreeValue(ctx, global);
	return 0;
}

static void script_destroy(struct js_script* s)
{
	if (!s)
		return;
	if (s->ctx)
	{
		script_free_handlers(s);
		JS_FreeContext(s->ctx);
	}
	hub_free(s->filename);
	hub_free(s);
}

static void free_script_handle(void* ptr)
{
	script_destroy((struct js_script*) ptr);
}

static struct js_script* script_load(struct js_plugin* jp, const char* path,
	struct linked_list* global_kv, struct linked_list* extra_kv)
{
	struct js_script* s;
	char* source;
	size_t len = 0;
	JSValue result;

	if (!script_path_is_safe(path, jp->handle))
		return NULL;

	source = read_file(path, &len);
	if (!source)
	{
		jp->handle->error_msg = "Unable to read script file";
		return NULL;
	}

	s = (struct js_script*) hub_malloc_zero(sizeof(struct js_script));
	if (!s)
	{
		hub_free(source);
		return NULL;
	}
	s->owner = jp;
	s->filename = hub_strdup(path);
	script_init_handlers(s);

	s->ctx = JS_NewContext(jp->rt);
	if (!s->ctx || !s->filename)
	{
		hub_free(source);
		script_destroy(s);
		jp->handle->error_msg = "Unable to create JS context";
		return NULL;
	}
	JS_SetContextOpaque(s->ctx, s);
	script_setup_globals(s, global_kv, extra_kv);

	js_arm_watchdog(jp);
	result = JS_Eval(s->ctx, source, len, path, JS_EVAL_TYPE_GLOBAL);
	js_disarm_watchdog(jp);
	hub_free(source);

	if (JS_IsException(result))
	{
		js_report_exception(s);
		JS_FreeValue(s->ctx, result);
		script_destroy(s);
		jp->handle->error_msg = "Script raised an exception at load time";
		return NULL;
	}
	JS_FreeValue(s->ctx, result);
	return s;
}

/* ---- config ------------------------------------------------------------- */

static void free_cfg_setting(void* ptr)
{
	cfg_settings_free((struct cfg_settings*) ptr);
}

static int path_is_absolute(const char* p)
{
#ifdef WIN32
	if (p[0] == '\\' || p[0] == '/')
		return 1;
	return (p[0] && p[1] == ':');
#else
	return p[0] == '/';
#endif
}

/* Join dir and name with a separator (unless dir already ends in one). */
static char* join_path(const char* dir, const char* name)
{
	size_t dl = strlen(dir);
	int sep = (dl > 0 && dir[dl - 1] != '/' && dir[dl - 1] != '\\');
	size_t len = dl + (sep ? 1 : 0) + strlen(name) + 1;
	char* out = (char*) hub_malloc(len);
	if (!out)
		return NULL;
	snprintf(out, len, sep ? "%s/%s" : "%s%s", dir, name);
	return out;
}

/* Directory portion of a path (own copy); "." when there is none. */
static char* dir_of(const char* path)
{
	const char* slash = strrchr(path, '/');
#ifdef WIN32
	const char* bslash = strrchr(path, '\\');
	if (bslash > slash)
		slash = bslash;
#endif
	if (!slash)
		return hub_strdup(".");
	return hub_strndup(path, (size_t) (slash - path));
}

/* Resolve a script path from a list file: relative paths are taken against the
   directory containing that list file. */
static char* resolve_against(const char* base_dir, const char* path)
{
	if (path_is_absolute(path))
		return hub_strdup(path);
	return join_path(base_dir, path);
}

#ifndef WIN32
static int has_js_ext(const char* name)
{
	size_t n = strlen(name);
	return n > 3 && strcmp(name + n - 3, ".js") == 0;
}

static int cmp_cstr(const void* a, const void* b)
{
	return strcmp(*(const char* const*) a, *(const char* const*) b);
}

/* Load every *.js in `dir`, in sorted (deterministic) order. Each file is
   validated (regular, not group/world-writable) by script_load. */
static int load_from_dir(struct js_plugin* jp, const char* dir, struct linked_list* global_kv)
{
	DIR* d = opendir(dir);
	struct dirent* de;
	char** names = NULL;
	size_t count = 0, cap = 0, i;
	int ok = 1;

	if (!d)
	{
		jp->handle->error_msg = "Unable to open script directory (dir=)";
		return -1;
	}
	while ((de = readdir(d)) != NULL)
	{
		if (de->d_name[0] == '.' || !has_js_ext(de->d_name))
			continue;
		if (count == cap)
		{
			char** grown;
			cap = cap ? cap * 2 : 16;
			grown = (char**) hub_realloc(names, cap * sizeof(char*));
			if (!grown) { ok = 0; break; }
			names = grown;
		}
		names[count++] = hub_strdup(de->d_name);
	}
	closedir(d);

	if (ok)
		qsort(names, count, sizeof(char*), cmp_cstr);

	for (i = 0; ok && i < count; i++)
	{
		char* full = join_path(dir, names[i]);
		struct js_script* s = full ? script_load(jp, full, global_kv, NULL) : NULL;
		hub_free(full);
		if (!s)
			ok = 0; /* error_msg already set */
		else
			list_append(jp->scripts, s);
	}

	for (i = 0; i < count; i++)
		hub_free(names[i]);
	hub_free(names);
	return ok ? 0 : -1;
}
#else
static int load_from_dir(struct js_plugin* jp, const char* dir, struct linked_list* global_kv)
{
	(void) dir; (void) global_kv;
	jp->handle->error_msg = "dir= is not supported on this platform; use config=";
	return -1;
}
#endif

/* Load scripts listed in a secondary config file: one script per line,
   "<path> [key=value ...]"; '#' begins a comment; blank lines are ignored.
   Relative paths resolve against the config file's own directory. The per-line
   key=value options are exposed to that script as uhub.config (over the globals). */
static int load_from_config(struct js_plugin* jp, const char* cfgfile, struct linked_list* global_kv)
{
	FILE* f = fopen(cfgfile, "r");
	char* base;
	char line[2048];
	int ok = 1;

	if (!f)
	{
		jp->handle->error_msg = "Unable to open config file (config=)";
		return -1;
	}
	base = dir_of(cfgfile);

	while (ok && fgets(line, sizeof(line), f))
	{
		struct cfg_tokens* tokens;
		struct linked_list* extra;
		char* first;
		char* tok;
		char* full;
		struct js_script* s;
		char* hash = strchr(line, '#');
		if (hash)
			*hash = '\0';
		line[strcspn(line, "\r\n")] = '\0'; /* fgets keeps the newline; drop it */

		tokens = cfg_tokenize(line);
		if (!tokens || cfg_token_count(tokens) == 0)
		{
			if (tokens) cfg_tokens_free(tokens);
			continue; /* blank / comment-only */
		}

		first = cfg_token_get_first(tokens);
		extra = list_create();
		for (tok = cfg_token_get_next(tokens); tok; tok = cfg_token_get_next(tokens))
		{
			struct cfg_settings* setting = cfg_settings_split(tok);
			if (setting)
				list_append(extra, setting);
		}

		full = resolve_against(base, first);
		s = full ? script_load(jp, full, global_kv, extra) : NULL;
		hub_free(full);
		if (!s)
			ok = 0; /* error_msg already set */
		else
			list_append(jp->scripts, s);

		list_clear(extra, free_cfg_setting);
		list_destroy(extra);
		cfg_tokens_free(tokens);
	}

	hub_free(base);
	fclose(f);
	return ok ? 0 : -1;
}

/* A script source named on the plugin line, processed after the whole line is
   parsed so a script always sees the complete global config. */
enum src_kind { SRC_SCRIPT, SRC_CONFIG, SRC_DIR };
struct src { enum src_kind kind; char* value; };

static void free_src(void* ptr)
{
	struct src* s = (struct src*) ptr;
	hub_free(s->value);
	hub_free(s);
}

static void add_src(struct linked_list* srcs, enum src_kind kind, const char* value)
{
	struct src* s = (struct src*) hub_malloc_zero(sizeof(struct src));
	if (!s)
		return;
	s->kind = kind;
	s->value = hub_strdup(value);
	list_append(srcs, s);
}

/*
 * Parse the plugin config line. Scripts are named by:
 *   config=<file>   a secondary list file (one script per line, +options)
 *   dir=<directory> load every *.js in the directory (sorted, validated)
 *   script=<file>   a single script (convenience; repeatable)
 * Every other key=value is exposed to all scripts as uhub.config. Recognised
 * tunables: memory_limit (bytes), stack_limit (bytes), time_limit (ms).
 */
static int parse_and_load(struct js_plugin* jp, const char* line)
{
	struct cfg_tokens* tokens = cfg_tokenize(line);
	struct linked_list* global_kv = list_create();
	struct linked_list* srcs = list_create();
	char* token;
	size_t mem_limit = DEFAULT_MEMORY_LIMIT;
	size_t stack_limit = DEFAULT_STACK_LIMIT;
	int ok = 1;

	if (!tokens || !global_kv || !srcs)
	{
		jp->handle->error_msg = "Out of memory";
		ok = 0;
		goto done;
	}

	for (token = cfg_token_get_first(tokens); token; token = cfg_token_get_next(tokens))
	{
		struct cfg_settings* setting = cfg_settings_split(token);
		const char* key;
		if (!setting)
		{
			jp->handle->error_msg = "Unable to parse startup parameters";
			ok = 0;
			goto done;
		}
		key = cfg_settings_get_key(setting);
		if (strcmp(key, "script") == 0)
			add_src(srcs, SRC_SCRIPT, cfg_settings_get_value(setting));
		else if (strcmp(key, "config") == 0)
			add_src(srcs, SRC_CONFIG, cfg_settings_get_value(setting));
		else if (strcmp(key, "dir") == 0)
			add_src(srcs, SRC_DIR, cfg_settings_get_value(setting));
		else if (strcmp(key, "memory_limit") == 0)
			mem_limit = (size_t) strtoull(cfg_settings_get_value(setting), NULL, 10);
		else if (strcmp(key, "stack_limit") == 0)
			stack_limit = (size_t) strtoull(cfg_settings_get_value(setting), NULL, 10);
		else if (strcmp(key, "time_limit") == 0)
			jp->time_limit_ms = atoi(cfg_settings_get_value(setting));
		else
		{
			list_append(global_kv, setting);
			continue; /* keep it: exposed via uhub.config, freed later */
		}
		cfg_settings_free(setting);
	}

	if (list_size(srcs) == 0)
	{
		jp->handle->error_msg = "No scripts given; use config=<file>, dir=<directory> or script=<file>";
		ok = 0;
		goto done;
	}
	if (jp->time_limit_ms <= 0)
		jp->time_limit_ms = DEFAULT_TIME_LIMIT;

	JS_SetMemoryLimit(jp->rt, mem_limit);
	JS_SetMaxStackSize(jp->rt, stack_limit);

	{
		struct src* src;
		struct node* cur;
		LIST_FOREACH_SAFE(struct src*, src, srcs, cur,
		{
			int r;
			if (src->kind == SRC_SCRIPT)
			{
				struct js_script* s = script_load(jp, src->value, global_kv, NULL);
				r = s ? (list_append(jp->scripts, s), 0) : -1;
			}
			else if (src->kind == SRC_CONFIG)
				r = load_from_config(jp, src->value, global_kv);
			else
				r = load_from_dir(jp, src->value, global_kv);
			if (r != 0)
			{
				ok = 0;
				break; /* error_msg already set */
			}
		});
	}

done:
	if (srcs)
	{
		list_clear(srcs, free_src);
		list_destroy(srcs);
	}
	if (global_kv)
	{
		list_clear(global_kv, free_cfg_setting);
		list_destroy(global_kv);
	}
	if (tokens)
		cfg_tokens_free(tokens);
	return ok ? 0 : -1;
}

/* ---- plugin entry points ------------------------------------------------ */

static void register_hub_callbacks(struct plugin_handle* plugin)
{
	plugin->funcs.on_user_login    = cb_user_login;
	plugin->funcs.on_user_logout   = cb_user_logout;
	plugin->funcs.on_chat_msg      = cb_chat_msg;
	plugin->funcs.on_private_msg   = cb_private_msg;
	plugin->funcs.on_search        = cb_search;
	plugin->funcs.on_search_result = cb_search_result;
	plugin->funcs.on_p2p_connect   = cb_p2p_connect;
	plugin->funcs.on_p2p_revconnect = cb_p2p_revconnect;
	plugin->funcs.on_check_ip_late = cb_check_ip_late;
	plugin->funcs.on_change_nick   = cb_change_nick;
	plugin->funcs.on_flood_detected = cb_flood_detected;
	plugin->funcs.on_hub_started   = cb_hub_started;
	plugin->funcs.on_hub_shutdown  = cb_hub_shutdown;
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	struct js_plugin* jp;

	PLUGIN_INITIALIZE(plugin, "JavaScript plugin host", "1.0",
		"Runs QuickJS scripts as uhub plugins.");

	jp = (struct js_plugin*) hub_malloc_zero(sizeof(struct js_plugin));
	if (!jp)
	{
		plugin->error_msg = "Out of memory";
		return -1;
	}
	jp->handle = plugin;
	jp->scripts = list_create();
	jp->rt = JS_NewRuntime();
	if (!jp->scripts || !jp->rt)
	{
		if (jp->rt)
			JS_FreeRuntime(jp->rt);
		if (jp->scripts)
			list_destroy(jp->scripts);
		hub_free(jp);
		plugin->error_msg = "Unable to create JS runtime";
		return -1;
	}
	JS_SetRuntimeOpaque(jp->rt, jp);
	JS_SetInterruptHandler(jp->rt, js_interrupt_handler, jp);

	if (!js_user_class_id)
		JS_NewClassID(jp->rt, &js_user_class_id);
	JS_NewClass(jp->rt, js_user_class_id, &js_user_class);

	plugin->ptr = jp;

	if (parse_and_load(jp, config) < 0)
	{
		plugin_unregister(plugin);
		return -1;
	}

	register_hub_callbacks(plugin);
	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	struct js_plugin* jp = (struct js_plugin*) plugin->ptr;
	if (!jp)
		return 0;

	if (jp->scripts)
	{
		/* Free every context (and its handler refs) before the runtime. */
		list_clear(jp->scripts, free_script_handle);
		list_destroy(jp->scripts);
	}
	if (jp->rt)
		JS_FreeRuntime(jp->rt);
	hub_free(jp);
	plugin->ptr = NULL;
	return 0;
}
