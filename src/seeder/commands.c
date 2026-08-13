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

#include "system.h"

#include "seeder/cache.h"
#include "seeder/commands.h"
#include "util/cbuffer.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"

/** Longest CID we will look at. The cache stores at most 63 characters. */
#define SEED_COMMAND_CID_MAX 63

/** Longest single reply line built here, before truncation. */
#define SEED_COMMAND_LINE_MAX 1024

struct seed_commands
{
	struct seed_cache* cache;
	seed_command_reply reply;
	void* ptr;
};

/**
 * A command implementation. @p client_type is carried through so that "help"
 * can list only what the caller may run; the rest ignore it, having already
 * been authorised.
 */
typedef void (*seed_command_handler)(struct seed_commands* cmds, sid_t from, int client_type, const char* args);

struct seed_command_def
{
	const char* verb;
	int cred;                     /** CT bits that must all be present. */
	seed_command_handler handler;
	const char* usage;
	const char* description;
};

/* -- output ---------------------------------------------------------------- */

/*
 * Replies are chat messages and chat is line oriented, so a control character
 * on its way out is not a cosmetic problem: a newline stored in a file name
 * would let whoever uploaded that file forge additional lines of operator
 * output. Everything echoed back is scrubbed field by field, and then the
 * assembled line is scrubbed once more on the way to the callback, so a field
 * added later cannot reintroduce the hole.
 */
static void seed_scrub(char* text)
{
	unsigned char* p = (unsigned char*) text;

	for (; *p; p++)
		if (*p < 0x20 || *p == 0x7f)
			*p = ' ';
}

void seed_command_sanitize(const char* text, char* out, size_t outlen)
{
	size_t len;

	if (!out || !outlen)
		return;

	if (!text || !*text)
	{
		snprintf(out, outlen, "-");
		return;
	}

	len = strlen(text);
	if (len > outlen - 1)
		len = outlen - 1;
	memcpy(out, text, len);
	out[len] = '\0';
	seed_scrub(out);
}

/** Send one assembled line, scrubbed, and consume the buffer. */
static void seed_send(struct seed_commands* cmds, sid_t to, struct cbuffer* buf)
{
	char* line;
	size_t len;

	if (!buf)
		return;

	if (!cmds->reply)
	{
		cbuf_destroy(buf);
		return;
	}

	len = cbuf_size(buf);
	line = hub_malloc(len + 1);
	if (line)
	{
		memcpy(line, cbuf_get(buf), len);
		line[len] = '\0';
		seed_scrub(line);
		cmds->reply(cmds->ptr, to, line);
		hub_free(line);
	}
	cbuf_destroy(buf);
}

static void seed_send_text(struct seed_commands* cmds, sid_t to, const char* text)
{
	struct cbuffer* buf = cbuf_create(strlen(text) + 1);
	cbuf_append(buf, text);
	seed_send(cmds, to, buf);
}

/* -- small helpers --------------------------------------------------------- */

/** A base32 TTH: exactly 39 characters from the alphabet, and nothing else. */
static int seed_command_valid_tth(const char* str)
{
	size_t i;

	if (!str)
		return 0;
	for (i = 0; i < SEED_TTH_STR_LEN; i++)
		if (!is_valid_base32_char(str[i]))
			return 0;
	return str[SEED_TTH_STR_LEN] == '\0';
}

/*
 * White space for the purposes of a command line. util/misc.h's
 * is_white_space() does not count a newline; here it must, so that a stray line
 * ending cannot end up glued to the end of a verb or a TTH.
 */
static int seed_is_space(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

/**
 * Copy the first white space delimited token of @p args into @p out.
 * @return the remainder of @p args, with leading white space skipped.
 */
static const char* seed_next_token(const char* args, char* out, size_t outlen)
{
	size_t len = 0;

	out[0] = '\0';
	if (!args)
		return "";

	while (seed_is_space(*args))
		args++;

	while (*args && !seed_is_space(*args))
	{
		if (len < outlen - 1)
			out[len++] = *args;
		else
			len = outlen; /* too long: keep going, but mark it unusable */
		args++;
	}

	if (len >= outlen)
		out[0] = '\0'; /* the token did not fit, so it is not a valid anything */
	else
		out[len] = '\0';

	while (seed_is_space(*args))
		args++;
	return args;
}

static void seed_format_time(time_t when, char* out, size_t outlen)
{
	struct tm* tm;

	if (when <= 0 || (tm = gmtime(&when)) == NULL ||
	    strftime(out, outlen, "%Y-%m-%d %H:%M:%S UTC", tm) == 0)
		snprintf(out, outlen, "-");
}

/** Format a limit, where 0 means "no limit was configured". */
static const char* seed_format_max_bytes(uint64_t value, char* out, size_t outlen)
{
	if (!value)
		snprintf(out, outlen, "unlimited");
	else
		format_size((size_t) value, out, outlen);
	return out;
}

static const char* seed_format_max_count(size_t value, char* out, size_t outlen)
{
	if (!value)
		snprintf(out, outlen, "unlimited");
	else
		snprintf(out, outlen, PRINTF_SIZE_T, value);
	return out;
}

int seed_command_parse_limit(const char* args)
{
	char token[16];
	int value = 0;

	seed_next_token(args, token, sizeof(token));
	if (!token[0] || !is_number(token, &value) || value <= 0)
		return SEED_COMMAND_LIST_DEFAULT;
	if (value > SEED_COMMAND_LIST_MAX)
		return SEED_COMMAND_LIST_MAX;
	return value;
}

/* -- command implementations ----------------------------------------------- */

/**
 * Resolve the cache, telling the caller when the daemon is running without one.
 * @return the cache, or NULL after a reply has been sent.
 */
static struct seed_cache* seed_command_cache(struct seed_commands* cmds, sid_t from)
{
	if (!cmds->cache)
	{
		seed_send_text(cmds, from, "The seed cache is not enabled.");
		return NULL;
	}
	return cmds->cache;
}

/**
 * Pull a TTH argument and validate it before it can reach the cache.
 * @return the remainder of @p args, or NULL after a reply has been sent.
 */
static const char* seed_command_arg_tth(struct seed_commands* cmds, sid_t from, const char* args, char tth[SEED_TTH_STR_LEN + 1])
{
	const char* rest = seed_next_token(args, tth, SEED_TTH_STR_LEN + 1);

	if (!seed_command_valid_tth(tth))
	{
		seed_send_text(cmds, from, "Not a valid TTH (expected 39 upper case base32 characters).");
		return NULL;
	}
	return rest;
}

static void seed_cmd_stats(struct seed_commands* cmds, sid_t from, int client_type, const char* args)
{
	struct seed_cache* cache = seed_command_cache(cmds, from);
	struct seed_cache_stats stats;
	struct cbuffer* buf;
	char used[32];
	char max[32];
	char emax[32];

	(void) args;
	(void) client_type;
	if (!cache)
		return;

	seed_cache_get_stats(cache, &stats);
	format_size((size_t) stats.bytes_used, used, sizeof(used));
	seed_format_max_bytes(stats.bytes_max, max, sizeof(max));
	seed_format_max_count(stats.entries_max, emax, sizeof(emax));

	buf = cbuf_create(256);
	cbuf_append_format(buf, "Seed cache: %s/%s, " PRINTF_SIZE_T "/%s entries, "
		PRINTF_SIZE_T " pinned, " PRINTF_SIZE_T " ingesting, " PRINTF_SIZE_T " blocked%s",
		used, max, stats.entries, emax, stats.pinned,
		stats.active_ingests, stats.blocked,
		stats.degraded ? " (DEGRADED: disk error)" : "");
	seed_send(cmds, from, buf);
}

static void seed_cmd_list(struct seed_commands* cmds, sid_t from, int client_type, const char* args)
{
	struct seed_cache* cache = seed_command_cache(cmds, from);
	struct seed_entry entry;
	int limit;
	int shown = 0;
	int more;

	(void) client_type;
	if (!cache)
		return;

	limit = seed_command_parse_limit(args);
	seed_send_text(cmds, from, "Cached files, most recently used first:");

	for (more = seed_cache_first(cache, &entry); more && shown < limit;
	     more = seed_cache_next(cache, &entry))
	{
		struct cbuffer* buf = cbuf_create(SEED_COMMAND_LINE_MAX);
		char size[32];
		char type[SEED_MIME_MAX];
		char name[SEED_NAME_MAX];

		format_size((size_t) entry.size, size, sizeof(size));
		seed_command_sanitize(entry.media_type, type, sizeof(type));
		seed_command_sanitize(entry.name, name, sizeof(name));

		cbuf_append_format(buf, "%s  %10s  %-24s %s", entry.tth, size, type, name);
		seed_send(cmds, from, buf);
		shown++;
	}

	/*
	 * Stopping at the limit leaves the cache's walk open, and the next command
	 * may well be a del or a block. Run the cursor out so the walk is closed
	 * before this returns.
	 */
	while (more)
		more = seed_cache_next(cache, &entry);

	if (!shown)
		seed_send_text(cmds, from, "(empty)");
}

static void seed_cmd_info(struct seed_commands* cmds, sid_t from, int client_type, const char* args)
{
	struct seed_cache* cache = seed_command_cache(cmds, from);
	struct seed_entry entry;
	struct cbuffer* buf;
	char tth[SEED_TTH_STR_LEN + 1];
	char size[32];
	char text[SEED_NAME_MAX];
	char stamp[64];

	(void) client_type;
	if (!cache || !seed_command_arg_tth(cmds, from, args, tth))
		return;

	/* Inspecting the cache must not reorder it. */
	if (!seed_cache_peek(cache, tth, &entry))
	{
		if (seed_cache_is_blocked(cache, tth))
			seed_send_text(cmds, from, "Not cached; that TTH is on the blocklist.");
		else
			seed_send_text(cmds, from, "No such file is cached.");
		return;
	}

	format_size((size_t) entry.size, size, sizeof(size));

	buf = cbuf_create(128);
	cbuf_append_format(buf, "TTH: %s", entry.tth);
	seed_send(cmds, from, buf);

	buf = cbuf_create(128);
	cbuf_append_format(buf, "Size: %s (%" PRIu64 " bytes)", size, entry.size);
	seed_send(cmds, from, buf);

	seed_command_sanitize(entry.media_type, text, sizeof(text));
	buf = cbuf_create(128);
	cbuf_append_format(buf, "Type: %s", text);
	seed_send(cmds, from, buf);

	seed_command_sanitize(entry.name, text, sizeof(text));
	buf = cbuf_create(SEED_COMMAND_LINE_MAX);
	cbuf_append_format(buf, "Name: %s", text);
	seed_send(cmds, from, buf);

	/* Provenance: this is what answers a takedown request months later. */
	buf = cbuf_create(SEED_COMMAND_LINE_MAX);
	seed_command_sanitize(entry.origin_nick, text, sizeof(text));
	cbuf_append_format(buf, "Posted by: %s", text);
	seed_command_sanitize(entry.origin_cid, text, sizeof(text));
	cbuf_append_format(buf, " (CID %s", text);
	seed_command_sanitize(entry.origin_addr, text, sizeof(text));
	cbuf_append_format(buf, ", from %s)", text);
	seed_send(cmds, from, buf);

	seed_format_time(entry.first_seen, stamp, sizeof(stamp));
	buf = cbuf_create(128);
	cbuf_append_format(buf, "First seen: %s", stamp);
	seed_send(cmds, from, buf);

	seed_format_time(entry.last_access, stamp, sizeof(stamp));
	buf = cbuf_create(128);
	cbuf_append_format(buf, "Last access: %s, %u hits", stamp, (unsigned) entry.hits);
	seed_send(cmds, from, buf);
}

static void seed_cmd_del(struct seed_commands* cmds, sid_t from, int client_type, const char* args)
{
	struct seed_cache* cache = seed_command_cache(cmds, from);
	char tth[SEED_TTH_STR_LEN + 1];

	(void) client_type;
	if (!cache || !seed_command_arg_tth(cmds, from, args, tth))
		return;

	if (seed_cache_remove(cache, tth, "operator"))
		seed_send_text(cmds, from, "File removed. It can be cached again unless you also block it.");
	else
		seed_send_text(cmds, from, "No such file is cached.");
}

static void seed_cmd_block(struct seed_commands* cmds, sid_t from, int client_type, const char* args)
{
	struct seed_cache* cache = seed_command_cache(cmds, from);
	const char* rest;
	char tth[SEED_TTH_STR_LEN + 1];
	char reason[SEED_NAME_MAX];
	char who[32];

	(void) client_type;
	if (!cache)
		return;

	rest = seed_command_arg_tth(cmds, from, args, tth);
	if (!rest)
		return;

	if (seed_cache_is_blocked(cache, tth))
	{
		seed_send_text(cmds, from, "That TTH is already blocked.");
		return;
	}

	seed_command_sanitize(rest, reason, sizeof(reason));
	snprintf(who, sizeof(who), "operator sid=%u", (unsigned) from);

	/* Deleting without blocking is useless: the next upload puts it back. */
	if (seed_cache_block(cache, tth, who, reason))
		seed_send_text(cmds, from, "File deleted and blocked; it will not be cached again.");
	else
		seed_send_text(cmds, from, "Could not block that TTH; the cache reported an error.");
}

static void seed_cmd_unblock(struct seed_commands* cmds, sid_t from, int client_type, const char* args)
{
	struct seed_cache* cache = seed_command_cache(cmds, from);
	char tth[SEED_TTH_STR_LEN + 1];

	(void) client_type;
	if (!cache || !seed_command_arg_tth(cmds, from, args, tth))
		return;

	seed_send_text(cmds, from, seed_cache_unblock(cache, tth)
		? "TTH unblocked." : "That TTH was not blocked.");
}

static void seed_cmd_purge(struct seed_commands* cmds, sid_t from, int client_type, const char* args)
{
	struct seed_cache* cache = seed_command_cache(cmds, from);
	struct cbuffer* buf;
	char cid[SEED_COMMAND_CID_MAX + 1];
	char safe[SEED_COMMAND_CID_MAX + 1];
	size_t removed;

	(void) client_type;
	if (!cache)
		return;

	seed_next_token(args, cid, sizeof(cid));
	if (!cid[0])
	{
		seed_send_text(cmds, from, "Usage: purge <cid>");
		return;
	}

	removed = seed_cache_remove_by_cid(cache, cid);
	seed_command_sanitize(cid, safe, sizeof(safe));

	buf = cbuf_create(160);
	cbuf_append_format(buf, "Removed " PRINTF_SIZE_T " file%s posted by CID %s.",
		removed, (removed == 1) ? "" : "s", safe);
	seed_send(cmds, from, buf);
}

static void seed_cmd_gc(struct seed_commands* cmds, sid_t from, int client_type, const char* args)
{
	struct seed_cache* cache = seed_command_cache(cmds, from);
	struct seed_cache_stats before;
	struct seed_cache_stats after;
	struct cbuffer* buf;
	char freed[32];

	(void) args;
	(void) client_type;
	if (!cache)
		return;

	seed_cache_get_stats(cache, &before);
	seed_cache_sweep(cache, time(NULL));
	seed_cache_get_stats(cache, &after);

	format_size((size_t) ((before.bytes_used > after.bytes_used) ? before.bytes_used - after.bytes_used : 0),
		freed, sizeof(freed));

	buf = cbuf_create(192);
	cbuf_append_format(buf, "Swept the seed cache: " PRINTF_SIZE_T " entries removed (%s freed), "
		PRINTF_SIZE_T " remaining.",
		(before.entries > after.entries) ? before.entries - after.entries : 0,
		freed, after.entries);
	seed_send(cmds, from, buf);
}

static void seed_cmd_help(struct seed_commands* cmds, sid_t from, int client_type, const char* args);

/*
 * The command table. Anything not listed here is unknown, and the credentials
 * are the ones the hub used for the corresponding !blob* command: everything is
 * an operator command except unblock and gc, which are the two that either undo
 * a takedown or delete in bulk.
 */
static const struct seed_command_def seed_command_table[] = {
	{ "stats",   SEED_CRED_OPERATOR, seed_cmd_stats,   "stats",              "Show seed cache usage" },
	{ "list",    SEED_CRED_OPERATOR, seed_cmd_list,    "list [N]",           "List cached files, most recently used first" },
	{ "info",    SEED_CRED_OPERATOR, seed_cmd_info,    "info <tth>",         "Show who posted a cached file, and when" },
	{ "del",     SEED_CRED_OPERATOR, seed_cmd_del,     "del <tth>",          "Delete a cached file by TTH" },
	{ "block",   SEED_CRED_OPERATOR, seed_cmd_block,   "block <tth> [why]",  "Delete a file and refuse it permanently" },
	{ "unblock", SEED_CRED_ADMIN,    seed_cmd_unblock, "unblock <tth>",      "Remove a TTH from the blocklist" },
	{ "purge",   SEED_CRED_OPERATOR, seed_cmd_purge,   "purge <cid>",        "Delete every file posted by a CID" },
	{ "gc",      SEED_CRED_ADMIN,    seed_cmd_gc,      "gc",                 "Expire and evict the cache now" },
	{ "help",    0,                  seed_cmd_help,    "help",               "Show this list" }
};

#define SEED_COMMAND_COUNT (sizeof(seed_command_table) / sizeof(seed_command_table[0]))

static const struct seed_command_def* seed_command_find(const char* verb)
{
	size_t i;

	if (!verb || !*verb)
		return NULL;
	for (i = 0; i < SEED_COMMAND_COUNT; i++)
		if (strcmp(seed_command_table[i].verb, verb) == 0)
			return &seed_command_table[i];
	return NULL;
}

/*
 * Only the commands this caller may actually run are listed. Anyone may ask for
 * help, so listing the lot would hand an unprivileged user the command names
 * that the refusal in seed_commands_handle() deliberately withholds.
 */
static void seed_cmd_help(struct seed_commands* cmds, sid_t from, int client_type, const char* args)
{
	size_t i;

	(void) args;
	seed_send_text(cmds, from, "Seeder commands (send as a private message; a leading '!' is optional):");

	for (i = 0; i < SEED_COMMAND_COUNT; i++)
	{
		struct cbuffer* buf;

		if (seed_command_check_access(seed_command_table[i].verb, client_type) != SEED_ACCESS_OK)
			continue;

		buf = cbuf_create(128);
		cbuf_append_format(buf, "  %-20s - %s",
			seed_command_table[i].usage, seed_command_table[i].description);
		seed_send(cmds, from, buf);
	}
}

/* -- parsing and authorisation --------------------------------------------- */

int seed_command_parse(const char* text, struct seed_command_line* out)
{
	size_t len = 0;

	if (!out)
		return 0;

	out->verb[0] = '\0';
	out->args = "";

	if (!text)
		return 0;

	while (seed_is_space(*text))
		text++;

	/* A private message needs no prefix, but an operator used to typing hub
	   commands will reach for one anyway. */
	if (*text == '!' || *text == '+')
		text++;

	while (seed_is_space(*text))
		text++;

	while (*text && !seed_is_space(*text))
	{
		if (len < SEED_COMMAND_VERB_MAX)
		{
			char c = *text;
			if (c >= 'A' && c <= 'Z')
				c = (char) (c - 'A' + 'a');
			out->verb[len++] = c;
		}
		text++;
	}
	out->verb[len] = '\0';

	while (seed_is_space(*text))
		text++;
	out->args = text;

	return len > 0;
}

enum seed_command_access seed_command_check_access(const char* verb, int client_type)
{
	const struct seed_command_def* def = seed_command_find(verb);

	/*
	 * An unknown verb is judged against the lowest credentials any command
	 * needs. A user who could not have run a command therefore gets the same
	 * refusal whether the verb exists or not, and learns nothing by guessing.
	 */
	int cred = def ? def->cred : SEED_CRED_OPERATOR;

	if ((client_type & cred) != cred)
		return SEED_ACCESS_DENIED;

	return def ? SEED_ACCESS_OK : SEED_ACCESS_UNKNOWN;
}

/* -- entry points ---------------------------------------------------------- */

struct seed_commands* seed_commands_create(struct seed_cache* cache, seed_command_reply reply, void* ptr)
{
	struct seed_commands* cmds = hub_malloc_zero(sizeof(struct seed_commands));

	if (!cmds)
		return NULL;

	cmds->cache = cache;
	cmds->reply = reply;
	cmds->ptr = ptr;
	return cmds;
}

void seed_commands_destroy(struct seed_commands* cmds)
{
	if (cmds)
		hub_free(cmds);
}

int seed_commands_handle(struct seed_commands* cmds, sid_t from, int client_type, const char* text)
{
	struct seed_command_line line;
	const struct seed_command_def* def;

	if (!cmds || !seed_command_parse(text, &line))
		return 0;

	/* Authorisation first, before the verb is even resolved to a handler. */
	switch (seed_command_check_access(line.verb, client_type))
	{
		case SEED_ACCESS_DENIED:
			seed_send_text(cmds, from, "You are not allowed to do that.");
			return 1;

		case SEED_ACCESS_UNKNOWN:
			seed_send_text(cmds, from, "Unknown command. Send \"help\" for the list.");
			return 1;

		case SEED_ACCESS_OK:
			break;
	}

	def = seed_command_find(line.verb);
	if (!def)
		return 1;

	if (def->cred)
		LOG_USER("seed: sid=%u ran command \"%s\"", (unsigned) from, def->verb);

	def->handler(cmds, from, client_type, line.args);
	return 1;
}
