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
#include "uhub_limits.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "util/rbtree.h"
#include "adc/adcconst.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "network/backend.h"
#include "network/timeout.h"
#include "tools/adcclient.h"
#include "seeder/cache.h"
#include "seeder/config.h"
#include "seeder/hubconn.h"

#include <openssl/rand.h>
#include <sys/stat.h>

/*
 * The reconnect delay is served by a chain of short timer arms rather than one
 * long one. The timeout wheel is indexed modulo TIMEOUT_QUEUE_MAX, so a delay
 * at or past that would alias onto an earlier slot; keeping every individual
 * arm well under it means the cap in SEED_RECONNECT_MAX can be raised later
 * without anyone having to remember this.
 */
#define SEED_HUB_TIMER_TICK 30

/** Raw bytes behind a PID: a TIGER hash worth, which base32s to 39 chars. */
#define SEED_PID_RAW 24

/** Name of the PID file inside the cache directory. */
#define SEED_PID_FILE "pid"

struct seed_roster
{
	struct rb_tree* by_sid;   /* key: &entry->sid, value: entry */
	struct rb_tree* by_cid;   /* key: entry->cid,  value: entry */
};

struct seed_hub
{
	struct ADC_client* client;
	struct seed_hub_callbacks cb;
	void* ptr;

	struct seed_roster* roster;

	char* url;
	char* nick;
	char* password;
	char* description;
	char* cache_dir;
	char  pid[MAX_CID_LEN + 1];
	char  cid[MAX_CID_LEN + 1];
	char  support[SEED_SUPPORT_MAX]; /** SU advertised in the INF; "" for none. */

	int bbs;             /** Offer BBS0 in the HSUP, i.e. seed_bbs_enable. */

	int started;         /** seed_hub_start() was called and stop() was not. */
	int logged_in;
	int announced;       /** on_logged_in has fired for the current connection. */
	int fatal;           /** A condition retrying cannot fix; no more reconnects. */

	struct timeout_evt* timer;
	unsigned int backoff;      /** Current delay in seconds; 0 before the first retry. */
	unsigned int retry_left;   /** Seconds of the current delay not yet waited out. */
	int retry_pending;         /** A reconnect is scheduled. */
};

static void seed_hub_open(struct seed_hub* hub);
static void seed_hub_schedule_retry(struct seed_hub* hub);

/* -------------------------------------------------------------------------
 * Client type helpers
 * ------------------------------------------------------------------------- */

int seed_user_is_bot(const struct seed_user* user)
{
	return (user && (user->client_type & SEED_CT_BOT)) ? 1 : 0;
}

int seed_user_is_operator(const struct seed_user* user)
{
	return (user && (user->client_type & SEED_CT_OPERATOR)) ? 1 : 0;
}

int seed_user_is_registered(const struct seed_user* user)
{
	return (user && (user->client_type & SEED_CT_REGISTERED)) ? 1 : 0;
}

int seed_user_is_hub(const struct seed_user* user)
{
	return (user && (user->client_type & SEED_CT_HUB)) ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * Roster
 * ------------------------------------------------------------------------- */

static int roster_compare_sid(const void* a, const void* b)
{
	sid_t x = *(const sid_t*) a;
	sid_t y = *(const sid_t*) b;

	if (x < y)
		return -1;
	return (x > y) ? 1 : 0;
}

static int roster_compare_cid(const void* a, const void* b)
{
	return strcmp((const char*) a, (const char*) b);
}

struct seed_roster* seed_roster_create(void)
{
	struct seed_roster* roster = (struct seed_roster*) hub_malloc_zero(sizeof(struct seed_roster));
	if (!roster)
		return NULL;

	roster->by_sid = rb_tree_create(roster_compare_sid, NULL, NULL);
	roster->by_cid = rb_tree_create(roster_compare_cid, NULL, NULL);
	if (!roster->by_sid || !roster->by_cid)
	{
		if (roster->by_sid)
			rb_tree_destroy(roster->by_sid);
		if (roster->by_cid)
			rb_tree_destroy(roster->by_cid);
		hub_free(roster);
		return NULL;
	}
	return roster;
}

void seed_roster_clear(struct seed_roster* roster)
{
	struct rb_node* node;

	if (!roster)
		return;

	/* The nodes in by_cid key off the entries, so that index has to go first:
	   once an entry is freed its cid is no longer a valid key to look up. */
	while ((node = rb_tree_first(roster->by_cid)) != NULL)
		rb_tree_remove(roster->by_cid, node->key);

	while ((node = rb_tree_first(roster->by_sid)) != NULL)
	{
		struct seed_user* entry = (struct seed_user*) node->value;
		rb_tree_remove(roster->by_sid, node->key);
		hub_free(entry);
	}
}

void seed_roster_destroy(struct seed_roster* roster)
{
	if (!roster)
		return;

	/* rb_tree_destroy() assumes an empty tree -- it frees the tree, not the
	   nodes -- so everything is unhooked first. */
	seed_roster_clear(roster);
	rb_tree_destroy(roster->by_sid);
	rb_tree_destroy(roster->by_cid);
	hub_free(roster);
}

size_t seed_roster_size(struct seed_roster* roster)
{
	return roster ? rb_tree_size(roster->by_sid) : 0;
}

const struct seed_user* seed_roster_get_sid(struct seed_roster* roster, sid_t sid)
{
	if (!roster)
		return NULL;
	return (const struct seed_user*) rb_tree_get(roster->by_sid, &sid);
}

const struct seed_user* seed_roster_get_cid(struct seed_roster* roster, const char* cid)
{
	if (!roster || !cid || !*cid)
		return NULL;
	return (const struct seed_user*) rb_tree_get(roster->by_cid, cid);
}

const struct seed_user* seed_roster_update(struct seed_roster* roster, const struct seed_user* user)
{
	struct seed_user* entry;

	if (!roster || !user)
		return NULL;

	entry = (struct seed_user*) rb_tree_get(roster->by_sid, &user->sid);
	if (entry)
	{
		/* A hub reuses a SID only after the previous holder has parted, but a
		   BINF for a SID we already know is routine (a user updating its INF),
		   so this is an update, not a duplicate to be refused. The CID is the
		   key of the second index, so it is re-indexed only when it changed. */
		if (strcmp(entry->cid, user->cid) != 0)
		{
			if (*entry->cid)
				rb_tree_remove(roster->by_cid, entry->cid);
			memcpy(entry, user, sizeof(*entry));
			if (*entry->cid)
				rb_tree_insert(roster->by_cid, entry->cid, entry);
		}
		else
		{
			memcpy(entry, user, sizeof(*entry));
		}
		return entry;
	}

	entry = (struct seed_user*) hub_malloc_zero(sizeof(struct seed_user));
	if (!entry)
		return NULL;
	memcpy(entry, user, sizeof(*entry));

	if (!rb_tree_insert(roster->by_sid, &entry->sid, entry))
	{
		hub_free(entry);
		return NULL;
	}

	/* A CID index entry is optional: two users cannot share a CID on a sane
	   hub, but the roster must not fall over if one manages it. */
	if (*entry->cid)
		rb_tree_insert(roster->by_cid, entry->cid, entry);

	return entry;
}

int seed_roster_remove(struct seed_roster* roster, sid_t sid)
{
	struct seed_user* entry;

	if (!roster)
		return 0;

	entry = (struct seed_user*) rb_tree_get(roster->by_sid, &sid);
	if (!entry)
		return 0;

	if (*entry->cid)
	{
		/* Only if this entry is the one indexed: a CID collision would
		   otherwise have the loser evict the winner's index entry. */
		if (rb_tree_get(roster->by_cid, entry->cid) == entry)
			rb_tree_remove(roster->by_cid, entry->cid);
	}
	rb_tree_remove(roster->by_sid, &entry->sid);
	hub_free(entry);
	return 1;
}

/* -------------------------------------------------------------------------
 * Wire parsing
 * ------------------------------------------------------------------------- */

/** A base32 TTH: exactly SEED_TTH_STR_LEN characters of the base32 alphabet. */
static int seed_hub_tth_is_valid(const char* tth)
{
	size_t i;

	if (!tth)
		return 0;

	for (i = 0; i < SEED_TTH_STR_LEN; i++)
	{
		char c = tth[i];
		if (!((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')))
			return 0;
	}
	return tth[SEED_TTH_STR_LEN] == '\0';
}

/**
 * Copy an unescaped wire argument into a fixed buffer, refusing anything that
 * does not fit rather than silently truncating it -- a truncated token would
 * be echoed back and never match.
 */
/*
 * Trim ASCII blanks from both ends, in place, returning the first kept byte.
 *
 * Only used on fixed-length tokens (a TTH), where surrounding space carries no
 * meaning and trimming cannot make two different values collide.
 */
static char* seed_hub_trim(char* str)
{
	char* end;

	while (*str == ' ' || *str == '\t')
		str++;

	end = str + strlen(str);
	while (end > str && (end[-1] == ' ' || end[-1] == '\t'))
		end--;
	*end = '\0';

	return str;
}

static int seed_hub_copy_arg(char* dst, size_t size, const char* src)
{
	size_t len;

	if (!src)
		return 0;

	len = strlen(src);
	if (len >= size)
		return 0;

	memcpy(dst, src, len + 1);
	return 1;
}

int seed_hub_parse_search(struct adc_message* msg, struct seed_search* out)
{
	char* tth;
	char* plain;
	char* token;
	int ok;

	if (!msg || !out)
		return 0;

	memset(out, 0, sizeof(*out));

	/* No TR, no answer: the cache is content-addressed and cannot serve a
	   substring search, so those are not worth waking the seeder for. */
	tth = adc_msg_get_named_argument(msg, ADC_SCH_FLAG_TTH);
	if (!tth)
		return 0;

	/*
	 * Unescaped before it is looked at, exactly like the token below. It arrives
	 * in wire form, so a value carrying any escape would otherwise be validated
	 * against the escape sequence itself and rejected -- which is precisely what
	 * happened: EiskaltDC++ sends "TR<tth>\s", a TTH with a trailing escaped
	 * space, and every one of those searches went unanswered.
	 *
	 * The blanks are then trimmed rather than being grounds for refusal. A TTH
	 * is fixed length, so surrounding space cannot change which file is meant,
	 * and refusing over it only means the file is not served to a client whose
	 * search says plainly what it wants.
	 */
	plain = adc_msg_unescape(tth);
	hub_free(tth);
	if (!plain)
		return 0;

	ok = seed_hub_copy_arg(out->tth, sizeof(out->tth), seed_hub_trim(plain))
		&& seed_hub_tth_is_valid(out->tth);
	hub_free(plain);

	if (!ok)
	{
		memset(out, 0, sizeof(*out));
		return 0;
	}

	/* The token is unescaped here and escaped again on the way out, so it
	   round-trips whatever the searcher chose. An over-long one costs us the
	   token, not the answer: the search is still worth replying to. */
	token = adc_msg_get_named_argument(msg, ADC_SCH_FLAG_TOKEN);
	if (token)
	{
		char* plain = adc_msg_unescape(token);
		if (plain)
			seed_hub_copy_arg(out->token, sizeof(out->token), plain);
		hub_free(plain);
		hub_free(token);
	}

	return 1;
}

/**
 * The shared half of CTM and RCM: the protocol is argument 0 and the token is
 * the last argument, with the port wedged between them only for a CTM.
 */
static int seed_hub_parse_connect(struct adc_message* msg, struct seed_connect* out, int with_port)
{
	char* protocol;
	char* port_str = NULL;
	char* token;
	int ok = 1;

	if (!msg || !out)
		return 0;

	memset(out, 0, sizeof(*out));

	protocol = adc_msg_get_argument(msg, 0);
	if (with_port)
		port_str = adc_msg_get_argument(msg, 1);
	token = adc_msg_get_argument(msg, with_port ? 2 : 1);

	if (!seed_hub_copy_arg(out->protocol, sizeof(out->protocol), protocol))
		ok = 0;
	if (ok && !seed_hub_copy_arg(out->token, sizeof(out->token), token))
		ok = 0;
	if (ok && (!*out->protocol || !*out->token))
		ok = 0;

	if (ok && with_port)
	{
		int port = 0;
		if (!port_str || !is_number(port_str, &port) || port <= 0 || port > 65535)
			ok = 0;
		else
			out->port = (uint16_t) port;
	}

	hub_free(protocol);
	hub_free(port_str);
	hub_free(token);

	if (!ok)
		memset(out, 0, sizeof(*out));
	return ok;
}

int seed_hub_parse_ctm(struct adc_message* msg, struct seed_connect* out)
{
	return seed_hub_parse_connect(msg, out, 1);
}

int seed_hub_parse_rcm(struct adc_message* msg, struct seed_connect* out)
{
	return seed_hub_parse_connect(msg, out, 0);
}

/* -------------------------------------------------------------------------
 * BBS0 bulletin boards
 * ------------------------------------------------------------------------- */

int seed_hub_bbs_board_valid(const char* board)
{
	size_t i;

	if (!board || !*board)
		return 0;

	for (i = 0; board[i]; i++)
	{
		char c = board[i];

		/* The set BBS0 fixes, and nothing else. It excludes the path
		   separators but permits '.', so ".." is a legal board name -- which is
		   exactly why a name from here must never reach the filesystem. */
		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'))
		{
			return 0;
		}
	}

	return (i <= SEED_BBS_BOARD_MAX) ? 1 : 0;
}

/*
 * Read a named argument as display text: unescaped, then bounded.
 *
 * @return 1 when the argument was present and fitted.
 */
static int seed_hub_named_text(struct adc_message* msg, const char* name, char* dst, size_t size)
{
	char* raw = adc_msg_get_named_argument(msg, name);
	char* plain;
	int ok;

	if (!raw)
		return 0;

	plain = adc_msg_unescape(raw);
	hub_free(raw);
	if (!plain)
		return 0;

	ok = seed_hub_copy_arg(dst, size, plain);
	hub_free(plain);
	return ok;
}

/*
 * Read a named argument as an unsigned decimal.
 *
 * Nothing is unescaped first: a number carrying an escape is not a number, and
 * accepting one would mean accepting "1\s" as 1. Overflow is a parse failure
 * rather than a wrap, since a timestamp is a cursor and a wrapped one would ask
 * the hub to replay from the wrong place forever.
 *
 * @return 1 when the argument was present and well formed.
 */
static int seed_hub_named_uint(struct adc_message* msg, const char* name, uint64_t* out)
{
	char* raw = adc_msg_get_named_argument(msg, name);
	uint64_t value = 0;
	int ok;
	size_t i;

	if (!raw)
		return 0;

	ok = (raw[0] != '\0');
	for (i = 0; ok && raw[i]; i++)
	{
		if (raw[i] < '0' || raw[i] > '9')
		{
			ok = 0;
			break;
		}
		if (value > (UINT64_MAX - (uint64_t) (raw[i] - '0')) / 10)
		{
			ok = 0;
			break;
		}
		value = value * 10 + (uint64_t) (raw[i] - '0');
	}

	hub_free(raw);

	if (ok)
		*out = value;
	return ok;
}

/* A TTH-shaped named argument: present, and 39 base32 characters. */
static int seed_hub_named_tth(struct adc_message* msg, const char* name, char* dst, size_t size)
{
	if (!seed_hub_named_text(msg, name, dst, size))
		return 0;

	if (!seed_hub_tth_is_valid(dst))
	{
		dst[0] = '\0';
		return 0;
	}
	return 1;
}

/* RM is "1" for gone/withdrawn; every other value is reserved and ignored. */
static int seed_hub_named_removed(struct adc_message* msg)
{
	uint64_t value = 0;

	if (!seed_hub_named_uint(msg, ADC_BBS_FLAG_REMOVED, &value))
		return 0;
	return (value == 1) ? 1 : 0;
}

int seed_hub_parse_bbs_board(struct adc_message* msg, struct seed_bbs_board* out)
{
	uint64_t value = 0;

	if (!msg || !out)
		return 0;

	memset(out, 0, sizeof(*out));

	if (!seed_hub_named_text(msg, ADC_BBS_FLAG_BOARD, out->board, sizeof(out->board)) ||
		!seed_hub_bbs_board_valid(out->board))
	{
		memset(out, 0, sizeof(*out));
		return 0;
	}

	out->removed = seed_hub_named_removed(msg);

	/*
	 * A descriptor announcing that the board is gone is accepted on the board
	 * name alone. The only thing to do with one is forget the board, and
	 * holding a removal notice to the full set of required fields would mean
	 * ignoring it -- leaving a subscription to a board that no longer exists.
	 */
	if (out->removed)
		return 1;

	if (!seed_hub_named_uint(msg, ADC_BBS_FLAG_PERMISSIONS, &value))
	{
		memset(out, 0, sizeof(*out));
		return 0;
	}
	out->permissions = (unsigned int) (value & 0xffffffffu);

	if (!seed_hub_named_uint(msg, ADC_BBS_FLAG_MAX_SIZE, &out->max_size) ||
		!seed_hub_named_uint(msg, ADC_MSG_FLAG_TIMESTAMP, &out->newest) ||
		!seed_hub_named_uint(msg, ADC_BBS_FLAG_OLDEST, &out->oldest))
	{
		memset(out, 0, sizeof(*out));
		return 0;
	}

	/* Informative, so absence is not a failure. */
	seed_hub_named_uint(msg, ADC_BBS_FLAG_NUM_POSTS, &out->num_posts);
	seed_hub_named_text(msg, ADC_INF_FLAG_NICK, out->name, sizeof(out->name));

	return 1;
}

int seed_hub_parse_bbs_entry(struct adc_message* msg, struct seed_bbs_entry* out)
{
	if (!msg || !out)
		return 0;

	memset(out, 0, sizeof(*out));

	/* TR, BD and TS are what a tombstone carries, so they are what every entry
	   is required to have here. */
	if (!seed_hub_named_tth(msg, ADC_SCH_FLAG_TTH, out->tth, sizeof(out->tth)) ||
		!seed_hub_named_text(msg, ADC_BBS_FLAG_BOARD, out->board, sizeof(out->board)) ||
		!seed_hub_bbs_board_valid(out->board) ||
		!seed_hub_named_uint(msg, ADC_MSG_FLAG_TIMESTAMP, &out->timestamp))
	{
		memset(out, 0, sizeof(*out));
		return 0;
	}

	out->removed = seed_hub_named_removed(msg);

	/*
	 * A tombstone is required to carry only the three fields above and should
	 * carry nothing else -- the subject and author of a withdrawn post are
	 * usually the reason it was withdrawn -- so nothing further is read from
	 * one even if the hub sent it.
	 */
	if (out->removed)
		return 1;

	if (!seed_hub_named_uint(msg, ADC_RES_FLAG_FILE_SIZE, &out->size) ||
		!seed_hub_named_text(msg, ADC_INF_FLAG_CLIENT_ID, out->author_cid, sizeof(out->author_cid)))
	{
		memset(out, 0, sizeof(*out));
		return 0;
	}

	/* Copied from the document, and hints until the document is in hand. */
	seed_hub_named_tth(msg, ADC_BBS_FLAG_PARENT, out->parent, sizeof(out->parent));
	seed_hub_named_text(msg, ADC_BBS_FLAG_SUBJECT, out->subject, sizeof(out->subject));

	/*
	 * TH is the hub's grouping and is never verified. A post with no parent is
	 * its own thread root, which is what it falls back to when the hub omits
	 * it: the seeder fetches by TR and does not thread anything, so this is
	 * carried for provenance rather than acted on.
	 */
	if (!seed_hub_named_tth(msg, ADC_BBS_FLAG_THREAD, out->thread, sizeof(out->thread)) &&
		!*out->parent)
	{
		strcpy(out->thread, out->tth);
	}

	seed_hub_named_text(msg, ADC_INF_FLAG_NICK, out->nick, sizeof(out->nick));

	return 1;
}

int seed_hub_parse_result(struct adc_message* msg, struct seed_result* out)
{
	if (!msg || !out)
		return 0;

	memset(out, 0, sizeof(*out));

	/* A content-addressed cache can do nothing with a result that names no
	   hash, so one is refused here rather than surfaced and dropped later. */
	if (!seed_hub_named_tth(msg, ADC_SCH_FLAG_TTH, out->tth, sizeof(out->tth)))
		return 0;

	out->from = msg->source;
	seed_hub_named_uint(msg, ADC_RES_FLAG_FILE_SIZE, &out->size);
	seed_hub_named_text(msg, ADC_RES_FLAG_TOKEN, out->token, sizeof(out->token));

	return 1;
}

/* -------------------------------------------------------------------------
 * Outgoing messages
 * ------------------------------------------------------------------------- */

/*
 * Render the RES filename as an absolute virtual path.
 *
 * ADC's FN is a path, not a bare name, and DC++-derived clients take the name
 * they display from whatever follows the last '/'. Sent without a leading
 * slash, EiskaltDC++ shows "oalsetting.jpg" for "Goalsetting.jpg" -- the first
 * character is eaten. The seeder publishes no directory structure, so every
 * entry lives at the root.
 *
 * Everything is published under one invented directory, SEED_SHARE_DIR. A share
 * with no directory at all is what clients handle worst -- a bare name leaves
 * them splitting a path that has no separator in it -- and a single obvious
 * prefix also makes the seeder's files recognisable as the cache's rather than
 * some user's.
 *
 * A separator inside the name is dropped along with everything before it. The
 * name originates in a magnet's "dn=", so it is whatever a user typed, and what
 * goes out has to be one component under that directory rather than a tree the
 * seeder does not have. Nothing is served by path in any case -- a download
 * names the file by its TTH, so this is a label, not an address.
 */
static void seed_hub_result_path(char* out, size_t size, const char* name)
{
	const char* base = name;
	const char* p;

	for (p = name; *p; p++)
	{
		if (*p == '/' || *p == '\\')
			base = p + 1;
	}

	snprintf(out, size, "/%s/%s", SEED_SHARE_DIR, base);
}

struct adc_message* seed_hub_build_result(sid_t from, sid_t to, const char* tth, uint64_t size,
	const char* name, int slots, const char* token)
{
	struct adc_message* res;
	char path[sizeof("/" SEED_SHARE_DIR "/") + SEED_NAME_MAX];

	if (!seed_hub_tth_is_valid(tth))
		return NULL;

	res = adc_msg_construct_source_dest(ADC_CMD_DRES, from, to, 128 + SEED_TOKEN_MAX + MAX_NICK_LEN);
	if (!res)
		return NULL;

	/* The name is user-supplied text on its way back onto the wire, so it is
	   escaped like any other; a nameless entry is announced by its TTH. */
	seed_hub_result_path(path, sizeof(path), (name && *name) ? name : tth);
	adc_msg_add_named_argument_string(res, ADC_RES_FLAG_FILE_NAME, path);
	adc_msg_add_named_argument_uint64(res, ADC_RES_FLAG_FILE_SIZE, size);
	adc_msg_add_named_argument_int(res, ADC_RES_FLAG_UPLOAD_SLOTS, (slots > 0) ? slots : 1);
	adc_msg_add_named_argument(res, ADC_SCH_FLAG_TTH, tth);

	/* The searcher matches the reply to its search by the token, so it goes
	   back exactly as it came in -- unescaped on the way here, escaped again
	   here. */
	if (token && *token)
		adc_msg_add_named_argument_string(res, ADC_RES_FLAG_TOKEN, token);

	return res;
}

/** Queue a message, if there is a connection able to carry it. */
static int seed_hub_send(struct seed_hub* hub, struct adc_message* msg)
{
	if (!hub || !msg)
		return 0;

	if (!hub->client || !hub->logged_in)
		return 0;

	ADC_client_send(hub->client, msg);
	return 1;
}

int seed_hub_send_result(struct seed_hub* hub, sid_t to, const char* tth, uint64_t size,
	const char* name, int slots, const char* token)
{
	struct adc_message* res;
	int ret;

	if (!hub || !hub->logged_in)
		return 0;

	res = seed_hub_build_result(seed_hub_own_sid(hub), to, tth, size, name, slots, token);
	if (!res)
		return 0;

	ret = seed_hub_send(hub, res);
	adc_msg_free(res);
	return ret;
}

int seed_hub_send_ctm(struct seed_hub* hub, sid_t to, const char* protocol, uint16_t port, const char* token)
{
	struct adc_message* ctm;
	char port_str[8];
	int ret;

	if (!hub || !hub->logged_in || !protocol || !*protocol || !token || !*token || !port)
		return 0;

	ctm = adc_msg_construct_source_dest(ADC_CMD_DCTM, seed_hub_own_sid(hub), to,
		32 + SEED_PROTOCOL_MAX + SEED_TOKEN_MAX);
	if (!ctm)
		return 0;

	snprintf(port_str, sizeof(port_str), "%u", (unsigned) port);
	adc_msg_add_argument(ctm, protocol);
	adc_msg_add_argument(ctm, port_str);
	adc_msg_add_argument(ctm, token);

	ret = seed_hub_send(hub, ctm);
	adc_msg_free(ctm);
	return ret;
}

int seed_hub_send_rcm(struct seed_hub* hub, sid_t to, const char* protocol, const char* token)
{
	struct adc_message* rcm;
	int ret;

	if (!hub || !hub->logged_in || !protocol || !*protocol || !token || !*token)
		return 0;

	rcm = adc_msg_construct_source_dest(ADC_CMD_DRCM, seed_hub_own_sid(hub), to,
		16 + SEED_PROTOCOL_MAX + SEED_TOKEN_MAX);
	if (!rcm)
		return 0;

	adc_msg_add_argument(rcm, protocol);
	adc_msg_add_argument(rcm, token);

	ret = seed_hub_send(hub, rcm);
	adc_msg_free(rcm);
	return ret;
}

int seed_hub_send_pm(struct seed_hub* hub, sid_t to, const char* text)
{
	struct adc_message* msg;
	char* escaped;
	char pm_flag[8];
	int ret;

	if (!hub || !hub->logged_in || !text || !*text)
		return 0;

	msg = adc_msg_construct_source_dest(ADC_CMD_DMSG, seed_hub_own_sid(hub), to, strlen(text) * 2 + 32);
	if (!msg)
		return 0;

	escaped = adc_msg_escape(text);
	if (!escaped)
	{
		adc_msg_free(msg);
		return 0;
	}
	adc_msg_add_argument(msg, escaped);
	hub_free(escaped);

	/* PM names the conversation, which for a one-to-one reply is our own SID
	   -- the same convention the hub itself uses for its command replies. */
	snprintf(pm_flag, sizeof(pm_flag), "%s%s", ADC_MSG_FLAG_PRIVATE, sid_to_string(seed_hub_own_sid(hub)));
	adc_msg_add_argument(msg, pm_flag);

	ret = seed_hub_send(hub, msg);
	adc_msg_free(msg);
	return ret;
}

int seed_hub_bbs_available(struct seed_hub* hub)
{
	if (!hub || !hub->client)
		return 0;

	return ADC_client_hub_supports(hub->client, ADC_EXT_BBS0);
}

/*
 * The one builder behind subscribe, cancel and single-entry request: all three
 * are an HBBL differing only in which fields they carry.
 *
 * BBS0 forbids sending BBL on a hub that has not announced the feature, whether
 * or not this end offered it, so the check is here rather than in each caller.
 * TR and TS must not both be present -- a request is a question and not a
 * subscription -- which the callers arrange by passing one or the other.
 */
static int seed_hub_send_bbl(struct seed_hub* hub, const char* board,
	const uint64_t* from_ts, const char* tth, int cancel)
{
	struct adc_message* msg;
	int ret;

	if (!hub || !hub->logged_in || !seed_hub_bbs_available(hub))
		return 0;

	if (!seed_hub_bbs_board_valid(board))
		return 0;

	if (tth && !seed_hub_tth_is_valid(tth))
		return 0;

	msg = adc_msg_construct(ADC_CMD_HBBL, 64 + SEED_BBS_BOARD_MAX + SEED_TTH_STR_LEN);
	if (!msg)
		return 0;

	/* The board name is protocol text from a set that contains none of the
	   characters ADC escapes, so it goes on the wire as it stands. */
	adc_msg_add_named_argument(msg, ADC_BBS_FLAG_BOARD, board);

	if (cancel)
		adc_msg_add_named_argument(msg, ADC_BBS_FLAG_REMOVED, "1");
	else if (tth)
		adc_msg_add_named_argument(msg, ADC_SCH_FLAG_TTH, tth);
	else if (from_ts)
		adc_msg_add_named_argument_uint64(msg, ADC_MSG_FLAG_TIMESTAMP, *from_ts);

	ret = seed_hub_send(hub, msg);
	adc_msg_free(msg);
	return ret;
}

int seed_hub_send_bbs_subscribe(struct seed_hub* hub, const char* board, uint64_t from_ts)
{
	return seed_hub_send_bbl(hub, board, &from_ts, NULL, 0);
}

int seed_hub_send_bbs_cancel(struct seed_hub* hub, const char* board)
{
	return seed_hub_send_bbl(hub, board, NULL, NULL, 1);
}

int seed_hub_send_bbs_request(struct seed_hub* hub, const char* board, const char* tth)
{
	return seed_hub_send_bbl(hub, board, NULL, tth, 0);
}

int seed_hub_send_search_tth(struct seed_hub* hub, const char* tth, const char* token)
{
	struct adc_message* msg;
	int ret;

	if (!hub || !hub->logged_in || !seed_hub_tth_is_valid(tth))
		return 0;

	/*
	 * Broadcast, because the point of searching is not knowing who has it. An
	 * exact TTH search is the cheapest question ADC has -- a client either
	 * holds that hash or does not -- and it is the only kind this cache can
	 * ask or answer.
	 */
	msg = adc_msg_construct_source(ADC_CMD_BSCH, seed_hub_own_sid(hub),
		32 + SEED_TTH_STR_LEN + SEED_TOKEN_MAX);
	if (!msg)
		return 0;

	adc_msg_add_named_argument(msg, ADC_SCH_FLAG_TTH, tth);
	if (token && *token)
		adc_msg_add_named_argument_string(msg, ADC_SCH_FLAG_TOKEN, token);

	ret = seed_hub_send(hub, msg);
	adc_msg_free(msg);
	return ret;
}

/* -------------------------------------------------------------------------
 * Identity
 * ------------------------------------------------------------------------- */

static int seed_hub_pid_is_valid(const char* pid)
{
	size_t i;

	if (!pid)
		return 0;

	for (i = 0; i < MAX_CID_LEN; i++)
	{
		char c = pid[i];
		if (!((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')))
			return 0;
	}
	return pid[MAX_CID_LEN] == '\0';
}

static int seed_hub_pid_read(const char* path, char* pid)
{
	FILE* file = fopen(path, "r");
	char buf[MAX_CID_LEN + 8];
	size_t len;

	if (!file)
		return 0;

	memset(buf, 0, sizeof(buf));
	len = fread(buf, 1, sizeof(buf) - 1, file);
	fclose(file);

	/* Tolerate a trailing newline: the file is small enough that an operator
	   may well have created or inspected it by hand. */
	while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' '))
		buf[--len] = '\0';

	if (len != MAX_CID_LEN || !seed_hub_pid_is_valid(buf))
		return 0;

	memcpy(pid, buf, MAX_CID_LEN + 1);
	return 1;
}

static int seed_hub_pid_write(const char* path, const char* pid)
{
	FILE* file;
	int fd;

	/* Created 0600 up front rather than chmod'ed afterwards: the PID is the
	   seeder's identity on the hub, and a window in which it is world-readable
	   is a window in which it can be stolen. */
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd == -1)
		return 0;

	file = fdopen(fd, "w");
	if (!file)
	{
		close(fd);
		return 0;
	}

	if (fprintf(file, "%s\n", pid) < 0)
	{
		fclose(file);
		return 0;
	}

	return (fclose(file) == 0);
}

int seed_hub_pid_load(const char* cache_dir, char* pid)
{
	char path[1024];
	uint8_t raw[SEED_PID_RAW];
	char encoded[64];

	if (!cache_dir || !*cache_dir || !pid)
		return 0;

	if ((size_t) snprintf(path, sizeof(path), "%s/%s", cache_dir, SEED_PID_FILE) >= sizeof(path))
		return 0;

	if (seed_hub_pid_read(path, pid))
		return 1;

	/* First run (or an unreadable file): mint one. Random rather than derived
	   from anything configured -- the PID is sent to the hub at login, so a PID
	   derived from the password would hand the password's entropy to the hub. */
	if (RAND_bytes(raw, (int) sizeof(raw)) != 1)
		return 0;

	memset(encoded, 0, sizeof(encoded));
	base32_encode(raw, sizeof(raw), encoded);
	encoded[MAX_CID_LEN] = '\0';

	if (!seed_hub_pid_is_valid(encoded))
		return 0;

	memcpy(pid, encoded, MAX_CID_LEN + 1);

	/* The directory is the cache's to create, but the PID is needed before the
	   cache is necessarily open, so make sure there is somewhere to put it. */
	mkdir(cache_dir, S_IRWXU);

	if (!seed_hub_pid_write(path, pid))
	{
		LOG_WARN("seeder: unable to persist the identity to %s; the seeder's CID will change on restart.", path);
		return 1;
	}

	LOG_INFO("seeder: generated a new identity in %s.", path);
	return 1;
}

/* -------------------------------------------------------------------------
 * Reconnection
 * ------------------------------------------------------------------------- */

unsigned int seed_hub_backoff_next(unsigned int seconds)
{
	unsigned int next;

	if (seconds < SEED_RECONNECT_MIN)
		return SEED_RECONNECT_MIN;

	if (seconds >= SEED_RECONNECT_MAX)
		return SEED_RECONNECT_MAX;

	next = seconds * 2;
	return (next > SEED_RECONNECT_MAX) ? SEED_RECONNECT_MAX : next;
}

/** Arm the timer for the next slice of the current delay. */
static void seed_hub_arm_timer(struct seed_hub* hub)
{
	struct timeout_queue* queue = net_backend_get_timeout_queue();
	size_t delay;

	if (!queue || !hub->timer)
	{
		/* Without a timeout queue there is nothing to drive a retry. Say so
		   once; the daemon always has one, so this is a test or a caller that
		   started us before net_initialize(). */
		LOG_WARN("seeder: no timeout queue, the hub connection will not reconnect.");
		hub->retry_pending = 0;
		return;
	}

	delay = (hub->retry_left > SEED_HUB_TIMER_TICK) ? SEED_HUB_TIMER_TICK : hub->retry_left;
	if (delay < 1)
		delay = 1;
	hub->retry_left -= (unsigned int) delay;

	if (timeout_evt_is_scheduled(hub->timer))
		timeout_queue_reschedule(queue, hub->timer, delay);
	else
		timeout_queue_insert(queue, hub->timer, delay);
}

static void seed_hub_cancel_timer(struct seed_hub* hub)
{
	struct timeout_queue* queue = net_backend_get_timeout_queue();

	if (hub->timer && queue && timeout_evt_is_scheduled(hub->timer))
		timeout_queue_remove(queue, hub->timer);

	hub->retry_pending = 0;
	hub->retry_left = 0;
}

static void seed_hub_timer_cb(struct timeout_evt* evt)
{
	struct seed_hub* hub = (struct seed_hub*) evt->ptr;

	if (!hub->started)
	{
		hub->retry_pending = 0;
		return;
	}

	/* The delay is served in slices, so most firings just re-arm. */
	if (hub->retry_left > 0)
	{
		seed_hub_arm_timer(hub);
		return;
	}

	hub->retry_pending = 0;
	seed_hub_open(hub);
}

static void seed_hub_schedule_retry(struct seed_hub* hub)
{
	if (!hub->started || hub->retry_pending)
		return;

	/* A hub that fails keyprint verification will fail it again in a second and
	   again in a minute: the certificate is wrong, or somebody is in the middle.
	   Backing off and retrying would turn an attack into a permanent one and
	   bury the reason under reconnect noise, so the connection stays down until
	   an operator restarts the seeder. */
	if (hub->fatal)
		return;

	hub->backoff = seed_hub_backoff_next(hub->backoff);
	hub->retry_left = hub->backoff;
	hub->retry_pending = 1;

	LOG_INFO("seeder: reconnecting to %s in %u second%s.", hub->url, hub->backoff,
		(hub->backoff == 1) ? "" : "s");

	seed_hub_arm_timer(hub);
}

/* -------------------------------------------------------------------------
 * Transport callbacks
 * ------------------------------------------------------------------------- */

/**
 * Fill in a seed_user for a message source. A user we have never seen a BINF
 * for still gets an entry -- with only the SID filled in -- so a callback never
 * has to cope with a NULL sender.
 */
static const struct seed_user* seed_hub_sender(struct seed_hub* hub, sid_t sid, struct seed_user* fallback)
{
	const struct seed_user* user = seed_roster_get_sid(hub->roster, sid);
	if (user)
		return user;

	memset(fallback, 0, sizeof(*fallback));
	fallback->sid = sid;
	return fallback;
}

static void seed_hub_on_login(struct seed_hub* hub)
{
	hub->logged_in = 1;

	/* The connection worked, so the next failure starts counting from scratch
	   rather than inheriting however long the last outage grew to. */
	hub->backoff = 0;

	/* Without a persisted PID the transport minted one when it sent its INF,
	   so the CID is only known now. */
	if (hub->client)
	{
		strncpy(hub->cid, ADC_client_get_cid(hub->client), sizeof(hub->cid) - 1);
		hub->cid[sizeof(hub->cid) - 1] = '\0';
	}

	LOG_INFO("seeder: logged in to %s as \"%s\" (SID %s, CID %s).", hub->url, hub->nick,
		sid_to_string(seed_hub_own_sid(hub)), seed_hub_own_cid(hub));

	if (!hub->announced)
	{
		hub->announced = 1;
		if (hub->cb.on_logged_in)
			hub->cb.on_logged_in(hub->ptr);
	}
}

static void seed_hub_on_disconnect(struct seed_hub* hub)
{
	int was_announced = hub->announced;

	hub->logged_in = 0;
	hub->announced = 0;
	seed_roster_clear(hub->roster);

	if (was_announced && hub->cb.on_disconnected)
		hub->cb.on_disconnected(hub->ptr);

	seed_hub_schedule_retry(hub);
}

static void seed_hub_on_user(struct seed_hub* hub, const struct ADC_user* adc_user)
{
	struct seed_user user;

	if (!adc_user || adc_user->sid == seed_hub_own_sid(hub))
		return;

	memset(&user, 0, sizeof(user));
	user.sid = adc_user->sid;
	user.client_type = adc_user->client_type;
	uhub_strlcpy(user.cid, adc_user->cid, sizeof(user.cid));
	uhub_strlcpy(user.nick, adc_user->name, sizeof(user.nick));
	uhub_strlcpy(user.address, adc_user->address, sizeof(user.address));
	uhub_strlcpy(user.support, adc_user->support, sizeof(user.support));

	/* SU decides whether a transfer with this peer can be encrypted, and it is
	   not the peer's own claim that arrives here but whatever the hub chose to
	   re-broadcast -- so what the seeder actually sees is worth recording. */
	LOG_DEBUG("seed_hub: user %s (CT %d) supports \"%s\"",
		user.nick, user.client_type, user.support);

	seed_roster_update(hub->roster, &user);
}

static void seed_hub_on_chat(struct seed_hub* hub, const struct ADC_chat_message* chat)
{
	struct seed_user fallback;
	const struct seed_user* from;
	int is_private;

	if (!chat || !chat->message)
		return;

	/* Our own message echoed back to us is not something to react to. */
	if (chat->from_sid == seed_hub_own_sid(hub))
		return;

	if (!hub->cb.on_chat)
		return;

	is_private = ((chat->flags & chat_flags_private) ||
		(chat->to_sid != 0 && chat->to_sid == seed_hub_own_sid(hub))) ? 1 : 0;

	from = seed_hub_sender(hub, chat->from_sid, &fallback);
	hub->cb.on_chat(hub->ptr, from, chat->message, is_private);
}

static void seed_hub_on_search(struct seed_hub* hub, struct adc_message* msg)
{
	struct seed_search search;
	struct seed_user fallback;
	const struct seed_user* from;

	if (!msg || msg->source == seed_hub_own_sid(hub))
		return;

	if (!hub->cb.on_search)
		return;

	if (!seed_hub_parse_search(msg, &search))
	{
		/*
		 * A search the seeder cannot answer is normal -- most searches are text,
		 * and the cache is content-addressed. The raw line is logged because the
		 * three reasons to land here (no TR at all, a TR that is not a TTH, and
		 * a search that never arrived) look identical from outside and have
		 * completely different causes.
		 */
		size_t len = msg->length;

		while (len && (msg->cache[len - 1] == '\n' || msg->cache[len - 1] == '\r'))
			len--;
		if (len > 200)
			len = 200;

		LOG_DEBUG("seed_hub: unanswerable search from SID %s: \"%.*s\"",
			sid_to_string(msg->source), (int) len, msg->cache);
		return;
	}

	from = seed_hub_sender(hub, msg->source, &fallback);
	hub->cb.on_search(hub->ptr, from, search.tth, search.token);
}

static void seed_hub_on_connect_req(struct seed_hub* hub, struct adc_message* msg)
{
	struct seed_connect req;
	struct seed_user fallback;
	const struct seed_user* from;

	if (!msg || msg->source == seed_hub_own_sid(hub))
		return;

	if (!seed_hub_parse_ctm(msg, &req))
	{
		LOG_DEBUG("seeder: dropping malformed CTM from %s", sid_to_string(msg->source));
		return;
	}

	if (!hub->cb.on_connect_req)
		return;

	from = seed_hub_sender(hub, msg->source, &fallback);
	hub->cb.on_connect_req(hub->ptr, from, req.protocol, req.port, req.token);
}

static void seed_hub_on_revconnect_req(struct seed_hub* hub, struct adc_message* msg)
{
	struct seed_connect req;
	struct seed_user fallback;
	const struct seed_user* from;

	if (!msg || msg->source == seed_hub_own_sid(hub))
		return;

	if (!seed_hub_parse_rcm(msg, &req))
	{
		LOG_DEBUG("seeder: dropping malformed RCM from %s", sid_to_string(msg->source));
		return;
	}

	if (!hub->cb.on_revconnect_req)
		return;

	from = seed_hub_sender(hub, msg->source, &fallback);
	hub->cb.on_revconnect_req(hub->ptr, from, req.protocol, req.token);
}

static int seed_hub_client_callback(struct ADC_client* client, enum ADC_client_callback_type type,
	struct ADC_client_callback_data* data)
{
	struct seed_hub* hub = (struct seed_hub*) ADC_client_get_ptr(client);

	if (!hub)
		return 1;

	switch (type)
	{
		case ADC_CLIENT_CONNECTING:
			LOG_DEBUG("seeder: connecting to %s", hub->url);
			break;

		case ADC_CLIENT_CONNECTED:
		case ADC_CLIENT_SSL_HANDSHAKE:
		case ADC_CLIENT_SSL_OK:
		case ADC_CLIENT_LOGGING_IN:
		case ADC_CLIENT_PASSWORD_REQ:
		case ADC_CLIENT_NAME_LOOKUP:
			break;

		case ADC_CLIENT_SSL_KEYPRINT_ERROR:
			/* Not a network failure: either the hub's certificate changed and
			   the configuration is stale, or the connection is being
			   intercepted. Neither improves by waiting, and everything the
			   seeder trusts -- operator authority, the peers it dials, the
			   password challenge it answers -- arrives over this link, so it
			   stays down. */
			LOG_FATAL("seeder: %s is not the hub it claims to be (expected keyprint %s, presented %s). "
				"Refusing to connect; fix seed_hub_url or the hub's certificate and restart.",
				hub->url,
				(data && data->keyprint) ? data->keyprint->expected : "",
				(data && data->keyprint && *data->keyprint->presented) ? data->keyprint->presented : "no certificate");
			hub->fatal = 1;
			break;

		case ADC_CLIENT_LOGGED_IN:
			seed_hub_on_login(hub);
			break;

		case ADC_CLIENT_LOGIN_ERROR:
			LOG_ERROR("seeder: login to %s rejected: %s", hub->url,
				(data && data->status && data->status->message) ? data->status->message : "unknown reason");
			/* The hub usually closes after a fatal status, but not always;
			   dropping it here means the retry is scheduled exactly once
			   either way. */
			ADC_client_disconnect(client);
			seed_hub_on_disconnect(hub);
			break;

		case ADC_CLIENT_DISCONNECTED:
			LOG_INFO("seeder: disconnected from %s.", hub->url);
			seed_hub_on_disconnect(hub);
			break;

		case ADC_CLIENT_PROTOCOL_STATUS:
			if (data && data->status && data->status->severity > 0)
				LOG_WARN("seeder: hub status %d: %s", data->status->code,
					data->status->message ? data->status->message : "");
			break;

		case ADC_CLIENT_MESSAGE:
			if (data)
				seed_hub_on_chat(hub, data->chat);
			break;

		case ADC_CLIENT_SEARCH_REQ:
			if (data)
				seed_hub_on_search(hub, data->message);
			break;

		case ADC_CLIENT_CONNECT_REQ:
			if (data)
				seed_hub_on_connect_req(hub, data->message);
			break;

		case ADC_CLIENT_REVCONNECT_REQ:
			if (data)
				seed_hub_on_revconnect_req(hub, data->message);
			break;

		case ADC_CLIENT_SEARCH_REP:
		{
			/* Answers to searches this seeder issued, looking for a peer that
			   holds a post document whose author has left the hub. */
			struct seed_result result;

			if (data && hub->cb.on_search_result && seed_hub_parse_result(data->message, &result))
				hub->cb.on_search_result(hub->ptr, &result);
			break;
		}

		case ADC_CLIENT_BBS_BOARD:
		{
			struct seed_bbs_board board;

			if (data && hub->cb.on_bbs_board && seed_hub_parse_bbs_board(data->message, &board))
				hub->cb.on_bbs_board(hub->ptr, &board);
			break;
		}

		case ADC_CLIENT_BBS_ENTRY:
		{
			struct seed_bbs_entry entry;

			if (data && hub->cb.on_bbs_entry && seed_hub_parse_bbs_entry(data->message, &entry))
				hub->cb.on_bbs_entry(hub->ptr, &entry);
			break;
		}

		case ADC_CLIENT_USER_JOIN:
		case ADC_CLIENT_USER_UPDATE:
			if (data)
				seed_hub_on_user(hub, data->user);
			break;

		case ADC_CLIENT_USER_QUIT:
			if (data && data->quit)
				seed_roster_remove(hub->roster, data->quit->sid);
			break;

		case ADC_CLIENT_HUB_INFO:
			if (data && data->hubinfo && data->hubinfo->name)
				LOG_INFO("seeder: hub is \"%s\".", data->hubinfo->name);
			break;

		case ADC_CLIENT_RAW_LINE:
			/* A test hook for observing commands the client does not model.
			   The seeder acts on the parsed events instead. */
			break;
	}

	return 1;
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

static void seed_hub_close_client(struct seed_hub* hub)
{
	if (hub->client)
	{
		ADC_client_destroy(hub->client);
		hub->client = NULL;
	}
	hub->logged_in = 0;
}

/**
 * Start one connection attempt.
 *
 * A fresh ADC_client per attempt rather than reconnecting the old one: the
 * transport keeps per-connection state (the receive queue, the INF it built,
 * the parsed address) that has no reset, and the one place it is safe to throw
 * it away is here -- from the timer, never from inside one of its own
 * callbacks.
 */
static void seed_hub_open(struct seed_hub* hub)
{
	seed_hub_close_client(hub);

	hub->client = ADC_client_create(hub->nick, hub->description, hub);
	if (!hub->client)
	{
		seed_hub_schedule_retry(hub);
		return;
	}

	ADC_client_set_callback(hub->client, seed_hub_client_callback);
	ADC_client_set_pid(hub->client, hub->pid);
	if (*hub->password)
		ADC_client_set_password(hub->client, hub->password);

	/* Re-applied per attempt: seed_hub_open() builds a fresh ADC_client every
	   time, and one that forgot its SU would come back as a passive seeder. */
	ADC_client_set_support(hub->client, hub->support);

	/*
	 * Offering BBS0 in the HSUP is what makes the hub send board descriptors:
	 * a session that did not offer it receives none. It is offered only when
	 * the operator wants boards seeded, because a client must not claim an
	 * extension it will not act on -- and because asking for descriptors the
	 * daemon would then ignore is work for the hub and noise on the wire.
	 */
	if (hub->bbs)
		ADC_client_add_support(hub->client, "AD" ADC_EXT_BBS0);

	/* Cached now so seed_hub_own_cid() answers even between connections. */
	memset(hub->cid, 0, sizeof(hub->cid));
	strncpy(hub->cid, ADC_client_get_cid(hub->client), sizeof(hub->cid) - 1);

	if (!ADC_client_connect(hub->client, hub->url))
	{
		LOG_WARN("seeder: unable to connect to %s.", hub->url);
		seed_hub_schedule_retry(hub);
	}
}

struct seed_hub* seed_hub_create(const struct seed_config* config, const struct seed_hub_callbacks* cb, void* ptr)
{
	struct seed_hub* hub;

	if (!config || !config->seed_hub_url || !*config->seed_hub_url)
		return NULL;

	hub = (struct seed_hub*) hub_malloc_zero(sizeof(struct seed_hub));
	if (!hub)
		return NULL;

	hub->url         = hub_strdup(config->seed_hub_url);
	hub->nick        = hub_strdup(config->seed_nick ? config->seed_nick : "");
	hub->password    = hub_strdup(config->seed_password ? config->seed_password : "");
	hub->description = hub_strdup(config->seed_description ? config->seed_description : "");
	hub->cache_dir   = hub_strdup(config->seed_cache_dir ? config->seed_cache_dir : "");
	hub->bbs         = config->seed_bbs_enable ? 1 : 0;

	if (cb)
		hub->cb = *cb;
	hub->ptr = ptr;

	hub->roster = seed_roster_create();
	hub->timer = (struct timeout_evt*) hub_malloc_zero(sizeof(struct timeout_evt));

	if (!hub->url || !hub->nick || !hub->password || !hub->description || !hub->cache_dir
		|| !hub->roster || !hub->timer)
	{
		seed_hub_destroy(hub);
		return NULL;
	}

	timeout_evt_initialize(hub->timer, seed_hub_timer_cb, hub);

	/* Worked out once, at create time: the CID it yields is the seeder's name
	   as far as every client on the hub is concerned, so it must not vary
	   between reconnects. */
	if (!seed_hub_pid_load(hub->cache_dir, hub->pid))
	{
		LOG_WARN("seeder: unable to establish a stable identity in %s; using a random one for this run.",
			hub->cache_dir);
		hub->pid[0] = '\0';
	}

	return hub;
}

void seed_hub_destroy(struct seed_hub* hub)
{
	if (!hub)
		return;

	hub->started = 0;
	seed_hub_cancel_timer(hub);
	seed_hub_close_client(hub);
	seed_roster_destroy(hub->roster);

	hub_free(hub->timer);
	hub_free(hub->url);
	hub_free(hub->nick);
	hub_free(hub->password);
	hub_free(hub->description);
	hub_free(hub->cache_dir);
	hub_free(hub);
}

/* The seeder names its own limit so that main.c need not know the transport's,
   but a list that fits here and not there would be silently refused. */
_Static_assert(SEED_SUPPORT_MAX <= ADC_SUPPORT_MAX,
	"SEED_SUPPORT_MAX must fit what ADC_client_set_support() accepts");

int seed_hub_set_support(struct seed_hub* hub, const char* su)
{
	if (!hub)
		return 0;

	if (!su || !*su)
	{
		hub->support[0] = '\0';
		return 1;
	}

	if (strlen(su) >= sizeof(hub->support))
		return 0;

	strcpy(hub->support, su);

	/* An already-open connection keeps the SU it logged in with; the value
	   here is what the next INF carries. */
	return 1;
}

int seed_hub_start(struct seed_hub* hub)
{
	if (!hub || !hub->url || !*hub->url || !hub->nick || !*hub->nick)
		return 0;

	if (hub->started)
		return 1;

	hub->started = 1;
	hub->backoff = 0;

	/* An explicit start is an operator saying "try again", so whatever made the
	   last run give up is not held against this one. */
	hub->fatal = 0;

	seed_hub_open(hub);
	return 1;
}

void seed_hub_stop(struct seed_hub* hub)
{
	if (!hub)
		return;

	hub->started = 0;
	seed_hub_cancel_timer(hub);
	seed_hub_close_client(hub);
	hub->announced = 0;
	seed_roster_clear(hub->roster);
}

int seed_hub_is_logged_in(struct seed_hub* hub)
{
	return (hub && hub->logged_in) ? 1 : 0;
}

sid_t seed_hub_own_sid(struct seed_hub* hub)
{
	if (!hub || !hub->client)
		return 0;
	return ADC_client_get_sid(hub->client);
}

const char* seed_hub_own_cid(struct seed_hub* hub)
{
	return hub ? hub->cid : "";
}

const struct seed_user* seed_hub_user_by_sid(struct seed_hub* hub, sid_t sid)
{
	return hub ? seed_roster_get_sid(hub->roster, sid) : NULL;
}

const struct seed_user* seed_hub_user_by_cid(struct seed_hub* hub, const char* cid)
{
	return hub ? seed_roster_get_cid(hub->roster, cid) : NULL;
}

size_t seed_hub_user_count(struct seed_hub* hub)
{
	return hub ? seed_roster_size(hub->roster) : 0;
}
