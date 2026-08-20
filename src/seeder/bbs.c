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

#include "adc/adcconst.h"
#include "seeder/bbs.h"
#include "seeder/cache.h"
#include "seeder/cc.h"
#include "seeder/config.h"
#include "seeder/embed.h"
#include "seeder/hubconn.h"
#include "seeder/post.h"
#include "util/log.h"
#include "util/memory.h"

/** Name of the cursor file inside the cache directory. */
#define SEED_BBS_CURSOR_FILE "bbs-cursors"

/**
 * How much of a post document is read back to look for attachments.
 *
 * The header is bounded by BBS0 and the scan is bounded by post.h, so this is
 * simply the sum: reading further could not change the answer.
 */
#define SEED_BBS_READ_MAX (SEED_POST_HEADER_MAX + SEED_POST_SCAN_MAX)

/** What a queue entry is for. */
enum bbs_work
{
	BBS_WORK_POST,       /** Fetch a post document. */
	BBS_WORK_ATTACHMENT, /** Fetch something a post's body links to. */
	BBS_WORK_SCAN        /** A document already held: look at what it links to. */
};

/** Where a queue entry is in its life. */
enum bbs_state
{
	BBS_IDLE,      /** Waiting for its due time. */
	BBS_ASKED,     /** A peer has been asked and has not yet delivered. */
	BBS_SEARCHING  /** A search is out, waiting for a result to name a source. */
};

struct bbs_want
{
	int used;
	enum bbs_work work;
	enum bbs_state state;

	char tth[SEED_TTH_STR_LEN + 1];
	char board[SEED_BBS_BOARD_MAX + 1];
	char name[SEED_EMBED_MAX_NAME];

	/** The CID the hub said it accepted the post from; the first source tried. */
	char author_cid[MAX_CID_LEN + 1];

	uint64_t size;          /** Declared size, 0 when unknown. Never trusted as a bound. */
	time_t   due;           /** Not before this. */
	time_t   asked;         /** When the current attempt started. */
	unsigned int attempts;  /** Attempts already spent. */
	int      author_tried;  /** The author has had its turn; go to a search next. */
};

struct bbs_board
{
	int used;
	char board[SEED_BBS_BOARD_MAX + 1];
	unsigned int permissions;
	uint64_t max_size;
	uint64_t oldest;        /** OT: the earliest the hub will replay. */
	uint64_t cursor;        /** Highest TS seen. What a resume asks for. */
	int subscribed;         /** A subscription is live on this connection. */
	int gap;                /** The cursor fell behind OT; history is unreachable. */
	size_t taken;           /** Entries accepted from this board this session. */
};

struct seed_bbs
{
	struct seed_cache* cache;
	const struct seed_cc_policy* cc;
	struct seed_hub* hub;
	const struct seed_config* config;

	int enabled;
	int attachments;
	int search_fallback;
	uint64_t max_size;      /** seed_max_file_size, in bytes. */
	size_t max_backlog;
	int fetch_delay;

	struct bbs_board boards[SEED_BBS_MAX_BOARDS];
	struct bbs_want wants[SEED_BBS_MAX_WANTS];

	size_t inflight;
	unsigned int token_seq;

	struct seed_bbs_stats stats;

	char* cursor_path;
	int cursors_dirty;
};

/* -------------------------------------------------------------- pure policy */

int seed_bbs_board_allowed(const char* board, const char* allowed)
{
	const char* p;
	size_t len;

	if (!board || !*board)
		return 0;

	/* No list means no restriction: the hub only sends a descriptor for a board
	   this session may read, so being told about one is permission enough. */
	if (!allowed || !*allowed)
		return 1;

	len = strlen(board);
	p = allowed;
	while (*p)
	{
		const char* end;
		size_t span;

		while (*p == ' ' || *p == '\t' || *p == ',')
			p++;
		if (!*p)
			break;

		end = strchr(p, ',');
		span = end ? (size_t) (end - p) : strlen(p);

		/* Trailing blanks inside an item are not part of the name. */
		while (span > 0 && (p[span - 1] == ' ' || p[span - 1] == '\t'))
			span--;

		/* Board names are case sensitive, so this comparison is too. */
		if (span == len && memcmp(p, board, len) == 0)
			return 1;

		if (!end)
			break;
		p = end + 1;
	}

	return 0;
}

unsigned int seed_bbs_retry_delay(unsigned int attempts)
{
	unsigned int delay = SEED_BBS_RETRY_MIN;
	unsigned int i;

	for (i = 1; i < attempts; i++)
	{
		if (delay >= SEED_BBS_RETRY_MAX / 2)
			return SEED_BBS_RETRY_MAX;
		delay *= 2;
	}

	return delay;
}

/* ------------------------------------------------------------ the want queue */

static struct bbs_want* bbs_find_want(struct seed_bbs* bbs, const char* tth)
{
	size_t i;

	for (i = 0; i < SEED_BBS_MAX_WANTS; i++)
	{
		if (bbs->wants[i].used && strcmp(bbs->wants[i].tth, tth) == 0)
			return &bbs->wants[i];
	}
	return NULL;
}

static void bbs_release_want(struct seed_bbs* bbs, struct bbs_want* want)
{
	if (want->state != BBS_IDLE && bbs->inflight > 0)
		bbs->inflight--;

	memset(want, 0, sizeof(*want));
}

/*
 * Queue a piece of work, unless it is already queued or already unnecessary.
 *
 * @return 1 if it was queued.
 */
static int bbs_enqueue(struct seed_bbs* bbs, enum bbs_work work, const char* tth,
	const char* board, const char* author_cid, uint64_t size, const char* name, time_t now)
{
	struct bbs_want* slot = NULL;
	size_t i;

	if (!bbs->enabled)
		return 0;

	/* Already on the list: one hash is one piece of work, however many entries
	   or bodies happen to name it. */
	if (bbs_find_want(bbs, tth))
		return 0;

	if (seed_cache_is_blocked(bbs->cache, tth))
		return 0;

	/*
	 * Peeking rather than looking up: asking whether the cache holds something
	 * must not count as an access, or a replay of a board would keep every post
	 * it mentions at the head of the eviction list.
	 */
	if (seed_cache_peek(bbs->cache, tth, NULL))
	{
		/* Held already. Nothing to fetch -- but a document whose attachments
		   were never fetched, or were fetched and later evicted, is worth
		   another look, and that is what a scan is. */
		if (work == BBS_WORK_POST && bbs->attachments)
			work = BBS_WORK_SCAN;
		else
			return 0;
	}

	/*
	 * The declared size is the author's claim and the hub's copy of it, and it
	 * bounds nothing by itself -- the transfer is capped independently. It is
	 * still worth refusing here: asking for a document that could not be stored
	 * if it arrived spends a peer's bandwidth to no purpose.
	 */
	if (work != BBS_WORK_SCAN && bbs->max_size && size > bbs->max_size)
	{
		LOG_DEBUG("seed_bbs: not asking for TTH=%s, declared %" PRIu64 " bytes exceeds the per file limit",
			tth, size);
		return 0;
	}

	for (i = 0; i < SEED_BBS_MAX_WANTS; i++)
	{
		if (!bbs->wants[i].used)
		{
			slot = &bbs->wants[i];
			break;
		}
	}

	if (!slot)
	{
		/*
		 * Said out loud, and counted. A silently truncated queue reads as "the
		 * board is fully seeded" when it is not, and the next replay from the
		 * board's start is what recovers the difference.
		 */
		bbs->stats.dropped++;
		LOG_WARN("seed_bbs: work queue full (%d); not queueing TTH=%s. It will be picked up on the next full replay.",
			SEED_BBS_MAX_WANTS, tth);
		return 0;
	}

	memset(slot, 0, sizeof(*slot));
	slot->used = 1;
	slot->work = work;
	slot->state = BBS_IDLE;
	slot->size = size;

	strncpy(slot->tth, tth, sizeof(slot->tth) - 1);
	if (board)
		strncpy(slot->board, board, sizeof(slot->board) - 1);
	if (author_cid)
		strncpy(slot->author_cid, author_cid, sizeof(slot->author_cid) - 1);
	if (name)
		strncpy(slot->name, name, sizeof(slot->name) - 1);

	/*
	 * Deferred rather than immediate. BBS0 asks a client not to fetch at the
	 * moment an entry arrives, and while the census argument does not apply to
	 * a daemon that fetches everything, the pacing does: a burst of entries
	 * becomes a queue to work through instead of a thundering herd of connect
	 * requests aimed at whoever just posted.
	 */
	slot->due = now + bbs->fetch_delay;

	/* A scan needs no peer and no delay; it is a local read. */
	if (work == BBS_WORK_SCAN)
		slot->due = now;

	return 1;
}

/* ------------------------------------------------------------------- cursors */

/*
 * The resume cursors, one line of "<board> <timestamp>".
 *
 * A plain file rather than a table in the cache database: it is a handful of
 * integers, it is rewritten whole, and keeping it out of the database means the
 * cache schema does not have to know that boards exist. It sits beside the PID
 * file, which is there for the same kind of reason.
 */
static void bbs_cursors_load(struct seed_bbs* bbs)
{
	FILE* f;
	char line[SEED_BBS_BOARD_MAX + 64];

	if (!bbs->cursor_path)
		return;

	f = fopen(bbs->cursor_path, "r");
	if (!f)
		return;

	while (fgets(line, sizeof(line), f))
	{
		char board[SEED_BBS_BOARD_MAX + 1];
		char* sep;
		uint64_t ts = 0;
		size_t i;

		sep = strchr(line, '\n');
		if (sep)
			*sep = '\0';

		sep = strchr(line, ' ');
		if (!sep)
			continue;
		*sep = '\0';

		/* The name comes off disk, but it was a hub's text before that, so it
		   is validated exactly as if it had just arrived. */
		if (!seed_hub_bbs_board_valid(line) || strlen(line) > SEED_BBS_BOARD_MAX)
			continue;

		/* A cursor for a board the operator has since excluded is dead weight,
		   and the table is small enough that keeping it could crowd out a board
		   that is wanted. */
		if (!seed_bbs_board_allowed(line, bbs->config->seed_bbs_boards))
			continue;

		strcpy(board, line);

		if (!*(sep + 1))
			continue;
		for (i = 0; sep[1 + i]; i++)
		{
			if (sep[1 + i] < '0' || sep[1 + i] > '9')
			{
				ts = 0;
				break;
			}
			if (ts > (UINT64_MAX - (uint64_t) (sep[1 + i] - '0')) / 10)
			{
				ts = 0;
				break;
			}
			ts = ts * 10 + (uint64_t) (sep[1 + i] - '0');
		}

		for (i = 0; i < SEED_BBS_MAX_BOARDS; i++)
		{
			if (!bbs->boards[i].used)
			{
				bbs->boards[i].used = 1;
				strcpy(bbs->boards[i].board, board);
				bbs->boards[i].cursor = ts;
				break;
			}
		}
	}

	fclose(f);
}

static void bbs_cursors_save(struct seed_bbs* bbs)
{
	char* tmp;
	size_t len;
	FILE* f;
	size_t i;

	if (!bbs->cursor_path || !bbs->cursors_dirty)
		return;

	/* Written to one side and renamed into place, so an interrupted write
	   cannot leave a half-written cursor file behind: half a cursor is a board
	   replayed from the wrong point. */
	len = strlen(bbs->cursor_path) + 5;
	tmp = hub_malloc(len);
	if (!tmp)
		return;
	snprintf(tmp, len, "%s.tmp", bbs->cursor_path);

	f = fopen(tmp, "w");
	if (!f)
	{
		LOG_DEBUG("seed_bbs: cannot write %s", tmp);
		hub_free(tmp);
		return;
	}

	for (i = 0; i < SEED_BBS_MAX_BOARDS; i++)
	{
		if (bbs->boards[i].used)
			fprintf(f, "%s %" PRIu64 "\n", bbs->boards[i].board, bbs->boards[i].cursor);
	}

	if (fclose(f) != 0 || rename(tmp, bbs->cursor_path) != 0)
		LOG_DEBUG("seed_bbs: cannot save cursors to %s", bbs->cursor_path);
	else
		bbs->cursors_dirty = 0;

	hub_free(tmp);
}

/* -------------------------------------------------------------------- boards */

static struct bbs_board* bbs_find_board(struct seed_bbs* bbs, const char* name)
{
	size_t i;

	for (i = 0; i < SEED_BBS_MAX_BOARDS; i++)
	{
		if (bbs->boards[i].used && strcmp(bbs->boards[i].board, name) == 0)
			return &bbs->boards[i];
	}
	return NULL;
}

static struct bbs_board* bbs_add_board(struct seed_bbs* bbs, const char* name)
{
	size_t i;

	for (i = 0; i < SEED_BBS_MAX_BOARDS; i++)
	{
		if (!bbs->boards[i].used)
		{
			memset(&bbs->boards[i], 0, sizeof(bbs->boards[i]));
			bbs->boards[i].used = 1;
			strncpy(bbs->boards[i].board, name, SEED_BBS_BOARD_MAX);
			return &bbs->boards[i];
		}
	}

	LOG_WARN("seed_bbs: already tracking %d boards; ignoring \"%s\".", SEED_BBS_MAX_BOARDS, name);
	return NULL;
}

static void bbs_subscribe(struct seed_bbs* bbs, struct bbs_board* board)
{
	uint64_t from = board->cursor;

	if (board->subscribed || !seed_hub_bbs_available(bbs->hub))
		return;

	/*
	 * A hub may refuse to replay from before OT, and says so in advance. Where
	 * the stored cursor is older, the board has a stretch of history that
	 * cannot be recovered from this hub: BBS0 requires treating that as a gap
	 * rather than as a complete view, and there is nothing to be done about it
	 * except say so.
	 */
	if (board->oldest > from)
	{
		if (!board->gap)
		{
			LOG_WARN("seed_bbs: board \"%s\" only replays from %" PRIu64 " and the cursor is %" PRIu64
				"; posts in between cannot be fetched from this hub.",
				board->board, board->oldest, from);
		}
		board->gap = 1;
		bbs->stats.gap = 1;
		from = board->oldest;
	}

	/*
	 * Resumed from the highest timestamp seen and deliberately not from one
	 * past it. Timestamps are not unique, so a cursor advanced past the last
	 * entry received would skip a post accepted in the same second. The cost is
	 * that the final second arrives again, which costs nothing: an entry for a
	 * hash already held is not work.
	 */
	if (!seed_hub_send_bbs_subscribe(bbs->hub, board->board, from))
		return;

	board->subscribed = 1;
	board->taken = 0;
	LOG_INFO("seed_bbs: subscribed to board \"%s\" from timestamp %" PRIu64 ".", board->board, from);
}

void seed_bbs_on_board(struct seed_bbs* bbs, const struct seed_bbs_board* desc)
{
	struct bbs_board* board;

	if (!bbs || !bbs->enabled || !desc)
		return;

	board = bbs_find_board(bbs, desc->board);

	if (desc->removed)
	{
		/* The board is gone. The subscription went with it, and the cursor is
		   worth nothing now, but cached documents are named by hash and were
		   verified against it -- they are not the board's to take away. */
		if (board)
		{
			LOG_INFO("seed_bbs: board \"%s\" no longer exists.", board->board);
			memset(board, 0, sizeof(*board));
			bbs->cursors_dirty = 1;
		}
		return;
	}

	if (!seed_bbs_board_allowed(desc->board, bbs->config->seed_bbs_boards))
	{
		LOG_DEBUG("seed_bbs: board \"%s\" is not in seed_bbs_boards; ignoring.", desc->board);
		return;
	}

	/*
	 * A hub is not supposed to describe a board this session cannot subscribe
	 * to -- withholding the descriptor is the whole mechanism for hiding one --
	 * but a descriptor arriving without that permission is a plain statement
	 * that subscribing would be refused, so it is taken at its word.
	 */
	if (!(desc->permissions & ADC_BBS_PERM_SUBSCRIBE))
	{
		if (board && board->subscribed)
		{
			LOG_INFO("seed_bbs: no longer permitted to read board \"%s\".", board->board);
			board->subscribed = 0;
		}
		return;
	}

	if (!board)
	{
		board = bbs_add_board(bbs, desc->board);
		if (!board)
			return;
		bbs->cursors_dirty = 1;
	}

	board->permissions = desc->permissions;
	board->max_size = desc->max_size;
	board->oldest = desc->oldest;

	bbs_subscribe(bbs, board);
}

/* ------------------------------------------------------------------- entries */

void seed_bbs_on_entry(struct seed_bbs* bbs, const struct seed_bbs_entry* entry)
{
	struct bbs_board* board;
	time_t now;

	if (!bbs || !bbs->enabled || !entry)
		return;

	board = bbs_find_board(bbs, entry->board);
	if (!board)
	{
		/* An entry for a board that was never described, or one the operator
		   excluded. Nothing here knows what to do with it. */
		return;
	}

	/*
	 * The cursor only ever moves forward. Nothing enters a BBS0 index in the
	 * past, so a lower timestamp is a duplicate from the resumption window or a
	 * hub misbehaving, and in neither case is it a reason to rewind.
	 */
	if (entry->timestamp > board->cursor)
	{
		board->cursor = entry->timestamp;
		bbs->cursors_dirty = 1;
	}

	now = time(NULL);

	if (entry->removed)
	{
		/*
		 * A tombstone. BBS0 is explicit that this is a request and not a
		 * deletion -- every client that read the post may still hold it -- but
		 * the seeder is a cache and honouring it is what a cache should do.
		 * Replies are separate posts and are not touched.
		 */
		struct bbs_want* want = bbs_find_want(bbs, entry->tth);

		if (want)
			bbs_release_want(bbs, want);

		if (seed_cache_peek(bbs->cache, entry->tth, NULL))
		{
			seed_cache_remove(bbs->cache, entry->tth, "withdrawn from a bulletin board");
			bbs->stats.withdrawn++;
			LOG_INFO("seed_bbs: post TTH=%s withdrawn from board \"%s\"; cached copy deleted.",
				entry->tth, entry->board);
		}
		return;
	}

	/*
	 * A ceiling on how much of one board's history is taken on in a session.
	 * A first run against a board with years of posts would otherwise try to
	 * fetch all of it at once; what is not taken now is taken on the next
	 * resume, because the cursor advances either way.
	 */
	if (bbs->max_backlog && board->taken >= bbs->max_backlog)
	{
		if (board->taken == bbs->max_backlog)
		{
			LOG_INFO("seed_bbs: reached seed_bbs_max_backlog (%lu) on board \"%s\"; "
				"the rest of the backlog waits for the next resume.",
				(unsigned long) bbs->max_backlog, board->board);
			board->taken++;
		}
		return;
	}
	board->taken++;

	bbs_enqueue(bbs, BBS_WORK_POST, entry->tth, entry->board, entry->author_cid,
		entry->size, entry->subject, now);
}

/* ---------------------------------------------------------------- retrieval */

/*
 * Ask one peer, named by CID, to hand over a hash.
 *
 * The seeder sends a connect request of its own rather than dialling out: an
 * address a client supplied is an address it chose, and a CTM works whether the
 * peer is active or passive. This is the same path a chat attachment takes.
 *
 * @return 1 if a request went out.
 */
static int bbs_ask_peer(struct seed_bbs* bbs, struct bbs_want* want, const struct seed_user* peer)
{
	char token[SEED_TOKEN_MAX + 1];
	const char* protocol;
	uint16_t port = (uint16_t) bbs->config->seed_client_port;

	if (!peer)
		return 0;

	/* The grant is the only thing that will authorise the connection when it
	   arrives; if the peer never turns up it expires and nothing is cached. */
	if (!seed_cc_request_token(bbs->cc, peer->cid, want->tth, want->size,
		*want->name ? want->name : NULL, token))
	{
		return 0;
	}

	protocol = seed_cc_protocol_for_peer(bbs->cc, peer->support, NULL);

	if (!seed_hub_send_ctm(bbs->hub, peer->sid, protocol, port, token))
		return 0;

	LOG_INFO("seed_bbs: asked %s for TTH=%s (%s)", peer->nick, want->tth, protocol);
	return 1;
}

/* Put a want back to sleep until its next attempt is due. */
static void bbs_defer(struct seed_bbs* bbs, struct bbs_want* want, time_t now)
{
	if (want->state != BBS_IDLE && bbs->inflight > 0)
		bbs->inflight--;

	want->state = BBS_IDLE;
	want->asked = 0;
	want->attempts++;

	if (want->attempts >= SEED_BBS_MAX_ATTEMPTS)
	{
		if (want->work == BBS_WORK_POST)
		{
			bbs->stats.posts_failed++;
			LOG_INFO("seed_bbs: giving up on post TTH=%s after %u attempts; no source answered.",
				want->tth, want->attempts);
		}
		else
		{
			LOG_DEBUG("seed_bbs: giving up on TTH=%s after %u attempts.", want->tth, want->attempts);
		}
		bbs_release_want(bbs, want);
		return;
	}

	want->due = now + (time_t) seed_bbs_retry_delay(want->attempts);

	/* The author had its turn. Every later attempt goes looking instead: if the
	   author were reachable the first attempt would have worked. */
	want->author_tried = 1;
}

/*
 * Read a document back out of the cache and queue whatever its body links to.
 *
 * The document has already been verified against its hash by the ingest path --
 * that is what a content-addressed cache guarantees -- so what is parsed here
 * is known to be the bytes that were asked for. The header is still parsed
 * strictly: a document that hashes correctly can still be malformed, and one
 * that is malformed is not a post.
 */
static void bbs_scan_document(struct seed_bbs* bbs, const char* tth, const char* board, time_t now)
{
	struct seed_entry entry;
	struct seed_post post;
	struct seed_embed attachments[SEED_POST_MAX_ATTACHMENTS];
	enum seed_post_error error = SEED_POST_OK;
	unsigned char* buf;
	size_t want_bytes;
	size_t have = 0;
	size_t count;
	size_t i;
	int fd;

	if (!bbs->attachments)
		return;

	if (!seed_cache_peek(bbs->cache, tth, &entry))
		return;

	/* A pin, so the file cannot be evicted out from under the read. */
	if (!seed_cache_pin(bbs->cache, tth))
		return;

	fd = seed_cache_open_file(bbs->cache, tth);
	if (fd < 0)
	{
		seed_cache_unpin(bbs->cache, tth);
		return;
	}

	want_bytes = (entry.size < SEED_BBS_READ_MAX) ? (size_t) entry.size : SEED_BBS_READ_MAX;
	buf = (unsigned char*) hub_malloc(want_bytes ? want_bytes : 1);
	if (!buf)
	{
		close(fd);
		seed_cache_unpin(bbs->cache, tth);
		return;
	}

	while (have < want_bytes)
	{
		ssize_t got = seed_cache_read(bbs->cache, fd, entry.size, (uint64_t) have,
			buf + have, want_bytes - have);

		if (got <= 0)
			break;
		have += (size_t) got;
	}

	close(fd);
	seed_cache_unpin(bbs->cache, tth);

	if (!seed_post_parse(buf, have, &post, &error))
	{
		/*
		 * Cached, correctly hashed, and not a post. Worth a line rather than
		 * silence: it means the board is carrying a document that no conforming
		 * client will display, and the seeder is now holding it.
		 */
		LOG_WARN("seed_bbs: TTH=%s is not a valid post document (%s).",
			tth, seed_post_error_string(error));
		hub_free(buf);
		return;
	}

	count = seed_post_attachments(buf, have, &post, attachments, SEED_POST_MAX_ATTACHMENTS);
	hub_free(buf);

	for (i = 0; i < count; i++)
	{
		/*
		 * The author of the attachment is the author of the post as far as
		 * anything here can tell, so that CID is the first source tried. It is
		 * a guess and not an assertion: whoever answers a search for the hash
		 * is just as good, and that is where this ends up if the author is
		 * gone.
		 */
		if (bbs_enqueue(bbs, BBS_WORK_ATTACHMENT, attachments[i].tth, board,
			post.author_cid, attachments[i].size, attachments[i].name, now))
		{
			LOG_DEBUG("seed_bbs: post TTH=%s links to attachment TTH=%s", tth, attachments[i].tth);
		}
	}
}

/* Start one attempt on a want. @return 1 when something went out. */
static int bbs_start(struct seed_bbs* bbs, struct bbs_want* want, time_t now)
{
	const struct seed_user* peer;

	/* A scan is local work and needs no peer at all. */
	if (want->work == BBS_WORK_SCAN)
	{
		bbs_scan_document(bbs, want->tth, want->board, now);
		bbs_release_want(bbs, want);
		return 1;
	}

	/*
	 * The author first, while they are still here. They are the one party
	 * certain to hold the bytes -- BBS0 requires a client to be able to serve a
	 * post before it submits it -- so this is the attempt most likely to work
	 * and the cheapest: no search, one connect request.
	 */
	if (!want->author_tried && *want->author_cid)
	{
		want->author_tried = 1;
		peer = seed_hub_user_by_cid(bbs->hub, want->author_cid);

		if (peer && !seed_user_is_bot(peer) && bbs_ask_peer(bbs, want, peer))
		{
			want->state = BBS_ASKED;
			want->asked = now;
			bbs->inflight++;
			return 1;
		}
	}

	/*
	 * Nobody named, or the author has gone. A search is the only way left to
	 * find a copy, and finding one is the whole reason a board needs a seeder:
	 * a post whose author left and whose readers logged off is an index entry
	 * with nothing behind it.
	 */
	if (bbs->search_fallback)
	{
		char token[SEED_TOKEN_MAX + 1];

		snprintf(token, sizeof(token), "bbs%u", ++bbs->token_seq);

		if (seed_hub_send_search_tth(bbs->hub, want->tth, token))
		{
			want->state = BBS_SEARCHING;
			want->asked = now;
			bbs->inflight++;
			LOG_DEBUG("seed_bbs: searching the hub for TTH=%s", want->tth);
			return 1;
		}
	}

	bbs_defer(bbs, want, now);
	return 0;
}

void seed_bbs_on_search_result(struct seed_bbs* bbs, const struct seed_result* result)
{
	struct bbs_want* want;
	const struct seed_user* peer;
	time_t now;

	if (!bbs || !bbs->enabled || !result)
		return;

	want = bbs_find_want(bbs, result->tth);

	/* Only a result answering a search this engine has out. The seeder also
	   answers searches, and other clients' results are none of its business. */
	if (!want || want->state != BBS_SEARCHING)
		return;

	peer = seed_hub_user_by_sid(bbs->hub, result->from);
	if (!peer || seed_user_is_bot(peer))
		return;

	now = time(NULL);

	/* The responder's own declared size is better than nothing where the index
	   entry carried none, and no worse where it did: neither bounds anything. */
	if (!want->size && result->size)
		want->size = result->size;

	if (bbs_ask_peer(bbs, want, peer))
	{
		want->state = BBS_ASKED;
		want->asked = now;
		/* Still one request in flight -- the search became the ask. */
	}
}

void seed_bbs_on_download(struct seed_bbs* bbs, const char* tth, enum seed_error err,
	const struct seed_entry* entry)
{
	struct bbs_want* want;
	enum bbs_work work;
	char board[SEED_BBS_BOARD_MAX + 1];
	time_t now;

	if (!bbs || !bbs->enabled || !tth)
		return;

	want = bbs_find_want(bbs, tth);
	if (!want)
		return; /* not ours: a chat attachment, most likely */

	work = want->work;
	strcpy(board, want->board);
	now = time(NULL);

	if (err != SEED_OK)
	{
		LOG_DEBUG("seed_bbs: transfer of TTH=%s failed (%s); will retry.", tth, seed_error_string(err));
		bbs_defer(bbs, want, now);
		return;
	}

	bbs_release_want(bbs, want);

	if (work == BBS_WORK_ATTACHMENT)
	{
		bbs->stats.attachments++;
		LOG_INFO("seed_bbs: cached attachment TTH=%s (%" PRIu64 " bytes)",
			tth, entry ? entry->size : 0);
		return;
	}

	bbs->stats.posts_fetched++;
	LOG_INFO("seed_bbs: cached post TTH=%s from board \"%s\" (%" PRIu64 " bytes)",
		tth, *board ? board : "-", entry ? entry->size : 0);

	/* Now that the bytes are here, find out what the post points at. */
	bbs_scan_document(bbs, tth, board, now);
}

/* ---------------------------------------------------------------------- tick */

void seed_bbs_tick(struct seed_bbs* bbs, time_t now)
{
	size_t i;
	size_t scans;

	if (!bbs || !bbs->enabled)
		return;

	/* Time out attempts first, so the slots they hold are available below. */
	for (i = 0; i < SEED_BBS_MAX_WANTS; i++)
	{
		struct bbs_want* want = &bbs->wants[i];

		if (!want->used || want->state == BBS_IDLE)
			continue;

		if (now - want->asked >= SEED_BBS_ASK_TIMEOUT)
		{
			LOG_DEBUG("seed_bbs: no answer for TTH=%s within %d seconds.",
				want->tth, SEED_BBS_ASK_TIMEOUT);
			bbs_defer(bbs, want, now);
		}
	}

	/*
	 * A subscription lives on a connection, so a board that lost one gets it
	 * back here rather than waiting for the hub to describe it again -- a hub
	 * only has to send descriptors at login, and a subscription cancelled
	 * mid-session would otherwise never come back.
	 */
	if (seed_hub_is_logged_in(bbs->hub) && seed_hub_bbs_available(bbs->hub))
	{
		for (i = 0; i < SEED_BBS_MAX_BOARDS; i++)
		{
			if (bbs->boards[i].used && !bbs->boards[i].subscribed &&
				(bbs->boards[i].permissions & ADC_BBS_PERM_SUBSCRIBE))
			{
				bbs_subscribe(bbs, &bbs->boards[i]);
			}
		}
	}

	scans = 0;
	for (i = 0; i < SEED_BBS_MAX_WANTS; i++)
	{
		struct bbs_want* want = &bbs->wants[i];

		if (!want->used || want->state != BBS_IDLE || want->due > now)
			continue;

		if (want->work == BBS_WORK_SCAN)
		{
			/*
			 * A scan is local work -- a file read and a parse -- so it needs no
			 * connection, but it also occupies no inflight slot and would
			 * therefore be paced by nothing. A replay of a board the cache
			 * already holds is entirely scans, so without a cap one tick would
			 * read every document on the board before returning to the loop.
			 */
			if (scans >= SEED_BBS_MAX_SCANS_PER_TICK)
				continue;
			scans++;
		}
		else
		{
			/* Nothing can be asked for without a connection to ask over. */
			if (bbs->inflight >= SEED_BBS_MAX_INFLIGHT)
				continue;
			if (!seed_hub_is_logged_in(bbs->hub))
				continue;
		}

		bbs_start(bbs, want, now);
	}

	bbs_cursors_save(bbs);
}

/* --------------------------------------------------------------- connection */

void seed_bbs_on_logged_in(struct seed_bbs* bbs)
{
	size_t i;

	if (!bbs || !bbs->enabled)
		return;

	/*
	 * Subscriptions do not survive a connection, and neither does the hub's
	 * feature announcement. Everything is marked unsubscribed and is
	 * re-established from the descriptors this session sends; the cursors are
	 * untouched, which is what makes a reconnect cheap.
	 */
	for (i = 0; i < SEED_BBS_MAX_BOARDS; i++)
		bbs->boards[i].subscribed = 0;

	if (!seed_hub_bbs_available(bbs->hub))
	{
		LOG_DEBUG("seed_bbs: the hub does not announce %s; boards will not be seeded.", ADC_EXT_BBS0);
		return;
	}

	LOG_INFO("seed_bbs: the hub announces %s; waiting for board descriptors.", ADC_EXT_BBS0);
}

void seed_bbs_on_disconnected(struct seed_bbs* bbs)
{
	size_t i;

	if (!bbs || !bbs->enabled)
		return;

	for (i = 0; i < SEED_BBS_MAX_BOARDS; i++)
		bbs->boards[i].subscribed = 0;

	/*
	 * Every request in flight was aimed at a peer over a hub that is now gone,
	 * so none of them can complete. They go back to waiting rather than being
	 * dropped: the entries are known, and the next connection can try again.
	 */
	for (i = 0; i < SEED_BBS_MAX_WANTS; i++)
	{
		struct bbs_want* want = &bbs->wants[i];

		if (want->used && want->state != BBS_IDLE)
		{
			want->state = BBS_IDLE;
			want->asked = 0;
		}
	}

	/* Set rather than decremented per want: nothing is in flight once the
	   connection every request depended on has gone. */
	bbs->inflight = 0;
	bbs_cursors_save(bbs);
}

/* ------------------------------------------------------------- construction */

struct seed_bbs* seed_bbs_create(struct seed_cache* cache, const struct seed_cc_policy* cc,
	struct seed_hub* hub, const struct seed_config* config)
{
	struct seed_bbs* bbs;

	if (!cache || !cc || !hub || !config)
		return NULL;

	bbs = (struct seed_bbs*) hub_malloc_zero(sizeof(struct seed_bbs));
	if (!bbs)
		return NULL;

	bbs->cache = cache;
	bbs->cc = cc;
	bbs->hub = hub;
	bbs->config = config;

	bbs->enabled = config->seed_bbs_enable ? 1 : 0;
	bbs->attachments = config->seed_bbs_attachments ? 1 : 0;
	bbs->search_fallback = config->seed_bbs_search_fallback ? 1 : 0;
	bbs->max_backlog = (size_t) config->seed_bbs_max_backlog;
	bbs->fetch_delay = config->seed_bbs_fetch_delay;
	bbs->max_size = (uint64_t) config->seed_max_file_size * 1024 * 1024;

	if (!bbs->enabled)
		return bbs;

	if (config->seed_cache_dir && *config->seed_cache_dir)
	{
		size_t len = strlen(config->seed_cache_dir) + sizeof(SEED_BBS_CURSOR_FILE) + 2;

		bbs->cursor_path = hub_malloc(len);
		if (bbs->cursor_path)
		{
			snprintf(bbs->cursor_path, len, "%s/%s", config->seed_cache_dir, SEED_BBS_CURSOR_FILE);
			bbs_cursors_load(bbs);
		}
	}

	return bbs;
}

void seed_bbs_destroy(struct seed_bbs* bbs)
{
	if (!bbs)
		return;

	bbs_cursors_save(bbs);
	hub_free(bbs->cursor_path);
	hub_free(bbs);
}

void seed_bbs_get_stats(struct seed_bbs* bbs, struct seed_bbs_stats* out)
{
	size_t i;

	if (!out)
		return;

	memset(out, 0, sizeof(*out));
	if (!bbs)
		return;

	*out = bbs->stats;
	out->inflight = bbs->inflight;

	for (i = 0; i < SEED_BBS_MAX_BOARDS; i++)
	{
		if (!bbs->boards[i].used)
			continue;

		out->boards++;
		if (bbs->boards[i].subscribed)
			out->subscribed++;
	}

	for (i = 0; i < SEED_BBS_MAX_WANTS; i++)
	{
		if (bbs->wants[i].used)
			out->queued++;
	}
}
