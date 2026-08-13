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

#include <openssl/rand.h>

#include "seeder/grant.h"
#include "util/list.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "util/rbtree.h"

/**
 * Ordering key for the expiry index: expiry first, token only to break ties.
 *
 * Every grant is issued with the same TTL, but `now' is an argument rather than
 * a reading of the clock, so the insertion order is not necessarily the expiry
 * order and the index cannot be a queue. Ordering explicitly costs one small
 * struct per grant and makes the sweep a prefix walk.
 */
struct grant_expiry_key
{
	time_t      expires;
	const char* token; /* Points into the entry's own grant.token. */
};

/**
 * One grant as stored. The public snapshot is embedded whole so that handing a
 * copy to a caller is a single assignment, and so that grant.token can serve as
 * the key of the token index -- the tree keeps the pointer, not the bytes, so
 * the key has to live exactly as long as the entry does.
 */
struct seed_grant_entry
{
	struct seed_grant       grant;
	struct grant_expiry_key expiry;
};

/** Grants outstanding for one CID. Dropped as soon as the count reaches zero. */
struct grant_cid_use
{
	char   cid[SEED_CID_LEN + 1];
	size_t count;
};

/*
 * Three indices over the same entries, none of them a linear scan:
 *
 *   by_token   the lookup every issue, check and release performs
 *   by_expiry  ordered, so a sweep is one walk of the expired prefix
 *   by_cid     the per-CID accounting the fair-share ceiling is made of
 *
 * The entry is owned by by_token; the other two only point at it.
 */
struct seed_grants
{
	struct rb_tree* by_token;  /* const char*             -> struct seed_grant_entry* */
	struct rb_tree* by_expiry; /* struct grant_expiry_key*-> struct seed_grant_entry* */
	struct rb_tree* by_cid;    /* const char*             -> struct grant_cid_use*    */
};

/* A CID and a TTH are both exactly SEED_CID_LEN/SEED_TTH_STR_LEN base32
   characters. Anything else could never name content the cache holds nor match
   a peer on the hub, so it is refused here rather than stored and carried
   around as an unvalidated string. */
static int grant_valid_base32(const char* str, size_t len)
{
	size_t i;

	if (!str)
		return 0;

	for (i = 0; i < len; i++)
		if (!is_valid_base32_char(str[i]))
			return 0;

	return str[len] == '\0';
}

/* Compare two NUL terminated strings used as tree keys. */
static int grant_string_compare(const void* a, const void* b)
{
	return strcmp((const char*) a, (const char*) b);
}

static int grant_expiry_compare(const void* a, const void* b)
{
	const struct grant_expiry_key* ka = (const struct grant_expiry_key*) a;
	const struct grant_expiry_key* kb = (const struct grant_expiry_key*) b;

	if (ka->expires < kb->expires)
		return -1;
	if (ka->expires > kb->expires)
		return 1;

	/* Tokens are unique in the table, so this makes the order total. */
	return strcmp(ka->token, kb->token);
}

/*
 * Constant-time equality, modelled on link_const_time_equal() in core/link.c.
 *
 * A token is a secret: it is the only thing standing between a stranger on the
 * transfer port and the seeder's data. The tree comparator that finds the entry
 * cannot be constant time -- an ordered container needs an ordering -- but the
 * comparison the accept decision is actually made on can be, and is.
 */
static int grant_const_time_equal(const char* a, const char* b, size_t len)
{
	unsigned char diff = 0;
	size_t i;

	for (i = 0; i < len; i++)
		diff |= (unsigned char) (a[i] ^ b[i]);
	return diff == 0;
}

/* The length of what the peer sent is not a secret -- the peer chose it -- so
   comparing lengths first leaks nothing that the peer does not already know. */
static int grant_secret_equal(const char* a, const char* b)
{
	size_t len = strlen(a);

	if (len != strlen(b))
		return 0;
	return grant_const_time_equal(a, b, len);
}

static struct seed_grant_entry* grant_lookup(struct seed_grants* grants, const char* token)
{
	if (!grants || !token || !*token)
		return NULL;

	return (struct seed_grant_entry*) rb_tree_get(grants->by_token, token);
}

static size_t grant_cid_count(struct seed_grants* grants, const char* cid)
{
	struct grant_cid_use* use = (struct grant_cid_use*) rb_tree_get(grants->by_cid, cid);

	return use ? use->count : 0;
}

static int grant_cid_ref(struct seed_grants* grants, const char* cid)
{
	struct grant_cid_use* use = (struct grant_cid_use*) rb_tree_get(grants->by_cid, cid);

	if (!use)
	{
		use = (struct grant_cid_use*) hub_malloc_zero(sizeof(struct grant_cid_use));
		if (!use)
			return 0;

		memcpy(use->cid, cid, SEED_CID_LEN);
		if (!rb_tree_insert(grants->by_cid, use->cid, use))
		{
			hub_free(use);
			return 0;
		}
	}
	use->count++;
	return 1;
}

/* Every path that removes an entry goes through grant_drop(), so the per-CID
   count cannot drift: expiry, release and replacement all unref here. */
static void grant_cid_unref(struct seed_grants* grants, const char* cid)
{
	struct grant_cid_use* use = (struct grant_cid_use*) rb_tree_get(grants->by_cid, cid);

	if (!use || use->count == 0)
		return;

	if (--use->count == 0)
	{
		rb_tree_remove(grants->by_cid, use->cid);
		hub_free(use);
	}
}

static void grant_drop(struct seed_grants* grants, struct seed_grant_entry* entry)
{
	/* The expiry index is keyed by a struct inside the entry, so it goes first,
	   while that key is still the one the tree was built with. */
	rb_tree_remove(grants->by_expiry, &entry->expiry);
	rb_tree_remove(grants->by_token, entry->grant.token);
	grant_cid_unref(grants, entry->grant.cid);
	hub_free(entry);
}

struct seed_grants* seed_grants_create(void)
{
	struct seed_grants* grants = (struct seed_grants*) hub_malloc_zero(sizeof(struct seed_grants));

	if (!grants)
		return NULL;

	grants->by_token  = rb_tree_create(grant_string_compare, NULL, NULL);
	grants->by_expiry = rb_tree_create(grant_expiry_compare, NULL, NULL);
	grants->by_cid    = rb_tree_create(grant_string_compare, NULL, NULL);

	if (!grants->by_token || !grants->by_expiry || !grants->by_cid)
	{
		seed_grants_destroy(grants);
		return NULL;
	}
	return grants;
}

void seed_grants_destroy(struct seed_grants* grants)
{
	struct rb_node* node;

	if (!grants)
		return;

	/* rb_tree_destroy() frees the tree but not its nodes, so drain first. */
	if (grants->by_token && grants->by_expiry && grants->by_cid)
	{
		while ((node = rb_tree_first(grants->by_expiry)) != NULL)
			grant_drop(grants, (struct seed_grant_entry*) node->value);
	}

	if (grants->by_cid)
	{
		while ((node = rb_tree_first(grants->by_cid)) != NULL)
		{
			struct grant_cid_use* use = (struct grant_cid_use*) node->value;
			rb_tree_remove(grants->by_cid, use->cid);
			hub_free(use);
		}
		rb_tree_destroy(grants->by_cid);
	}

	if (grants->by_expiry)
		rb_tree_destroy(grants->by_expiry);
	if (grants->by_token)
		rb_tree_destroy(grants->by_token);

	hub_free(grants);
}

int seed_grant_issue(struct seed_grants* grants, const char* token, const char* cid,
	const char* tth, time_t now)
{
	struct seed_grant_entry* entry;
	struct seed_grant_entry* existing;
	size_t token_len;
	size_t total;
	size_t per_cid;

	if (!grants || !token || !*token || !cid)
		return 0;

	/* A token is echoed back to a peer, so an unbounded one would let a peer
	   size the seeder's state. Anything this long is not a token we minted. */
	token_len = strlen(token);
	if (token_len > SEED_TOKEN_MAX)
	{
		LOG_DEBUG("seed_grant: refusing an oversized token");
		return 0;
	}

	if (!grant_valid_base32(cid, SEED_CID_LEN))
		return 0;

	if (tth && !grant_valid_base32(tth, SEED_TTH_STR_LEN))
		return 0;

	/*
	 * A repeated token replaces the previous grant rather than accumulating, so
	 * the entry it would displace must not be counted against either ceiling --
	 * otherwise re-issuing at the limit would fail even though it frees a slot
	 * as it goes. The existing entry is looked up now but dropped only once the
	 * replacement is certain, so a refusal never destroys what it refuses.
	 */
	existing = grant_lookup(grants, token);

	total = rb_tree_size(grants->by_token) - (existing ? 1 : 0);
	per_cid = grant_cid_count(grants, cid);
	if (existing && strcmp(existing->grant.cid, cid) == 0)
		per_cid--;

	/* Both ceilings live here rather than in the callers: a caller that forgot
	   is exactly how an unauthenticated request came to grow this without
	   bound. Refuse, never evict -- one peer must not cost another its grant. */
	if (total >= SEED_GRANT_MAX_TOTAL)
	{
		LOG_DEBUG("seed_grant: table is full, refusing a grant for %s", cid);
		return 0;
	}

	if (per_cid >= SEED_GRANT_MAX_PER_CID)
	{
		LOG_DEBUG("seed_grant: %s already holds its share of grants, refusing", cid);
		return 0;
	}

	entry = (struct seed_grant_entry*) hub_malloc_zero(sizeof(struct seed_grant_entry));
	if (!entry)
		return 0;

	memcpy(entry->grant.token, token, token_len);
	memcpy(entry->grant.cid, cid, SEED_CID_LEN);
	if (tth)
		memcpy(entry->grant.tth, tth, SEED_TTH_STR_LEN);
	entry->grant.expires = now + SEED_GRANT_TTL;
	entry->expiry.expires = entry->grant.expires;
	entry->expiry.token = entry->grant.token;

	if (!grant_cid_ref(grants, cid))
	{
		hub_free(entry);
		return 0;
	}

	/* Now the replacement is committed, the predecessor can go. Doing it in
	   this order also frees its token key before the new one is inserted. */
	if (existing)
		grant_drop(grants, existing);

	if (!rb_tree_insert(grants->by_token, entry->grant.token, entry))
	{
		grant_cid_unref(grants, cid);
		hub_free(entry);
		return 0;
	}

	if (!rb_tree_insert(grants->by_expiry, &entry->expiry, entry))
	{
		rb_tree_remove(grants->by_token, entry->grant.token);
		grant_cid_unref(grants, cid);
		hub_free(entry);
		return 0;
	}
	return 1;
}

int seed_grant_issue_download(struct seed_grants* grants, const char* token, const char* cid,
	const char* tth, uint64_t size, const char* name, time_t now)
{
	struct seed_grant_entry* entry;

	/* A download grant without a TTH would let the peer decide what the seeder
	   ingests, which is exactly what must not be negotiable. */
	if (!tth)
		return 0;

	if (!seed_grant_issue(grants, token, cid, tth, now))
		return 0;

	entry = grant_lookup(grants, token);
	if (!entry)
		return 0;

	entry->grant.is_download = 1;
	entry->grant.size = size;
	if (name)
	{
		strncpy(entry->grant.name, name, sizeof(entry->grant.name) - 1);
		entry->grant.name[sizeof(entry->grant.name) - 1] = '\0';
	}
	return 1;
}

int seed_grant_check(struct seed_grants* grants, const char* token, const char* cid,
	time_t now, struct seed_grant* out)
{
	struct seed_grant_entry* entry = grant_lookup(grants, token);

	if (out)
		memset(out, 0, sizeof(*out));

	if (!entry)
		return 0;

	if (entry->grant.expires <= now)
		return 0;

	/* Found by an ordering comparator, but granted on a constant-time compare:
	   the decision itself must not time out differently for a token that shares
	   a prefix with the one we issued. */
	if (!grant_secret_equal(entry->grant.token, token))
		return 0;

	/* The CID is what ties the grant to the peer it was issued to. A caller
	   that cannot learn the peer's CID may pass NULL and rely on the token
	   alone, which is only safe because tokens are never reused across peers. */
	if (cid && !grant_secret_equal(entry->grant.cid, cid))
		return 0;

	if (out)
		*out = entry->grant;

	return 1;
}

int seed_grant_is_download(struct seed_grants* grants, const char* token, time_t now,
	struct seed_grant* out)
{
	struct seed_grant_entry* entry = grant_lookup(grants, token);

	if (out)
		memset(out, 0, sizeof(*out));

	if (!entry || !entry->grant.is_download)
		return 0;

	if (entry->grant.expires <= now)
		return 0;

	if (!grant_secret_equal(entry->grant.token, token))
		return 0;

	if (out)
		*out = entry->grant;

	return 1;
}

void seed_grant_release(struct seed_grants* grants, const char* token)
{
	struct seed_grant_entry* entry = grant_lookup(grants, token);

	if (!entry)
		return;

	grant_drop(grants, entry);
}

void seed_grant_sweep(struct seed_grants* grants, time_t now)
{
	struct rb_node* node;

	if (!grants)
		return;

	/*
	 * by_expiry is ordered by expiry, so everything due to go is a prefix of
	 * it: take the front, stop at the first survivor. That is one pass over
	 * the expired set at O(log n) a removal, rather than a walk of the whole
	 * table restarted once per entry removed.
	 *
	 * rb_tree_remove() moves keys between nodes, so no node pointer survives a
	 * removal -- hence rb_tree_first() each time round rather than an iterator.
	 */
	while ((node = rb_tree_first(grants->by_expiry)) != NULL)
	{
		struct seed_grant_entry* entry = (struct seed_grant_entry*) node->value;

		if (entry->grant.expires > now)
			break;

		grant_drop(grants, entry);
	}
}

size_t seed_grant_count(struct seed_grants* grants)
{
	if (!grants)
		return 0;
	return rb_tree_size(grants->by_token);
}

int seed_grant_make_token(char out[SEED_TOKEN_MAX + 1])
{
	/* 15 bytes encode to exactly 24 base32 characters, which need no ADC
	   escaping and are comfortably inside SEED_TOKEN_MAX. */
	unsigned char raw[15];

	if (!out)
		return 0;

	out[0] = '\0';
	if (RAND_bytes(raw, (int) sizeof(raw)) != 1)
		return 0;

	base32_encode(raw, sizeof(raw), out);
	out[24] = '\0';
	return 1;
}
