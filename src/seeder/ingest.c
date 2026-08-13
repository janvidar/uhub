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
#include "seeder/cc.h"
#include "seeder/config.h"
#include "seeder/embed.h"
#include "seeder/fetch.h"
#include "seeder/hubconn.h"
#include "seeder/ingest.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"

/* The anchor a URL embed keys on: the closing bracket of the link label
   immediately followed by an http(s) destination. Mirrors the magnet anchor in
   seeder/embed.c. */
#define SEED_URL_ANCHOR      "](http"
#define SEED_URL_ANCHOR_LEN  6

/* URL mirroring goes straight to seeder/fetch.c. */
static struct seed_fetch* si_fetch_start(struct seed_cache* cache, const struct seed_config* config,
	const char* url, const struct seed_ingest_request* req, seed_fetch_cb cb, void* ptr)
{
	return seed_fetch_start(cache, config, url, req, cb, ptr);
}

static void si_fetch_cancel(struct seed_fetch* job)
{
	seed_fetch_cancel(job);
}

/* -------------------------------------------------------------- pure policy */

int seed_ingest_ct_permitted(int client_type, const char* min_credentials)
{
	/*
	 * The seeder is a client on the hub, not the hub, so it cannot read the
	 * ACL: all it ever learns about another user is the CT bit mask in their
	 * INF. What follows is therefore an approximation of the hub's own
	 * credential ladder (see enum auth_credentials in util/credentials.h) and
	 * not a reading of it -- a hub may well hand out a credential that shows up
	 * in no CT bit at all.
	 *
	 * Every test here is a mask test. CT is a set of flags, not a rank: a super
	 * user is 12 (8|4) and an admin is 20 (16|4), so both carry the operator bit
	 * while neither is numerically "greater" in a way that == would catch.
	 */
	if (min_credentials && *min_credentials)
	{
		if (strcasecmp(min_credentials, "guest") == 0)
			return 1; /* anyone who can post at all */

		if (strcasecmp(min_credentials, "operator") == 0)
			return (client_type & SEED_CT_OPERATOR) ? 1 : 0;

		if (strcasecmp(min_credentials, "super") == 0)
		{
			/* An admin does not carry the super bit, but does outrank one. */
			return (client_type & (SEED_CT_SUPER | SEED_CT_ADMIN)) ? 1 : 0;
		}

		if (strcasecmp(min_credentials, "admin") == 0)
			return (client_type & SEED_CT_ADMIN) ? 1 : 0;
	}

	/*
	 * "user", and the fallback for anything unrecognised or unset. Anyone who
	 * can post could otherwise make the seeder spend disk on their behalf, so
	 * the floor is a registered user rather than a guest. A user who is an
	 * operator but somehow not flagged registered still clears it.
	 */
	return (client_type & (SEED_CT_REGISTERED | SEED_CT_OPERATOR | SEED_CT_SUPER | SEED_CT_ADMIN))
		? 1 : 0;
}

/**
 * True for the characters that terminate a URL: the closing parenthesis of the
 * CommonMark destination, or any whitespace. End-of-string terminates it too,
 * but that is handled by the NUL check at each call site.
 */
static int si_is_url_end(char c)
{
	return (c == ')' || c == '\n' || is_white_space(c));
}

/**
 * Walk backwards from the ']' of an anchor to the '[' that opens the link
 * label. A ']' may legitimately occur inside the label, so brackets are counted
 * rather than matched on sight.
 *
 * @return the opening '[', or NULL when there is no label on this line.
 */
static const char* si_find_label_start(const char* start, const char* pos)
{
	const char* p = pos;
	size_t depth = 0;

	while (p > start)
	{
		char c = *(--p);

		if (c == '\n')
			return NULL;

		if (c == ']')
		{
			depth++;
		}
		else if (c == '[')
		{
			if (depth == 0)
				return p;
			depth--;
		}
	}
	return NULL;
}

size_t seed_ingest_scan_urls(const char* text, struct seed_ingest_url* out, size_t max)
{
	size_t count = 0;
	const char* p;

	if (!text || !out || max == 0)
		return 0;

	for (p = text; *p; p++)
	{
		const char* url;
		const char* end;
		const char* label;
		size_t url_len;
		size_t label_len;

		if (*p != ']' || strncmp(p, SEED_URL_ANCHOR, SEED_URL_ANCHOR_LEN) != 0)
			continue;

		url = p + 2; /* past "](" -- the anchor already matched "http" */
		for (end = url; *end && !si_is_url_end(*end); end++)
			;
		url_len = (size_t) (end - url);

		label = si_find_label_start(text, p);

		/*
		 * Only the inline image form is mirrored. A plain "[text](http...)" is a
		 * link to a page, and following it would make the seeder a general
		 * purpose web fetcher aimed by whoever is typing.
		 */
		if (label && label > text && label[-1] == '!' && url_len > 0 && url_len < SEED_URL_MAX_LEN)
		{
			struct seed_ingest_url* entry = &out[count];

			memset(entry, 0, sizeof(*entry));
			memcpy(entry->url, url, url_len);
			entry->url[url_len] = '\0';

			label_len = (size_t) (p - (label + 1));
			if (label_len >= sizeof(entry->name))
				label_len = sizeof(entry->name) - 1;
			memcpy(entry->name, label + 1, label_len);
			entry->name[label_len] = '\0';

			count++;
			if (count == max)
				break;
		}

		/* Resume after the url. `end` is always past `p`, so this makes
		   progress even when the destination was empty. */
		p = end - 1;
	}

	return count;
}

size_t seed_ingest_select(struct seed_cache* cache, const char* text,
	struct seed_embed* out, size_t max)
{
	struct seed_embed embeds[SEED_INGEST_MAX_PER_MESSAGE];
	size_t found;
	size_t count = 0;
	size_t i;
	size_t j;

	if (!cache || !text || !out || max == 0)
		return 0;

	/* Never look at more of a message than one message may ever ask for. */
	found = seed_scan_message(text, embeds, SEED_INGEST_MAX_PER_MESSAGE);

	for (i = 0; i < found && count < max; i++)
	{
		int duplicate = 0;

		/* An operator said no to this content; do not fetch it again. */
		if (seed_cache_is_blocked(cache, embeds[i].tth))
		{
			LOG_DEBUG("seed_ingest: refusing blocked TTH=%s", embeds[i].tth);
			continue;
		}

		/* Already held. Inspected with peek(), not lookup(): a message merely
		   mentioning a file is not an access, and counting it as one would let
		   chatter reorder the eviction queue. */
		if (seed_cache_peek(cache, embeds[i].tth, NULL))
			continue;

		/* The scanner emits one entry per occurrence, so the same TTH posted
		   twice in one line must not be asked for twice. */
		for (j = 0; j < count; j++)
			if (strcmp(out[j].tth, embeds[i].tth) == 0)
				duplicate = 1;
		if (duplicate)
			continue;

		out[count++] = embeds[i];
	}

	return count;
}

/* ------------------------------------------------------------ the daemon side */

struct seed_ingest_fetch
{
	struct seed_ingest_trigger* trigger;
	struct seed_fetch* job; /** NULL when this slot is free. */
};

struct seed_ingest_trigger
{
	struct seed_cache*           cache;
	const struct seed_cc_policy* cc;
	struct seed_hub*             hub;
	const struct seed_config*    config;

	struct seed_ingest_fetch fetches[SEED_INGEST_MAX_FETCHES];
	size_t num_fetches;
};

struct seed_ingest_trigger* seed_ingest_trigger_create(struct seed_cache* cache,
	const struct seed_cc_policy* cc, struct seed_hub* hub, const struct seed_config* config)
{
	struct seed_ingest_trigger* trigger;

	if (!cache || !cc || !hub || !config)
		return NULL;

	trigger = (struct seed_ingest_trigger*) hub_malloc_zero(sizeof(struct seed_ingest_trigger));
	if (!trigger)
		return NULL;

	trigger->cache = cache;
	trigger->cc = cc;
	trigger->hub = hub;
	trigger->config = config;
	return trigger;
}

void seed_ingest_trigger_destroy(struct seed_ingest_trigger* trigger)
{
	size_t i;

	if (!trigger)
		return;

	/* Nothing else holds these handles, so an in-flight fetch that is not
	   cancelled here leaks its connection. Cancelling does not invoke the
	   callback, so no slot is freed twice. */
	for (i = 0; i < SEED_INGEST_MAX_FETCHES; i++)
	{
		if (trigger->fetches[i].job)
		{
			si_fetch_cancel(trigger->fetches[i].job);
			trigger->fetches[i].job = NULL;
		}
	}

	hub_free(trigger);
}

size_t seed_ingest_active_fetches(struct seed_ingest_trigger* trigger)
{
	return trigger ? trigger->num_fetches : 0;
}

/*
 * Ask the poster to hand a file over.
 *
 * The poster is the one party certain to have the bytes. The seeder cannot
 * connect out to them on the strength of a CTM -- an address a client supplied
 * is an address it chose -- so it sends a CTM of its own instead and lets the
 * peer connect back, which works whether that peer is active or passive.
 *
 * @return 1 if a request went out.
 */
static int si_request_from_user(struct seed_ingest_trigger* trigger,
	const struct seed_user* from, const struct seed_embed* embed)
{
	char token[SEED_TOKEN_MAX + 1];
	uint16_t port = (uint16_t) trigger->config->seed_client_port;
	const char* protocol;

	/*
	 * The grant is minted first: it is the only thing that will authorise the
	 * connection when it arrives, and if the peer never turns up it simply
	 * expires and nothing is cached.
	 */
	if (!seed_cc_request_token(trigger->cc, from->cid, embed->tth, embed->size,
		*embed->name ? embed->name : NULL, token))
	{
		return 0;
	}

	/*
	 * Name the protocol the connection will actually speak: TLS when the
	 * transfer port has a certificate *and* the poster's own INF says it can do
	 * an encrypted transfer, at the ADCS revision that peer knows about.
	 *
	 * Both halves matter. Claiming TLS with no certificate hangs the peer on a
	 * handshake nothing answers; naming a revision the peer has never heard of
	 * loses the transfer just as completely, only more confusingly.
	 */
	protocol = seed_cc_protocol_for_peer(trigger->cc, from->support, NULL);

	if (!seed_hub_send_ctm(trigger->hub, from->sid, protocol, port, token))
	{
		LOG_DEBUG("seed_ingest: could not send a connect request to %s", from->nick);
		return 0;
	}

	/* The protocol is worth saying out loud rather than at debug level: when a
	   transfer never happens, what was offered and what the peer then did with
	   it is the first thing an operator needs, and the two are otherwise
	   indistinguishable from this end. */
	LOG_INFO("seed_ingest: asked %s to connect to port %u speaking %s for TTH=%s",
		from->nick, (unsigned) port, protocol, embed->tth);
	return 1;
}

/* The one and only completion path for a mirror fetch: free the slot. */
static void si_fetch_done(void* ptr, enum seed_error err, const struct seed_entry* entry)
{
	struct seed_ingest_fetch* slot = (struct seed_ingest_fetch*) ptr;

	if (!slot || !slot->trigger)
		return;

	/* The handle was released before this ran; never touch it again. */
	slot->job = NULL;
	if (slot->trigger->num_fetches > 0)
		slot->trigger->num_fetches--;

	if (err == SEED_OK && entry)
		LOG_INFO("seed_ingest: mirrored a URL as TTH=%s (%" PRIu64 " bytes)", entry->tth, entry->size);
	else
		LOG_DEBUG("seed_ingest: URL mirror failed (%s)", seed_error_string(err));
}

/* @return 1 if a fetch was started. */
static int si_mirror_url(struct seed_ingest_trigger* trigger, const struct seed_user* from,
	const struct seed_ingest_url* embed)
{
	struct seed_ingest_request req;
	struct seed_ingest_fetch* slot = NULL;
	size_t i;

	for (i = 0; i < SEED_INGEST_MAX_FETCHES; i++)
	{
		if (!trigger->fetches[i].job)
		{
			slot = &trigger->fetches[i];
			break;
		}
	}

	if (!slot)
	{
		LOG_DEBUG("seed_ingest: too many URL fetches in flight; not mirroring.");
		return 0;
	}

	memset(&req, 0, sizeof(req));
	req.expect_tth = NULL; /* the hash of a mirrored URL is not known in advance */
	req.name = *embed->name ? embed->name : NULL;
	req.origin_cid = *from->cid ? from->cid : NULL;
	req.origin_nick = *from->nick ? from->nick : NULL;
	req.origin_addr = *from->address ? from->address : NULL;

	slot->trigger = trigger;
	slot->job = si_fetch_start(trigger->cache, trigger->config, embed->url, &req,
		si_fetch_done, slot);
	if (!slot->job)
		return 0;

	trigger->num_fetches++;
	return 1;
}

size_t seed_ingest_on_chat(struct seed_ingest_trigger* trigger, const struct seed_user* from,
	const char* text)
{
	struct seed_embed embeds[SEED_INGEST_MAX_PER_MESSAGE];
	struct seed_ingest_url urls[SEED_INGEST_MAX_PER_MESSAGE];
	size_t count;
	size_t sent = 0;
	size_t i;

	if (!trigger || !from || !text)
		return 0;

	/* Never ask ourselves, or another bot, for anything. */
	if (seed_user_is_bot(from) || seed_user_is_hub(from))
		return 0;

	if (!seed_ingest_ct_permitted(from->client_type, trigger->config->seed_min_credentials))
		return 0;

	count = seed_ingest_select(trigger->cache, text, embeds, SEED_INGEST_MAX_PER_MESSAGE);
	for (i = 0; i < count; i++)
		sent += (size_t) si_request_from_user(trigger, from, &embeds[i]);

	/*
	 * URL mirroring is a server side request forgery primitive by construction:
	 * the destination is chosen by whoever typed the message. It is off unless
	 * an operator turned it on, and seeder/fetch.c applies the address and host
	 * policy from there on.
	 */
	if (trigger->config->seed_url_mirror)
	{
		count = seed_ingest_scan_urls(text, urls, SEED_INGEST_MAX_PER_MESSAGE);
		for (i = 0; i < count; i++)
			sent += (size_t) si_mirror_url(trigger, from, &urls[i]);
	}

	return sent;
}
