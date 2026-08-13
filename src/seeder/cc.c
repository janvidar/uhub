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

#include "adc/adcconst.h"
#include "adc/adctypes.h"
#include "adc/message.h"
#include "network/connection.h"
#include "network/ipcalc.h"
#include "seeder/cache.h"
#include "seeder/cc.h"
#include "seeder/grant.h"
#include "util/cbuffer.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"

/* A CID is a CID whichever module names its length. */
#if SEED_CID_LEN != MAX_CID_LEN
#error "SEED_CID_LEN and MAX_CID_LEN disagree about the length of a CID"
#endif

/* The client-to-client context commands. These are deliberately not in
   adc/adcconst.h: nothing on the hub side may ever dispatch on them. */
#define ADC_CMD_CSUP FOURCC('C', 'S', 'U', 'P')
#define ADC_CMD_CINF FOURCC('C', 'I', 'N', 'F')
#define ADC_CMD_CGET FOURCC('C', 'G', 'E', 'T')
#define ADC_CMD_CGFI FOURCC('C', 'G', 'F', 'I')
#define ADC_CMD_CSND FOURCC('C', 'S', 'N', 'D')
#define ADC_CMD_CSTA FOURCC('C', 'S', 'T', 'A')
#define ADC_CMD_CRES FOURCC('C', 'R', 'E', 'S')

/* How long a peer may stall before we drop it. Re-armed on every byte that
   moves, so it bounds idleness and not the length of a transfer -- which is
   what keeps it well inside the TIMEOUT_QUEUE_MAX deep timeout wheel. */
#define SEED_CC_TIMEOUT 30

#if SEED_CC_TIMEOUT >= TIMEOUT_QUEUE_MAX
#error "SEED_CC_TIMEOUT must fit inside the timeout wheel (TIMEOUT_QUEUE_MAX)"
#endif

/* Transfer granularity, and the most payload moved per readable/writable event
   so one transfer cannot monopolise the reactor. Both backends are level
   triggered, so returning early simply gets us called again. */
#define SEED_CC_CHUNK        (16 * 1024)
#define SEED_CC_WRITE_BUDGET (64 * 1024)
#define SEED_CC_READ_BUDGET  (64 * 1024)

/* Bytes peeked to tell a TLS ClientHello from an ADC line. The test needs 11;
   src/core/probe.c reads 12 for the same job. */
#define SEED_CC_PROBE_SIZE 12

/* Ceiling on queued protocol lines. Replies are a few hundred bytes at most, so
   anything near this means the peer is pipelining commands faster than we drain
   them; that is a peer to drop, not a buffer to grow. */
#define SEED_CC_OUT_MAX 8192

/*
 * Ceiling on outstanding grants before the seeder stops asking peers for new
 * content. Grants expire after SEED_GRANT_TTL, so this only bounds what a burst
 * of chat traffic can make the seeder remember at once.
 */
#define SEED_CC_MAX_GRANTS 256

/*
 * Client connections currently streaming a file out, capped by
 * policy->max_concurrent_upload.
 *
 * This is a *separate* counter from the one seeder/http.c keeps for the HTTP
 * endpoint: the two are different protocols with different clients. The
 * configured limit therefore applies to each endpoint on its own, not to their
 * sum. Ingest needs no counter here at all -- seed_ingest_begin() already
 * enforces the concurrent ingest limit for every ingest path in the daemon.
 */
static size_t seed_cc_uploads = 0;

/*
 * Outbound connect attempts in flight. Separate from the upload slots because a
 * burst of CTMs would otherwise let the seeder open unbounded sockets while
 * every one of them is still resolving.
 */
#define SEED_CC_MAX_CONNECTING 8
static size_t seed_cc_connecting = 0;

enum seed_cc_state
{
	CC_STATE_SUP,     /* waiting for the peer's CSUP */
	CC_STATE_INF,     /* waiting for the peer's CINF (which carries the grant) */
	CC_STATE_READY,   /* upload role: waiting for a CGET/CGFI */
	CC_STATE_SENDING, /* upload role: streaming a body, no longer reading */
	CC_STATE_DL_SND,  /* download role: our CGET is out, waiting for the CSND */
	CC_STATE_DL_BODY  /* download role: reading the body into the ingest */
};

static const char* cc_state_name(enum seed_cc_state state)
{
	switch (state)
	{
		case CC_STATE_SUP:     return "SUP";
		case CC_STATE_INF:     return "INF";
		case CC_STATE_READY:   return "READY";
		case CC_STATE_SENDING: return "SENDING";
		case CC_STATE_DL_SND:  return "DL_SND";
		case CC_STATE_DL_BODY: return "DL_BODY";
	}
	return "?";
}

struct seed_cc_connection
{
	const struct seed_cc_policy* policy; /* owned by the daemon; outlives us */
	struct net_connection* connection;
	struct ip_addr_encap addr;
	enum seed_cc_state state;
	int close_after_flush; /* hang up once the queued reply is on the wire */

	/*
	 * Set when we dialled out, which happens when an active peer sends a CTM.
	 * It reverses two things: we send CSUP first rather than answering one, and
	 * we carry the token in our own CINF, because in ADC the token travels with
	 * whichever side received the connect request.
	 */
	int initiator;
	int use_tls;
	/*
	 * Set on an accepted connection until its first bytes have been classified
	 * (and any TLS handshake they asked for has completed). Nothing is read as
	 * ADC while it is set.
	 */
	int probing;
	struct net_connect_handle* connect_job; /* live only until the connect callback */
	struct ssl_context_handle* ssl_ctx;     /* client context we own, TLS dials only */
	char token[SEED_TOKEN_MAX + 1];         /* echoed in our CINF when dialling out */
	char peer_cid[SEED_CID_LEN + 1];        /* CID the peer must present when dialling out */

	char   line[SEED_CC_LINE_MAX + 1];
	size_t line_len;

	struct cbuffer* out; /* queued protocol lines, NULL when nothing is queued */
	size_t out_sent;

	char cid[SEED_CID_LEN + 1]; /* the peer's CID, once its CINF has been accepted */

	/* Upload role. The pin, the descriptor and the slot are taken one at a time
	   and released together in seed_cc_destroy(), which is the single exit
	   path. */
	char     pin_tth[SEED_TTH_STR_LEN + 1]; /* pinned while pinned is set */
	int      pinned;
	int      fd;              /* -1 when not open */
	int      counted;         /* this transfer is counted in seed_cc_uploads */
	uint64_t entry_size;      /* size the cache recorded for the pinned entry */
	uint64_t offset;          /* next byte to read out of the file */
	uint64_t remaining;       /* body bytes still to send */
	char     chunk[SEED_CC_CHUNK];
	size_t   chunk_len;
	size_t   chunk_sent;

	/* Download role. */
	struct seed_ingest* ingest; /* live job while non-NULL */
	char     want_tth[SEED_TTH_STR_LEN + 1];
	uint64_t want_size;
	char     want_name[SEED_NAME_MAX];
	uint64_t in_remaining; /* body bytes still to read */
	uint64_t in_total;     /* body bytes the peer announced in its CSND */
};

/* -- parsing (pure) -------------------------------------------------------- */

static int cc_parse_u64(const char* str, uint64_t* out)
{
	uint64_t value = 0;
	size_t i;

	if (!str || !*str)
		return 0;

	for (i = 0; str[i]; i++)
	{
		if (!is_num(str[i]))
			return 0;
		if (value > (UINT64_MAX - (uint64_t) (str[i] - '0')) / 10)
			return 0;
		value = (value * 10) + (uint64_t) (str[i] - '0');
	}

	*out = value;
	return 1;
}

/* A CGET/CSND length field: a non-negative count, or exactly "-1" for "to the
   end of the file". */
static int cc_parse_length(const char* str, int64_t* out)
{
	uint64_t value;

	if (!str)
		return 0;

	if (strcmp(str, "-1") == 0)
	{
		*out = SEED_CC_TO_EOF;
		return 1;
	}

	if (!cc_parse_u64(str, &value) || value > (uint64_t) INT64_MAX)
		return 0;

	*out = (int64_t) value;
	return 1;
}

/* Exactly SEED_TTH_STR_LEN characters from the base32 alphabet, and nothing
   else. This is what makes a TTH safe to use as a cache key and as a file name
   component. */
static int cc_valid_tth(const char* str)
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
 * A file identifier, which for the seeder is only ever "TTH/<base32 root>".
 */
static int cc_parse_identifier(const char* ident, char out[SEED_TTH_STR_LEN + 1])
{
	if (!ident || strncmp(ident, "TTH/", 4) != 0)
		return 0;
	if (!cc_valid_tth(ident + 4))
		return 0;

	memcpy(out, ident + 4, SEED_TTH_STR_LEN);
	out[SEED_TTH_STR_LEN] = '\0';
	return 1;
}

/* CGET/CSND share their argument shape: "<type> <identifier> <start> <bytes>". */
static void cc_parse_transfer(struct adc_message* msg, struct seed_cc_request* req,
	enum seed_cc_type file_type, enum seed_cc_type tthl_type)
{
	char* type = adc_msg_get_argument(msg, 0);
	char* ident = adc_msg_get_argument(msg, 1);
	char* start = adc_msg_get_argument(msg, 2);
	char* bytes = adc_msg_get_argument(msg, 3);

	if (type && strcmp(type, "tthl") == 0 && tthl_type != SEED_CC_UNSUPPORTED)
	{
		/* The identifier and range are not looked at: the answer does not
		   depend on them (see the CGET tthl handling). */
		req->type = tthl_type;
	}
	else if (type && strcmp(type, "file") == 0 &&
		cc_parse_identifier(ident, req->tth) &&
		cc_parse_u64(start, &req->start) &&
		cc_parse_length(bytes, &req->bytes))
	{
		req->type = file_type;
	}

	hub_free(type);
	hub_free(ident);
	hub_free(start);
	hub_free(bytes);
}

static void cc_parse_sup(struct adc_message* msg, struct seed_cc_request* req)
{
	int i;

	/* A SUP line is a list of AD<feature>/RM<feature> tokens; only the two the
	   transfer depends on are of any interest here. */
	for (i = 0; i < 16; i++)
	{
		char* arg = adc_msg_get_argument(msg, i);
		if (!arg)
			break;
		if (strcmp(arg, "ADBASE") == 0 || strcmp(arg, "ADBAS0") == 0)
			req->have_base = 1;
		else if (strcmp(arg, "ADTIGR") == 0)
			req->have_tigr = 1;
		hub_free(arg);
	}

	req->type = SEED_CC_SUP;
}

static void cc_parse_inf(struct adc_message* msg, struct seed_cc_request* req)
{
	char* cid = adc_msg_get_named_argument(msg, ADC_INF_FLAG_CLIENT_ID);
	char* token = adc_msg_get_named_argument(msg, "TO");

	/* A CID has the same shape as a TTH: exactly 39 base32 characters. Anything
	   else simply never matches a grant, so it is dropped here rather than
	   carried around as an unvalidated string. */
	if (cid && cc_valid_tth(cid))
	{
		memcpy(req->cid, cid, SEED_CID_LEN);
		req->cid[SEED_CID_LEN] = '\0';
	}

	/* The token is kept exactly as it came off the wire (still ADC-escaped),
	   because that is the form the grant was issued in. */
	if (token && *token && strlen(token) <= SEED_TOKEN_MAX)
	{
		strncpy(req->token, token, SEED_TOKEN_MAX);
		req->token[SEED_TOKEN_MAX] = '\0';
	}

	hub_free(cid);
	hub_free(token);
	req->type = SEED_CC_INF;
}

int seed_cc_parse(const char* line, size_t length, struct seed_cc_request* out)
{
	struct adc_message* msg;
	struct seed_cc_request req;

	memset(&req, 0, sizeof(req));
	req.type = SEED_CC_INVALID;
	if (out)
		*out = req;

	if (!line || length < 4 || length > SEED_CC_LINE_MAX)
		return 0;

	/* A NUL inside a command is never legitimate, and letting one through would
	   mean this length bounded parse and any later string handling disagree
	   about where the line ends. */
	if (memchr(line, '\0', length))
		return 0;

	/* 'C' context only. adc_msg_parse_client() rejects every hub context, all
	   non-printable UTF-8 and every malformed escape for us. */
	msg = adc_msg_parse_client(line, length);
	if (!msg)
		return 0;

	/* From here the line is a valid client-to-client command: anything we do not
	   serve is reported as unsupported, so the caller answers with a status
	   message rather than hanging up on a peer that merely asked for something
	   else. */
	req.type = SEED_CC_UNSUPPORTED;

	switch (msg->cmd)
	{
		case ADC_CMD_CSUP:
			cc_parse_sup(msg, &req);
			break;

		case ADC_CMD_CINF:
			cc_parse_inf(msg, &req);
			break;

		case ADC_CMD_CGET:
			cc_parse_transfer(msg, &req, SEED_CC_GET_FILE, SEED_CC_GET_TTHL);
			break;

		case ADC_CMD_CSND:
			cc_parse_transfer(msg, &req, SEED_CC_SND, SEED_CC_UNSUPPORTED);
			break;

		case ADC_CMD_CGFI:
		{
			char* type = adc_msg_get_argument(msg, 0);
			char* ident = adc_msg_get_argument(msg, 1);
			if (type && strcmp(type, "file") == 0 && cc_parse_identifier(ident, req.tth))
				req.type = SEED_CC_GFI;
			hub_free(type);
			hub_free(ident);
			break;
		}

		case ADC_CMD_CSTA:
		{
			char* code = adc_msg_get_argument(msg, 0);
			uint64_t value = 0;
			if (code && cc_parse_u64(code, &value) && value <= INT32_MAX)
				req.status = (int) value;
			hub_free(code);
			req.type = SEED_CC_STA;
			break;
		}

		default:
			break;
	}

	adc_msg_free(msg);

	if (out)
		*out = req;
	return 1;
}

int seed_cc_take_line(const char* buf, size_t len, size_t* out_len)
{
	const char* nl;

	if (out_len)
		*out_len = 0;

	if (!buf)
		return -1;

	nl = (const char*) memchr(buf, '\n', len);
	if (nl)
	{
		size_t n = (size_t) (nl - buf) + 1;
		if (n > SEED_CC_LINE_MAX)
			return -1;
		if (memchr(buf, '\0', n))
			return -1;
		if (out_len)
			*out_len = n;
		return 1;
	}

	/* No terminator yet. Once as much as a whole command has arrived without
	   one, no further byte can make this a valid line. */
	if (len >= SEED_CC_LINE_MAX)
		return -1;
	if (memchr(buf, '\0', len))
		return -1;
	return 0;
}

int seed_cc_range_ok(uint64_t size, uint64_t start, int64_t bytes, uint64_t* out_len)
{
	uint64_t length;

	if (out_len)
		*out_len = 0;

	if (start > size)
		return 0;

	if (bytes == SEED_CC_TO_EOF)
	{
		length = size - start;
	}
	else if (bytes < 0)
	{
		return 0;
	}
	else
	{
		length = (uint64_t) bytes;
		if (length > (size - start))
			return 0;
	}

	if (out_len)
		*out_len = length;
	return 1;
}

enum seed_cc_probe seed_cc_probe_classify(const char* buf, size_t len)
{
	const unsigned char* b = (const unsigned char*) buf;

	if (!buf || len == 0)
		return SEED_CC_PROBE_MORE;

	/*
	 * Only a TLS record can start with the handshake content type, and an ADC
	 * line never does -- so one byte is enough to rule TLS out. Deciding this
	 * early matters: a peer whose first line is shorter than the TLS test needs
	 * would otherwise be stalled until its idle timeout.
	 */
	if (b[0] != 22)
		return SEED_CC_PROBE_PLAIN;

	if (len < 11)
		return SEED_CC_PROBE_MORE;

	/*
	 * The same shape probe_classify() looks for in src/core/probe.c: a
	 * handshake record (22), major version 3, handshake type client_hello (1)
	 * at offset 5, and the version echoed at offset 9.
	 */
	if (b[1] == 3 && b[5] == 1 && b[9] == b[1])
		return SEED_CC_PROBE_TLS;

	return SEED_CC_PROBE_PLAIN;
}

const char* seed_cc_offered_protocol(const struct seed_cc_policy* policy)
{
	return (policy && policy->ssl_ctx) ? ADC_CC_PROTOCOL_TLS : ADC_CC_PROTOCOL_PLAIN;
}

int seed_cc_support_has(const char* support, const char* feature)
{
	const char* p;

	if (!support || !feature)
		return 0;

	/* Whole tokens only. SU is comma separated and every token is exactly four
	   characters, so a match must start at the front or just after a comma and
	   end at a comma or the end of the string. */
	for (p = support; *p; p++)
	{
		if (p != support && p[-1] != ',')
			continue;
		if (strncmp(p, feature, 4) != 0)
			continue;
		if (p[4] == '\0' || p[4] == ',')
			return 1;
	}
	return 0;
}

const char* seed_cc_protocol_for_peer(const struct seed_cc_policy* policy,
	const char* support, const char* requested)
{
	/* No certificate here means no handshake to answer, whatever the peer can
	   do; naming TLS would hang it waiting for one that never comes. */
	if (!policy || !policy->ssl_ctx)
		return ADC_CC_PROTOCOL_PLAIN;

	/*
	 * A peer that named a TLS revision has told us which one it speaks, so that
	 * choice is kept exactly. This is the only thing the request decides --
	 * whether the connection is encrypted at all is settled below, from what the
	 * peer says it can do rather than from what it happened to ask for.
	 */
	if (requested)
	{
		if (strcmp(requested, ADC_CC_PROTOCOL_TLS_1) == 0)
			return ADC_CC_PROTOCOL_TLS_1;
		if (strcmp(requested, ADC_CC_PROTOCOL_TLS) == 0)
			return ADC_CC_PROTOCOL_TLS;
	}

	/*
	 * ADCS and ADC0 are the same claim in two spellings, the second predating
	 * ADCS 1.0 -- which is exactly what the "0.10" in the older protocol string
	 * refers to. Either one means this peer does encrypted transfers, and
	 * clients that advertise it expect every connection with them to be
	 * encrypted, so a request for plain ADC does not override it.
	 */
	if (seed_cc_support_has(support, "ADCS"))
		return ADC_CC_PROTOCOL_TLS_1;

	if (seed_cc_support_has(support, "ADC0"))
		return ADC_CC_PROTOCOL_TLS;

	/* Neither token: the peer has not said it can do an encrypted transfer, so
	   asking it for one is a guess that costs the transfer when it is wrong. */
	return ADC_CC_PROTOCOL_PLAIN;
}

int seed_cc_quota_allow(const struct seed_cc_policy* policy, const char* cid, uint64_t size, time_t now)
{
	struct seed_entry entry;
	uint64_t bytes = 0;
	uint64_t max_bytes;
	size_t count = 0;
	time_t cutoff;
	int max_files;
	int interval;

	if (!policy || !policy->cache || !cid || !*cid)
		return 0;

	interval = policy->ingest_interval;
	max_files = policy->ingest_per_user;
	max_bytes = (policy->ingest_quota_kb > 0)
		? ((uint64_t) policy->ingest_quota_kb * 1024) : 0;

	/* No window, or neither limit set: nothing to enforce. */
	if (interval <= 0 || (max_files <= 0 && max_bytes == 0))
		return 1;

	cutoff = now - interval;

	/* Counted straight off the cache rather than from a side table, so a peer
	   whose content was evicted is not still paying for it, and so there is no
	   per-peer bookkeeping to leak or to keep in sync. The walk is bounded by
	   the configured entry limit. */
	if (seed_cache_first(policy->cache, &entry))
	{
		do
		{
			if (entry.first_seen < cutoff)
				continue;
			if (strcmp(entry.origin_cid, cid) != 0)
				continue;
			count++;
			bytes += entry.size;
		}
		while (seed_cache_next(policy->cache, &entry));
	}

	if (max_files > 0 && count >= (size_t) max_files)
		return 0;

	if (max_bytes && (size > max_bytes || bytes > (max_bytes - size)))
		return 0;

	return 1;
}

/* -- connection plumbing --------------------------------------------------- */

/*
 * The one and only teardown. Every error and completion path funnels through
 * here, which is what makes "the pin is released exactly once" checkable by
 * inspection: the pin is taken in exactly one place, recorded in b->pinned
 * immediately, and dropped only here -- and only when b->pinned is still set,
 * which it never is twice because the struct is freed on the way out. The
 * ingest job and the upload slot are held and released the same way.
 *
 * The connection grant is deliberately *not* released here: it is consumed the
 * moment the CINF that quoted it is accepted, so a grant is good for exactly
 * one connection whatever happens to that connection afterwards.
 */
static void seed_cc_destroy(struct seed_cc_connection* b)
{
	/* An unfinished download says how far it got. "Stalled after 0 bytes" and
	   "stalled with 12 KB to go" are different faults with different owners, and
	   the closing line is the only place either is visible. */
	if (b->state == CC_STATE_DL_BODY && b->in_remaining)
	{
		LOG_INFO("seed_cc[%s %s %s] closing with %" PRIu64 " of %" PRIu64 " bytes still to come (peer cid=%s)",
			b->initiator ? "dialled" : "accepted",
			ip_convert_to_string(&b->addr),
			cc_state_name(b->state),
			b->in_remaining, b->in_total,
			b->cid[0] ? b->cid : "-");
	}
	else
	{
		LOG_INFO("seed_cc[%s %s %s] closing (peer cid=%s)",
			b->initiator ? "dialled" : "accepted",
			ip_convert_to_string(&b->addr),
			cc_state_name(b->state),
			b->cid[0] ? b->cid : "-");
	}

	if (b->ingest)
	{
		/* Nothing was published: the bytes live under tmp/ and are unlinked. */
		seed_ingest_abort(b->ingest, SEED_ERR_TRUNCATED);
		b->ingest = NULL;
	}

	if (b->fd >= 0)
	{
		close(b->fd);
		b->fd = -1;
	}

	if (b->pinned)
	{
		seed_cache_unpin(b->policy->cache, b->pin_tth);
		b->pinned = 0;
	}

	if (b->counted)
	{
		if (seed_cc_uploads > 0)
			seed_cc_uploads--;
		b->counted = 0;
	}

	if (b->connect_job)
	{
		/* Still resolving or connecting: stop it before the callback can fire
		   on a freed handle. */
		net_connect_destroy(b->connect_job);
		b->connect_job = NULL;
		if (seed_cc_connecting > 0)
			seed_cc_connecting--;
	}

	if (b->connection)
	{
		net_con_close(b->connection);
		b->connection = NULL;
	}

	if (b->ssl_ctx)
	{
		net_ssl_context_destroy(b->ssl_ctx);
		b->ssl_ctx = NULL;
	}

	if (b->out)
	{
		cbuf_destroy(b->out);
		b->out = NULL;
	}

	hub_free(b);
}

static int cc_out_pending(struct seed_cc_connection* b)
{
	return b->out && b->out_sent < cbuf_size(b->out);
}

/*
 * Wire logging. Deliberately LOG_INFO rather than LOG_DEBUG: it must be visible
 * in a release build too, because the ordering of these lines is the only way
 * to tell which side is expected to speak first. Volume is a handful of lines
 * per transfer.
 */
static void cc_log_wire(struct seed_cc_connection* b, const char* dir, const char* line, size_t length)
{
	char buf[SEED_CC_LINE_MAX + 1];
	size_t out = 0;
	size_t i;

	for (i = 0; i < length && out < sizeof(buf) - 1; i++)
	{
		unsigned char c = (unsigned char) line[i];
		if (c == '\n' || c == '\r')
			break;
		buf[out++] = (c >= 0x20 && c < 0x7f) ? (char) c : '.';
	}
	buf[out] = '\0';

	LOG_INFO("seed_cc[%s %s %s] %s %s",
		b->initiator ? "dialled" : "accepted",
		ip_convert_to_string(&b->addr),
		cc_state_name(b->state), dir, buf);
}

/* Queue a protocol line. @return 0 when the peer is queueing faster than it
   reads, in which case the connection has been destroyed. */
static int cc_queue(struct seed_cc_connection* b, const char* line)
{
	cc_log_wire(b, "-->", line, strlen(line));

	if (!b->out)
	{
		b->out = cbuf_create(256);
		b->out_sent = 0;
	}

	cbuf_append(b->out, line);

	if (cbuf_size(b->out) > SEED_CC_OUT_MAX)
	{
		LOG_DEBUG("seed_cc: reply backlog exceeded for %s", ip_convert_to_string(&b->addr));
		seed_cc_destroy(b);
		return 0;
	}
	return 1;
}

size_t seed_cc_format_status(char* buf, size_t size, int code, const char* description)
{
	int len;

	if (!buf || size == 0)
		return 0;

	buf[0] = '\0';
	if (code < 0)
		return 0;

	/* The severity digit is hard-coded to 1 (recoverable), which is what makes
	   every refusal here something a client can carry on from. */
	len = snprintf(buf, size, "CSTA 1%02d %s\n", code % 100, description ? description : "");
	if (len < 0 || (size_t) len >= size)
	{
		buf[0] = '\0';
		return 0;
	}
	return (size_t) len;
}

/*
 * Answer with a status message.
 *
 * @p description must already be ADC-escaped.
 * @return 0 if the connection was destroyed.
 */
static int cc_send_status(struct seed_cc_connection* b, int code, const char* description, int close_after)
{
	char line[128];

	if (!seed_cc_format_status(line, sizeof(line), code, description))
	{
		seed_cc_destroy(b);
		return 0;
	}

	if (close_after)
		b->close_after_flush = 1;
	return cc_queue(b, line);
}

static void cc_update_events(struct seed_cc_connection* b)
{
	int events = 0;

	if (cc_out_pending(b) || b->state == CC_STATE_SENDING)
		events |= NET_EVENT_WRITE;

	/* While streaming a body there is nothing the peer can tell us that we act
	   on, so it is not read; anything it sends stays in the socket buffer. */
	if (b->state != CC_STATE_SENDING)
		events |= NET_EVENT_READ;

	net_con_update(b->connection, events);
}

/* -- upload role ----------------------------------------------------------- */

/* @return 0 if the connection was destroyed. */
static int cc_handle_get(struct seed_cc_connection* b, const struct seed_cc_request* req)
{
	struct seed_cache* cache = b->policy->cache;
	struct seed_entry entry;
	size_t max_uploads = b->policy->max_concurrent_upload;
	uint64_t length = 0;
	char line[128];

	if (!seed_cache_lookup(cache, req->tth, &entry) || seed_cache_is_blocked(cache, req->tth))
		return cc_send_status(b, SEED_CC_STATUS_NO_FILE, "File\\snot\\savailable", 0);

	if (!seed_cc_range_ok(entry.size, req->start, req->bytes, &length))
	{
		/* A short body would look exactly like a truncated transfer to the peer,
		   which would then cache a corrupt file. Refuse instead. */
		return cc_send_status(b, SEED_CC_STATUS_BAD_RANGE, "File\\spart\\snot\\savailable", 0);
	}

	/* A connection we dialled already took its slot when it dialled, so it is
	   neither charged twice nor refused for occupying its own slot. */
	if (!b->counted && max_uploads > 0 && seed_cc_uploads >= max_uploads)
	{
		LOG_TRACE("seed_cc: upload limit (%lu) reached, refusing %s",
			(unsigned long) max_uploads, ip_convert_to_string(&b->addr));
		return cc_send_status(b, SEED_CC_STATUS_SLOTS_FULL, "Slots\\sfull", 0);
	}

	/* Pin first and record it immediately, so that from this point on every exit
	   runs through seed_cc_destroy() and drops it exactly once. */
	if (!seed_cache_pin(cache, entry.tth))
		return cc_send_status(b, SEED_CC_STATUS_NO_FILE, "File\\snot\\savailable", 0);

	memcpy(b->pin_tth, entry.tth, SEED_TTH_STR_LEN + 1);
	b->pinned = 1;
	b->entry_size = entry.size;

	b->fd = seed_cache_open_file(cache, b->pin_tth);
	if (b->fd < 0)
		return cc_send_status(b, SEED_CC_STATUS_NO_FILE, "File\\snot\\savailable", 1);

	b->offset = req->start;
	b->remaining = length;
	if (!b->counted)
	{
		seed_cc_uploads++;
		b->counted = 1;
	}

	snprintf(line, sizeof(line), "CSND file TTH/%s %" PRIu64 " %" PRIu64 "\n",
		b->pin_tth, req->start, length);
	if (!cc_queue(b, line))
		return 0;

	b->state = CC_STATE_SENDING;
	LOG_TRACE("seed_cc: sending TTH=%s (%" PRIu64 " bytes) to %s",
		b->pin_tth, length, ip_convert_to_string(&b->addr));
	return 1;
}

/* @return 0 if the connection was destroyed. */
static int cc_handle_gfi(struct seed_cc_connection* b, const struct seed_cc_request* req)
{
	struct seed_cache* cache = b->policy->cache;
	struct seed_entry entry;
	char* name;
	char line[SEED_NAME_MAX * 2 + 128];

	/* Metadata only: answering CGFI is not an access, so it must not reorder
	   the LRU or inflate the hit count. */
	if (!seed_cache_peek(cache, req->tth, &entry) || seed_cache_is_blocked(cache, req->tth))
		return cc_send_status(b, SEED_CC_STATUS_NO_FILE, "File\\snot\\savailable", 0);

	/* The stored name is sanitized at ingest, but it is still peer-supplied text
	   going onto the wire, so it is escaped like any other. */
	name = adc_msg_escape(*entry.name ? entry.name : entry.tth);
	if (!name)
		return cc_send_status(b, SEED_CC_STATUS_NO_FILE, "File\\snot\\savailable", 0);

	snprintf(line, sizeof(line), "CRES FN%s SI%" PRIu64 " TRTTH/%s\n", name, entry.size, entry.tth);
	hub_free(name);

	return cc_queue(b, line);
}

/* -- download role --------------------------------------------------------- */

/* Publish what was received and hang up. Always destroys the connection. */
static void cc_finish_ingest(struct seed_cc_connection* b)
{
	struct seed_ingest* job = b->ingest;
	enum seed_error error = SEED_OK;

	b->ingest = NULL; /* seed_ingest_finish() owns and frees the job */

	if (!seed_ingest_finish(job, NULL, &error))
		LOG_DEBUG("seed_cc: ingest of TTH=%s from %s failed (%s)",
			b->want_tth, ip_convert_to_string(&b->addr), seed_error_string(error));

	seed_cc_destroy(b);
}

/* Feed received body bytes to the ingest. @return 0 if the connection is gone. */
static int cc_ingest_bytes(struct seed_cc_connection* b, const char* data, size_t len)
{
	if ((uint64_t) len > b->in_remaining)
		len = (size_t) b->in_remaining; /* the peer overran its own announcement */

	if (len && seed_ingest_write(b->ingest, data, len) != 0)
	{
		seed_cc_destroy(b);
		return 0;
	}

	b->in_remaining -= (uint64_t) len;

	if (b->in_remaining == 0)
	{
		cc_finish_ingest(b);
		return 0;
	}
	return 1;
}

/* @return 0 if the connection was destroyed. */
static int cc_handle_snd(struct seed_cc_connection* b, const struct seed_cc_request* req)
{
	struct seed_ingest_request ireq;
	enum seed_error error = SEED_OK;

	/* Only the exact content we asked for, at the offset we asked for, and with
	   a length stated up front: a peer must not be able to redirect the transfer
	   onto something else, and "to end of file" gives nothing to check the body
	   length against. */
	if (strcmp(req->tth, b->want_tth) != 0 || req->start != 0 || req->bytes <= 0 ||
		(b->want_size && (uint64_t) req->bytes > b->want_size))
	{
		LOG_DEBUG("seed_cc: unexpected CSND from %s", ip_convert_to_string(&b->addr));
		seed_cc_destroy(b);
		return 0;
	}

	memset(&ireq, 0, sizeof(ireq));
	ireq.expect_tth = b->want_tth;
	ireq.announced_size = (uint64_t) req->bytes;
	ireq.name = *b->want_name ? b->want_name : NULL;
	ireq.origin_cid = *b->cid ? b->cid : NULL;
	ireq.origin_addr = ip_convert_to_string(&b->addr);

	b->ingest = seed_ingest_begin(b->policy->cache, &ireq, &error);
	if (!b->ingest)
	{
		LOG_DEBUG("seed_cc: refusing ingest of TTH=%s (%s)", b->want_tth, seed_error_string(error));
		seed_cc_destroy(b);
		return 0;
	}

	b->in_remaining = (uint64_t) req->bytes;
	b->in_total = (uint64_t) req->bytes;
	b->state = CC_STATE_DL_BODY;
	return 1;
}

/* -- handshake ------------------------------------------------------------- */

/*
 * Send our CINF. @p with_token is set only when we dialled: in ADC the token
 * travels with whichever side received the connect request, which is us in that
 * direction and the peer in the other.
 *
 * @return 0 if the connection was destroyed.
 */
static int cc_send_inf(struct seed_cc_connection* b, int with_token)
{
	char line[64 + SEED_CID_LEN + SEED_TOKEN_MAX];

	if (with_token)
		snprintf(line, sizeof(line), "CINF ID%s TO%s\n", b->policy->cid, b->token);
	else
		snprintf(line, sizeof(line), "CINF ID%s\n", b->policy->cid);

	return cc_queue(b, line);
}

static int cc_handle_sup(struct seed_cc_connection* b, const struct seed_cc_request* req)
{
	if (!req->have_base || !req->have_tigr)
	{
		LOG_DEBUG("seed_cc: peer %s did not offer BASE/TIGR", ip_convert_to_string(&b->addr));
		return cc_send_status(b, SEED_CC_STATUS_UNAUTHORIZED, "Protocol\\sunsupported", 1);
	}

	if (b->initiator)
	{
		/*
		 * We dialled, so the peer is the side that was connected to and sends
		 * its INF first. Ours follows in cc_handle_inf(), carrying the token
		 * the peer gave us in its CTM.
		 */
		b->state = CC_STATE_INF;
		return 1;
	}

	if (!cc_queue(b, "CSUP ADBASE ADTIGR\n"))
		return 0;

	/*
	 * The side that was connected to sends its INF first, and the connecting
	 * side answers with one carrying the token. Waiting for theirs before
	 * sending ours deadlocks: both ends sit in INF until the idle timeout.
	 *
	 * This goes out before the token has been seen, so it is sent to a peer we
	 * have not authorised yet. That is fine -- it discloses only our own CID,
	 * which is already public in the hub's user list -- and nothing else is
	 * served until the grant checks out below.
	 */
	if (!cc_send_inf(b, 0))
		return 0;

	b->state = CC_STATE_INF;
	return 1;
}

/* @return 0 if the connection was destroyed. */
static int cc_handle_inf(struct seed_cc_connection* b, const struct seed_cc_request* req)
{
	struct seed_grant grant;
	time_t now = time(NULL);
	char line[64 + SEED_TTH_STR_LEN];

	if (b->initiator)
	{
		/*
		 * We dialled this peer, so there is no token to check -- we sent it.
		 * What has to hold is that the client which answered is the one that
		 * asked us to connect. That CID check is the identity guarantee here:
		 * a DC client presents a self-signed certificate, so a TLS dial proves
		 * nothing about who is on the other end.
		 */
		if (!*req->cid || strcmp(req->cid, b->peer_cid) != 0)
		{
			LOG_DEBUG("seed_cc: %s answered our connection with the wrong CID",
				ip_convert_to_string(&b->addr));
			return cc_send_status(b, SEED_CC_STATUS_UNAUTHORIZED, "Unexpected\\sclient", 1);
		}

		memcpy(b->cid, req->cid, SEED_CID_LEN + 1);

		/* Their INF arrived, so ours goes out now, carrying the token. */
		if (!cc_send_inf(b, 1))
			return 0;

		b->state = CC_STATE_READY;
		return 1;
	}

	/*
	 * No grant, no data. The transfer port is reachable pre-authentication by
	 * anyone who can open a socket, so the token -- which we issued ourselves,
	 * to this CID, less than SEED_GRANT_TTL ago -- is the only thing that makes
	 * the connection anything other than a stranger's.
	 */
	if (!*req->cid || !*req->token ||
		!seed_grant_check(b->policy->grants, req->token, req->cid, now, &grant))
	{
		LOG_DEBUG("seed_cc: rejecting unauthorised client connection from %s",
			ip_convert_to_string(&b->addr));
		return cc_send_status(b, SEED_CC_STATUS_UNAUTHORIZED, "Invalid\\sor\\sexpired\\stoken", 1);
	}

	/* Single use: consumed here, so neither a replay nor a second parallel
	   connection can ride the same token. */
	seed_grant_release(b->policy->grants, req->token);

	memcpy(b->cid, req->cid, SEED_CID_LEN + 1);

	/* Our INF already went out right after the SUP exchange. */

	if (!grant.is_download)
	{
		b->state = CC_STATE_READY;
		return 1;
	}

	memcpy(b->want_tth, grant.tth, SEED_TTH_STR_LEN + 1);
	b->want_size = grant.size;
	memcpy(b->want_name, grant.name, sizeof(b->want_name));
	b->want_name[sizeof(b->want_name) - 1] = '\0';

	snprintf(line, sizeof(line), "CGET file TTH/%s 0 -1\n", b->want_tth);
	if (!cc_queue(b, line))
		return 0;

	b->state = CC_STATE_DL_SND;
	return 1;
}

/* Dispatch one framed line. @return 0 if the connection was destroyed. */
static int cc_handle_line(struct seed_cc_connection* b, const char* line, size_t length)
{
	struct seed_cc_request req;

	cc_log_wire(b, "<--", line, length);

	if (!seed_cc_parse(line, length, &req))
	{
		LOG_DEBUG("seed_cc: malformed client command from %s", ip_convert_to_string(&b->addr));
		seed_cc_destroy(b);
		return 0;
	}

	/*
	 * A status from the peer. The leading digit is the severity: 0 informational,
	 * 1 recoverable, 2 fatal.
	 *
	 * Only 1 and 2 end the connection. A 0 is the peer saying something while
	 * carrying on -- EiskaltDC++ answers our CINF with "CSTA 000" naming the hub
	 * it came from -- and treating that as "the peer gave up on us" hung up on
	 * every download from that client before it had asked for a file.
	 */
	if (req.type == SEED_CC_STA)
	{
		if (req.status / 100 == 0)
		{
			LOG_DEBUG("seed_cc: peer %s sent informational status %d; continuing",
				ip_convert_to_string(&b->addr), req.status);
			return 1;
		}

		LOG_DEBUG("seed_cc: peer %s reported status %d", ip_convert_to_string(&b->addr), req.status);
		seed_cc_destroy(b);
		return 0;
	}

	switch (b->state)
	{
		case CC_STATE_SUP:
			if (req.type != SEED_CC_SUP)
				break;
			return cc_handle_sup(b, &req);

		case CC_STATE_INF:
			if (req.type != SEED_CC_INF)
				break;
			return cc_handle_inf(b, &req);

		case CC_STATE_READY:
			if (req.type == SEED_CC_GET_FILE)
				return cc_handle_get(b, &req);
			if (req.type == SEED_CC_GFI)
				return cc_handle_gfi(b, &req);
			if (req.type == SEED_CC_GET_TTHL)
			{
				/*
				 * Leaf hashes are not kept: the seeder serves whole, small files
				 * from a single source, and a downloader verifies those by
				 * hashing the lot against the root it already knows. The reply
				 * is deliberately a recoverable 1xx and never a fatal 2xx, so
				 * clients treat it as "no leaves here" and fall back to a plain
				 * file GET instead of aborting the download.
				 */
				return cc_send_status(b, SEED_CC_STATUS_NO_TTHL, "Leaf\\shashes\\snot\\savailable", 0);
			}
			break;

		case CC_STATE_DL_SND:
			if (req.type != SEED_CC_SND)
				break;
			return cc_handle_snd(b, &req);

		case CC_STATE_SENDING:
		case CC_STATE_DL_BODY:
			/* Not read in these states; getting here would be a bug. */
			break;
	}

	/* A valid command, but not one the seeder serves, or not one that belongs in
	   this state. */
	return cc_send_status(b, SEED_CC_STATUS_BAD_COMMAND, "Unexpected\\sor\\sunsupported\\scommand", 0);
}

/* -- event handling -------------------------------------------------------- */

static void cc_read_body(struct seed_cc_connection* b, struct net_connection* con)
{
	size_t budget = SEED_CC_READ_BUDGET;

	while (budget > 0 && b->in_remaining > 0)
	{
		size_t want = sizeof(b->chunk);
		ssize_t got;

		if ((uint64_t) want > b->in_remaining)
			want = (size_t) b->in_remaining;
		if (want > budget)
			want = budget;

		got = net_con_recv(con, b->chunk, want);
		if (got < 0)
		{
			seed_cc_destroy(b);
			return;
		}
		if (got == 0)
			return; /* EWOULDBLOCK -- resume on the next readable event */

		net_con_set_timeout(con, SEED_CC_TIMEOUT);
		budget -= (size_t) got;

		if (!cc_ingest_bytes(b, b->chunk, (size_t) got))
			return; /* finished or failed; b is gone either way */
	}
}

/*
 * Decide what an accepted connection is speaking, before a single byte reaches
 * the ADC state machine.
 *
 * Modelled on probe_net_event() in src/core/probe.c: peek (never consume) the
 * first bytes, and on a TLS ClientHello start a server handshake and carry on
 * with the ordinary CSUP exchange over the decrypted stream. net_ssl_callback()
 * drives the handshake and re-enters this connection's handler with
 * NET_EVENT_READ once it is established, at which point net_con_recv() returns
 * decrypted bytes -- so unlike the hub, which installs a new handler and has to
 * kick it, there is nothing to hand over here.
 *
 * @return 1 when the caller may go on and read the stream now, 0 when it must
 *         wait (more bytes, or a handshake in flight) or when @p b is gone.
 */
static int cc_probe_event(struct seed_cc_connection* b, struct net_connection* con)
{
	char peeked[SEED_CC_PROBE_SIZE];
	ssize_t bytes;
	ssize_t handshake;

	bytes = net_con_peek(con, peeked, sizeof(peeked));
	if (bytes < 0)
	{
		seed_cc_destroy(b);
		return 0;
	}

	switch (seed_cc_probe_classify(peeked, (size_t) bytes))
	{
		case SEED_CC_PROBE_MORE:
			/* Both backends are level triggered, so the unread bytes bring us
			   straight back once more of them arrive. */
			return 0;

		case SEED_CC_PROBE_PLAIN:
			b->probing = 0;
			LOG_DEBUG("seed_cc[accepted %s] plain ADC connection", ip_convert_to_string(&b->addr));
			return 1;

		case SEED_CC_PROBE_TLS:
			break;
	}

	b->probing = 0;
	b->use_tls = 1;

	LOG_DEBUG("seed_cc[accepted %s] TLS %d.%d connection; starting the handshake",
		ip_convert_to_string(&b->addr), (int) (unsigned char) peeked[9],
		(int) (unsigned char) peeked[10]);

	handshake = net_con_ssl_handshake(con, net_con_ssl_mode_server, b->policy->ssl_ctx);
	if (handshake < 0)
	{
		LOG_DEBUG("seed_cc[accepted %s] TLS handshake failed", ip_convert_to_string(&b->addr));
		seed_cc_destroy(b);
		return 0;
	}

	/* A handshake cannot normally complete on the ClientHello alone, but if it
	   does the decrypted bytes are already buffered and there is no further
	   event to wait for. */
	return handshake > 0;
}

static void cc_read_event(struct seed_cc_connection* b, struct net_connection* con)
{
	ssize_t bytes;

	if (b->probing && !cc_probe_event(b, con))
		return;

	if (b->state == CC_STATE_DL_BODY)
	{
		cc_read_body(b, con);
		return;
	}

	bytes = net_con_recv(con, b->line + b->line_len, (sizeof(b->line) - 1) - b->line_len);
	if (bytes < 0)
	{
		seed_cc_destroy(b);
		return;
	}
	if (bytes == 0)
		return; /* EWOULDBLOCK/EINTR -- wait for more */

	b->line_len += (size_t) bytes;
	net_con_set_timeout(con, SEED_CC_TIMEOUT);

	while (b->line_len)
	{
		size_t used = 0;
		int framed = seed_cc_take_line(b->line, b->line_len, &used);

		if (framed < 0)
		{
			LOG_DEBUG("seed_cc: oversized or malformed line from %s", ip_convert_to_string(&b->addr));
			seed_cc_destroy(b);
			return;
		}
		if (framed == 0)
			break; /* incomplete; wait for the rest */

		if (!cc_handle_line(b, b->line, used))
			return; /* destroyed */

		b->line_len -= used;
		if (b->line_len)
			memmove(b->line, b->line + used, b->line_len);

		if (b->close_after_flush)
		{
			/* Already decided to hang up: whatever the peer pipelined behind the
			   command that lost it the connection is not acted on. */
			b->line_len = 0;
			break;
		}

		if (b->state == CC_STATE_DL_BODY)
		{
			/* Whatever followed the CSND line is already body. */
			size_t rest = b->line_len;
			b->line_len = 0;
			if (rest && !cc_ingest_bytes(b, b->line, rest))
				return;
			break;
		}

		if (b->state == CC_STATE_SENDING)
		{
			/* Anything the peer pipelined behind its CGET is dropped: the
			   connection is closed once the body is out. */
			b->line_len = 0;
			break;
		}
	}

	cc_update_events(b);
}

static void cc_write_event(struct seed_cc_connection* b, struct net_connection* con)
{
	size_t budget = SEED_CC_WRITE_BUDGET;

	while (cc_out_pending(b))
	{
		size_t total = cbuf_size(b->out);
		ssize_t sent = net_con_send(con, cbuf_get(b->out) + b->out_sent, total - b->out_sent);

		if (sent < 0)
		{
			seed_cc_destroy(b);
			return;
		}
		if (sent == 0)
			return; /* EWOULDBLOCK -- resume on the next writable event */

		b->out_sent += (size_t) sent;
		net_con_set_timeout(con, SEED_CC_TIMEOUT);

		if (b->out_sent >= cbuf_size(b->out))
		{
			cbuf_destroy(b->out);
			b->out = NULL;
			b->out_sent = 0;
		}
	}

	if (b->close_after_flush)
	{
		seed_cc_destroy(b);
		return;
	}

	if (b->state != CC_STATE_SENDING)
	{
		cc_update_events(b);
		return;
	}

	while (b->remaining > 0 || b->chunk_sent < b->chunk_len)
	{
		if (budget == 0)
			return; /* yield the reactor; level triggered, so we come straight back */

		if (b->chunk_sent == b->chunk_len)
		{
			size_t want = SEED_CC_CHUNK;
			ssize_t got;

			if ((uint64_t) want > b->remaining)
				want = (size_t) b->remaining;

			got = seed_cache_read(b->policy->cache, b->fd, b->entry_size, b->offset, b->chunk, want);
			if (got <= 0)
			{
				/* The file shrank or the read failed. The CSND header is already
				   out, so there is no way to report this other than by cutting
				   the connection short. */
				LOG_WARN("seed_cc: read failed for TTH=%s at offset %" PRIu64, b->pin_tth, b->offset);
				seed_cc_destroy(b);
				return;
			}

			b->chunk_len = (size_t) got;
			b->chunk_sent = 0;
			b->offset += (uint64_t) got;
			b->remaining -= (uint64_t) got;
		}

		while (b->chunk_sent < b->chunk_len)
		{
			ssize_t sent = net_con_send(con, b->chunk + b->chunk_sent, b->chunk_len - b->chunk_sent);
			if (sent < 0)
			{
				seed_cc_destroy(b);
				return;
			}
			if (sent == 0)
				return; /* EWOULDBLOCK */

			b->chunk_sent += (size_t) sent;
			net_con_set_timeout(con, SEED_CC_TIMEOUT);
			budget = ((size_t) sent >= budget) ? 0 : budget - (size_t) sent;
		}
	}

	/* One transfer per connection: the peer gets what it asked for and the
	   socket goes away with it, which is also what releases the pin and the
	   descriptor. */
	seed_cc_destroy(b);
}

static void seed_cc_net_event(struct net_connection* con, int events, void* arg)
{
	struct seed_cc_connection* b = (struct seed_cc_connection*) arg;

	/* NET_EVENT_ERROR is how the TLS layer reports a handshake that failed or a
	   peer that went away mid-handshake; without it such a connection would sit
	   idle until its timeout. */
	if (events & (NET_EVENT_TIMEOUT | NET_EVENT_ERROR))
	{
		seed_cc_destroy(b);
		return;
	}

	if (events & NET_EVENT_WRITE)
	{
		cc_write_event(b, con);
		return;
	}

	if (events & NET_EVENT_READ)
		cc_read_event(b, con);
}

/* Everything a connection needs before it is worth accepting or dialling. */
static int cc_policy_usable(const struct seed_cc_policy* policy)
{
	if (!policy || !policy->cache || !policy->grants)
		return 0;

	/* Without our own CID there is no CINF to send, so no peer could ever
	   identify us -- and nothing we issued could be quoted back. */
	if (!policy->cid || strlen(policy->cid) != SEED_CID_LEN)
		return 0;

	return 1;
}

int seed_cc_accept(const struct seed_cc_policy* policy, struct net_connection* con,
	const struct ip_addr_encap* addr)
{
	struct seed_cc_connection* b;

	if (!con || !addr || !cc_policy_usable(policy))
		return 0;

	b = (struct seed_cc_connection*) hub_malloc_zero(sizeof(struct seed_cc_connection));
	if (!b)
		return 0; /* OOM -- the caller still owns the connection */

	LOG_TRACE("seed_cc_accept(): %p from %s", (void*) b, ip_convert_to_string(addr));

	b->policy = policy;
	b->connection = con;
	b->state = CC_STATE_SUP;
	b->fd = -1;
	/* With a certificate the same port serves ADCS and plain ADC, so the first
	   bytes decide which; without one there is nothing to unwrap TLS with and
	   the stream is read as ADC straight away. */
	b->probing = policy->ssl_ctx ? 1 : 0;
	memcpy(&b->addr, addr, sizeof(struct ip_addr_encap));

	net_con_reinitialize(con, seed_cc_net_event, b, NET_EVENT_READ);
	net_con_set_timeout(con, SEED_CC_TIMEOUT);
	LOG_INFO("seed_cc[accepted %s] inbound connection; waiting for %s",
		ip_convert_to_string(addr),
		b->probing ? "a TLS ClientHello or the peer's CSUP" : "the peer's CSUP");
	return 1;
}

/* -- dialling out to an active peer ----------------------------------------- */

int seed_cc_protocol_ok(const char* protocol, int* use_tls)
{
	if (!protocol)
		return 0;

	if (strcmp(protocol, ADC_CC_PROTOCOL_PLAIN) == 0)
	{
		if (use_tls)
			*use_tls = 0;
		return 1;
	}

	/* Both revisions name a TLS connection; nothing below this layer cares
	   which of them the peer used to ask for it. */
	if (strcmp(protocol, ADC_CC_PROTOCOL_TLS) == 0 || strcmp(protocol, ADC_CC_PROTOCOL_TLS_1) == 0)
	{
		if (use_tls)
			*use_tls = 1;
		return 1;
	}

	return 0;
}

int seed_cc_port_ok(uint16_t port)
{
	/*
	 * A DC client never listens below 1024, and dialling a privileged port on
	 * an address of the caller's choosing is a useful primitive to hand nobody.
	 */
	return port >= 1024;
}

int seed_cc_may_dial(const struct seed_cc_policy* policy, const struct seed_cc_peer* peer)
{
	if (!cc_policy_usable(policy))
		return 0;

	if (!peer || !peer->addr || !peer->cid || strlen(peer->cid) != SEED_CID_LEN)
		return 0;

	/*
	 * The address dialled must be one the hub observed for itself. A peer the
	 * hub lets name its own address (nat_override) is the exception: that
	 * address is unproven, so dialling it would let them aim our connections at
	 * a third party.
	 */
	if (peer->addr_is_client_supplied)
		return 0;

	return 1;
}

static void cc_connect_cb(struct net_connect_handle* handle, enum net_connect_status status,
	struct net_connection* con, void* ptr)
{
	struct seed_cc_connection* b = (struct seed_cc_connection*) ptr;

	(void) handle;

	b->connect_job = NULL; /* the handle destroys itself once this returns */
	if (seed_cc_connecting > 0)
		seed_cc_connecting--;

	if (status != net_connect_status_ok)
	{
		LOG_INFO("seed_cc[dialled %s] connect failed (status %d)",
			ip_convert_to_string(&b->addr), (int) status);
		seed_cc_destroy(b);
		return;
	}

	LOG_INFO("seed_cc[dialled %s] connected%s; we speak first",
		ip_convert_to_string(&b->addr), b->use_tls ? " (starting TLS)" : "");

	b->connection = con;
	net_con_reinitialize(con, seed_cc_net_event, b, NET_EVENT_READ | NET_EVENT_WRITE);
	net_con_set_timeout(con, SEED_CC_TIMEOUT);

	if (b->use_tls)
	{
		/*
		 * No certificate verification: a DC client presents a self-signed
		 * certificate, so requiring a chain would refuse every transfer. The
		 * peer is identified by the CID in its CINF instead.
		 */
		net_con_ssl_handshake(con, net_con_ssl_mode_client, b->ssl_ctx);
	}

	/* We connected, so we speak first. */
	if (!cc_queue(b, "CSUP ADBASE ADTIGR\n"))
		return;

	cc_update_events(b);
}

int seed_cc_connect_to_peer(const struct seed_cc_policy* policy, const struct seed_cc_peer* peer,
	const char* protocol, uint16_t port, const char* token)
{
	struct seed_cc_connection* b;
	int use_tls = 0;

	if (!seed_cc_may_dial(policy, peer))
		return 0;

	if (!token || !*token || strlen(token) > SEED_TOKEN_MAX)
		return 0;

	if (!seed_cc_protocol_ok(protocol, &use_tls))
	{
		LOG_DEBUG("seed_cc: refusing to dial %s: unsupported protocol \"%s\"",
			peer->cid, protocol ? protocol : "");
		return 0;
	}

	if (!seed_cc_port_ok(port))
	{
		LOG_DEBUG("seed_cc: refusing to dial %s on port %u", peer->cid, (unsigned) port);
		return 0;
	}

	if (seed_cc_connecting >= SEED_CC_MAX_CONNECTING)
		return 0;

	/* An outbound transfer occupies exactly the same upload slot as an inbound
	   one, so it is charged against the same cap, from the moment we dial. */
	if (policy->max_concurrent_upload > 0 && seed_cc_uploads >= policy->max_concurrent_upload)
		return 0;

	b = (struct seed_cc_connection*) hub_malloc_zero(sizeof(struct seed_cc_connection));
	if (!b)
		return 0;

	b->policy = policy;
	b->state = CC_STATE_SUP;
	b->fd = -1;
	b->initiator = 1;
	b->use_tls = use_tls;
	memcpy(&b->addr, peer->addr, sizeof(struct ip_addr_encap));
	strncpy(b->token, token, SEED_TOKEN_MAX);
	memcpy(b->peer_cid, peer->cid, SEED_CID_LEN + 1);

	seed_cc_uploads++;
	b->counted = 1;

	if (use_tls)
	{
		b->ssl_ctx = net_ssl_context_create(policy->tls_version,
			policy->tls_ciphersuite, policy->tls_ciphersuites);
		if (!b->ssl_ctx)
		{
			seed_cc_destroy(b);
			return 0;
		}
	}

	seed_cc_connecting++;
	b->connect_job = net_con_connect(ip_convert_to_string(&b->addr), port, cc_connect_cb, b);
	if (!b->connect_job)
	{
		seed_cc_connecting--;
		seed_cc_destroy(b);
		return 0;
	}

	LOG_INFO("seed_cc[dialled %s] connecting on port %u for %s (%s)",
		ip_convert_to_string(&b->addr), (unsigned) port, peer->cid, protocol);
	return 1;
}

/* -- asking a peer for content --------------------------------------------- */

int seed_cc_request_token(const struct seed_cc_policy* policy, const char* cid,
	const char* tth, uint64_t size, const char* name, char out_token[SEED_TOKEN_MAX + 1])
{
	char token[SEED_TOKEN_MAX + 1];
	time_t now;

	if (!out_token)
		return 0;

	out_token[0] = '\0';

	if (!cc_policy_usable(policy) || !cid || !tth)
		return 0;

	if (!cc_valid_tth(tth))
		return 0;

	if (seed_cache_is_blocked(policy->cache, tth))
		return 0;

	if (seed_cache_peek(policy->cache, tth, NULL))
		return 0; /* already held; asking is not an access */

	now = time(NULL);

	if (!seed_cc_quota_allow(policy, cid, size, now))
	{
		LOG_DEBUG("seed_cc: ingest quota reached for %s", cid);
		return 0;
	}

	if (seed_grant_count(policy->grants) >= SEED_CC_MAX_GRANTS)
	{
		LOG_DEBUG("seed_cc: too many outstanding connection grants; not requesting content");
		return 0;
	}

	if (!seed_grant_make_token(token))
		return 0;

	if (!seed_grant_issue_download(policy->grants, token, cid, tth, size, name, now))
		return 0;

	memcpy(out_token, token, sizeof(token));
	LOG_DEBUG("seed_cc: prepared a request to %s for TTH=%s", cid, tth);
	return 1;
}

size_t seed_cc_active_uploads(void)
{
	return seed_cc_uploads;
}
