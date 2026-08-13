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

#ifndef HAVE_UHUB_SEEDER_CC_H
#define HAVE_UHUB_SEEDER_CC_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "adc/adcconst.h"
#include "seeder/cache.h"
#include "seeder/grant.h"

struct net_connection;
struct ip_addr_encap;
struct ssl_context_handle;

/**
 * ADC client-to-client ('C' context) transfers for cached files.
 *
 * This is the DC-native counterpart to seeder/http.c: instead of an HTTP GET, a
 * peer opens a client connection to the seeder's own transfer port and runs the
 * ordinary CSUP / CINF / CGET / CSND exchange over it.
 *
 * Two roles run over the same connection, decided by the grant quoted in the
 * CINF:
 *
 *   upload     the seeder is the source; the peer CGETs a cached file.
 *   download   the seeder is the sink; it CGETs content it asked a peer for
 *              (see seed_cc_request_token) and ingests the reply.
 *
 * Either role can run in either direction on the wire. The seeder serves
 * connections it accepted, and dials out to a peer that asked it to
 * (seed_cc_connect_to_peer) -- an active downloader's CTM.
 *
 * SECURITY: the transfer port is reachable, pre-authentication, by anyone who
 * can open a socket to it. Nothing is served and nothing is ingested without a
 * live connection grant (seeder/grant.h), and every line is parsed
 * length-bounded through adc_msg_parse_client(), which accepts the 'C' context
 * only.
 *
 * This module knows nothing about the hub connection or the user roster on
 * purpose: identity arrives as a plain CID and address from the caller. That
 * keeps the state machine drivable over a bare socket in a test, and keeps
 * seeder/hubconn.c free to depend on this without a cycle.
 */

/** Longest client-to-client line accepted; ADC's own command length limit. */
#define SEED_CC_LINE_MAX MAX_ADC_CMD_LEN

/** "to the end of the file" in a CGET/CSND length field. */
#define SEED_CC_TO_EOF ((int64_t) -1)

/*
 * Status codes the seeder answers with. seed_cc_format_status() prefixes the
 * severity digit, which is always 1 (recoverable): the seeder never tells a peer
 * its session is broken because one request could not be served. In particular
 * "no leaf hashes" MUST stay recoverable, or clients abort the download instead
 * of falling back to a plain file GET.
 */
#define SEED_CC_STATUS_BAD_COMMAND  40 /** Unexpected or unsupported command. */
#define SEED_CC_STATUS_UNAUTHORIZED 41 /** Missing, expired or wrong-CID token. */
#define SEED_CC_STATUS_NO_FILE      51 /** Not cached, or blocked. */
#define SEED_CC_STATUS_NO_TTHL      51 /** Leaf hashes are not kept. */
#define SEED_CC_STATUS_BAD_RANGE    52 /** Range not satisfiable. */
#define SEED_CC_STATUS_SLOTS_FULL   53 /** Concurrent upload limit reached. */

/**
 * Format a CSTA line for @p code. Pure.
 *
 * @param description must already be ADC-escaped.
 * @return the number of bytes written, or 0 if it did not fit.
 */
extern size_t seed_cc_format_status(char* buf, size_t size, int code, const char* description);

/** What a parsed client-to-client line asks for. */
enum seed_cc_type
{
	SEED_CC_INVALID = 0, /** Not a valid 'C' context command at all: drop the connection. */
	SEED_CC_UNSUPPORTED, /** A valid line the seeder does not serve (-> CSTA 140). */
	SEED_CC_SUP,         /** CSUP: feature negotiation. */
	SEED_CC_INF,         /** CINF: identification, and the connection grant. */
	SEED_CC_GET_FILE,    /** CGET file TTH/<b32> <start> <bytes> */
	SEED_CC_GET_TTHL,    /** CGET tthl ...: deliberately not served (-> CSTA 151). */
	SEED_CC_GFI,         /** CGFI file TTH/<b32>: metadata only. */
	SEED_CC_SND,         /** CSND: the peer is about to send a body. */
	SEED_CC_STA          /** CSTA: the peer reported a status/error. */
};

/** Everything the connection handler needs out of one parsed line. */
struct seed_cc_request
{
	enum seed_cc_type type;
	char     tth[SEED_TTH_STR_LEN + 1];  /** GET/GFI/SND identifier, "" if none. */
	char     cid[SEED_CID_LEN + 1];      /** CINF ID, "" if absent. */
	char     token[SEED_TOKEN_MAX + 1];  /** CINF TO, "" if absent. Kept ADC-escaped. */
	int      have_base;                  /** CSUP advertised BASE. */
	int      have_tigr;                  /** CSUP advertised TIGR. */
	uint64_t start;                      /** GET/SND first byte. */
	int64_t  bytes;                      /** GET/SND length, or SEED_CC_TO_EOF. */
	int      status;                     /** CSTA code, 0 if not a CSTA. */
};

/**
 * Parse one client-to-client line.
 *
 * Pure: no I/O, no globals. The line is read length-bounded and is never
 * required to be NUL terminated; an embedded NUL, a line longer than
 * SEED_CC_LINE_MAX, and anything adc_msg_parse_client() rejects (which is every
 * hub context, all invalid UTF-8 and every bad escape) come back as
 * SEED_CC_INVALID.
 *
 * A command that parses but that the seeder does not serve -- an unknown fourcc,
 * a CGET for something other than "file"/"tthl", a malformed TTH, an unparsable
 * offset -- is reported as SEED_CC_UNSUPPORTED rather than as a parse failure,
 * so the caller can answer it with a status message instead of hanging up.
 *
 * @param out filled in on every call; never left partially written.
 * @return 1 when the line is a valid 'C' context command, 0 otherwise.
 */
extern int seed_cc_parse(const char* line, size_t length, struct seed_cc_request* out);

/**
 * Frame one '\n' terminated line out of a receive buffer.
 *
 * Pure. @p len is the number of bytes buffered so far.
 *
 * @param out_len receives the length of the line including its terminator.
 * @return  1 when a complete line is available,
 *          0 when more bytes are needed,
 *         -1 when the buffer can no longer become a valid line (no terminator
 *            within SEED_CC_LINE_MAX bytes, or an embedded NUL): drop the
 *            connection.
 */
extern int seed_cc_take_line(const char* buf, size_t len, size_t* out_len);

/**
 * Validate a requested byte range against the size of a cached file.
 *
 * A @p bytes of SEED_CC_TO_EOF means "to the end of the file". An unsatisfiable
 * range is refused outright -- a short body would be indistinguishable from a
 * truncated transfer to the peer, which then caches a corrupt file.
 *
 * @param out_len receives the number of bytes to transfer. May be NULL.
 * @return 1 when the range is satisfiable.
 */
extern int seed_cc_range_ok(uint64_t size, uint64_t start, int64_t bytes, uint64_t* out_len);

/**
 * Everything this module is allowed to decide with.
 *
 * The daemon fills one of these in from its configuration and passes it to every
 * entry point; the connection keeps the pointer, so it -- and every string in it
 * -- must outlive the connections started with it. There is deliberately no path
 * from here back into a hub, a roster or a config parser: what a peer is
 * permitted to do is decided by the caller and handed over as data.
 */
struct seed_cc_policy
{
	struct seed_cache*  cache;   /** What is served, and what is ingested into. */
	struct seed_grants* grants;  /** The only thing that authorises a connection. */

	/** Our own CID, as the hub knows us; sent in our CINF. Required. */
	const char* cid;

	/** Concurrent uploads across this module. 0 means no limit. */
	size_t max_concurrent_upload;

	/*
	 * Per-peer ingest quota, over a sliding window. Mirrors the seed_ingest_*
	 * configuration keys. An interval of 0, or both limits at 0, switches the
	 * quota off.
	 */
	int ingest_interval;  /** Window, in seconds. */
	int ingest_per_user;  /** Files per window, 0 = unlimited. */
	int ingest_quota_kb;  /** KiB per window, 0 = unlimited. */

	/* TLS parameters for an outbound ADCS dial. NULL selects the defaults. */
	const char* tls_version;
	const char* tls_ciphersuite;
	const char* tls_ciphersuites;

	/**
	 * Server context for inbound connections, or NULL when the seeder has no
	 * certificate. It is owned by the daemon and is never destroyed by this
	 * module -- unlike the throwaway client context a TLS dial creates for
	 * itself.
	 *
	 * When it is set the transfer port accepts ADCS and plain ADC on the same
	 * socket (see seed_cc_probe_classify), and ADCS is what the seeder offers
	 * in a CTM. When it is NULL an inbound TLS ClientHello is just an ADC line
	 * that fails to parse, and the connection is dropped.
	 */
	struct ssl_context_handle* ssl_ctx;
};

/**
 * Would caching @p size more bytes for @p cid stay within the per-peer ingest
 * limits?
 *
 * The window is measured against what the cache already holds for that CID, so
 * there is no per-peer bookkeeping to keep in sync with eviction: content that
 * has been evicted no longer counts against whoever contributed it.
 *
 * @return 1 when a further ingest is permitted.
 */
extern int seed_cc_quota_allow(const struct seed_cc_policy* policy, const char* cid,
                               uint64_t size, time_t now);

/** What the first bytes of an inbound connection turned out to be. */
enum seed_cc_probe
{
	SEED_CC_PROBE_MORE = 0, /** Too few bytes to tell yet; peek again later. */
	SEED_CC_PROBE_TLS,      /** A TLS ClientHello: handshake, then speak ADC. */
	SEED_CC_PROBE_PLAIN     /** Anything else: an ADC line, or a line that will fail as one. */
};

/**
 * Classify the first bytes of an inbound connection. Pure.
 *
 * The transfer port serves ADCS and plain ADC on the same socket, exactly as
 * the hub's port does, so which one this is has to be read off the wire. This
 * is the same test probe_classify() makes in src/core/probe.c; it is duplicated
 * rather than shared because linking that file into the seeder would drag in
 * the whole hub.
 *
 * A buffer that cannot begin a TLS record is reported as PLAIN immediately, so
 * a peer that sends a short ADC line and waits is never left waiting for bytes
 * that were only needed to rule TLS out.
 */
extern enum seed_cc_probe seed_cc_probe_classify(const char* buf, size_t len);

/**
 * The client-to-client protocol the seeder can be reached with: ADCS/0.10 when
 * @p policy carries a server context, ADC/1.0 otherwise. This is what belongs
 * in a CTM the seeder sends, and what an RCM asking for ADCS may be answered
 * with.
 */
extern const char* seed_cc_offered_protocol(const struct seed_cc_policy* policy);

/**
 * Adopt an inbound client-to-client connection.
 *
 * The caller must relinquish ownership of @p con when this returns 1; when it
 * returns 0 nothing was adopted and the caller still owns the connection.
 *
 * A connection adopted while policy->ssl_ctx is set is not read as ADC until
 * seed_cc_probe_classify() has seen its first bytes, and a TLS handshake it
 * asks for has completed.
 *
 * @return 1 if adopted.
 */
extern int seed_cc_accept(const struct seed_cc_policy* policy, struct net_connection* con,
                          const struct ip_addr_encap* addr);

/**
 * A peer, as far as this module needs to know one.
 *
 * This replaces the hub's struct hub_user: identity is a CID and an address the
 * caller vouches for, not a roster entry.
 */
struct seed_cc_peer
{
	/** The CID the peer must present in its CINF. Required. */
	const char* cid;

	/**
	 * Where to dial. This must be the address the *hub* reported for the peer,
	 * which the hub overwrote with the one it observed (see check_network() in
	 * src/core/inf.c) -- never an address taken out of a CTM.
	 */
	const struct ip_addr_encap* addr;

	/**
	 * Set when even the hub's address for this peer is client-supplied, i.e.
	 * the peer is covered by the hub's nat_override. Such an address is
	 * unproven, so dialling it would let the peer aim the seeder's connections
	 * at a third party; seed_cc_may_dial() refuses it.
	 */
	int addr_is_client_supplied;
};

/*
 * The protocol strings carried by CTM and RCM. Note these are not the INF SU
 * feature token "ADCS" (or its older spelling "ADC0"), which says a client
 * understands encrypted client-to-client connections -- these name the protocol
 * to speak on the connection itself. The "0.10" is why that older token exists:
 * both predate ADCS 1.0.
 */
#ifndef ADC_CC_PROTOCOL_PLAIN
#define ADC_CC_PROTOCOL_PLAIN "ADC/1.0"
#endif
#ifndef ADC_CC_PROTOCOL_TLS
#define ADC_CC_PROTOCOL_TLS   "ADCS/0.10"
#endif
#ifndef ADC_CC_PROTOCOL_TLS_1
#define ADC_CC_PROTOCOL_TLS_1 "ADCS/1.0"
#endif

/**
 * @return 1 if @p protocol is one the seeder's client connections speak, and set
 *         @p use_tls accordingly. @p use_tls may be NULL.
 *
 * Both TLS spellings are accepted. They name the same thing on the wire -- the
 * connection is TLS either way -- and differ only in which revision of the ADCS
 * extension the peer knows about.
 */
extern int seed_cc_protocol_ok(const char* protocol, int* use_tls);

/**
 * Pick the protocol for a transfer with a peer, from what that peer advertised
 * and what (if anything) it asked for.
 *
 * The decision is driven by capability, not by the request. A client that
 * advertises ADCS or ADC0 has said it does encrypted transfers, and real ones
 * -- QuickDC among them -- then expect every connection with that peer to be
 * TLS whatever protocol string appears in the CTM or RCM. Answering such a peer
 * in plain because it happened to name ADC/1.0 produces a connection neither
 * side wants.
 *
 * So: TLS whenever the seeder has a certificate and the peer claims either
 * token. An explicit request only chooses the revision -- ADCS/0.10 and
 * ADCS/1.0 are the same thing on the wire -- and is honoured as sent, since a
 * peer that names a revision has told us which one it speaks. Absent a request,
 * the current token gets the current revision and the older token gets the
 * older one: naming a revision the peer has never heard of loses the transfer
 * as surely as naming TLS with no certificate behind it.
 *
 * @param support   the peer's SU value; NULL or "" means it advertised none.
 * @param requested the protocol from its CTM or RCM, or NULL when the seeder is
 *                  the one initiating and nothing has been requested.
 */
extern const char* seed_cc_protocol_for_peer(const struct seed_cc_policy* policy,
                                             const char* support, const char* requested);

/**
 * @return 1 if @p support (an SU feature list) contains @p feature, which must
 *         be a four character token. Comparison is on whole tokens, so "ADCS"
 *         does not match inside some longer name.
 */
extern int seed_cc_support_has(const char* support, const char* feature);

/** @return 1 if @p port is one the seeder is willing to dial. */
extern int seed_cc_port_ok(uint16_t port);

/** @return 1 if the seeder may open a client connection to @p peer. */
extern int seed_cc_may_dial(const struct seed_cc_policy* policy, const struct seed_cc_peer* peer);

/**
 * Connect out to a peer that asked the seeder to connect to it -- an active
 * downloader's CTM -- and serve it as an upload connection.
 *
 * Because the seeder received the connect request, it is the seeder that carries
 * @p token in its CINF.
 *
 * @return 1 if the attempt was started.
 */
extern int seed_cc_connect_to_peer(const struct seed_cc_policy* policy,
                                   const struct seed_cc_peer* peer,
                                   const char* protocol, uint16_t port, const char* token);

/**
 * Prepare to ask @p cid to hand over @p tth: mint a token and record a download
 * grant for it.
 *
 * Sending the CTM (or RCM) that quotes the token is the caller's job -- this
 * module has no hub connection. If the peer never turns up, the grant simply
 * expires and nothing is cached.
 *
 * Refuses when the content is blocked, already cached, over the peer's ingest
 * quota, or when too many grants are already outstanding. Whether the peer holds
 * credentials enough to make the seeder spend disk on their behalf is the
 * caller's decision: it is the caller, not this module, that knows the roster.
 *
 * @param size the announced size, or 0 when unknown.
 * @param name the display name, or NULL.
 * @param out_token receives the minted token. Always NUL terminated.
 * @return 1 if a grant was issued.
 */
extern int seed_cc_request_token(const struct seed_cc_policy* policy, const char* cid,
                                 const char* tth, uint64_t size, const char* name,
                                 char out_token[SEED_TOKEN_MAX + 1]);

/** Transfers currently occupying an upload slot. */
extern size_t seed_cc_active_uploads(void);

#endif /* HAVE_UHUB_SEEDER_CC_H */
