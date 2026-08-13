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

#ifndef HAVE_UHUB_ADC_CLIENT_H
#define HAVE_UHUB_ADC_CLIENT_H

#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "util/tiger.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "network/connection.h"
#include "network/network.h"
#include "network/notify.h"
#include "core/ioqueue.h"
#include "core/user.h"

#define ADC_BUFSIZE 16384

/**
 * Room for an ADC keyprint: "SHA256/" plus the 52 base32 characters of a
 * SHA-256 digest, plus the terminator.
 */
#define ADC_KEYPRINT_MAX 64

/** Room for an SU feature list, including the terminating NUL. */
#define ADC_SUPPORT_MAX 64

struct ADC_client;

/**
 * Security contract of this transport
 * ===================================
 *
 * An "adcs://" URL gets a TLS connection, but TLS on its own only says the
 * connection is private -- not who is on the other end of it. This client trusts
 * the hub with a great deal: the CT bits that decide whether a peer may command
 * it, the addresses it is told to dial, and (when a password is configured) a
 * challenge it answers with tiger(password + challenge). An attacker who can
 * intercept the connection and is not authenticated away gets all of that.
 *
 * The hub is therefore authenticated by *keyprint pinning*, not by the public
 * CA system: an ADC hub's certificate is normally self-signed, and the hub
 * publishes the fingerprint of it in its own URL:
 *
 *     adcs://hub.example.org:1511/?kp=SHA256/<52 base32 characters>
 *
 * When the URL passed to ADC_client_connect() carries such a "kp=", the peer
 * certificate is fingerprinted once the handshake completes and compared
 * against it; a mismatch (or a hub that presents no certificate at all) aborts
 * the connection before a single byte of ADC is exchanged, and is reported as
 * ADC_CLIENT_SSL_KEYPRINT_ERROR. A keyprint naming a hash algorithm this build
 * does not implement, or one that is not a well-formed keyprint, is refused by
 * ADC_client_connect() rather than ignored.
 *
 * When the URL carries no "kp=", the connection is encrypted but
 * **unauthenticated** -- exactly as interceptable as it has always been. This
 * is permitted (it is the only thing that works against a hub whose keyprint
 * the operator does not know, and uhub-admin and adcrush rely on it) but it is
 * not silent: a warning naming the hub is logged on the first connect. Any
 * deployment that cares about the integrity of the hub link should pin a
 * keyprint. A plain "adc://" URL is unencrypted and unauthenticated and warns
 * for neither.
 */

/**
 * Events delivered to the adc_client_cb callback.
 *
 * Each event names the member of struct ADC_client_callback_data that is
 * valid for it; every other member of the union is undefined. Events
 * documented as "no data" are invoked with a NULL data pointer, and a few
 * events may pass NULL even though they normally carry data (noted below),
 * so a callback must always check the pointer before dereferencing it.
 *
 * All payloads -- including the strings inside them -- are owned by the
 * client and are only valid for the duration of the callback. A consumer
 * that needs to keep anything must copy it.
 */
enum ADC_client_callback_type
{
	ADC_CLIENT_NAME_LOOKUP      = 1000, /* no data (not currently emitted) */
	ADC_CLIENT_CONNECTING       = 1001, /* no data */
	ADC_CLIENT_CONNECTED        = 1002, /* no data */
	ADC_CLIENT_DISCONNECTED     = 1003, /* no data */
	ADC_CLIENT_SSL_HANDSHAKE    = 1101, /* no data */
	ADC_CLIENT_SSL_OK           = 1102, /* data->tls_info */
	ADC_CLIENT_SSL_KEYPRINT_ERROR
	                            = 1103, /* data->keyprint; the hub did not present
	                                       the pinned certificate, so the
	                                       connection was dropped without logging
	                                       in. Always followed by
	                                       ADC_CLIENT_DISCONNECTED. This is a
	                                       configuration error or an interception
	                                       attempt, never a transient fault: a
	                                       consumer that reconnects on
	                                       DISCONNECTED must stop when it sees
	                                       this. */

	ADC_CLIENT_LOGGING_IN       = 2001, /* no data */
	ADC_CLIENT_PASSWORD_REQ     = 2002, /* no data */
	ADC_CLIENT_LOGGED_IN        = 2003, /* no data */
	ADC_CLIENT_LOGIN_ERROR      = 2004, /* data->status, but NULL when the
	                                       failure is local (no password
	                                       configured for a hub asking for
	                                       one) rather than a hub status. */

	ADC_CLIENT_PROTOCOL_STATUS  = 3001, /* data->status */
	ADC_CLIENT_MESSAGE          = 3002, /* data->chat */
	ADC_CLIENT_CONNECT_REQ      = 3003, /* data->message (CTM) */
	ADC_CLIENT_REVCONNECT_REQ   = 3004, /* data->message (RCM) */
	ADC_CLIENT_SEARCH_REQ       = 3005, /* data->message (SCH) */
	ADC_CLIENT_SEARCH_REP       = 3006, /* data->message (RES) */

	ADC_CLIENT_USER_JOIN        = 4001, /* data->user */
	ADC_CLIENT_USER_QUIT        = 4002, /* data->quit */
	ADC_CLIENT_USER_UPDATE      = 4003, /* no data (not currently emitted) */

	ADC_CLIENT_HUB_INFO         = 5001, /* data->hubinfo */

	/* Every line received from the hub, raw, before it is dispatched. Set only
	   by tests that need to observe commands this client does not model -- the
	   BBS0 descriptors and index entries, for instance. */
	ADC_CLIENT_RAW_LINE         = 6001,
};

struct ADC_hub_info
{
	char* name;
	char* description;
	char* version;
};

enum ADC_chat_message_flags
{
	chat_flags_none = 0,
	chat_flags_action = 1,
	chat_flags_private = 2
};

struct ADC_chat_message
{
	sid_t from_sid;
	sid_t to_sid;
	char* message;
	int flags;
};

#define MAX_DESC_LEN 128
struct ADC_user
{
	sid_t sid;
	char cid[MAX_CID_LEN+1];
	char name[MAX_NICK_LEN+1];
	char description[MAX_DESC_LEN+1];
	char address[INET6_ADDRSTRLEN+1];
	char version[MAX_UA_LEN+1];

	/**
	 * The CT (client type) bits from the user's INF: 1 bot, 2 registered,
	 * 4 operator, 8 super, 16 admin, 32 the hub itself. It is a mask, so an
	 * operator that is also a bot has both bits set -- test with '&'. Zero
	 * when the user advertised no CT at all, which is the ordinary case for
	 * an unregistered user.
	 */
	int client_type;

	/**
	 * The SU (support) feature list from the user's INF, verbatim: a comma
	 * separated list of four character tokens such as "TCP4,UDP4,ADCS". Empty
	 * when the user advertised none.
	 *
	 * This is what says whether a peer can be connected to at all (TCP4/TCP6)
	 * and whether it understands encrypted client-to-client transfers (ADCS,
	 * or ADC0 in the spelling that predates ADCS 1.0).
	 */
	char support[ADC_SUPPORT_MAX];
};

/**
 * Parse the value of an ADC CT argument into client-type bits.
 *
 * @param ct the argument value, or NULL.
 * @return the bits, or 0 when @p ct is NULL, empty or not a number.
 */
int ADC_client_parse_client_type(const char* ct);

struct ADC_client_quit_reason
{
	sid_t sid;
	sid_t initator; // 0 = default/hub.
	char message[128]; // optional
	int flags;
};

struct ADC_client_tls_info
{
	const char* cipher;
	const char* version;
};

/** Why a pinned hub failed verification. Both strings are NUL-terminated and
    may be "" -- notably `presented` is empty when the hub sent no certificate. */
struct ADC_client_keyprint_error
{
	const char* expected;   /* the "kp=" from the hub URL */
	const char* presented;  /* what the hub actually presented, or "" */
};

struct ADC_client_status
{
	int code;       /* full 3-digit ADC status code */
	int severity;   /* 0 = success, 1 = recoverable, 2 = fatal */
	char* message;
};

/**
 * Payload for one callback invocation. Which member is valid is determined
 * entirely by the enum ADC_client_callback_type the callback was invoked
 * with -- see the per-event comments on that enum.
 */
struct ADC_client_callback_data
{
	union {
		struct ADC_hub_info* hubinfo;         /* ADC_CLIENT_HUB_INFO */
		struct ADC_chat_message* chat;        /* ADC_CLIENT_MESSAGE */
		struct ADC_user* user;                /* ADC_CLIENT_USER_JOIN */
		struct ADC_client_quit_reason* quit;  /* ADC_CLIENT_USER_QUIT */
		struct ADC_client_tls_info* tls_info; /* ADC_CLIENT_SSL_OK */
		struct ADC_client_keyprint_error* keyprint; /* ADC_CLIENT_SSL_KEYPRINT_ERROR */
		struct ADC_client_status* status;     /* ADC_CLIENT_PROTOCOL_STATUS, ADC_CLIENT_LOGIN_ERROR */
		const char* line;                     /* ADC_CLIENT_RAW_LINE */

		/* The raw parsed command, for the events that have no richer payload:
		   ADC_CLIENT_SEARCH_REQ, ADC_CLIENT_SEARCH_REP, ADC_CLIENT_CONNECT_REQ
		   and ADC_CLIENT_REVCONNECT_REQ. The search/CTM/RCM grammar belongs to
		   the consumer, not to this transport, so the arguments are left
		   unparsed here.

		   The message is owned by the client and is freed as soon as the
		   callback returns: it is valid for the duration of the call only.
		   Do not retain the pointer, free it, or take a reference to it --
		   copy out whatever is needed instead. */
		struct adc_message* message;
	};
};

sid_t ADC_client_get_sid(const struct ADC_client* client);
const char* ADC_client_get_cid(const struct ADC_client* client);
const char* ADC_client_get_nick(const struct ADC_client* client);
const char* ADC_client_get_description(const struct ADC_client* client);
void* ADC_client_get_ptr(const struct ADC_client* client);

/**
 * The keyprint pinned by the URL this client was last pointed at, or "" when
 * none was given (in which case the hub is not authenticated -- see the
 * security contract above).
 */
const char* ADC_client_get_keyprint(const struct ADC_client* client);

/**
 * Extract the "kp=" keyprint from an ADC hub URL.
 *
 * The keyprint lives in the query string of the URL --
 * "adcs://host:1511/?kp=SHA256/<52 base32 chars>" -- and is what pins the hub's
 * certificate. Only the SHA256 form is implemented; any other hash name is a
 * failure rather than something to skip past, since silently ignoring a
 * keyprint the operator asked for would leave the connection unauthenticated
 * while looking configured.
 *
 * Pure: it parses a string and touches nothing else.
 *
 * @param address the URL.
 * @param out receives the keyprint verbatim (e.g. "SHA256/ABC..."), or "" when
 *            there is none. Set to "" on every outcome but success.
 * @param out_size size of @p out; ADC_KEYPRINT_MAX is always enough.
 *
 * @return 1 a keyprint was found and is usable, 0 the URL pins no keyprint,
 *         -1 the URL carries a keyprint that is malformed, of an unknown hash
 *         algorithm, or of the wrong length.
 */
int ADC_client_parse_keyprint(const char* address, char* out, size_t out_size);

typedef int (*adc_client_cb)(struct ADC_client*, enum ADC_client_callback_type, struct ADC_client_callback_data* data);

struct ADC_client* ADC_client_create(const char* nickname, const char* description, void* ptr);
void ADC_client_set_callback(struct ADC_client* client, adc_client_cb);
void ADC_client_set_password(struct ADC_client* client, const char* password);
void ADC_client_set_pid(struct ADC_client* client, const char* pid);

/**
 * Set the comma-separated SU feature list this client advertises in its INF,
 * for example "TCP4,ADCS". Pass NULL or "" to advertise none, which is the
 * default and the right answer for a client that does not listen.
 *
 * SU is a claim other clients act on: TCP4/TCP6 says connections are accepted,
 * so a client that omits it is treated as passive and never dialled, and ADCS
 * says those connections are encrypted. ADC0 is the older spelling of ADCS and
 * is understood from peers, but not what this end sends. Claim only what is
 * true -- advertising
 * TCP4 without a reachable listener makes every transfer to this client fail
 * to connect rather than fall back.
 *
 * Takes effect on the next INF, so it must be set before ADC_client_connect().
 *
 * @return 1 if stored, 0 if @p su is longer than ADC_SUPPORT_MAX - 1 (refused
 *         rather than truncated, since a truncated token is a different claim).
 */
int ADC_client_set_support(struct ADC_client* client, const char* su);

/** The SU currently advertised, or "" if none. Never NULL. */
const char* ADC_client_get_support(const struct ADC_client* client);

/**
 * Build the INF this client would send, without sending it or needing a
 * connection. The caller owns the message and must adc_msg_free() it.
 *
 * Exists so that what goes on the wire can be asserted directly: an INF is only
 * otherwise observable over a live socket, which is how a missing SU field went
 * unnoticed.
 *
 * @return the message, or NULL if @p client is NULL or allocation failed.
 */
struct adc_message* ADC_client_build_info(struct ADC_client* client);

/**
 * Offer an additional feature in the HSUP sent at connect, e.g. "ADBBS0".
 *
 * Must be called before ADC_client_connect(). May be called more than once;
 * each feature is appended to the handshake in the order given.
 */
void ADC_client_add_support(struct ADC_client* client, const char* feature);
void ADC_client_destroy(struct ADC_client* client);
/**
 * Connect to @p address ("adc://host:port" or "adcs://host:port[/?kp=...]").
 * @return 1 if the attempt was started, 0 if the URL is unusable -- which
 *         includes a keyprint that is malformed or of an unknown algorithm.
 */
int ADC_client_connect(struct ADC_client* client, const char* address);
void ADC_client_disconnect(struct ADC_client* client);
void ADC_client_send(struct ADC_client* client, struct adc_message* msg);

#endif /* HAVE_UHUB_ADC_CLIENT_H */


