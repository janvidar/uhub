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

/* ------------------------------------------------------------------ *
 *  Ownership & threading contract  (read this first)
 *
 *  - The library owns all protocol state. A frontend renders events and
 *    issues intent; it never constructs wire messages (an escape hatch,
 *    ADC_client_send_raw(), exists for protocol features not yet wrapped).
 *
 *  - Every pointer inside a struct ADC_client_event is owned by the
 *    library and valid ONLY for the duration of the callback. Copy what
 *    you need before returning. Do not free it.
 *
 *  - The persistent user list (ADC_client_get_user / _foreach_user) is
 *    the exception: it lives as long as the client and is safe to read
 *    between callbacks. Pointers it returns are invalidated by the next
 *    dispatched event (a QUIT can free a user). Tracking is on by default
 *    and can be disabled with ADC_client_set_track_users() -- adcrush
 *    does this because thousands of bots must not each mirror the hub.
 *
 *  - The client is single-threaded and bound to one net_backend event
 *    loop. A GUI either drives net_backend_process() from its own
 *    idle/timer source, or runs the loop on a dedicated thread and
 *    marshals events across via its own queue. All ADC_client_* calls
 *    must happen on the loop thread.
 * ------------------------------------------------------------------ */

#define ADC_BUFSIZE 16384
#define MAX_DESC_LEN 128

struct ADC_client;

/* ==================================================================
 *  Events  (library -> frontend)
 * ================================================================== */

enum ADC_client_event_type
{
	/* --- transport / TLS --- */
	ADC_CLIENT_NAME_LOOKUP      = 1000, /* resolving hostname          (payload: none)      */
	ADC_CLIENT_CONNECTING       = 1001, /* tcp connect in progress     (payload: none)      */
	ADC_CLIENT_CONNECTED        = 1002, /* tcp established             (payload: none)      */
	ADC_CLIENT_DISCONNECTED     = 1003, /* connection gone             (payload: none)      */
	ADC_CLIENT_SSL_HANDSHAKE    = 1101, /* tls handshake started       (payload: none)      */
	ADC_CLIENT_SSL_OK           = 1102, /* tls established             (payload: tls)       */

	/* --- login --- */
	ADC_CLIENT_LOGGING_IN       = 2001, /* got SID, sending INF        (payload: none)      */
	ADC_CLIENT_PASSWORD_REQ     = 2002, /* hub asked for password      (payload: none)      */
	ADC_CLIENT_LOGGED_IN        = 2003, /* fully in the hub            (payload: none)      */
	ADC_CLIENT_LOGIN_ERROR      = 2004, /* fatal status pre-login      (payload: status)    */

	/* --- protocol traffic --- */
	ADC_CLIENT_PROTOCOL_STATUS  = 3001, /* non-fatal ISTA              (payload: status)    */
	ADC_CLIENT_MESSAGE          = 3002, /* chat / pm / me              (payload: chat)      */
	ADC_CLIENT_CONNECT_REQ      = 3003, /* CTM: peer wants to connect  (payload: connect)   */
	ADC_CLIENT_REVCONNECT_REQ   = 3004, /* RCM: reverse connect req    (payload: connect)   */
	ADC_CLIENT_SEARCH_REQ       = 3005, /* another user searched       (payload: search_req)*/
	ADC_CLIENT_SEARCH_REP       = 3006, /* a search result (RES)       (payload: search_res)*/

	/* --- user list --- */
	ADC_CLIENT_USER_JOIN        = 4001, /* new user (INF, unknown SID) (payload: user)      */
	ADC_CLIENT_USER_UPDATE      = 4002, /* INF for a known SID         (payload: user)      */
	ADC_CLIENT_USER_QUIT        = 4003, /* QUI                         (payload: quit)      */

	/* --- hub --- */
	ADC_CLIENT_HUB_INFO         = 5001, /* IINF                        (payload: hubinfo)   */
};

enum ADC_client_state
{
	adc_state_none,       /* disconnected            */
	adc_state_connecting, /* tcp/dns in flight       */
	adc_state_ssl,        /* tls handshake           */
	adc_state_protocol,   /* HSUP sent               */
	adc_state_identify,   /* BINF sent               */
	adc_state_verify,     /* HPAS sent               */
	adc_state_normal,     /* logged in               */
};

enum ADC_chat_flags
{
	chat_flags_none    = 0,
	chat_flags_action  = 1, /* /me                     */
	chat_flags_private = 2, /* PM                      */
};

/* Mirrors the ADC CT field (bitmask). */
enum ADC_user_type
{
	adc_user_none       = 0,
	adc_user_bot        = 1,
	adc_user_registered = 2,
	adc_user_operator   = 4,
	adc_user_super      = 8,
	adc_user_hub_owner  = 16,
	adc_user_hub        = 32,
};

enum ADC_away_state
{
	adc_away_none     = 0,
	adc_away_away     = 1,
	adc_away_extended = 2,
};

/* ------------------------------------------------------------------ *
 *  Event payloads
 * ------------------------------------------------------------------ */

struct ADC_hub_info
{
	char* name;
	char* description;
	char* version;      /* AP/VE of the hub          */
};

struct ADC_chat_message
{
	sid_t from_sid;
	sid_t to_sid;       /* 0 for broadcast           */
	char* message;      /* already unescaped         */
	int   flags;        /* enum ADC_chat_flags       */
};

struct ADC_user
{
	sid_t sid;
	char  cid[MAX_CID_LEN + 1];
	char  name[MAX_NICK_LEN + 1];
	char  description[MAX_DESC_LEN + 1];
	char  address[INET6_ADDRSTRLEN + 1];  /* I4, kept for source compat  */
	char  address6[INET6_ADDRSTRLEN + 1]; /* I6, if present              */
	char  version[MAX_UA_LEN + 1];        /* AP + VE                     */
	uint16_t udp4_port;       /* U4, 0 = passive on v4     */
	uint16_t udp6_port;       /* U6, 0 = passive on v6     */
	int      type;            /* enum ADC_user_type (CT)   */
	int      away;            /* enum ADC_away_state (AW)  */
	uint64_t shared_size;     /* SS                        */
	uint64_t shared_files;    /* SF                        */
};

struct ADC_client_quit_reason
{
	sid_t sid;
	sid_t initator;           /* 0 = default/hub.          */
	char  message[128];       /* optional                  */
	int   flags;
};

struct ADC_client_tls_info
{
	const char* cipher;
	const char* version;
};

struct ADC_client_status
{
	int   code;       /* full 3-digit ADC status code */
	int   severity;   /* 0 = success, 1 = recoverable, 2 = fatal */
	char* message;
};

/* Peer wants a client-client connection (CTM) or asks us to (RCM). */
struct ADC_connect_request
{
	sid_t from_sid;
	char  protocol[16];       /* e.g. "ADC/1.0"            */
	char  token[64];
	uint16_t port;            /* 0 for RCM (reverse)       */
	int   secure;             /* ADCS requested            */
};

struct ADC_search_request
{
	sid_t from_sid;           /* who is searching          */
	char* raw;                /* raw AN/NO/EX/TR terms      */
	char  token[64];
};

/* One entry of an incoming search result (RES). */
struct ADC_search_result
{
	sid_t from_sid;
	char* filename;
	uint64_t size;
	char  tth[MAX_CID_LEN + 1]; /* TR                      */
	int   slots_free;           /* SL                      */
	char  token[64];            /* TO, echoes the query    */
};

/* Tagged union delivered with every event. Inspect the matching member
   for the event's payload class (see the enum table above). */
struct ADC_client_callback_data
{
	union {
		struct ADC_hub_info*         hubinfo;
		struct ADC_chat_message*     chat;
		struct ADC_user*             user;
		struct ADC_client_quit_reason* quit;
		struct ADC_client_tls_info*  tls_info;
		struct ADC_client_status*    status;
		struct ADC_connect_request*  connect;
		struct ADC_search_request*   search_req;
		struct ADC_search_result*    search_res;
	};
};

/* Return value is reserved; return 0. Kept non-void so a future
   "handled/veto" contract does not break the ABI. */
typedef int (*adc_client_cb)(struct ADC_client*, enum ADC_client_event_type, struct ADC_client_callback_data* data);

/* Diagnostic/log sink. Replaces the hard-wired fprintf(stdout,...).
   level follows util/log.h verbosity. A NULL sink restores the default
   (print to stdout). */
typedef void (*adc_client_log_cb)(struct ADC_client*, int level, const char* msg);

/* ==================================================================
 *  Lifecycle
 * ================================================================== */

struct ADC_client* ADC_client_create(const char* nickname, const char* description, void* ptr);
void ADC_client_destroy(struct ADC_client* client);

void ADC_client_set_callback(struct ADC_client* client, adc_client_cb);
void ADC_client_set_log_callback(struct ADC_client* client, adc_client_log_cb);
void ADC_client_set_password(struct ADC_client* client, const char* password);

/* Override advertised INF fields before connecting. Unset fields use
   library defaults (product/version = uhub, share = 0, slots = 0). */
void ADC_client_set_user_agent(struct ADC_client* client, const char* product, const char* version);
void ADC_client_set_share(struct ADC_client* client, uint64_t size, uint64_t files);

/* Maintain the internal SID->user map (default: on). Disable for large
   fleets that never read the user list. */
void ADC_client_set_track_users(struct ADC_client* client, int enable);

int  ADC_client_connect(struct ADC_client* client, const char* address); /* adc[s]://host:port */
void ADC_client_disconnect(struct ADC_client* client);

/* ==================================================================
 *  Outbound intent  (frontend -> hub). None of these expose adc_message.
 *  Text arguments are plain (unescaped); the library escapes them.
 *  Each returns 1 on success, 0 if not connected / not logged in.
 * ================================================================== */

int ADC_client_say(struct ADC_client* client, const char* text);           /* BMSG           */
int ADC_client_say_me(struct ADC_client* client, const char* text);        /* BMSG +ME       */
int ADC_client_pm(struct ADC_client* client, sid_t to, const char* text);  /* DMSG           */

int ADC_client_search(struct ADC_client* client, const char* terms);       /* BSCH raw terms */

int ADC_client_connect_to_me(struct ADC_client* client, sid_t to,
                             const char* token, uint16_t port, int secure); /* DCTM          */
int ADC_client_rev_connect_to_me(struct ADC_client* client, sid_t to, const char* token); /* DRCM */

int ADC_client_set_away(struct ADC_client* client, enum ADC_away_state);   /* INF update     */
int ADC_client_update_info(struct ADC_client* client, const char named_field[2], const char* value);

/* Escape hatch: hand the library a fully built message. Prefer the typed
   calls above; this exists for protocol features not yet wrapped (and is
   how adcrush drives its stress traffic). Takes ownership of nothing --
   the caller still frees msg. */
void ADC_client_send(struct ADC_client* client, struct adc_message* msg);

/* ==================================================================
 *  Accessors  (safe to call between events, on the loop thread)
 * ================================================================== */

sid_t                 ADC_client_get_sid(const struct ADC_client* client);
const char*           ADC_client_get_nick(const struct ADC_client* client);
const char*           ADC_client_get_description(const struct ADC_client* client);
enum ADC_client_state ADC_client_get_state(const struct ADC_client* client);
void*                 ADC_client_get_ptr(const struct ADC_client* client);

const struct ADC_hub_info*        ADC_client_get_hub_info(const struct ADC_client* client);
const struct ADC_client_tls_info* ADC_client_get_tls_info(const struct ADC_client* client); /* NULL if plaintext */

/* Client-owned user list, maintained across JOIN/UPDATE/QUIT so a GUI
   need not keep its own map. Returned pointers are valid until the next
   event is dispatched. Requires user tracking (on by default). */
const struct ADC_user* ADC_client_get_user(const struct ADC_client* client, sid_t sid);
size_t                 ADC_client_user_count(const struct ADC_client* client);

typedef void (*adc_user_iter_cb)(const struct ADC_user*, void* data);
void ADC_client_foreach_user(const struct ADC_client* client, adc_user_iter_cb, void* data);

#endif /* HAVE_UHUB_ADC_CLIENT_H */
