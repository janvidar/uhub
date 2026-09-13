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

#include "tools/adcclient.h"

#include "network/dnsresolver.h"
#include "network/ipcalc.h"

#define ADC_HANDSHAKE "HSUP ADBASE ADTIGR ADPING"

/*
 * How long the HBRI validation connection is given to connect, hand over its
 * token and be answered. It is one short exchange over a network this host has
 * just been shown a route to, so a generous timeout only delays giving up: the
 * session is logged in and unaffected either way.
 */
#define ADC_HBRI_TIMEOUT 30

/*
 * How long the login INF waits for the address lookups to land.
 *
 * They are started before the connection is even made, so on any real network
 * they are long finished by the time the hub has answered with a SID. Against a
 * hub on loopback there is no round trip to hide them behind, and a lookup that
 * is a few milliseconds late would otherwise cost the session its second
 * protocol -- see ADC_client_send_login_info().
 */
#define ADC_HBRI_LOOKUP_GRACE 3
#define ADC_CID_SIZE 39
#define BIG_BUFSIZE 32768
#define TIGERSIZE 24
#define MAX_RECV_BUFFER 65536

// #define ADCC_DEBUG
// #define ADC_CLIENT_DEBUG_PROTO

struct ADC_client_global
{
	size_t references;
	struct ssl_context_handle* ctx;
};

static struct ADC_client_global* g_adc_client = NULL;


enum ADC_client_state
{
	ps_none, /* Not connected */
	ps_conn, /* Connecting... */
	ps_conn_ssl, /* SSL handshake */
	ps_protocol, /* Have sent HSUP */
	ps_identify, /* Have sent BINF */
	ps_verify, /* Have sent HPAS */
	ps_normal, /* Are fully logged in */
};

enum ADC_client_flags
{
	cflag_none = 0,
	cflag_ssl = 1,
	cflag_choke = 2,
	cflag_pipe = 4,
	cflag_kp_warned = 8,  /* the "hub is not verified" warning has been said once */
};

struct ADC_client_address
{
	enum Protocol { ADC, ADCS } protocol;
	char* hostname;
	uint16_t port;
	/** The "?kp=" pinned by the URL, or "" for an unauthenticated connection. */
	char keyprint[ADC_KEYPRINT_MAX];
};

struct ADC_client
{
	sid_t sid;
	enum ADC_client_state state;
	struct adc_message* info;
	struct ioq_recv* recv_queue;
	struct ioq_send* send_queue;
	adc_client_cb callback;
	size_t s_offset;
	size_t r_offset;
	struct net_connection* con;
	struct sockaddr_storage addr;
	struct net_connect_handle* connect_job;
	struct ADC_client_address address;
	char* nick;
	char* desc;
	char* password;
	char* fixed_pid;             /* caller-supplied PID (base32); NULL = generate a random one */
	char* extra_support;         /* extra HSUP features, e.g. " ADBBS0"; NULL for none */
	char* extra_inf;             /* extra login INF fields, e.g. " I6::1"; NULL for none */
	char cid[MAX_CID_LEN + 1];   /* CID for the current identity (set by adc_cid_pid / set_pid) */
	char support[ADC_SUPPORT_MAX]; /* SU field, or "" to send none */

	/*
	 * The features the hub announced in ISUP, as a comma separated list of
	 * bare FOURCCs ("BASE,TIGR,BBS0"). Rebuilt from every ISUP, so an AD/RM
	 * pair issued later in the session takes effect, and cleared on connect:
	 * an extension a hub announced once is not a promise about the next
	 * connection.
	 */
	char hub_support[ADC_SUPPORT_MAX];

	/*
	 * HBRI. primary_af is the family the current connection was made over (0
	 * before it is known); local4/local6 are this host's own source addresses
	 * for reaching the hub, with af 0 meaning "not known". See the extension's
	 * description in adcclient.h.
	 */
	int hbri;                              /* the caller opted in */
	int primary_af;
	struct ip_addr_encap local4;
	struct ip_addr_encap local6;
	struct net_dns_job* hbri_dns4;         /* the hub's address lookups, in flight */
	struct net_dns_job* hbri_dns6;
	struct timeout_evt* hbri_timer;        /* bounds the wait for those lookups */
	int info_pending;                      /* the login INF is waiting on them */
	struct ADC_client_hbri* validation;    /* validation connection in flight */

	int flags;
	void* ptr;
};

/*
 * One HBRI validation connection: a second, short-lived connection to the hub
 * over the protocol the session did not use, whose only purpose is to let the
 * hub observe this host's address in that family. It carries a single command
 * and is then closed, from either end.
 *
 * It is deliberately not an ADC_client of its own: there is no handshake, no
 * SID and no INF on it -- HTCP is its first and last word.
 */
struct ADC_client_hbri
{
	struct ADC_client* client;
	struct net_connect_handle* connect_job;
	struct net_connection* con;
	int af;                                /* the family being proven */
	uint16_t port;
	char address[INET6_ADDRSTRLEN + 1];    /* the hub, in that family */
	char token[ADC_HBRI_TOKEN_MAX];
	int tls;                               /* the session is adcs://, so this is too */
	int sent;                              /* the HTCP has been fully written */
	char out[ADC_HBRI_TOKEN_MAX + 16];     /* "HTCP TO<token>\n" */
	size_t out_length;
	size_t out_offset;
};


static ssize_t ADC_client_recv(struct ADC_client* client);
static void ADC_client_send_info(struct ADC_client* client);
static void ADC_client_send_password(struct ADC_client* client, const char* challenge);
static void ADC_client_on_connected(struct ADC_client* client);
static void ADC_client_on_connected_ssl(struct ADC_client* client);
static void ADC_client_on_disconnected(struct ADC_client* client);
static void ADC_client_on_login(struct ADC_client* client);
static int ADC_client_parse_address(struct ADC_client* client, const char* arg);
static void ADC_client_hbri_release_login(struct ADC_client* client);
static int ADC_client_on_recv_line(struct ADC_client* client, const char* line, size_t length);
static int ADC_client_send_queue(struct ADC_client* client);

/** The hub this client is talking to, for a log line. */
static const char* ADC_client_host(struct ADC_client* client)
{
	return client->address.hostname ? client->address.hostname : "?";
}

/*
 * The hub-side wire trace: every line this client sends or receives, verbatim.
 *
 * This is the counterpart to seed_cc's transfer trace, and the two are meant to
 * be read together -- a transfer that never happens usually failed here, in a
 * CTM that was refused or answered with a status nobody looked at, rather than
 * on the transfer connection that was consequently never made.
 *
 * LOG_WIRE, so it costs nothing until the verbosity is raised to log_protocol.
 */
static void ADC_client_log_wire(struct ADC_client* client, const char* dir, const char* line, size_t length)
{
	char buf[512];
	size_t out = 0;
	size_t i;

	if (!hub_log_enabled(log_protocol))
		return;

	/*
	 * HPAS carries the answer to the hub's password challenge. It is a hash
	 * over a nonce rather than the password itself, but it is the credential
	 * for that login, and traces like this one end up pasted into bug reports.
	 */
	if (length >= 4 && memcmp(line, "HPAS", 4) == 0)
	{
		LOG_WIRE("adc[%s] %s HPAS <redacted>",
			ADC_client_host(client), dir);
		return;
	}

	for (i = 0; i < length && out < sizeof(buf) - 1; i++)
	{
		unsigned char c = (unsigned char) line[i];
		if (c == '\n' || c == '\r')
			break;
		buf[out++] = (c >= 0x20 && c < 0x7f) ? (char) c : '.';
	}
	buf[out] = '\0';

	LOG_WIRE("adc[%s] %s %s", ADC_client_host(client), dir, buf);
}

#ifdef ADCC_DEBUG
#define ADC_TRACE fprintf(stderr, "TRACE: %s\n", __PRETTY_FUNCTION__)
#else
#define ADC_TRACE do { } while(0)
#endif

/* Not under a debug ifdef any more: where the login had got to is exactly what
   a trace of a session that goes wrong has to say. */
static const char* ADC_client_state_string[] =
{
	"ps_none",
	"ps_conn",
	"ps_conn_ssl",
	"ps_protocol",
	"ps_identify",
	"ps_verify",
	"ps_normal",
	0
};

static void ADC_client_set_state(struct ADC_client* client, enum ADC_client_state state)
{
	ADC_TRACE;
	if (client->state != state)
	{
		LOG_WIRE("adc[%s] state %s (was %s)", ADC_client_host(client),
			ADC_client_state_string[(int) state],
			ADC_client_state_string[(int) client->state]);
		client->state = state;
	}
}


/* Appends ID/PD to @p info rather than to client->info, so the INF can be built
   for inspection without one having been sent. */
static void adc_cid_pid(struct ADC_client* client, struct adc_message* info)
{
	ADC_TRACE;
	static uint32_t counter = 0;
	char seed[64];
	char pid[64];
	char cid[64];
	uint64_t tiger_res1[3];
	uint64_t tiger_res2[3];

	if (client->fixed_pid)
	{
		/* Use the caller-supplied PID; the CID is derived from it below and
		   must equal base32(tiger(PID)) (which the hub verifies). Decode into a
		   generous buffer -- base32_decode of MAX_CID_LEN chars writes >24 bytes. */
		uint64_t decoded[8];
		memset(decoded, 0, sizeof(decoded));
		base32_decode(client->fixed_pid, (unsigned char*) decoded, MAX_CID_LEN);
		memcpy(tiger_res1, decoded, TIGERSIZE);
		snprintf(pid, sizeof(pid), "%s", client->fixed_pid);
	}
	else
	{
		/* create cid+pid pair; mix in pid, time and a per-instance counter so
		 * the identity is not a predictable function of the heap pointer alone. */
		memset(seed, 0, 64);
		snprintf(seed, 64, VERSION "%p%d%ld%u", client, (int) getpid(), (long) time(NULL), ++counter);

		tiger((uint64_t*) seed, strlen(seed), tiger_res1);
		base32_encode((unsigned char*) tiger_res1, TIGERSIZE, pid);
	}

	tiger((uint64_t*) tiger_res1, TIGERSIZE, tiger_res2);
	base32_encode((unsigned char*) tiger_res2, TIGERSIZE, cid);
	cid[ADC_CID_SIZE] = 0;
	pid[ADC_CID_SIZE] = 0;

	/* The CID is always exactly ADC_CID_SIZE (== MAX_CID_LEN) base32 chars; copy
	   a fixed length rather than snprintf'ing from the larger local buffer (which
	   trips -Werror=format-truncation under gcc). */
	memcpy(client->cid, cid, MAX_CID_LEN);
	client->cid[MAX_CID_LEN] = '\0';

	adc_msg_add_named_argument(info, ADC_INF_FLAG_PRIVATE_ID, pid);
	adc_msg_add_named_argument(info, ADC_INF_FLAG_CLIENT_ID, cid);
}

static void event_callback(struct net_connection* con, int events, void *arg)
{
	(void) arg;
	ADC_TRACE;
	struct ADC_client* client = (struct ADC_client*) net_con_get_ptr(con);

	switch (client->state)
	{
		case ps_conn:
			if (events == NET_EVENT_TIMEOUT)
			{
				client->callback(client, ADC_CLIENT_DISCONNECTED, 0);
				return;
			}
			break;

		case ps_conn_ssl:
			if (events == NET_EVENT_TIMEOUT)
			{
				client->callback(client, ADC_CLIENT_DISCONNECTED, 0);
				return;
			}

			if (events == NET_EVENT_ERROR)
			{
				ADC_client_on_disconnected(client);
				return;
			}
			else
			{
				ADC_client_on_connected_ssl(client);
			}
			break;

		default:
			if (events & NET_EVENT_READ)
			{
				if (ADC_client_recv(client) == -1)
				{
					ADC_client_on_disconnected(client);
					return; /* connection gone; don't touch it for WRITE below */
				}
			}

			if (events & NET_EVENT_WRITE)
			{
				ADC_client_send_queue(client);
			}
	}
}

#define UNESCAPE_ARG(TMP, TARGET) \
		if (TMP) \
			TARGET = adc_msg_unescape(TMP); \
		else \
			TARGET = NULL; \
		hub_free(TMP);

#define UNESCAPE_ARG_X(TMP, TARGET, SIZE) \
		if (TMP) \
			adc_msg_unescape_to_target(TMP, TARGET, SIZE); \
		else \
			TARGET[0] = '\0'; \
		hub_free(TMP);

#define EXTRACT_NAMED_ARG(MSG, NAME, TARGET) \
		do { \
			char* tmp = adc_msg_get_named_argument(MSG, NAME); \
			UNESCAPE_ARG(tmp, TARGET); \
		} while (0)

#define EXTRACT_NAMED_ARG_X(MSG, NAME, TARGET, SIZE) \
		do { \
			char* tmp = adc_msg_get_named_argument(MSG, NAME); \
			UNESCAPE_ARG_X(tmp, TARGET, SIZE); \
		} while(0)

#define EXTRACT_POS_ARG(MSG, POS, TARGET) \
		do { \
			char* tmp = adc_msg_get_argument(MSG, POS); \
			UNESCAPE_ARG(tmp, TARGET); \
		} while (0)


/* ------------------------------------------------------- the hub's SUP list */

/*
 * The hub's announced features are kept as a comma separated list of bare
 * FOURCCs rather than as a bitmask. This library models no extension itself, so
 * it has nothing to map a bitmask onto, and a caller asking whether the hub
 * speaks something names it as text.
 */
static int adc_sup_has(const char* list, const char* feature)
{
	const char* p = list;
	size_t len;

	if (!list || !feature || !*feature)
		return 0;

	len = strlen(feature);
	while (*p)
	{
		const char* end = strchr(p, ',');
		size_t span = end ? (size_t) (end - p) : strlen(p);

		if (span == len && strncasecmp(p, feature, len) == 0)
			return 1;
		if (!end)
			break;
		p = end + 1;
	}
	return 0;
}

static void adc_sup_add(char* list, size_t size, const char* feature)
{
	size_t used = strlen(list);

	if (adc_sup_has(list, feature))
		return;

	/* +1 for the separator when the list is not empty, +1 for the NUL. */
	if (used + strlen(feature) + (used ? 1 : 0) + 1 > size)
		return;

	if (used)
		list[used++] = ',';
	strcpy(list + used, feature);
}

static void adc_sup_remove(char* list, size_t size, const char* feature)
{
	char kept[ADC_SUPPORT_MAX];
	const char* p = list;
	size_t len;

	if (!adc_sup_has(list, feature))
		return;

	len = strlen(feature);
	kept[0] = '\0';
	while (*p)
	{
		const char* end = strchr(p, ',');
		size_t span = end ? (size_t) (end - p) : strlen(p);

		if (span != len || strncasecmp(p, feature, len) != 0)
		{
			char token[ADC_SUPPORT_MAX];

			if (span < sizeof(token))
			{
				memcpy(token, p, span);
				token[span] = '\0';
				adc_sup_add(kept, sizeof(kept), token);
			}
		}
		if (!end)
			break;
		p = end + 1;
	}

	if (strlen(kept) < size)
		strcpy(list, kept);
}

/*
 * Record what the hub said in ISUP.
 *
 * A hub may revise the list later in the session -- the BBS0 extension makes a
 * point of allowing it -- so this applies AD and RM against what is already
 * held rather than replacing it wholesale.
 */
static void ADC_client_on_hub_support(struct ADC_client* client, struct adc_message* msg)
{
	char* arg;
	int i = 0;

	while ((arg = adc_msg_get_argument(msg, i++)))
	{
		/* A SUP token is a two character verb and a four character FOURCC.
		   Anything else is not this grammar, and is left unrecorded rather
		   than guessed at. */
		if (strlen(arg) == 6 && memcmp(arg, "AD", 2) == 0)
			adc_sup_add(client->hub_support, sizeof(client->hub_support), arg + 2);
		else if (strlen(arg) == 6 && memcmp(arg, "RM", 2) == 0)
			adc_sup_remove(client->hub_support, sizeof(client->hub_support), arg + 2);

		hub_free(arg);
	}
}

/* ---------------------------------------------------------------- HBRI ---- */

/* The slot holding this host's own address for @p af, or NULL for any other
   address family. */
static struct ip_addr_encap* ADC_client_local_slot(struct ADC_client* client, int af)
{
	if (af == AF_INET)
		return &client->local4;
	if (af == AF_INET6)
		return &client->local6;
	return NULL;
}

static const char* ADC_client_af_name(int af)
{
	return (af == AF_INET6) ? "IPv6" : "IPv4";
}

/*
 * Whether two addresses are the same address.
 *
 * Compared field by field rather than with one memcmp over the struct: the
 * union is wide enough for IPv6, so the twelve bytes past an IPv4 address are
 * whatever the caller's stack held, and a memcmp over them reports two
 * identical IPv4 addresses as different -- which here means re-announcing an
 * address that never changed.
 */
static int ADC_client_addr_equal(const struct ip_addr_encap* a, const struct ip_addr_encap* b)
{
	if (a->af != b->af)
		return 0;

	if (a->af == AF_INET6)
		return memcmp(&a->internal_ip_data.in6, &b->internal_ip_data.in6, sizeof(struct in6_addr)) == 0;

	return memcmp(&a->internal_ip_data.in, &b->internal_ip_data.in, sizeof(struct in_addr)) == 0;
}

/*
 * Record one of this host's own addresses.
 *
 * Nothing is sent from here, deliberately. An address that lands after the
 * login INF has gone out cannot be handed to the hub in a second INF: a hub's
 * update flood control counts the login INF itself, so with uhub's own defaults
 * -- two INFs per five seconds -- the very next one is refused with "Update
 * flood detected". Naming the address in the *login* INF is the only way to ask
 * for a validation challenge without that, which is why the lookups start
 * before the connection and the login waits a moment for them. One that is
 * later still than that is kept (it is what this host will offer on its next
 * connection, and what ADC_client_get_local_address reports meanwhile) but
 * costs this session its second protocol.
 */
static void ADC_client_set_local_address(struct ADC_client* client, const struct ip_addr_encap* addr)
{
	struct ip_addr_encap* slot = ADC_client_local_slot(client, addr->af);

	if (!slot || ADC_client_addr_equal(slot, addr))
		return;

	*slot = *addr;

	LOG_WIRE("adc[%s] own %s address is %s", ADC_client_host(client),
		ADC_client_af_name(addr->af), ip_convert_to_string(addr));
}

/*
 * One family's worth of the hub's addresses is in: ask the routing table which
 * source address would reach the first of them.
 *
 * Only the first that answers is taken. A multi-homed hub may publish several
 * addresses in a family, but they all reach the same hub, and "which source
 * address would I use" has one answer per family.
 */
static int ADC_client_hbri_dns_callback(struct net_dns_job* job, const struct net_dns_result* result)
{
	struct ADC_client* client = (struct ADC_client*) net_dns_job_get_ptr(job);
	struct ip_addr_encap* addr;

	if (client->hbri_dns4 == job)
		client->hbri_dns4 = NULL;
	else if (client->hbri_dns6 == job)
		client->hbri_dns6 = NULL;

	if (!result)
		return 1;

	for (addr = net_dns_result_first(result); addr; addr = net_dns_result_next(result))
	{
		struct ip_addr_encap* slot = ADC_client_local_slot(client, addr->af);
		struct ip_addr_encap local;

		if (!slot || slot->af == addr->af)
			continue; /* not a family this tracks, or one already answered */

		if (net_local_address_for(addr, client->address.port, &local))
			ADC_client_set_local_address(client, &local);
		else
			LOG_WIRE("adc[%s] no %s route to the hub at %s; not offering it for validation.",
				ADC_client_host(client), ADC_client_af_name(addr->af), ip_convert_to_string(addr));
	}

	if (!client->hbri_dns4 && !client->hbri_dns6)
		ADC_client_hbri_release_login(client);

	return 1;
}

/*
 * Send the login INF that was held back, now that there is nothing left to wait
 * for -- either the lookups have all landed, or the grace period has run out.
 */
static void ADC_client_hbri_release_login(struct ADC_client* client)
{
	if (!client->info_pending)
		return;

	client->info_pending = 0;

	if (client->hbri_timer && timeout_evt_is_scheduled(client->hbri_timer))
		timeout_queue_remove(net_backend_get_timeout_queue(), client->hbri_timer);

	ADC_client_send_info(client);
}

/* The grace period expired: log in with whatever is known. */
static void ADC_client_hbri_grace_expired(struct timeout_evt* evt)
{
	struct ADC_client* client = (struct ADC_client*) evt->ptr;

	LOG_WIRE("adc[%s] address lookup did not finish in time; logging in with one protocol.",
		ADC_client_host(client));
	ADC_client_hbri_release_login(client);
}

/*
 * The login INF, held just long enough for the address lookups.
 *
 * They were started before the connection was made, so against any hub reached
 * over a network they are long done by the time its SID arrives and this waits
 * for nothing. It is loopback, where there is no round trip to hide them
 * behind, that needs the grace -- and losing the second protocol there by a
 * millisecond is exactly the kind of thing that never reproduces later.
 */
static void ADC_client_send_login_info(struct ADC_client* client)
{
	if (client->hbri && (client->hbri_dns4 || client->hbri_dns6) && client->hbri_timer)
	{
		client->info_pending = 1;
		timeout_queue_insert(net_backend_get_timeout_queue(), client->hbri_timer,
			ADC_HBRI_LOOKUP_GRACE);
		return;
	}

	ADC_client_send_info(client);
}

static void ADC_client_hbri_cancel_lookup(struct ADC_client* client)
{
	if (client->info_pending)
	{
		client->info_pending = 0;
		if (client->hbri_timer && timeout_evt_is_scheduled(client->hbri_timer))
			timeout_queue_remove(net_backend_get_timeout_queue(), client->hbri_timer);
	}

	if (client->hbri_dns4)
	{
		net_dns_job_cancel(client->hbri_dns4);
		client->hbri_dns4 = NULL;
	}

	if (client->hbri_dns6)
	{
		net_dns_job_cancel(client->hbri_dns6);
		client->hbri_dns6 = NULL;
	}
}

/*
 * Forget what was worked out for the connection being replaced, and -- when
 * this client takes part in HBRI -- start working it out again for the new one.
 *
 * Started here, before the connection rather than once it is up, because the
 * answer is wanted for the *login* INF: naming the second family there is what
 * asks the hub for a validation challenge. The INF goes out one round trip
 * after a connect that itself waits on a lookup of this very name, so a lookup
 * started here has all of that to complete in and effectively always wins.
 * Started after the connection instead, it routinely lost that race and arrived
 * only in time for an INF update -- which, right after the login INF, is
 * exactly what a hub's update flood control refuses.
 *
 * One lookup per family, rather than one AF_UNSPEC lookup for both. They are
 * not the same question: glibc answers "localhost" with 127.0.0.1 for AF_UNSPEC
 * and with ::1 for AF_INET6, and a family this asked about and was told nothing
 * of is a family this host would then never offer.
 *
 * A hub named by an address literal resolves in one family only. The other
 * lookup finds nothing, which is the right answer: there is no second address
 * to reach the hub at, so none is claimed.
 */
static void ADC_client_hbri_restart_lookup(struct ADC_client* client)
{
	ADC_client_hbri_cancel_lookup(client);

	/* A reconnect may be from another network entirely; nothing carries over. */
	client->info_pending = 0;
	client->primary_af = 0;
	memset(&client->local4, 0, sizeof(client->local4));
	memset(&client->local6, 0, sizeof(client->local6));

	if (!client->hbri || !client->address.hostname)
		return;

	client->hbri_dns4 = net_dns_gethostbyname(client->address.hostname, AF_INET,
		ADC_client_hbri_dns_callback, client);

	if (net_is_ipv6_supported())
		client->hbri_dns6 = net_dns_gethostbyname(client->address.hostname, AF_INET6,
			ADC_client_hbri_dns_callback, client);
}

/*
 * The address this connection was actually made from, read straight off the
 * socket once it is up. It is the same answer the route lookup above gives for
 * that family, but observed rather than predicted, so it wins.
 *
 * A dual-stack socket names an IPv4 address as "::ffff:a.b.c.d", which belongs
 * in the IPv4 slot: taken at face value it would be published as IPv6
 * connectivity this host does not have.
 */
static void ADC_client_discover_local_address(struct ADC_client* client)
{
	struct ip_addr_encap addr;
	const char* text;

	if (!client->con)
		return;

	text = net_get_local_address(net_con_get_sd(client->con));
	if (!text || !*text)
		return;

	/* An IPv4 address in IPv6 spelling is an IPv4 address. */
	if (strncmp(text, "::ffff:", 7) == 0)
		text += 7;

	memset(&addr, 0, sizeof(addr));
	if (ip_convert_to_binary(text, &addr) <= 0)
		return;

	client->primary_af = addr.af;
	ADC_client_set_local_address(client, &addr);
}

int ADC_client_parse_hbri_request(struct adc_message* cmd, struct ADC_client_hbri_request* out)
{
	char* address;
	char* port;
	char* token;
	int af;
	int ok = 0;

	if (!cmd || !out)
		return 0;

	memset(out, 0, sizeof(*out));

	/* The address flag names the family; the port flag has to agree with it. */
	address = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_IPV6_ADDR);
	af = AF_INET6;
	if (!address)
	{
		address = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR);
		af = AF_INET;
	}

	port = adc_msg_get_named_argument(cmd,
		(af == AF_INET6) ? ADC_INF_FLAG_IPV6_TCP_PORT : ADC_INF_FLAG_IPV4_TCP_PORT);
	token = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_TOKEN);

	if (address && port && token)
	{
		int value = 0;
		size_t token_len = strlen(token);

		ok = strlen(address) < sizeof(out->address)
			&& (af == AF_INET6 ? ip_is_valid_ipv6(address) : ip_is_valid_ipv4(address))
			&& is_number(port, &value) && value > 0 && value <= 65535
			/* Echoed back as one argument, so no separator may hide in it. */
			&& token_len > 0 && token_len < sizeof(out->token)
			&& !strpbrk(token, " \n\r");

		if (ok)
		{
			out->af = af;
			out->port = (uint16_t) value;
			uhub_strlcpy(out->address, address, sizeof(out->address));
			uhub_strlcpy(out->token, token, sizeof(out->token));
		}
	}

	hub_free(address);
	hub_free(port);
	hub_free(token);

	if (!ok)
		memset(out, 0, sizeof(*out));

	return ok;
}

/*
 * Abandon the validation connection, whatever state it had reached.
 *
 * The client's handle on it is cleared before anything is torn down: closing
 * the connection re-enters this through the connection's own callback on some
 * paths, and it must find nothing left to do.
 */
static void ADC_client_hbri_close(struct ADC_client* client)
{
	struct ADC_client_hbri* v = client->validation;

	if (!v)
		return;

	client->validation = NULL;

	if (v->connect_job)
		net_connect_destroy(v->connect_job);

	if (v->con)
		net_con_close(v->con);

	hub_free(v);
}

/*
 * Write what is left of the HTCP.
 *
 * It is one short line on a socket that has just connected, so it almost always
 * leaves in a single write -- but "almost always" is not a reason to lose the
 * one command this connection exists to carry, so the remainder is kept and
 * finished on the next writable event.
 */
static void ADC_client_hbri_flush(struct ADC_client_hbri* v)
{
	ssize_t size;

	if (!v->con || v->sent)
		return;

	while (v->out_offset < v->out_length)
	{
		size = net_con_send(v->con, v->out + v->out_offset, v->out_length - v->out_offset);
		if (size < 0)
		{
			LOG_WIRE("adc[%s] the HBRI validation connection failed while sending.",
				ADC_client_host(v->client));
			ADC_client_hbri_close(v->client);
			return;
		}
		if (size == 0)
		{
			net_con_update(v->con, NET_EVENT_READ | NET_EVENT_WRITE);
			return;
		}
		v->out_offset += (size_t) size;
	}

	v->sent = 1;
	ADC_client_log_wire(v->client, "hbri -->", v->out, v->out_length);
	net_con_update(v->con, NET_EVENT_READ);
}

/*
 * Check the hub's certificate on the validation connection against the pinned
 * keyprint. It is the same hub, so the same certificate is expected; a
 * different one means this connection is not reaching it.
 *
 * @return 1 to carry on, 0 when the validation has been abandoned.
 */
static int ADC_client_hbri_verify_keyprint(struct ADC_client_hbri* v)
{
	struct ADC_client* client = v->client;
	char presented[ADC_KEYPRINT_MAX];

	if (!client->address.keyprint[0])
		return 1;

	if (!net_ssl_get_peer_keyprint(v->con, presented, sizeof(presented)))
		presented[0] = '\0';

	if (presented[0] && net_ssl_keyprint_equal(presented, client->address.keyprint))
		return 1;

	LOG_ERROR("adc[%s] the HBRI validation connection to %s presented %s, not the pinned certificate. Abandoning it.",
		ADC_client_host(client), v->address, presented[0] ? presented : "no certificate");
	ADC_client_hbri_close(client);
	return 0;
}

/* The hub's answer: one ISTA, and then it closes. Read for the log -- there is
   nothing to do about it either way, since the session is unaffected. */
static void ADC_client_hbri_on_reply(struct ADC_client_hbri* v, const char* line, size_t length)
{
	struct ADC_client* client = v->client;
	struct adc_message* msg;
	char* code;
	int value = 0;
	int succeeded;

	ADC_client_log_wire(client, "hbri <--", line, length);

	msg = adc_msg_parse(line, length);
	if (!msg)
		return;

	/* Severity 0 -- a code below 100 -- is the only success. */
	code = (msg->cmd == ADC_CMD_ISTA) ? adc_msg_get_argument(msg, 0) : NULL;
	succeeded = code && is_number(code, &value) && value >= 0 && value < 100;

	if (succeeded)
	{
		LOG_INFO("adc[%s] validated this host's %s address with the hub; it is now published on both protocols.",
			ADC_client_host(client), ADC_client_af_name(v->af));
	}
	else
	{
		char* text = adc_msg_get_argument(msg, 1);
		LOG_WARN("adc[%s] the hub refused the %s validation (%s); staying %s-only.",
			ADC_client_host(client), ADC_client_af_name(v->af),
			text ? text : "no reason given",
			ADC_client_af_name(client->primary_af));
		hub_free(text);
	}

	hub_free(code);
	adc_msg_free(msg);
}

/*
 * The validation connection's only event handler.
 *
 * On a TLS connection the first event is the completed handshake -- and it
 * arrives as a READ, which is what it is not: the hub cannot have answered yet,
 * since the question is only going out now. The HTCP waits for that event,
 * because net_ssl_callback() delivers nothing before it.
 */
static void ADC_client_hbri_event(struct net_connection* con, int events, void* arg)
{
	struct ADC_client_hbri* v = (struct ADC_client_hbri*) net_con_get_ptr(con);
	char buf[512];
	ssize_t size;
	char* end;

	(void) arg;
	ADC_TRACE;

	if (events == NET_EVENT_TIMEOUT)
	{
		LOG_WARN("adc[%s] the HBRI validation connection to %s timed out; staying %s-only.",
			ADC_client_host(v->client), v->address, ADC_client_af_name(v->client->primary_af));
		ADC_client_hbri_close(v->client);
		return;
	}

	if (events & NET_EVENT_ERROR)
	{
		LOG_WIRE("adc[%s] the HBRI validation connection to %s failed.",
			ADC_client_host(v->client), v->address);
		ADC_client_hbri_close(v->client);
		return;
	}

	/* On TLS this first event is the handshake finishing, not an answer. */
	if (!v->sent)
	{
		if (v->tls && !ADC_client_hbri_verify_keyprint(v))
			return;

		ADC_client_hbri_flush(v);
		return;
	}

	if (!(events & NET_EVENT_READ))
		return;

	size = net_con_recv(con, buf, sizeof(buf) - 1);
	if (size == 0)
		return; /* woken with nothing readable yet */

	if (size > 0)
	{
		buf[size] = '\0';
		end = strchr(buf, '\n');
		if (end)
			*end = '\0';
		if (*buf)
			ADC_client_hbri_on_reply(v, buf, strlen(buf));
	}

	/* One command, one answer: it has served its entire purpose. */
	ADC_client_hbri_close(v->client);
}

static void ADC_client_hbri_connect_callback(struct net_connect_handle* handle,
	enum net_connect_status status, struct net_connection* con, void* ptr)
{
	struct ADC_client_hbri* v = (struct ADC_client_hbri*) ptr;
	struct ADC_client* client = v->client;

	(void) handle;
	v->connect_job = NULL;

	if (status != net_connect_status_ok)
	{
		LOG_WARN("adc[%s] unable to reach the hub at %s port %u over %s; staying %s-only.",
			ADC_client_host(client), v->address, (unsigned) v->port,
			ADC_client_af_name(v->af), ADC_client_af_name(client->primary_af));
		ADC_client_hbri_close(client);
		return;
	}

	v->con = con;
	net_con_reinitialize(con, ADC_client_hbri_event, v, NET_EVENT_READ);
	net_con_set_timeout(con, ADC_HBRI_TIMEOUT);

	if (v->tls)
	{
		/* Same hub, same port, which demultiplexes ADC and TLS on it. */
		net_con_update(con, NET_EVENT_READ | NET_EVENT_WRITE);
		if (net_con_ssl_handshake(con, net_con_ssl_mode_client, g_adc_client->ctx) < 0)
		{
			LOG_WARN("adc[%s] the HBRI validation connection to %s could not start a TLS handshake.",
				ADC_client_host(client), v->address);
			ADC_client_hbri_close(client);
		}
		return; /* the HTCP goes out once the handshake completes */
	}

	ADC_client_hbri_flush(v);
}

/*
 * An ITCP: the hub is asking this client to prove the protocol it did not
 * connect over, by reaching it at the address named here.
 *
 * A request naming the family this session already runs over is refused rather
 * than dialled. It would prove nothing the hub has not already observed, and no
 * hub has a reason to send one.
 */
static void ADC_client_on_hbri_request(struct ADC_client* client, struct adc_message* cmd)
{
	struct ADC_client_hbri_request req;
	struct ADC_client_hbri* v;

	if (!client->hbri)
	{
		LOG_WIRE("adc[%s] ignoring an HBRI validation request: this client does not offer HBRI.",
			ADC_client_host(client));
		return;
	}

	if (!ADC_client_parse_hbri_request(cmd, &req))
	{
		LOG_WARN("adc[%s] the hub sent an HBRI validation request that cannot be used.",
			ADC_client_host(client));
		return;
	}

	/* The whole point is to prove the *other* protocol. */
	if (req.af == client->primary_af)
	{
		LOG_WARN("adc[%s] the hub asked for %s validation over the protocol this session already uses; ignoring it.",
			ADC_client_host(client), ADC_client_af_name(req.af));
		return;
	}

	/* One at a time: the newest token is the only one the hub still accepts. */
	ADC_client_hbri_close(client);

	v = (struct ADC_client_hbri*) hub_malloc_zero(sizeof(struct ADC_client_hbri));
	if (!v)
		return;

	v->client = client;
	v->af = req.af;
	v->port = req.port;
	v->tls = (client->flags & cflag_ssl) ? 1 : 0;
	uhub_strlcpy(v->address, req.address, sizeof(v->address));
	uhub_strlcpy(v->token, req.token, sizeof(v->token));

	v->out_length = (size_t) snprintf(v->out, sizeof(v->out), "HTCP %s%s\n",
		ADC_INF_FLAG_TOKEN, v->token);
	if (v->out_length >= sizeof(v->out))
	{
		hub_free(v);
		return;
	}

	client->validation = v;

	LOG_WIRE("adc[%s] opening an HBRI %s validation connection to %s port %u.",
		ADC_client_host(client), ADC_client_af_name(v->af), v->address, (unsigned) v->port);

	/* A literal in one family only, so this connects over that protocol. */
	v->connect_job = net_con_connect(v->address, v->port, ADC_client_hbri_connect_callback, v);
	if (!v->connect_job)
	{
		LOG_WARN("adc[%s] unable to start the HBRI validation connection to %s.",
			ADC_client_host(client), v->address);
		ADC_client_hbri_close(client);
	}
}

void ADC_client_set_hbri(struct ADC_client* client, int enable)
{
	ADC_TRACE;
	if (client)
		client->hbri = enable ? 1 : 0;
}

int ADC_client_get_hbri(const struct ADC_client* client)
{
	return client ? client->hbri : 0;
}

const char* ADC_client_get_local_address(const struct ADC_client* client, int af)
{
	const struct ip_addr_encap* slot;

	if (!client)
		return "";

	slot = (af == AF_INET) ? &client->local4 : (af == AF_INET6) ? &client->local6 : NULL;
	if (!slot || slot->af != af)
		return "";

	return ip_convert_to_string(slot);
}


static int ADC_client_on_recv_line(struct ADC_client* client, const char* line, size_t length)
{
	struct ADC_chat_message chat;
	struct ADC_client_callback_data data;

	ADC_TRACE;
	ADC_client_log_wire(client, "<--", line, length);

	/* Hand the raw line over before anything is parsed, so a caller can see
	   commands the switch below does not model. */
	{
		struct ADC_client_callback_data raw;
		raw.line = line;
		client->callback(client, ADC_CLIENT_RAW_LINE, &raw);
	}

	if (length < 4)
	{
		LOG_WARN("adc[%s] unexpected response from the hub: \"%s\"",
			ADC_client_host(client), line);
		return -1;
	}

	/* Parse message */
	struct adc_message* msg = adc_msg_parse(line, length);
	if (!msg)
	{
		LOG_WARN("adc[%s] a line from the hub cannot be decoded: \"%s\"",
			ADC_client_host(client), line);
		return -1;
	}

	switch (msg->cmd)
	{
		case ADC_CMD_ISUP:
			ADC_client_on_hub_support(client, msg);
			break;

		case ADC_CMD_ITCP:
			/* HBRI: the hub wants the other protocol proven. */
			ADC_client_on_hbri_request(client, msg);
			break;

		case ADC_CMD_IGPA:
			if (client->state == ps_identify || client->state == ps_verify)
			{
				char* challenge = adc_msg_get_argument(msg, 0);
				client->callback(client, ADC_CLIENT_PASSWORD_REQ, 0);
				if (challenge)
					ADC_client_send_password(client, challenge);
				hub_free(challenge);
			}
			break;

		case ADC_CMD_ISID:
			if (client->state == ps_protocol)
			{
				char* sid = adc_msg_get_argument(msg, 0);
				if (sid)
				{
					client->sid = string_to_sid(sid);
					hub_free(sid);
					client->callback(client, ADC_CLIENT_LOGGING_IN, 0);
					ADC_client_set_state(client, ps_identify);
					ADC_client_send_login_info(client);
				}
			}
			break;

		case ADC_CMD_BMSG:
		case ADC_CMD_EMSG:
		case ADC_CMD_DMSG:
		case ADC_CMD_IMSG:
		{
			chat.from_sid       = msg->source;
			chat.to_sid         = msg->target;
			data.chat = &chat;
			EXTRACT_POS_ARG(msg, 0, chat.message);
			chat.flags = 0;

			if (adc_msg_has_named_argument(msg, ADC_MSG_FLAG_ACTION))
				chat.flags |= chat_flags_action;

			if (adc_msg_has_named_argument(msg, ADC_MSG_FLAG_PRIVATE))
				chat.flags |= chat_flags_private;

			client->callback(client, ADC_CLIENT_MESSAGE, &data);
			hub_free(chat.message);
			break;
		}

		case ADC_CMD_IINF:
		{
			struct ADC_hub_info hubinfo;
			EXTRACT_NAMED_ARG(msg, "NI", hubinfo.name);
			EXTRACT_NAMED_ARG(msg, "DE", hubinfo.description);
			EXTRACT_NAMED_ARG(msg, "VE", hubinfo.version);

			struct ADC_client_callback_data data;
			data.hubinfo = &hubinfo;
			client->callback(client, ADC_CLIENT_HUB_INFO, &data);
			hub_free(hubinfo.name);
			hub_free(hubinfo.description);
			hub_free(hubinfo.version);
			break;
		}

		case ADC_CMD_BSCH:
		case ADC_CMD_FSCH:
		{
			/* The raw message is handed to the consumer; the search grammar is
			   the consumer's business. It is only valid until this returns,
			   since msg is freed at the end of this function. */
			data.message = msg;
			client->callback(client, ADC_CLIENT_SEARCH_REQ, &data);
			break;
		}

		case ADC_CMD_DRES:
		{
			data.message = msg;
			client->callback(client, ADC_CLIENT_SEARCH_REP, &data);
			break;
		}

		case ADC_CMD_IBBD:
		{
			/* BBS0 board descriptor. Handed over raw: the board grammar
			   belongs to the consumer, exactly as the search grammar does. */
			data.message = msg;
			client->callback(client, ADC_CLIENT_BBS_BOARD, &data);
			break;
		}

		case ADC_CMD_IBBL:
		{
			/* BBS0 index entry, or a tombstone when it carries RM1. */
			data.message = msg;
			client->callback(client, ADC_CLIENT_BBS_ENTRY, &data);
			break;
		}

		case ADC_CMD_DCTM:
		case ADC_CMD_ECTM:
		{
			data.message = msg;
			client->callback(client, ADC_CLIENT_CONNECT_REQ, &data);
			break;
		}

		case ADC_CMD_DRCM:
		case ADC_CMD_ERCM:
		{
			data.message = msg;
			client->callback(client, ADC_CLIENT_REVCONNECT_REQ, &data);
			break;
		}

		case ADC_CMD_BINF:
		{
			if (msg->source == client->sid)
			{
				if (client->state == ps_verify || client->state == ps_identify)
				{
					ADC_client_on_login(client);
				}
			}
			else
			{
				if (adc_msg_has_named_argument(msg, "ID"))
				{
					struct ADC_user user;
					user.sid = msg->source;
					EXTRACT_NAMED_ARG_X(msg, "NI", user.name, sizeof(user.name));
					EXTRACT_NAMED_ARG_X(msg, "DE", user.description, sizeof(user.description));
					EXTRACT_NAMED_ARG_X(msg, "VE", user.version, sizeof(user.version));
					EXTRACT_NAMED_ARG_X(msg, "ID", user.cid, sizeof(user.cid));
					/* IPv4 by preference, IPv6 when that is all there is. */
					EXTRACT_NAMED_ARG_X(msg, ADC_INF_FLAG_IPV4_ADDR, user.address, sizeof(user.address));
					if (!user.address[0])
						EXTRACT_NAMED_ARG_X(msg, ADC_INF_FLAG_IPV6_ADDR, user.address, sizeof(user.address));

					{
						char ct[8];
						EXTRACT_NAMED_ARG_X(msg, ADC_INF_FLAG_CLIENT_TYPE, ct, sizeof(ct));
						user.client_type = ADC_client_parse_client_type(ct);
					}

					/* SU says whether this peer can be connected to, and whether
					   it understands an encrypted transfer. */
					EXTRACT_NAMED_ARG_X(msg, ADC_INF_FLAG_SUPPORT, user.support, sizeof(user.support));

					struct ADC_client_callback_data data;
					data.user = &user;
					client->callback(client, ADC_CLIENT_USER_JOIN, &data);
				}
			}
		}
		break;

		case ADC_CMD_IQUI:
		{
			struct ADC_client_quit_reason reason;
			char* sid = adc_msg_get_argument(msg, 0);
			char* initiator = adc_msg_get_named_argument(msg, ADC_QUI_FLAG_KICK_OPERATOR);
			memset(&reason, 0, sizeof(reason));

			if (sid)
				reason.sid = string_to_sid(sid);
			if (initiator)
				reason.initator = string_to_sid(initiator);
			EXTRACT_NAMED_ARG_X(msg, ADC_QUI_FLAG_MESSAGE, reason.message, sizeof(reason.message));

			if (adc_msg_has_named_argument(msg, ADC_QUI_FLAG_DISCONNECT))
				reason.flags |= 1;

			hub_free(sid);
			hub_free(initiator);

			data.quit = &reason;
			client->callback(client, ADC_CLIENT_USER_QUIT, &data);
			break;
		}

		/*
		 * DSTA and ESTA are how a *peer* answers a connect request it will not
		 * take: "141 Protocol unsupported", naming the protocol in PR and the
		 * token in TO. They were dropped on the floor here, which is what made
		 * a transfer that never happened indistinguishable from one nobody ever
		 * replied to. They reach the caller through the same event as a hub
		 * status, told apart by status->from.
		 */
		case ADC_CMD_ISTA:
		case ADC_CMD_DSTA:
		case ADC_CMD_ESTA:
		{
			struct ADC_client_status status;
			char* code = adc_msg_get_argument(msg, 0);
			memset(&status, 0, sizeof(status));
			if (code)
			{
				status.code = (int) strtol(code, NULL, 10);
				status.severity = status.code / 100;
				hub_free(code);
			}
			EXTRACT_POS_ARG(msg, 1, status.message);

			if (msg->cmd != ADC_CMD_ISTA)
			{
				status.from = msg->source;
				status.protocol = adc_msg_get_named_argument(msg, ADC_STA_FLAG_PROTOCOL);
				status.token = adc_msg_get_named_argument(msg, ADC_INF_FLAG_TOKEN);
			}

			data.status = &status;
			/* A peer's refusal is never a login failure, whatever its severity:
			   the session with the hub is unaffected by it. */
			if (status.severity == 2 && client->state != ps_normal && !status.from)
				client->callback(client, ADC_CLIENT_LOGIN_ERROR, &data);
			else
				client->callback(client, ADC_CLIENT_PROTOCOL_STATUS, &data);

			hub_free(status.message);
			hub_free(status.protocol);
			hub_free(status.token);
			break;
		}

		default:
			break;
	}

	adc_msg_free(msg);
	return 0;
}

static ssize_t ADC_client_recv(struct ADC_client* client)
{
	static char buf[BIG_BUFSIZE];
	struct ioq_recv* q = client->recv_queue;
	size_t buf_size = ioq_recv_get(q, buf, BIG_BUFSIZE);
	ssize_t size;

	ADC_TRACE;

	if (client->flags & cflag_choke)
		buf_size = 0;
	size = net_con_recv(client->con, buf + buf_size, BIG_BUFSIZE - buf_size);

	if (size > 0)
		buf_size += size;

	if (size < 0)
		return -1;
	else if (size == 0)
		return 0;
	else
	{
		char* lastPos = 0;
		char* start = buf;
		char* pos = 0;
		size_t remaining = buf_size;

		while ((pos = memchr(start, '\n', remaining)))
		{
			lastPos = pos+1;
			pos[0] = '\0';

			if (client->flags & cflag_choke)
				client->flags &= ~cflag_choke;
			else
			{
				if (((pos - start) > 0) && MAX_RECV_BUFFER > (pos - start))
				{
					if (ADC_client_on_recv_line(client, start, pos - start) == -1)
						return -1;
				}
			}

			pos ++;
			remaining -= (pos - start);
			start = pos;
		}

		if (lastPos || remaining)
		{
			if (remaining < (size_t) MAX_RECV_BUFFER)
			{
				ioq_recv_set(q, lastPos ? lastPos : buf, remaining);
			}
			else
			{
				ioq_recv_set(q, 0, 0);
				client->flags |= cflag_choke;
				LOG_WARN("Received message past MAX_RECV_BUFFER (%d), dropping message.", MAX_RECV_BUFFER);
			}
		}
		else
		{
			ioq_recv_set(q, 0, 0);
		}
	}
	return 0;
}

static int ADC_client_send_queue(struct ADC_client* client)
{
	int ret = 0;
	while (ioq_send_get_bytes(client->send_queue))
	{
		ret = ioq_send_send(client->send_queue, client->con);
		if (ret <= 0)
			break;
	}

	if (ret < 0)
		return quit_socket_error;

	if (ioq_send_get_bytes(client->send_queue))
	{
		net_con_update(client->con, NET_EVENT_READ | NET_EVENT_WRITE);
	}
	else
	{
		net_con_update(client->con, NET_EVENT_READ);
	}
	return 0;
}


void ADC_client_send(struct ADC_client* client, struct adc_message* msg)
{
	ADC_TRACE;

	uhub_assert(client->con != NULL);
	uhub_assert(msg->cache && *msg->cache);

	ADC_client_log_wire(client, "-->", msg->cache, msg->length);

	if (ioq_send_is_empty(client->send_queue) && !(client->flags & cflag_pipe))
	{
		/* Perform oportunistic write */
		ioq_send_add(client->send_queue, msg);
		ADC_client_send_queue(client);
	}
	else
	{
		ioq_send_add(client->send_queue, msg);
		if (!(client->flags & cflag_pipe))
			net_con_update(client->con, NET_EVENT_READ | NET_EVENT_WRITE);
	}
}

int ADC_client_keepalive(struct ADC_client* client, int interval)
{
	struct adc_message* msg;
	time_t now;

	ADC_TRACE;

	/* Anything short of a logged-in connection is either already exchanging
	   handshake traffic or has nothing to keep alive. */
	if (!client || interval <= 0 || client->state != ps_normal || !client->con)
		return 0;

	if (ioq_send_get_bytes(client->send_queue))
		return 0;

	now = net_get_time();

	if (difftime(now, net_con_get_last_send(client->con)) < (double) interval ||
	    difftime(now, net_con_get_last_recv(client->con)) < (double) interval)
		return 0;

	msg = adc_msg_construct_keepalive();
	if (!msg)
		return 0;

	ADC_client_send(client, msg);
	adc_msg_free(msg);
	return 1;
}

struct adc_message* ADC_client_build_info(struct ADC_client* client)
{
	struct adc_message* info;

	ADC_TRACE;

	if (!client)
		return NULL;

	info = adc_msg_construct_source(ADC_CMD_BINF, client->sid, 96);
	if (!info)
		return NULL;

	adc_msg_add_named_argument_string(info, ADC_INF_FLAG_NICK, client->nick);

	if (client->desc)
	{
		adc_msg_add_named_argument_string(info, ADC_INF_FLAG_DESCRIPTION, client->desc);
	}

	/*
	 * SU is what tells the hub and every other client what this one can do:
	 * TCP4/TCP6 that it accepts connections, ADCS that those connections are
	 * encrypted. A client that listens but does not say so is treated as passive,
	 * and two passive parties cannot connect to each other at all.
	 */
	if (client->support[0])
		adc_msg_add_named_argument_string(info, ADC_INF_FLAG_SUPPORT, client->support);

	/* Only what the routing table answered; an unknown address is left out. */
	if (client->hbri)
	{
		if (client->local4.af == AF_INET)
			adc_msg_add_named_argument(info, ADC_INF_FLAG_IPV4_ADDR, ip_convert_to_string(&client->local4));
		if (client->local6.af == AF_INET6)
			adc_msg_add_named_argument(info, ADC_INF_FLAG_IPV6_ADDR, ip_convert_to_string(&client->local6));
	}

	adc_msg_add_named_argument_string(info, ADC_INF_FLAG_USER_AGENT_PRODUCT, PRODUCT);
	adc_msg_add_named_argument_string(info, ADC_INF_FLAG_USER_AGENT_VERSION, VERSION);
	adc_msg_add_named_argument_int(info, ADC_INF_FLAG_UPLOAD_SLOTS, 0);
	adc_msg_add_named_argument_int(info, ADC_INF_FLAG_SHARED_SIZE, 0);
	adc_msg_add_named_argument_int(info, ADC_INF_FLAG_SHARED_FILES, 0);

	adc_msg_add_named_argument_int(info, ADC_INF_FLAG_COUNT_HUB_NORMAL, 1);
	adc_msg_add_named_argument_int(info, ADC_INF_FLAG_COUNT_HUB_REGISTER, 0);
	adc_msg_add_named_argument_int(info, ADC_INF_FLAG_COUNT_HUB_OPERATOR, 0);

	adc_msg_add_named_argument_int(info, ADC_INF_FLAG_DOWNLOAD_SPEED, 5 * 1024 * 1024);
	adc_msg_add_named_argument_int(info, ADC_INF_FLAG_UPLOAD_SPEED, 10 * 1024 * 1024);

	adc_cid_pid(client, info);

	/* Caller-supplied fields go on last, so a test can state things this client
	   does not model -- an I6 for HBRI, say. */
	if (client->extra_inf)
	{
		char* p = client->extra_inf;
		while (*p)
		{
			char* end = strchr(p, ' ');
			if (end)
				*end = 0;
			if (*p)
				adc_msg_add_argument(info, p);
			if (!end)
				break;
			*end = ' ';
			p = end + 1;
		}
	}

	return info;
}

void ADC_client_send_info(struct ADC_client* client)
{
	ADC_TRACE;

	/* A client that reconnects builds a second INF; the send queue holds its
	   own reference (ioq_send_add increfs), so dropping ours here retires the
	   previous one instead of leaking it. */
	adc_msg_free(client->info);
	client->info = ADC_client_build_info(client);
	if (!client->info)
		return;

	ADC_client_send(client, client->info);
}


static void ADC_client_send_password(struct ADC_client* client, const char* challenge)
{
	struct adc_message* hpas;
	char buf[MAX_PASS_LEN + TIGERSIZE];
	/* Generous buffer: base32_decode zero-fills and writes `len` (MAX_CID_LEN)
	   bytes, which is wider than the 24-byte TIGER hash it yields. */
	char raw_challenge[64];
	char response[MAX_CID_LEN + 1];
	uint64_t tiger_res[3];
	size_t password_len;

	ADC_TRACE;

	if (!client->password)
	{
		/* The hub asked for a password and there is none. Nothing else will
		   happen on this connection, so it is said plainly rather than as a
		   debug aside. */
		LOG_ERROR("adc[%s] the hub asked for a password and none is configured.",
			ADC_client_host(client));
		client->callback(client, ADC_CLIENT_LOGIN_ERROR, 0);
		return;
	}

	/* The challenge is a base32-encoded TIGER hash (MAX_CID_LEN chars). */
	if (strlen(challenge) != MAX_CID_LEN)
	{
		LOG_ERROR("adc[%s] the hub sent a password challenge that cannot be used: \"%s\"",
			ADC_client_host(client), challenge);
		return;
	}

	password_len = strlen(client->password);
	if (password_len > MAX_PASS_LEN)
		password_len = MAX_PASS_LEN;

	base32_decode(challenge, (unsigned char*) raw_challenge, MAX_CID_LEN);

	memcpy(&buf[0], client->password, password_len);
	memcpy(&buf[password_len], raw_challenge, TIGERSIZE);

	tiger((uint64_t*) buf, password_len + TIGERSIZE, tiger_res);
	base32_encode((unsigned char*) tiger_res, TIGERSIZE, response);
	response[MAX_CID_LEN] = 0;

	hpas = adc_msg_construct(ADC_CMD_HPAS, MAX_CID_LEN + 8);
	adc_msg_add_argument(hpas, response);
	ADC_client_set_state(client, ps_verify);
	ADC_client_send(client, hpas);
	adc_msg_free(hpas);
}

struct ADC_client* ADC_client_create(const char* nickname, const char* description, void* ptr)
{
	ADC_TRACE;
	struct ADC_client* client = (struct ADC_client*) hub_malloc_zero(sizeof(struct ADC_client));

	ADC_client_set_state(client, ps_none);

	client->nick = hub_strdup(nickname);
	client->desc = hub_strdup(description);

	client->send_queue = ioq_send_create();
	client->recv_queue = ioq_recv_create();

	client->hbri_timer = (struct timeout_evt*) hub_malloc_zero(sizeof(struct timeout_evt));
	if (client->hbri_timer)
		timeout_evt_initialize(client->hbri_timer, ADC_client_hbri_grace_expired, client);

	client->ptr = ptr;

	if (!g_adc_client)
	{
		g_adc_client = (struct ADC_client_global*) hub_malloc_zero(sizeof(struct ADC_client_global));
		g_adc_client->ctx = net_ssl_context_create("1.2", "HIGH", "");
	}
	g_adc_client->references++;

	return client;
}

void ADC_client_destroy(struct ADC_client* client)
{
	ADC_TRACE;
	ADC_client_disconnect(client);
	ioq_send_destroy(client->send_queue);
	ioq_recv_destroy(client->recv_queue);
	adc_msg_free(client->info);
	hub_free(client->nick);
	hub_free(client->desc);
	hub_free(client->password);
	hub_free(client->fixed_pid);
	hub_free(client->extra_support);
	hub_free(client->extra_inf);
	hub_free(client->address.hostname);
	hub_free(client->hbri_timer);
	hub_free(client);

	if (g_adc_client && g_adc_client->references > 0)
	{
		g_adc_client->references--;
		if (!g_adc_client->references)
		{
			net_ssl_context_destroy(g_adc_client->ctx);
			g_adc_client->ctx = NULL;
			hub_free(g_adc_client);
			g_adc_client = NULL;
		}
	}
}

static void connect_callback(struct net_connect_handle* handle, enum net_connect_status status, struct net_connection* con, void* ptr)
{
	(void) handle;
	struct ADC_client* client = (struct ADC_client*) ptr;
	client->connect_job = NULL;
	switch (status)
	{
		case net_connect_status_ok:
			client->con = con;
			net_con_reinitialize(client->con, event_callback, client, 0);
			ADC_client_on_connected(client);
			break;

		case net_connect_status_host_not_found:
		case net_connect_status_no_address:
		case net_connect_status_dns_error:
		case net_connect_status_refused:
		case net_connect_status_unreachable:
		case net_connect_status_timeout:
		case net_connect_status_socket_error:
			ADC_client_disconnect(client);
			ADC_client_set_state(client, ps_none);
			client->callback(client, ADC_CLIENT_DISCONNECTED, 0);
			break;
	}
}

int ADC_client_connect(struct ADC_client* client, const char* address)
{
	ADC_TRACE;
	if (client->state == ps_none)
	{
		if (!ADC_client_parse_address(client, address))
			return 0;
	}

	/* A feature list is per connection. Carrying one across a reconnect would
	   let a client keep using an extension the hub has stopped announcing. */
	client->hub_support[0] = '\0';

	/* Both the addresses and the lookup that finds them belong to one attempt. */
	ADC_client_hbri_restart_lookup(client);

	ADC_client_set_state(client, ps_conn);
	client->callback(client, ADC_CLIENT_CONNECTING, 0);
	client->connect_job = net_con_connect(client->address.hostname, client->address.port, connect_callback, client);
	if (!client->connect_job)
	{
		ADC_client_on_disconnected(client);
		return 0;
	}
	return 1;
}

static void ADC_client_send_handshake(struct ADC_client* client)
{
	ADC_TRACE;
	struct adc_message* handshake;
	char buf[256];

	/* Announced here or not at all: no ADHBRI in the SUP, no ITCP. */
	snprintf(buf, sizeof(buf), "%s%s%s\n", ADC_HANDSHAKE,
	         client->hbri ? " AD" ADC_EXT_HBRI : "",
	         client->extra_support ? client->extra_support : "");
	handshake = adc_msg_create(buf);

	client->callback(client, ADC_CLIENT_CONNECTED, 0);
	net_con_update(client->con, NET_EVENT_READ);
	ADC_client_send(client, handshake);
	ADC_client_set_state(client, ps_protocol);
	adc_msg_free(handshake);
}

static void ADC_client_on_connected(struct ADC_client* client)
{
	ADC_TRACE;

	/* On the socket right now, and wanted for the login INF. */
	ADC_client_discover_local_address(client);

	if (client->flags & cflag_ssl)
	{
		/* No "kp=" means TLS without an identity: encrypted, but anyone able to
		   intercept the connection can be the hub. Permitted -- it is all that
		   works against a hub whose keyprint is unknown -- but never silent.
		   Said once per client, so a reconnect loop does not drown the log. */
		if (!client->address.keyprint[0] && !(client->flags & cflag_kp_warned))
		{
			client->flags |= cflag_kp_warned;
			LOG_WARN("The identity of hub %s is not being verified: the address pins no certificate. "
				"Append \"/?kp=SHA256/<the hub's keyprint>\" to the address to authenticate it.",
				client->address.hostname ? client->address.hostname : "");
		}

		net_con_update(client->con, NET_EVENT_READ | NET_EVENT_WRITE);
		client->callback(client, ADC_CLIENT_SSL_HANDSHAKE, 0);
		ADC_client_set_state(client, ps_conn_ssl);
		net_con_ssl_handshake(client->con, net_con_ssl_mode_client, g_adc_client->ctx);
	}
	else
	ADC_client_send_handshake(client);
	
}

/**
 * Check the certificate the hub presented against the keyprint pinned in its
 * URL. Runs after the handshake and before anything the hub says is acted on --
 * in particular before HSUP, so an impostor never gets to issue a password
 * challenge.
 *
 * @return 1 to carry on, 0 when the connection has been torn down.
 */
static int ADC_client_verify_keyprint(struct ADC_client* client)
{
	struct ADC_client_callback_data data;
	struct ADC_client_keyprint_error error;
	char presented[ADC_KEYPRINT_MAX];

	if (!client->address.keyprint[0])
		return 1;  /* nothing pinned; warned about at connect time */

	if (!net_ssl_get_peer_keyprint(client->con, presented, sizeof(presented)))
		presented[0] = '\0';

	if (presented[0] && net_ssl_keyprint_equal(presented, client->address.keyprint))
		return 1;

	LOG_ERROR("Hub %s failed keyprint verification: expected %s, hub presented %s. Disconnecting.",
		client->address.hostname ? client->address.hostname : "",
		client->address.keyprint,
		presented[0] ? presented : "no certificate");

	error.expected = client->address.keyprint;
	error.presented = presented;
	data.keyprint = &error;
	client->callback(client, ADC_CLIENT_SSL_KEYPRINT_ERROR, &data);

	ADC_client_on_disconnected(client);
	return 0;
}

static void ADC_client_on_connected_ssl(struct ADC_client* client)
{
	ADC_TRACE;
	struct ADC_client_callback_data data;
	struct ADC_client_tls_info tls_info;
	data.tls_info = &tls_info;

	if (!ADC_client_verify_keyprint(client))
		return;

	tls_info.version = net_ssl_get_tls_version(client->con);
	tls_info.cipher = net_ssl_get_tls_cipher(client->con);

	client->callback(client, ADC_CLIENT_SSL_OK, &data);
	ADC_client_send_handshake(client);
}

static void ADC_client_on_disconnected(struct ADC_client* client)
{
	ADC_TRACE;

	/* Both belong to the connection that is going away. */
	ADC_client_hbri_close(client);
	ADC_client_hbri_cancel_lookup(client);

	if (client->con)
	{
		net_con_close(client->con);
		client->con = 0;
	}
	ADC_client_set_state(client, ps_none);

	/* Notify the owner that the connection is gone. Without this an unexpected
	   drop (peer reset, recv error) leaves the client with a NULL connection but
	   the owner still believing it is logged in, so the next attempt to send a
	   message trips the uhub_assert(client->con != NULL) in ADC_client_send(). */
	client->callback(client, ADC_CLIENT_DISCONNECTED, 0);
}

static void ADC_client_on_login(struct ADC_client* client)
{
	ADC_TRACE;
	ADC_client_set_state(client, ps_normal);
	client->callback(client, ADC_CLIENT_LOGGED_IN, 0);
}

void ADC_client_disconnect(struct ADC_client* client)
{
	ADC_TRACE;

	ADC_client_hbri_close(client);
	ADC_client_hbri_cancel_lookup(client);

	/* Cancel a still-pending connect (DNS/connect in flight). connect_callback()
	   clears connect_job before it fires and the net layer frees the handle
	   itself afterwards, so a non-NULL connect_job here means the callback has
	   not run yet -- without this the handle outlives the client and the eventual
	   callback dereferences freed memory. */
	if (client->connect_job)
	{
		net_connect_destroy(client->connect_job);
		client->connect_job = 0;
	}

	if (client->con && net_con_get_sd(client->con) != -1)
	{
		net_con_close(client->con);
		client->con = 0;
	}
}

/** Number of base32 characters a SHA-256 digest encodes to. */
#define ADC_KEYPRINT_SHA256_LEN 52

int ADC_client_parse_keyprint(const char* address, char* out, size_t out_size)
{
	const char* path;
	const char* p;
	const char* value = NULL;
	const char* slash;
	const char* hash;
	size_t len;
	size_t alg_len;
	size_t hash_len;
	size_t i;

	if (!out || out_size == 0)
		return -1;
	out[0] = '\0';

	if (!address)
		return 0;

	/* The keyprint lives in the query string, so nothing before the authority
	   ends can be one -- "kp=" inside a hostname is part of the hostname. The
	   scheme's own "//" is skipped first, or it would be mistaken for the start
	   of the path and make the hostname look like a query string. */
	path = strstr(address, "://");
	path = path ? path + 3 : address;

	path = strpbrk(path, "/?#");
	if (!path)
		return 0;

	for (p = path; (p = strstr(p, "kp=")) != NULL; p += 3)
	{
		/* Only a whole parameter named "kp", never the tail of e.g. "xkp=". */
		char prev = (p > address) ? p[-1] : '\0';
		if (prev == '?' || prev == '&' || prev == ';' || prev == '/' || prev == '#')
		{
			value = p + 3;
			break;
		}
	}

	if (!value)
		return 0;

	/* The value contains a '/' of its own, so only a parameter separator or the
	   end of the string terminates it. */
	len = strcspn(value, "&#");
	if (len == 0 || len >= out_size)
		return -1;

	slash = (const char*) memchr(value, '/', len);
	if (!slash)
		return -1;

	/* An algorithm we do not implement cannot be checked, and pretending
	   otherwise would leave the connection unauthenticated while looking
	   pinned, so it is refused rather than skipped. */
	alg_len = (size_t) (slash - value);
	if (alg_len != 6 || strncasecmp(value, "SHA256", 6) != 0)
		return -1;

	hash = slash + 1;
	hash_len = len - alg_len - 1;
	if (hash_len != ADC_KEYPRINT_SHA256_LEN)
		return -1;

	for (i = 0; i < hash_len; i++)
	{
		/* Base32 is case-insensitive; is_valid_base32_char() only knows the
		   canonical upper-case alphabet. */
		char c = hash[i];
		if (c >= 'a' && c <= 'z')
			c = (char) (c - ('a' - 'A'));
		if (!is_valid_base32_char(c))
			return -1;
	}

	memcpy(out, value, len);
	out[len] = '\0';
	return 1;
}

static int ADC_client_parse_address(struct ADC_client* client, const char* arg)
{
	ADC_TRACE;
	const char* hub_address = arg;
	const char* split;
	int ssl = 0;

	if (!arg)
		return 0;

	/* Minimum length of a valid address */
	if (strlen(arg) < 9)
		return 0;

	/* Check for ADC or ADCS */
	if (!strncmp(arg, "adc://", 6))
	{
		client->flags &= ~cflag_ssl;
		client->address.protocol = ADC;
	}
	else if (!strncmp(arg, "adcs://", 7))
	{
		client->flags |= cflag_ssl;
		ssl = 1;
		client->address.protocol = ADCS;
	}
	else
		return 0;

	/* Split hostname and port (if possible) */
	hub_address = arg + 6 + ssl;

	/*
	 * An ADC URL may carry a path, and the keyprint form always does:
	 * "adcs://host:1511/?kp=SHA256/...". Everything from the first '/' belongs
	 * to the path, so the authority ends there. Searching the whole string for
	 * the last ':' made the trailing slash part of the port and rejected the
	 * address outright -- and only for ports of other than four digits, since
	 * ":1511/" is exactly the six characters the length check allowed.
	 */
	const char* end = strpbrk(hub_address, "/?#");
	if (!end)
		end = hub_address + strlen(hub_address);

	/*
	 * An IPv6 literal is bracketed -- "adc://[::1]:1511" -- because its own
	 * colons would otherwise be indistinguishable from the port separator.
	 * The brackets delimit the host; the port separator is the colon that
	 * follows them, and never one inside.
	 */
	const char* host_start = hub_address;
	const char* host_end;

	if (*hub_address == '[')
	{
		const char* rbracket = memchr(hub_address, ']', (size_t) (end - hub_address));
		if (!rbracket || rbracket == hub_address + 1)
			return 0;
		host_start = hub_address + 1;
		host_end = rbracket;
		split = (rbracket + 1 < end && rbracket[1] == ':') ? rbracket + 1 : NULL;
	}
	else
	{
		split = NULL;
		for (const char* p = end; p > hub_address; )
		{
			if (*--p == ':')
			{
				split = p;
				break;
			}
		}
		host_end = split;
	}

	if (split == 0 || (end - split) < 2 || (end - split) > 6)
		return 0;

	/* Ensure the port is all digits: strtol would otherwise accept "80x". */
	for (const char* p = split + 1; p < end; p++)
		if (*p < '0' || *p > '9')
			return 0;

	/* Ensure port number is valid (validate before narrowing to uint16_t). */
	long port = strtol(split+1, NULL, 10);
	if (port <= 0 || port > 65535)
		return 0;
	client->address.port = (uint16_t) port;

	/*
	 * The pinned keyprint, if the URL carries one. A "kp=" that cannot be used
	 * fails the whole address: an operator who wrote one down expects the hub to
	 * be checked against it, and connecting anyway would quietly do the opposite.
	 */
	if (ADC_client_parse_keyprint(arg, client->address.keyprint, sizeof(client->address.keyprint)) < 0)
	{
		LOG_ERROR("Unusable keyprint in hub address; expected \"kp=SHA256/<52 base32 characters>\".");
		return 0;
	}

	/* There is no certificate to check on a plain adc:// connection, so a
	   keyprint there is a configuration that looks authenticated and is not. */
	if (client->address.keyprint[0] && !ssl)
	{
		LOG_ERROR("A keyprint was given for a plain adc:// address, which cannot verify it. Use adcs://.");
		return 0;
	}

	/* Re-parsed on every reconnect, so the previous hostname has to go. */
	hub_free(client->address.hostname);
	client->address.hostname = hub_strndup(host_start, (size_t) (host_end - host_start));

	return 1;
}

void ADC_client_set_password(struct ADC_client* client, const char* password)
{
	ADC_TRACE;
	hub_free(client->password);
	client->password = password ? hub_strdup(password) : NULL;
}

int ADC_client_set_support(struct ADC_client* client, const char* su)
{
	ADC_TRACE;

	if (!client)
		return 0;

	if (!su || !*su)
	{
		client->support[0] = '\0';
		return 1;
	}

	/* Refused rather than truncated: a half-written SU is a different claim
	   from the one the caller made, and "TCP4,ADC" is not a token at all. */
	if (strlen(su) >= sizeof(client->support))
		return 0;

	strcpy(client->support, su);
	return 1;
}

/* Pin the client's PID (base32, MAX_CID_LEN chars) instead of generating a
   random one, giving the client a stable identity. The CID is derived from it
   (CID = base32(tiger(PID))) and cached so ADC_client_get_cid() is valid before
   connecting. Passing NULL restores random per-connection identities. */
void ADC_client_add_support(struct ADC_client* client, const char* feature)
{
	size_t length;
	char* buf;

	ADC_TRACE;
	if (!feature || !*feature)
		return;

	/* " " + feature, appended to whatever is already there. */
	length = (client->extra_support ? strlen(client->extra_support) : 0) + strlen(feature) + 2;
	buf = hub_malloc_zero(length);
	if (!buf)
		return;

	snprintf(buf, length, "%s %s", client->extra_support ? client->extra_support : "", feature);
	hub_free(client->extra_support);
	client->extra_support = buf;
}

void ADC_client_add_inf(struct ADC_client* client, const char* field)
{
	size_t length;
	char* buf;

	ADC_TRACE;
	if (!field || !*field || strchr(field, ' '))
		return;

	length = (client->extra_inf ? strlen(client->extra_inf) + 1 : 0) + strlen(field) + 1;
	buf = hub_malloc_zero(length);
	if (!buf)
		return;

	if (client->extra_inf)
		snprintf(buf, length, "%s %s", client->extra_inf, field);
	else
		snprintf(buf, length, "%s", field);
	hub_free(client->extra_inf);
	client->extra_inf = buf;
}

void ADC_client_set_pid(struct ADC_client* client, const char* pid)
{
	ADC_TRACE;
	hub_free(client->fixed_pid);
	client->fixed_pid = NULL;
	client->cid[0] = '\0';
	if (pid && strlen(pid) == MAX_CID_LEN)
	{
		uint64_t t1[8];   /* base32_decode of MAX_CID_LEN chars writes >24 bytes */
		uint64_t t2[3];
		client->fixed_pid = hub_strdup(pid);
		memset(t1, 0, sizeof(t1));
		base32_decode(pid, (unsigned char*) t1, MAX_CID_LEN);
		tiger((uint64_t*) t1, TIGERSIZE, t2);
		base32_encode((unsigned char*) t2, TIGERSIZE, client->cid);
		client->cid[MAX_CID_LEN] = '\0';
	}
}

void ADC_client_set_callback(struct ADC_client* client, adc_client_cb cb)
{
	ADC_TRACE;
	client->callback = cb;
}

sid_t ADC_client_get_sid(const struct ADC_client* client)
{
	return client->sid;
}

const char* ADC_client_get_cid(const struct ADC_client* client)
{
	return client->cid;
}

const char* ADC_client_get_nick(const struct ADC_client* client)
{
	return client->nick;
}

const char* ADC_client_get_description(const struct ADC_client* client)
{
	return client->desc;
}

void* ADC_client_get_ptr(const struct ADC_client* client)
{
	return client->ptr;
}

const char* ADC_client_get_keyprint(const struct ADC_client* client)
{
	return client ? client->address.keyprint : "";
}

const char* ADC_client_get_support(const struct ADC_client* client)
{
	return client ? client->support : "";
}

int ADC_client_hub_supports(const struct ADC_client* client, const char* feature)
{
	return client ? adc_sup_has(client->hub_support, feature) : 0;
}

const char* ADC_client_hub_support_list(const struct ADC_client* client)
{
	return client ? client->hub_support : "";
}

int ADC_client_parse_client_type(const char* ct)
{
	int bits = 0;

	/* CT is a decimal bit mask. A hub is free to send something that is not
	   one -- it is just a string on the wire -- so anything unparseable is
	   read as "no client type" rather than being guessed at. */
	if (!ct || !*ct || !is_number(ct, &bits) || bits < 0)
		return 0;

	return bits;
}
