#include "system.h"
#include "util/misc.h"
#include "adc/message.h"
#include "network/network.h"
#include "network/ipcalc.h"
#include "network/backend.h"
#include "network/dnsresolver.h"
#include "network/timeout.h"

#include <poll.h>
#include "tools/adcclient.h"
#include "testutil_net.h"

/*
 * The client half of HBRI: working out this host's own address in each protocol
 * family, and reading the ITCP that asks it to prove the family it did not
 * connect over.
 *
 * Both are decisions made on bytes the hub supplied, or on what the routing
 * table answers, and both are otherwise only observable over a live dual-stack
 * socket -- which is exactly why they are broken out to be called directly.
 * The connect tests use loopback, as test_connect.tcc does.
 */

static struct adc_message* ah_msg(const char* line)
{
	return adc_msg_parse(line, strlen(line));
}

/* A parse that must fail, without leaking the message. */
static int ah_parse_fails(const char* line)
{
	struct ADC_client_hbri_request req;
	struct adc_message* msg = ah_msg(line);
	int ret;

	if (!msg)
		return 1; /* it did not even parse as ADC, which is a failure too */

	ret = (ADC_client_parse_hbri_request(msg, &req) == 0 && req.af == 0);
	adc_msg_free(msg);
	return ret;
}

/* ---------------------------------------------------------------------------
 * net_local_address_for(): which source address would reach a given peer
 * ------------------------------------------------------------------------- */

/* Loopback is the one route every host has, and it answers with itself. */
EXO_TEST(adchbri_local_addr_v4_loopback, {
	struct ip_addr_encap remote;
	struct ip_addr_encap local;

	if (ip_convert_to_binary("127.0.0.1", &remote) <= 0)
		return 0;

	return net_local_address_for(&remote, 1511, &local) == 1
		&& local.af == AF_INET
		&& strcmp(ip_convert_to_string(&local), "127.0.0.1") == 0;
});

EXO_TEST(adchbri_local_addr_v6_loopback, {
	struct ip_addr_encap remote;
	struct ip_addr_encap local;

	if (!net_is_ipv6_supported())
		EXO_SKIP("no IPv6 on this host");

	if (ip_convert_to_binary("::1", &remote) <= 0)
		return 0;

	return net_local_address_for(&remote, 1511, &local) == 1
		&& local.af == AF_INET6
		&& strcmp(ip_convert_to_string(&local), "::1") == 0;
});

/* The answer must never be handed back through a half-filled struct: on any
   failure the caller's address is left exactly as it was. */
EXO_TEST(adchbri_local_addr_leaves_out_alone, {
	struct ip_addr_encap remote;
	struct ip_addr_encap local;

	memset(&remote, 0, sizeof(remote));
	memset(&local, 0, sizeof(local));
	remote.af = AF_UNSPEC; /* not an address family this can be asked about */
	local.af = AF_INET;

	return net_local_address_for(&remote, 1511, &local) == 0 && local.af == AF_INET;
});

EXO_TEST(adchbri_local_addr_null_args, {
	struct ip_addr_encap addr;
	memset(&addr, 0, sizeof(addr));
	addr.af = AF_INET;
	return net_local_address_for(NULL, 1511, &addr) == 0
		&& net_local_address_for(&addr, 1511, NULL) == 0;
});

/* ---------------------------------------------------------------------------
 * ADC_client_parse_hbri_request(): reading an ITCP
 * ------------------------------------------------------------------------- */

EXO_TEST(adchbri_parse_ipv6_request, {
	struct ADC_client_hbri_request req;
	struct adc_message* msg = ah_msg("ITCP I62001:db8::10 P61511 TOAAABTOKEN\n");
	int ok;

	if (!msg)
		return 0;

	ok = ADC_client_parse_hbri_request(msg, &req) == 1
		&& req.af == AF_INET6
		&& req.port == 1511
		&& strcmp(req.address, "2001:db8::10") == 0
		&& strcmp(req.token, "AAABTOKEN") == 0;

	adc_msg_free(msg);
	return ok;
});

EXO_TEST(adchbri_parse_ipv4_request, {
	struct ADC_client_hbri_request req;
	struct adc_message* msg = ah_msg("ITCP I4192.0.2.10 P4411 TOAAABTOKEN\n");
	int ok;

	if (!msg)
		return 0;

	ok = ADC_client_parse_hbri_request(msg, &req) == 1
		&& req.af == AF_INET
		&& req.port == 411
		&& strcmp(req.address, "192.0.2.10") == 0;

	adc_msg_free(msg);
	return ok;
});

/*
 * The address flag names the family, and the port flag has to agree with it. A
 * P4 next to an I6 is not this grammar, and reading the port out of it anyway
 * would let a hub aim the callback connection with fields that contradict each
 * other.
 */
EXO_TEST(adchbri_parse_mismatched_port_flag, {
	return ah_parse_fails("ITCP I62001:db8::10 P41511 TOAAABTOKEN\n");
});

EXO_TEST(adchbri_parse_missing_token, {
	return ah_parse_fails("ITCP I62001:db8::10 P61511\n");
});

EXO_TEST(adchbri_parse_missing_port, {
	return ah_parse_fails("ITCP I62001:db8::10 TOAAABTOKEN\n");
});

EXO_TEST(adchbri_parse_missing_address, {
	return ah_parse_fails("ITCP P61511 TOAAABTOKEN\n");
});

/* The address has to be one, and one of the family its flag claims. */
EXO_TEST(adchbri_parse_bad_address, {
	return ah_parse_fails("ITCP I6not-an-address P61511 TOAAABTOKEN\n")
		&& ah_parse_fails("ITCP I4192.0.2.999 P41511 TOAAABTOKEN\n")
		/* an IPv4 address under the IPv6 flag: valid text, wrong family */
		&& ah_parse_fails("ITCP I6192.0.2.10 P61511 TOAAABTOKEN\n");
});

/* Ports are dialled, so they must be plain decimal numbers in range. */
EXO_TEST(adchbri_parse_bad_port, {
	return ah_parse_fails("ITCP I4192.0.2.10 P40 TOAAABTOKEN\n")
		&& ah_parse_fails("ITCP I4192.0.2.10 P465536 TOAAABTOKEN\n")
		&& ah_parse_fails("ITCP I4192.0.2.10 P4-1 TOAAABTOKEN\n")
		&& ah_parse_fails("ITCP I4192.0.2.10 P4141x TOAAABTOKEN\n");
});

/* An empty token would be echoed back as a bare "TO", which names no session. */
EXO_TEST(adchbri_parse_empty_token, {
	return ah_parse_fails("ITCP I4192.0.2.10 P41511 TO\n");
});

/* The token goes back on the wire verbatim as one argument, so a token longer
   than there is room for is refused rather than truncated -- a truncated token
   is a different token, and would fail verification at the hub with no clue as
   to why. */
EXO_TEST(adchbri_parse_oversized_token, {
	char line[256];
	char token[ADC_HBRI_TOKEN_MAX + 8];

	memset(token, 'A', sizeof(token) - 1);
	token[sizeof(token) - 1] = '\0';
	snprintf(line, sizeof(line), "ITCP I4192.0.2.10 P41511 TO%s\n", token);

	return ah_parse_fails(line);
});

/* Not an ITCP field set at all. */
EXO_TEST(adchbri_parse_null_args, {
	struct ADC_client_hbri_request req;
	struct adc_message* msg = ah_msg("ITCP I4192.0.2.10 P41511 TOAAABTOKEN\n");
	int ok;

	if (!msg)
		return 0;

	ok = ADC_client_parse_hbri_request(NULL, &req) == 0
		&& ADC_client_parse_hbri_request(msg, NULL) == 0;

	adc_msg_free(msg);
	return ok;
});

/* ---------------------------------------------------------------------------
 * The client: opting in, and what the INF then carries
 * ------------------------------------------------------------------------- */

static struct ADC_client* ah_client = NULL;
static int ah_connected = 0;
static int ah_listener = -1;
static uint16_t ah_port = 0;

static int ah_callback(struct ADC_client* client, enum ADC_client_callback_type type,
	struct ADC_client_callback_data* data)
{
	(void) client;
	(void) data;
	if (type == ADC_CLIENT_CONNECTED)
		ah_connected = 1;
	return 1;
}

/* A loopback socket that accepts, so a connection completes without a hub. */
static int ah_make_listener(uint16_t* out_port)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int sd = socket(AF_INET, SOCK_STREAM, 0);

	if (sd == -1)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0
		|| getsockname(sd, (struct sockaddr*) &addr, &len) != 0
		|| listen(sd, 4) != 0)
	{
		close(sd);
		return -1;
	}

	*out_port = ntohs(addr.sin_port);
	return sd;
}

/*
 * Every client test starts with ah_start() and ends with ah_stop(): a client
 * that has opted in to HBRI, and -- when `connect` is set -- is connected over
 * loopback to a listener standing in for the hub.
 */
static int ah_start(int connect)
{
	char url[64];
	int i;

	ah_client = ADC_client_create("hbritest", "", NULL);
	if (!ah_client)
		return 0;
	ADC_client_set_callback(ah_client, ah_callback);
	ADC_client_set_hbri(ah_client, 1);
	if (!connect)
		return 1;

	ah_listener = ah_make_listener(&ah_port);
	if (ah_listener == -1)
		return 0;

	snprintf(url, sizeof(url), "adc://127.0.0.1:%u", (unsigned) ah_port);
	ah_connected = 0;

	if (!ADC_client_connect(ah_client, url))
		return 0;

	for (i = 0; i < 10000 && !ah_connected; i++)
		net_backend_process();

	return ah_connected == 1;
}

static void ah_stop(void)
{
	if (ah_client)
		ADC_client_destroy(ah_client);
	ah_client = NULL;
	if (ah_listener != -1)
		close(ah_listener);
	ah_listener = -1;
}

EXO_TEST(adchbri_client_create, {
	int ok;
	ah_client = ADC_client_create("hbritest", "", NULL);
	if (!ah_client)
		return 0;
	ADC_client_set_callback(ah_client, ah_callback);
	ok = ADC_client_get_hbri(ah_client) == 0;
	ah_stop();
	return ok;
});

/* Opting in is explicit: a client that does not listen has nothing to prove. */
EXO_TEST(adchbri_client_opt_in, {
	int ok = ah_start(0) && ADC_client_get_hbri(ah_client) == 1;
	ah_stop();
	return ok;
});

/* Nothing is known before there is a connection to read an address off. */
EXO_TEST(adchbri_no_address_before_connect, {
	int ok = ah_start(0)
		&& strcmp(ADC_client_get_local_address(ah_client, AF_INET), "") == 0
		&& strcmp(ADC_client_get_local_address(ah_client, AF_INET6), "") == 0
		&& strcmp(ADC_client_get_local_address(ah_client, AF_UNSPEC), "") == 0
		&& strcmp(ADC_client_get_local_address(NULL, AF_INET), "") == 0;
	ah_stop();
	return ok;
});

/* ...and an address that is not known is left out of the INF rather than
   invented: an I4 the hub cannot reach is worse than no I4 at all. */
EXO_TEST(adchbri_inf_omits_unknown_address, {
	struct adc_message* info;
	int ok;

	if (!ah_start(0))
	{
		ah_stop();
		return 0;
	}
	info = ADC_client_build_info(ah_client);
	ok = info
		&& !adc_msg_has_named_argument(info, "I4")
		&& !adc_msg_has_named_argument(info, "I6");

	adc_msg_free(info);
	ah_stop();
	return ok;
});

EXO_TEST(adchbri_connect_loopback, {
	int ok = ah_start(1);
	ah_stop();
	return ok;
});

/*
 * The address the connection was made from is read straight off the socket, so
 * it is known the moment the connection is up.
 */
EXO_TEST(adchbri_primary_address_discovered, {
	int ok = ah_start(1)
		&& strcmp(ADC_client_get_local_address(ah_client, AF_INET), "127.0.0.1") == 0;
	ah_stop();
	return ok;
});

/* And it is what the INF then states. */
EXO_TEST(adchbri_inf_states_known_address, {
	struct adc_message* info;
	char* addr;
	int ok;

	if (!ah_start(1))
	{
		ah_stop();
		return 0;
	}
	info = ADC_client_build_info(ah_client);
	if (!info)
	{
		ah_stop();
		return 0;
	}

	addr = adc_msg_get_named_argument(info, "I4");
	ok = addr && strcmp(addr, "127.0.0.1") == 0;

	hub_free(addr);
	adc_msg_free(info);
	ah_stop();
	return ok;
});

/*
 * The second family is only ever worked out from the hub's other DNS records,
 * and an address literal has none -- so nothing is claimed for it. Pumped for a
 * while first, since that answer arrives through a lookup rather than at once.
 */
EXO_TEST(adchbri_no_second_family_for_literal, {
	int ok = ah_start(1);

	/* Directly, not by pumping: with nothing due a poll would block. */
	net_dns_wait_idle();
	net_dns_process();

	ok = ok && strcmp(ADC_client_get_local_address(ah_client, AF_INET6), "") == 0;
	ah_stop();
	return ok;
});

/*
 * A disconnect does not erase what was worked out: the last known address is
 * still the best answer there is, and an offline mount showing nothing at all
 * would be less useful than one showing where it was. It is a reconnect that
 * discards it -- the next connection may be from another network entirely, and
 * re-reads everything off the new socket.
 */
EXO_TEST(adchbri_address_survives_disconnect, {
	int ok = ah_start(1);
	ADC_client_disconnect(ah_client);
	ok = ok && strcmp(ADC_client_get_local_address(ah_client, AF_INET), "127.0.0.1") == 0;
	ah_stop();
	return ok;
});

EXO_TEST(adchbri_client_destroy, {
	int ok = ah_start(1);
	ah_stop();
	return ok;
});

/* ---------------------------------------------------------------------------
 * The validation connection: ITCP -> connect -> HTCP -> ISTA
 *
 * Driven against a fake hub rather than a mocked transport, because what is
 * under test is a real second connection: the client has to dial it over the
 * protocol the session did not use, put its token on it, and let go of it
 * afterwards. Two loopback listeners stand in for the hub -- one on 127.0.0.1
 * for the session, one on ::1 for the validation it is asked to make.
 * ------------------------------------------------------------------------- */

#define VH_TOKEN "AAABVALIDATIONTOKEN"

static struct ADC_client* vh_client = NULL;
static int vh_listen4 = -1;      /* the fake hub */
static int vh_listen6 = -1;      /* where it asks to be reached over IPv6 */
static int vh_hub = -1;          /* the hub's end of the session */
static int vh_val = -1;          /* the hub's end of the validation connection */
static uint16_t vh_port4 = 0;
static uint16_t vh_port6 = 0;
static uint16_t vh_dead6 = 0;    /* an IPv6 port with nothing listening */
static int vh_connected = 0;
static int vh_lines = 0;         /* lines the client has taken off the socket */
static int vh_joins = 0;
static char vh_join_address[INET6_ADDRSTRLEN + 1];
static int vh_skip = 0;
static struct timeout_evt vh_tick;

static void vh_tick_cb(struct timeout_evt* evt)
{
	(void) evt;
}

static int vh_callback(struct ADC_client* client, enum ADC_client_callback_type type,
	struct ADC_client_callback_data* data)
{
	(void) client;
	(void) data;
	if (type == ADC_CLIENT_CONNECTED)
		vh_connected = 1;
	else if (type == ADC_CLIENT_RAW_LINE)
		vh_lines++;
	else if (type == ADC_CLIENT_USER_JOIN && data && data->user)
	{
		uhub_strlcpy(vh_join_address, data->user->address, sizeof(vh_join_address));
		vh_joins++;
	}
	return 1;
}

/* A loopback listener on ::1, so a connection to it can only be IPv6. */
static int vh_make_listener6(uint16_t* out_port, int do_listen)
{
	struct sockaddr_in6 addr;
	socklen_t len = sizeof(addr);
	int on = 1;
	int sd = socket(AF_INET6, SOCK_STREAM, 0);

	if (sd == -1)
		return -1;

	/* v6-only, so that reaching it is proof of IPv6 and not of a dual-stack
	   socket quietly accepting an IPv4 connection. */
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) != 0)
	{
		close(sd);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_loopback;
	addr.sin6_port = 0;

	if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0
		|| getsockname(sd, (struct sockaddr*) &addr, &len) != 0
		|| (do_listen && listen(sd, 4) != 0))
	{
		close(sd);
		return -1;
	}

	*out_port = ntohs(addr.sin6_port);
	return sd;
}

static int vh_ready(int fd, int msec)
{
	struct pollfd p;

	if (fd == -1)
		return 0;

	p.fd = fd;
	p.events = POLLIN;
	p.revents = 0;
	return poll(&p, 1, msec) == 1 && (p.revents & POLLIN) != 0;
}

/*
 * One turn of the client's event loop.
 *
 * A one second tick is kept in the timeout queue while these tests run: with
 * nothing else due, the poll inside net_backend_process() would otherwise wait
 * out the validation connection's own 30 second timeout, so a test that is
 * going to fail would take half an hour to say so.
 */
static void vh_turn(void)
{
	if (!timeout_evt_is_scheduled(&vh_tick))
		timeout_queue_insert(net_backend_get_timeout_queue(), &vh_tick, 1);
	net_backend_process();
}

/* Run the loop until the client has taken another line off the socket. */
static int vh_wait_line(int seconds)
{
	int before = vh_lines;
	time_t deadline = time(NULL) + seconds;

	while (vh_lines == before && time(NULL) <= deadline)
		vh_turn();

	return vh_lines != before;
}

/*
 * Turn the loop a few times, to let something finish that has no observable
 * result at this end -- a refused connect being noticed and cleaned up.
 */
static void vh_turn_a_few(void)
{
	int i;

	for (i = 0; i < 5; i++)
		vh_turn();
}

/* Run the loop until @p fd has something to read (or has reached EOF). */
static int vh_wait_readable(int fd, int seconds)
{
	time_t deadline = time(NULL) + seconds;

	while (!vh_ready(fd, 0) && time(NULL) <= deadline)
		vh_turn();

	return vh_ready(fd, 0);
}

/*
 * Let a connection the client decided to make actually get made.
 *
 * The address is a literal, but it still goes through the resolver, and the
 * connect is only issued from that callback -- so draining the resolver by hand
 * is what turns "the client wants to connect" into a SYN the listener can see.
 */
static void vh_settle(void)
{
	net_dns_wait_idle();
	net_dns_process();
}

/* Hand the client an ITCP, and let it read and act on it. */
static int vh_send_itcp(const char* body)
{
	char line[256];
	int len = snprintf(line, sizeof(line), "ITCP %s\n", body);

	if (len <= 0 || (size_t) len >= sizeof(line))
		return 0;
	if (send(vh_hub, line, (size_t) len, 0) != len)
		return 0;
	if (!vh_wait_line(5))
		return 0;

	vh_settle();
	return 1;
}

/*
 * The fake hub's listeners, made once for the file. Each validation test then
 * makes its own session with vh_start() and ends it with vh_stop().
 */
EXO_SETUP({
	int dead;

	if (!test_net_acquire())
		return 0;

	memset(&vh_tick, 0, sizeof(vh_tick));
	timeout_evt_initialize(&vh_tick, vh_tick_cb, NULL);

	vh_listen4 = ah_make_listener(&vh_port4);
	vh_listen6 = net_is_ipv6_supported() ? vh_make_listener6(&vh_port6, 1) : -1;

	/* A port that was bound and released: connecting to it is refused at once
	   rather than left to time out. */
	dead = net_is_ipv6_supported() ? vh_make_listener6(&vh_dead6, 0) : -1;
	if (dead != -1)
		close(dead);

	vh_skip = (vh_listen4 == -1 || vh_listen6 == -1 || dead == -1);
	return 1;
});

EXO_TEARDOWN({
	if (vh_client)
		ADC_client_destroy(vh_client);
	vh_client = NULL;

	if (timeout_evt_is_scheduled(&vh_tick))
		timeout_queue_remove(net_backend_get_timeout_queue(), &vh_tick);

	if (vh_val != -1) close(vh_val);
	if (vh_hub != -1) close(vh_hub);
	if (vh_listen4 != -1) close(vh_listen4);
	if (vh_listen6 != -1) close(vh_listen6);
	vh_val = vh_hub = vh_listen4 = vh_listen6 = -1;
	test_net_release();
	return 1;
});

/* Accept and drop whatever is still queued on a listener, so a connection one
   test left behind cannot look like something the next test caused. */
static void vh_drain(int listener)
{
	while (vh_ready(listener, 0))
	{
		int sd = accept(listener, NULL, NULL);
		if (sd == -1)
			break;
		close(sd);
	}
}

static void vh_stop(void)
{
	if (vh_client)
		ADC_client_destroy(vh_client);
	vh_client = NULL;
	if (vh_val != -1) close(vh_val);
	if (vh_hub != -1) close(vh_hub);
	vh_val = vh_hub = -1;
	vh_drain(vh_listen4);
	vh_drain(vh_listen6);
}

/* A client with HBRI on, connected to the fake hub over IPv4, and the hub's
   end of that session accepted as vh_hub. */
static int vh_start(void)
{
	char url[64];
	time_t deadline;

	vh_client = ADC_client_create("hbrival", "", NULL);
	if (!vh_client)
		return 0;

	ADC_client_set_callback(vh_client, vh_callback);
	ADC_client_set_hbri(vh_client, 1);

	snprintf(url, sizeof(url), "adc://127.0.0.1:%u", (unsigned) vh_port4);
	vh_connected = 0;
	if (!ADC_client_connect(vh_client, url))
		return 0;

	deadline = time(NULL) + 10;
	while (!vh_connected && time(NULL) <= deadline)
		vh_turn();

	if (!vh_ready(vh_listen4, 1000))
		return 0;

	vh_hub = accept(vh_listen4, NULL, NULL);

	/* The session is over IPv4, so IPv6 is the protocol left to prove. */
	return vh_connected == 1 && vh_hub != -1
		&& strcmp(ADC_client_get_local_address(vh_client, AF_INET), "127.0.0.1") == 0;
}

/* vh_start(), then challenge the client to prove IPv6 and accept the
   validation connection it opens as vh_val. */
static int vh_open_validation(void)
{
	char body[128];

	if (!vh_start())
		return 0;
	snprintf(body, sizeof(body), "I6::1 P6%u TO" VH_TOKEN, (unsigned) vh_port6);
	if (!vh_send_itcp(body))
		return 0;
	if (!vh_ready(vh_listen6, 2000))
		return 0;
	vh_val = accept(vh_listen6, NULL, NULL);
	return vh_val != -1;
}

/* Read what the client sent on the validation connection. */
static int vh_read_validation(char* buf, size_t size)
{
	ssize_t n;
	if (!vh_wait_readable(vh_val, 5))
		return 0;
	n = recv(vh_val, buf, size - 1, 0);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	return 1;
}

EXO_TEST(adchbri_val_connect, {
	int ok;
	if (vh_skip)
		EXO_SKIP("no IPv6 loopback listener on this host");
	ok = vh_start();
	vh_stop();
	return ok;
});

/*
 * A request naming the protocol the session already runs over proves nothing
 * the hub has not seen, so nothing is dialled -- in particular not the hub's
 * own listener, which is what such a request points at.
 */
EXO_TEST(adchbri_val_ignores_same_family, {
	char body[128];
	int ok;

	if (vh_skip)
		EXO_SKIP("no IPv6 loopback listener on this host");

	if (!vh_start())
	{
		vh_stop();
		return 0;
	}
	snprintf(body, sizeof(body), "I4127.0.0.1 P4%u TO" VH_TOKEN, (unsigned) vh_port4);
	ok = vh_send_itcp(body)
		&& !vh_ready(vh_listen4, 200) && !vh_ready(vh_listen6, 0);
	vh_stop();
	return ok;
});

/* A request that cannot be read is dropped, not guessed at. */
EXO_TEST(adchbri_val_ignores_malformed, {
	char body[128];
	int ok;

	if (vh_skip)
		EXO_SKIP("no IPv6 loopback listener on this host");

	if (!vh_start())
	{
		vh_stop();
		return 0;
	}
	/* A valid address and token, but no port to dial. */
	snprintf(body, sizeof(body), "I6::1 TO" VH_TOKEN);
	ok = vh_send_itcp(body) && !vh_ready(vh_listen6, 200);
	vh_stop();
	return ok;
});

/* The real thing: the client dials the address it was given, over IPv6. */
EXO_TEST(adchbri_val_opens_connection, {
	int ok;

	if (vh_skip)
		EXO_SKIP("no IPv6 loopback listener on this host");

	ok = vh_open_validation();
	vh_stop();
	return ok;
});

/*
 * HTCP is its first and only command -- there is no HSUP on this connection --
 * and it carries the hub's token back exactly as it arrived.
 */
EXO_TEST(adchbri_val_sends_token, {
	char buf[256];
	int ok;

	if (vh_skip)
		EXO_SKIP("no IPv6 loopback listener on this host");

	ok = vh_open_validation()
		&& vh_read_validation(buf, sizeof(buf))
		&& strcmp(buf, "HTCP TO" VH_TOKEN "\n") == 0;
	vh_stop();
	return ok;
});

/* One command, one answer: the client lets the connection go afterwards. */
EXO_TEST(adchbri_val_closes_after_reply, {
	const char* reply = "ISTA 000 Validation\\ssucceeded\n";
	char buf[64];

	char token[256];
	int ok;

	if (vh_skip)
		EXO_SKIP("no IPv6 loopback listener on this host");

	/* Take the HTCP off first, so that what is read below is the close. */
	ok = vh_open_validation()
		&& vh_read_validation(token, sizeof(token))
		&& send(vh_val, reply, strlen(reply), 0) == (ssize_t) strlen(reply)
		/* The close reaches this end as readable-then-EOF. */
		&& vh_wait_readable(vh_val, 5)
		&& recv(vh_val, buf, sizeof(buf), 0) == 0;
	vh_stop();
	return ok;
});

/*
 * A validation that cannot be made costs the session nothing, and must not
 * leave the client unable to make the next one: the hub re-challenges, and a
 * client still holding the wreck of the last attempt would ignore it.
 */
EXO_TEST(adchbri_val_survives_refusal, {
	char body[128];

	int ok;

	if (vh_skip)
		EXO_SKIP("no IPv6 loopback listener on this host");

	if (!vh_start())
	{
		vh_stop();
		return 0;
	}

	snprintf(body, sizeof(body), "I6::1 P6%u TO" VH_TOKEN, (unsigned) vh_dead6);
	if (!vh_send_itcp(body))
	{
		vh_stop();
		return 0;
	}

	/* Let the refusal be noticed and cleaned up before the next challenge, so
	   that what is under test is recovery from a failure and not the tearing
	   down of an attempt still in flight. */
	vh_turn_a_few();

	snprintf(body, sizeof(body), "I6::1 P6%u TO" VH_TOKEN, (unsigned) vh_port6);
	ok = vh_send_itcp(body) && vh_ready(vh_listen6, 2000);
	if (ok)
	{
		vh_val = accept(vh_listen6, NULL, NULL);
		ok = vh_val != -1 && vh_wait_readable(vh_val, 5);
	}
	vh_stop();
	return ok;
});

/* ---------------------------------------------------------------------------
 * Which address the roster reports for a peer
 *
 * It is the address the seeder dials on a connect request, so a peer the hub
 * published without one is a peer that can never be connected to -- and the
 * failure is silent, which is how it survived: a DC++ user on an IPv6-only
 * connection sent CTM after CTM into nothing.
 * ------------------------------------------------------------------------- */

/* Hand the client a BINF for some other user and report what the roster made
   of its address. */
static const char* vh_join(const char* inf)
{
	char line[512];
	int len = snprintf(line, sizeof(line), "%s\n", inf);
	int before = vh_joins;

	vh_join_address[0] = '\0';

	if (len <= 0 || (size_t) len >= sizeof(line))
		return NULL;
	if (send(vh_hub, line, (size_t) len, 0) != len)
		return NULL;
	if (!vh_wait_line(5))
		return NULL;

	return (vh_joins == before + 1) ? vh_join_address : NULL;
}

/* The ordinary case, and the one that always worked. */
EXO_TEST(adchbri_roster_ipv4, {
	const char* addr;
	int ok;

	if (vh_skip)
		EXO_SKIP("no IPv6 loopback listener on this host");

	if (!vh_start())
	{
		vh_stop();
		return 0;
	}
	addr = vh_join("BINF AAAE IDMUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA NIv4peer I4192.0.2.5");
	ok = addr && strcmp(addr, "192.0.2.5") == 0;
	vh_stop();
	return ok;
});

/*
 * A peer the hub published over IPv6 only -- which is every client that does
 * not speak HBRI and reached a dual-stack hub over IPv6. Reading I4 alone left
 * this empty, and a connect request from such a peer went unanswered.
 */
EXO_TEST(adchbri_roster_ipv6_only, {
	const char* addr;
	int ok;

	if (vh_skip)
		EXO_SKIP("no IPv6 loopback listener on this host");

	if (!vh_start())
	{
		vh_stop();
		return 0;
	}
	addr = vh_join("BINF AAAF IDNUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA NIv6peer I62001:db8::5");
	ok = addr && strcmp(addr, "2001:db8::5") == 0;
	vh_stop();
	return ok;
});

/* Both published: IPv4 wins, since a peer reachable over both is reachable
   over IPv4 and not every client is. */
EXO_TEST(adchbri_roster_prefers_ipv4, {
	const char* addr;
	int ok;

	if (vh_skip)
		EXO_SKIP("no IPv6 loopback listener on this host");

	if (!vh_start())
	{
		vh_stop();
		return 0;
	}
	addr = vh_join("BINF AAAG IDPUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA NIboth I4192.0.2.6 I62001:db8::6");
	ok = addr && strcmp(addr, "192.0.2.6") == 0;
	vh_stop();
	return ok;
});

/* Neither: nothing to dial, and the roster says so rather than inventing one. */
EXO_TEST(adchbri_roster_no_address, {
	const char* addr;
	int ok;

	if (vh_skip)
		EXO_SKIP("no IPv6 loopback listener on this host");

	if (!vh_start())
	{
		vh_stop();
		return 0;
	}
	addr = vh_join("BINF AAAH IDQUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA NInoaddr");
	ok = addr && *addr == '\0';
	vh_stop();
	return ok;
});

/*
 * The contract the dialling guards depend on: a failed conversion is -1, and
 * never 0. Two call sites tested it for zero, so the guard never fired and the
 * caller went on to use an address that had not been parsed.
 */
EXO_TEST(adchbri_ip_convert_failure_is_minus_one, {
	struct ip_addr_encap addr;

	return ip_convert_to_binary("", &addr) == -1
		&& ip_convert_to_binary("not-an-address", &addr) == -1
		&& ip_convert_to_binary("192.0.2.999", &addr) == -1
		&& ip_convert_to_binary("192.0.2.5", &addr) == AF_INET
		&& ip_convert_to_binary("2001:db8::5", &addr) == AF_INET6;
});
