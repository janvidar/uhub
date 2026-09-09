#include "system.h"
#include "util/misc.h"
#include "adc/message.h"
#include "network/network.h"
#include "network/ipcalc.h"
#include "network/backend.h"
#include "network/dnsresolver.h"
#include "tools/adcclient.h"

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

EXO_TEST(adchbri_setup, {
	net_initialize();
	return 1;
});

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

EXO_TEST(adchbri_client_create, {
	ah_client = ADC_client_create("hbritest", "", NULL);
	if (!ah_client)
		return 0;
	ADC_client_set_callback(ah_client, ah_callback);
	return ADC_client_get_hbri(ah_client) == 0;
});

/* Opting in is explicit: a client that does not listen has nothing to prove. */
EXO_TEST(adchbri_client_opt_in, {
	ADC_client_set_hbri(ah_client, 1);
	return ADC_client_get_hbri(ah_client) == 1;
});

/* Nothing is known before there is a connection to read an address off. */
EXO_TEST(adchbri_no_address_before_connect, {
	return strcmp(ADC_client_get_local_address(ah_client, AF_INET), "") == 0
		&& strcmp(ADC_client_get_local_address(ah_client, AF_INET6), "") == 0
		&& strcmp(ADC_client_get_local_address(ah_client, AF_UNSPEC), "") == 0
		&& strcmp(ADC_client_get_local_address(NULL, AF_INET), "") == 0;
});

/* ...and an address that is not known is left out of the INF rather than
   invented: an I4 the hub cannot reach is worse than no I4 at all. */
EXO_TEST(adchbri_inf_omits_unknown_address, {
	struct adc_message* info = ADC_client_build_info(ah_client);
	int ok;

	if (!info)
		return 0;

	ok = !adc_msg_has_named_argument(info, "I4")
		&& !adc_msg_has_named_argument(info, "I6");

	adc_msg_free(info);
	return ok;
});

EXO_TEST(adchbri_connect_loopback, {
	char url[64];
	int i;

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
});

/*
 * The address the connection was made from is read straight off the socket, so
 * it is known the moment the connection is up.
 */
EXO_TEST(adchbri_primary_address_discovered, {
	return strcmp(ADC_client_get_local_address(ah_client, AF_INET), "127.0.0.1") == 0;
});

/* And it is what the INF then states. */
EXO_TEST(adchbri_inf_states_known_address, {
	struct adc_message* info = ADC_client_build_info(ah_client);
	char* addr;
	int ok;

	if (!info)
		return 0;

	addr = adc_msg_get_named_argument(info, "I4");
	ok = addr && strcmp(addr, "127.0.0.1") == 0;

	hub_free(addr);
	adc_msg_free(info);
	return ok;
});

/*
 * The second family is only ever worked out from the hub's other DNS records,
 * and an address literal has none -- so nothing is claimed for it. Pumped for a
 * while first, since that answer arrives through a lookup rather than at once.
 */
EXO_TEST(adchbri_no_second_family_for_literal, {
	/* Directly, not by pumping: with nothing due a poll would block. */
	net_dns_wait_idle();
	net_dns_process();

	return strcmp(ADC_client_get_local_address(ah_client, AF_INET6), "") == 0;
});

/*
 * A disconnect does not erase what was worked out: the last known address is
 * still the best answer there is, and an offline mount showing nothing at all
 * would be less useful than one showing where it was. It is a reconnect that
 * discards it -- the next connection may be from another network entirely, and
 * re-reads everything off the new socket.
 */
EXO_TEST(adchbri_address_survives_disconnect, {
	ADC_client_disconnect(ah_client);
	return strcmp(ADC_client_get_local_address(ah_client, AF_INET), "127.0.0.1") == 0;
});

EXO_TEST(adchbri_client_destroy, {
	ADC_client_destroy(ah_client);
	ah_client = NULL;
	if (ah_listener != -1)
		close(ah_listener);
	ah_listener = -1;
	return 1;
});

EXO_TEST(adchbri_teardown, {
	return net_destroy() == 0;
});
