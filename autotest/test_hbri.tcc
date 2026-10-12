#include "system.h"
#include "util/memory.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "core/config.h"
#include "core/hbri.h"
#include "core/hub.h"
#include "core/user.h"
#include "core/usermanager.h"

/*
 * Exercises the stateless HBRI validation-token primitives in src/core/hbri.c:
 * hbri_token_make() and hbri_token_check(). A token is the user's SID prefix
 * plus a Tiger MAC over a per-hub secret, the SID and the connection id.
 * The security property under test: a token verifies only for the exact user
 * (SID + session) and hub secret it was minted for, and any tampering fails.
 *
 * The connection id is what names the session. The SID cannot: it is drawn
 * from a pool and handed to the next user once this one leaves.
 */

static struct hub_info hbri_hub;
static struct hub_user hbri_user;

static void hbri_set_secret(struct hub_info* hub, unsigned char fill)
{
	memset(hub->hub_secret, fill, sizeof(hub->hub_secret));
}

static void hbri_make_user(struct hub_user* user, sid_t sid, uint64_t conn_id, time_t tm)
{
	memset(user, 0, sizeof(*user));
	user->id.sid = sid;
	user->connection_id = conn_id;
	user->tm_connected = tm;
}

/* The hub secret and user the token tests mint for. A test that changes the
   secret puts it back before it returns. */
EXO_SETUP({
	memset(&hbri_hub, 0, sizeof(hbri_hub));
	hbri_set_secret(&hbri_hub, 0xA5);
	hbri_make_user(&hbri_user, 5, 1, 1000);
	return 1;
});

/* A freshly minted token verifies for the user it was made for. */
EXO_TEST(hbri_token_roundtrip, {
	char token[HBRI_TOKEN_LEN + 1];
	hbri_token_make(&hbri_hub, &hbri_user, token);
	return strlen(token) == HBRI_TOKEN_LEN && hbri_token_check(&hbri_hub, &hbri_user, token) == 1;
});

/* The first 4 characters are the SID, encoded the usual way. */
EXO_TEST(hbri_token_sid_prefix, {
	char token[HBRI_TOKEN_LEN + 1];
	hbri_token_make(&hbri_hub, &hbri_user, token);
	return strncmp(token, sid_to_string(5), HBRI_SID_LEN) == 0;
});

/* Flipping a byte of the MAC must fail verification. */
EXO_TEST(hbri_token_tampered_mac, {
	char token[HBRI_TOKEN_LEN + 1];
	hbri_token_make(&hbri_hub, &hbri_user, token);
	token[HBRI_TOKEN_LEN - 1] = (token[HBRI_TOKEN_LEN - 1] == 'A') ? 'B' : 'A';
	return hbri_token_check(&hbri_hub, &hbri_user, token) == 0;
});

/* A token for one SID must not verify against a different user. */
EXO_TEST(hbri_token_wrong_user, {
	char token[HBRI_TOKEN_LEN + 1];
	struct hub_user other;
	hbri_token_make(&hbri_hub, &hbri_user, token);
	hbri_make_user(&other, 6, 1, 1000);
	return hbri_token_check(&hbri_hub, &other, token) == 0;
});

/* A token is bound to the session, not just the SID. */
EXO_TEST(hbri_token_wrong_session, {
	char token[HBRI_TOKEN_LEN + 1];
	struct hub_user reused;
	hbri_token_make(&hbri_hub, &hbri_user, token);
	hbri_make_user(&reused, 5, 2, 2000); /* same SID, later session */
	return hbri_token_check(&hbri_hub, &reused, token) == 0;
});

/*
 * The same, for a takeover that happens inside one second. The MAC used to
 * cover tm_connected, which is only granular to the second, so a user handed
 * the SID quickly enough matched the departed user's token -- and the address
 * on a replayed validation connection landed in its INF. The connection id is
 * never reused, so the second here being identical changes nothing.
 */
EXO_TEST(hbri_token_same_second_takeover, {
	char token[HBRI_TOKEN_LEN + 1];
	struct hub_user reused;
	hbri_token_make(&hbri_hub, &hbri_user, token);
	hbri_make_user(&reused, 5, 2, 1000); /* same SID, same second, new session */
	return hbri_token_check(&hbri_hub, &reused, token) == 0;
});

/* A token minted under a different hub secret must not verify. */
EXO_TEST(hbri_token_wrong_secret, {
	char token[HBRI_TOKEN_LEN + 1];
	struct hub_info other_hub;
	hbri_token_make(&hbri_hub, &hbri_user, token);
	memset(&other_hub, 0, sizeof(other_hub));
	hbri_set_secret(&other_hub, 0x5A);
	return hbri_token_check(&other_hub, &hbri_user, token) == 0;
});

/* Malformed tokens (too short / empty) are rejected, not misparsed. */
EXO_TEST(hbri_token_malformed, {
	return hbri_token_check(&hbri_hub, &hbri_user, "") == 0
	    && hbri_token_check(&hbri_hub, &hbri_user, "AAAB") == 0
	    && hbri_token_check(&hbri_hub, &hbri_user, NULL) == 0;
});

/* Ports coming off the wire are echoed into everyone's INF, so they must be
   plain decimal numbers in range -- not arbitrary client-supplied text. */
EXO_TEST(hbri_port_valid, {
	return hbri_port_is_valid("1")
	    && hbri_port_is_valid("411")
	    && hbri_port_is_valid("65535");
});

EXO_TEST(hbri_port_invalid, {
	return !hbri_port_is_valid(NULL)
	    && !hbri_port_is_valid("")
	    && !hbri_port_is_valid("0")        /* port 0 is not usable */
	    && !hbri_port_is_valid("65536")    /* out of range */
	    && !hbri_port_is_valid("123456")   /* too long */
	    && !hbri_port_is_valid("12a")      /* not a number */
	    && !hbri_port_is_valid("-1")
	    && !hbri_port_is_valid(" 12")
	    && !hbri_port_is_valid("12\\s34"); /* escaped space: must not pass */
});

/* hbri_remember_udp_port only touches the stored value when the field is
   present, so an INF update that omits it means "unchanged". */
EXO_TEST(hbri_remember_port, {
	struct hub_user user;
	struct adc_message* msg;
	int ok = 1;

	memset(&user, 0, sizeof(user));
	user.id.sid = 1; /* must match the "AAAB" source SID below */

	msg = adc_msg_parse_verify(&user, "BINF AAAB U612345\n", 18);
	if (!msg) return 0;
	hbri_remember_udp_port(&user, msg, AF_INET6);
	ok &= (strcmp(user.hbri_udp_port, "12345") == 0);
	adc_msg_free(msg);

	/* absent -> unchanged */
	msg = adc_msg_parse_verify(&user, "BINF AAAB NIx\n", 14);
	if (!msg) return 0;
	hbri_remember_udp_port(&user, msg, AF_INET6);
	ok &= (strcmp(user.hbri_udp_port, "12345") == 0);
	adc_msg_free(msg);

	/* present but bogus -> cleared, never republished */
	msg = adc_msg_parse_verify(&user, "BINF AAAB U6bogus\n", 18);
	if (!msg) return 0;
	hbri_remember_udp_port(&user, msg, AF_INET6);
	ok &= (user.hbri_udp_port[0] == 0);
	adc_msg_free(msg);

	return ok;
});

/* hbri_is_enabled requires the feature toggle and both advertised addresses. */
EXO_TEST(hbri_enabled_gating, {
	struct hub_info hub;
	struct hub_config config;
	int ok = 1;
	memset(&hub, 0, sizeof(hub));
	memset(&config, 0, sizeof(config));
	hub.config = &config;

	config.hbri_enable = 0;
	config.hbri_address4 = (char*) "192.0.2.1";
	config.hbri_address6 = (char*) "2001:db8::1";
	ok &= (hbri_is_enabled(&hub) == 0); /* disabled */

	config.hbri_enable = 1;
	config.hbri_address6 = (char*) "";
	ok &= (hbri_is_enabled(&hub) == 0); /* missing IPv6 */

	config.hbri_address6 = (char*) "2001:db8::1";
	ok &= (hbri_is_enabled(&hub) != 0); /* enabled and dual-stack */
	return ok;
});
