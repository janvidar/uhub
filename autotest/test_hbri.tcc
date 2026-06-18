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
 * plus a Tiger MAC over a per-hub secret, the SID and the connection timestamp.
 * The security property under test: a token verifies only for the exact user
 * (SID + session) and hub secret it was minted for, and any tampering fails.
 */

static struct hub_info hbri_hub;
static struct hub_user hbri_user;

static void hbri_set_secret(struct hub_info* hub, unsigned char fill)
{
	memset(hub->hub_secret, fill, sizeof(hub->hub_secret));
}

static void hbri_make_user(struct hub_user* user, sid_t sid, time_t tm)
{
	memset(user, 0, sizeof(*user));
	user->id.sid = sid;
	user->tm_connected = tm;
}

EXO_TEST(hbri_setup, {
	memset(&hbri_hub, 0, sizeof(hbri_hub));
	hbri_set_secret(&hbri_hub, 0xA5);
	hbri_make_user(&hbri_user, 5, 1000);
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
	hbri_make_user(&other, 6, 1000);
	return hbri_token_check(&hbri_hub, &other, token) == 0;
});

/* A token is bound to the session timestamp, not just the SID. */
EXO_TEST(hbri_token_wrong_session, {
	char token[HBRI_TOKEN_LEN + 1];
	struct hub_user reused;
	hbri_token_make(&hbri_hub, &hbri_user, token);
	hbri_make_user(&reused, 5, 2000); /* same SID, later session */
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
