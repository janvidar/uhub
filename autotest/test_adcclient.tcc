/*
 * Unit tests for the ADC client's pure parsing helpers.
 *
 * The functions under test (adc_user_apply_inf, ADC_client_parse_address)
 * are static inside tools/adcclient.c and need no socket, event loop or TLS
 * context, so the whole translation unit is included here to reach them.
 * autotest-bin already links the network/adc/util/core objects every other
 * adcclient symbol resolves against.
 */
#include "tools/adcclient.c"

/* ---- ADC_client_parse_address: adc[s]:// URL parsing ---- */

EXO_TEST(adcclient_addr_adc, {
	struct ADC_client c;
	memset(&c, 0, sizeof(c));
	int ok = ADC_client_parse_address(&c, "adc://example.com:411");
	int good = ok
		&& c.address.port == 411
		&& (c.flags & cflag_ssl) == 0
		&& c.address.hostname && strcmp(c.address.hostname, "example.com") == 0;
	hub_free(c.address.hostname);
	return good;
});

EXO_TEST(adcclient_addr_adcs, {
	struct ADC_client c;
	memset(&c, 0, sizeof(c));
	int ok = ADC_client_parse_address(&c, "adcs://hub.local:1511");
	int good = ok
		&& c.address.port == 1511
		&& (c.flags & cflag_ssl) != 0
		&& c.address.hostname && strcmp(c.address.hostname, "hub.local") == 0;
	hub_free(c.address.hostname);
	return good;
});

EXO_TEST(adcclient_addr_bad_scheme, {
	struct ADC_client c;
	memset(&c, 0, sizeof(c));
	int ok = ADC_client_parse_address(&c, "http://example.com:80");
	hub_free(c.address.hostname);
	return ok == 0;
});

EXO_TEST(adcclient_addr_port_zero, {
	struct ADC_client c;
	memset(&c, 0, sizeof(c));
	int ok = ADC_client_parse_address(&c, "adc://example.com:0");
	hub_free(c.address.hostname);
	return ok == 0;
});

EXO_TEST(adcclient_addr_port_overflow, {
	struct ADC_client c;
	memset(&c, 0, sizeof(c));
	/* 70000 would wrap to a valid uint16_t if not range-checked first */
	int ok = ADC_client_parse_address(&c, "adc://example.com:70000");
	hub_free(c.address.hostname);
	return ok == 0;
});

EXO_TEST(adcclient_addr_no_port, {
	struct ADC_client c;
	memset(&c, 0, sizeof(c));
	int ok = ADC_client_parse_address(&c, "adc://hostonly");
	hub_free(c.address.hostname);
	return ok == 0;
});

/* ---- adc_user_apply_inf: BINF -> struct ADC_user ---- */

static const char* inf_full =
	"BINF AAAB IDAN7ZMSLIEBL53OPTM7WXGSTXUS3XOY6KQS5LBGX NIFriend DEstuff\\stext "
	"APQuickDC VE0.4.17 SL3 SS1234 SF7 I4127.0.0.1 I6fe80::1 U41234 U65678 CT4 AW1";

EXO_TEST(adcclient_inf_name, {
	struct ADC_user u;
	memset(&u, 0, sizeof(u));
	struct adc_message* m = adc_msg_parse(inf_full, strlen(inf_full));
	if (!m) return 0;
	adc_user_apply_inf(&u, m);
	adc_msg_free(m);
	return strcmp(u.name, "Friend") == 0;
});

EXO_TEST(adcclient_inf_description_unescaped, {
	struct ADC_user u;
	memset(&u, 0, sizeof(u));
	struct adc_message* m = adc_msg_parse(inf_full, strlen(inf_full));
	if (!m) return 0;
	adc_user_apply_inf(&u, m);
	adc_msg_free(m);
	return strcmp(u.description, "stuff text") == 0;
});

EXO_TEST(adcclient_inf_cid, {
	struct ADC_user u;
	memset(&u, 0, sizeof(u));
	struct adc_message* m = adc_msg_parse(inf_full, strlen(inf_full));
	if (!m) return 0;
	adc_user_apply_inf(&u, m);
	adc_msg_free(m);
	return strcmp(u.cid, "AN7ZMSLIEBL53OPTM7WXGSTXUS3XOY6KQS5LBGX") == 0;
});

EXO_TEST(adcclient_inf_addresses, {
	struct ADC_user u;
	memset(&u, 0, sizeof(u));
	struct adc_message* m = adc_msg_parse(inf_full, strlen(inf_full));
	if (!m) return 0;
	adc_user_apply_inf(&u, m);
	adc_msg_free(m);
	return strcmp(u.address, "127.0.0.1") == 0
		&& strcmp(u.address6, "fe80::1") == 0;
});

EXO_TEST(adcclient_inf_version_product_and_version, {
	struct ADC_user u;
	memset(&u, 0, sizeof(u));
	struct adc_message* m = adc_msg_parse(inf_full, strlen(inf_full));
	if (!m) return 0;
	adc_user_apply_inf(&u, m);
	adc_msg_free(m);
	return strcmp(u.version, "QuickDC 0.4.17") == 0;
});

EXO_TEST(adcclient_inf_ports, {
	struct ADC_user u;
	memset(&u, 0, sizeof(u));
	struct adc_message* m = adc_msg_parse(inf_full, strlen(inf_full));
	if (!m) return 0;
	adc_user_apply_inf(&u, m);
	adc_msg_free(m);
	return u.udp4_port == 1234 && u.udp6_port == 5678;
});

EXO_TEST(adcclient_inf_type_and_away, {
	struct ADC_user u;
	memset(&u, 0, sizeof(u));
	struct adc_message* m = adc_msg_parse(inf_full, strlen(inf_full));
	if (!m) return 0;
	adc_user_apply_inf(&u, m);
	adc_msg_free(m);
	return u.type == 4 && u.away == 1;
});

EXO_TEST(adcclient_inf_share, {
	struct ADC_user u;
	memset(&u, 0, sizeof(u));
	struct adc_message* m = adc_msg_parse(inf_full, strlen(inf_full));
	if (!m) return 0;
	adc_user_apply_inf(&u, m);
	adc_msg_free(m);
	return u.shared_size == 1234 && u.shared_files == 7;
});

/* A large share size must survive as a 64-bit value (the SS field is uint64). */
EXO_TEST(adcclient_inf_share_64bit, {
	struct ADC_user u;
	memset(&u, 0, sizeof(u));
	const char* s = "BINF AAAB IDAN7ZMSLIEBL53OPTM7WXGSTXUS3XOY6KQS5LBGX SS5000000000";
	struct adc_message* m = adc_msg_parse(s, strlen(s));
	if (!m) return 0;
	adc_user_apply_inf(&u, m);
	adc_msg_free(m);
	return u.shared_size == 5000000000ULL; /* > UINT32_MAX */
});

/* Passive user: no U4/U6 advertised, ports stay zero. */
EXO_TEST(adcclient_inf_passive_ports_zero, {
	struct ADC_user u;
	memset(&u, 0, sizeof(u));
	const char* s = "BINF AAAB IDAN7ZMSLIEBL53OPTM7WXGSTXUS3XOY6KQS5LBGX NIPassive";
	struct adc_message* m = adc_msg_parse(s, strlen(s));
	if (!m) return 0;
	adc_user_apply_inf(&u, m);
	adc_msg_free(m);
	return u.udp4_port == 0 && u.udp6_port == 0;
});

/* A partial INF update must overlay only the present fields and leave the
   rest of a known user intact (the merge behaviour USER_UPDATE relies on). */
EXO_TEST(adcclient_inf_partial_merge, {
	struct ADC_user u;
	memset(&u, 0, sizeof(u));
	strcpy(u.name, "Existing");
	u.udp4_port = 4000;
	u.away = 0;

	const char* s = "BINF AAAB AW2";
	struct adc_message* m = adc_msg_parse(s, strlen(s));
	if (!m) return 0;
	adc_user_apply_inf(&u, m);
	adc_msg_free(m);

	return u.away == 2                       /* updated  */
		&& strcmp(u.name, "Existing") == 0   /* preserved */
		&& u.udp4_port == 4000;              /* preserved */
});
