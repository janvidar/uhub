#include "core/regserver.h"

static struct regserver_url u;

EXO_TEST(regserver_url_plain_http, {
	return regserver_parse_url("http://hub.example.org/register", &u)
		&& u.use_tls == 0
		&& u.port == 80
		&& strcmp(u.host, "hub.example.org") == 0
		&& strcmp(u.path, "/register") == 0;
});

EXO_TEST(regserver_url_https_default_port, {
	return regserver_parse_url("https://hub.example.org/register", &u)
		&& u.use_tls == 1
		&& u.port == 443
		&& strcmp(u.host, "hub.example.org") == 0;
});

EXO_TEST(regserver_url_explicit_port, {
	return regserver_parse_url("http://adcreg.dchublist.org:8080/register", &u)
		&& u.use_tls == 0
		&& u.port == 8080
		&& strcmp(u.host, "adcreg.dchublist.org") == 0
		&& strcmp(u.path, "/register") == 0;
});

EXO_TEST(regserver_url_default_path_no_slash, {
	return regserver_parse_url("http://hub.example.org", &u)
		&& u.port == 80
		&& strcmp(u.host, "hub.example.org") == 0
		&& strcmp(u.path, "/register") == 0;
});

EXO_TEST(regserver_url_default_path_with_port, {
	return regserver_parse_url("http://hub.example.org:1234", &u)
		&& u.port == 1234
		&& strcmp(u.host, "hub.example.org") == 0
		&& strcmp(u.path, "/register") == 0;
});

EXO_TEST(regserver_url_custom_path, {
	return regserver_parse_url("https://example.org:9000/adc/reg", &u)
		&& u.use_tls == 1
		&& u.port == 9000
		&& strcmp(u.host, "example.org") == 0
		&& strcmp(u.path, "/adc/reg") == 0;
});

EXO_TEST(regserver_url_ipv4_literal, {
	return regserver_parse_url("http://127.0.0.1:8080/register", &u)
		&& u.port == 8080
		&& strcmp(u.host, "127.0.0.1") == 0;
});

EXO_TEST(regserver_url_ipv6_literal, {
	return regserver_parse_url("http://[2001:db8::1]:8080/register", &u)
		&& u.port == 8080
		&& strcmp(u.host, "2001:db8::1") == 0
		&& strcmp(u.path, "/register") == 0;
});

EXO_TEST(regserver_url_ipv6_literal_default_path, {
	return regserver_parse_url("https://[::1]", &u)
		&& u.use_tls == 1
		&& u.port == 443
		&& strcmp(u.host, "::1") == 0
		&& strcmp(u.path, "/register") == 0;
});

EXO_TEST(regserver_url_case_insensitive_scheme, {
	return regserver_parse_url("HTTP://hub.example.org/register", &u)
		&& u.use_tls == 0
		&& u.port == 80;
});

EXO_TEST(regserver_url_reject_unknown_scheme, {
	return regserver_parse_url("ftp://hub.example.org/register", &u) == 0;
});

EXO_TEST(regserver_url_reject_no_scheme, {
	return regserver_parse_url("hub.example.org/register", &u) == 0;
});

EXO_TEST(regserver_url_reject_empty_host, {
	return regserver_parse_url("http:///register", &u) == 0;
});

EXO_TEST(regserver_url_reject_bad_port, {
	return regserver_parse_url("http://hub.example.org:0/register", &u) == 0
		&& regserver_parse_url("http://hub.example.org:70000/register", &u) == 0;
});

EXO_TEST(regserver_url_reject_unterminated_ipv6, {
	return regserver_parse_url("http://[2001:db8::1/register", &u) == 0;
});

EXO_TEST(regserver_url_reject_null, {
	return regserver_parse_url(NULL, &u) == 0;
});

/* regserver_hub_url(): normalize hub_address into the advertised HH adc(s) URL. */
static char hh[256 + 8];

/* A complete adc:// URL with a port is passed through unchanged. */
EXO_TEST(regserver_hh_complete, {
	return regserver_hub_url("adc://hub.example.org:1511", 0, 411, hh, sizeof(hh))
		&& strcmp(hh, "adc://hub.example.org:1511") == 0;
});

/* A complete adcs:// URL with a port is passed through unchanged. */
EXO_TEST(regserver_hh_complete_tls, {
	return regserver_hub_url("adcs://hub.example.org:1511", 0, 411, hh, sizeof(hh))
		&& strcmp(hh, "adcs://hub.example.org:1511") == 0;
});

/* Missing port -> server_port appended. */
EXO_TEST(regserver_hh_add_port, {
	return regserver_hub_url("adc://hub.example.org", 0, 1511, hh, sizeof(hh))
		&& strcmp(hh, "adc://hub.example.org:1511") == 0;
});

/* Missing scheme, no TLS -> adc:// prepended. */
EXO_TEST(regserver_hh_add_scheme_plain, {
	return regserver_hub_url("hub.example.org:1511", 0, 411, hh, sizeof(hh))
		&& strcmp(hh, "adc://hub.example.org:1511") == 0;
});

/* Missing scheme, TLS enabled -> adcs:// prepended. */
EXO_TEST(regserver_hh_add_scheme_tls, {
	return regserver_hub_url("hub.example.org:1511", 1, 411, hh, sizeof(hh))
		&& strcmp(hh, "adcs://hub.example.org:1511") == 0;
});

/* Bare host: both scheme and port are synthesized. */
EXO_TEST(regserver_hh_bare_host, {
	return regserver_hub_url("hub.example.org", 1, 1511, hh, sizeof(hh))
		&& strcmp(hh, "adcs://hub.example.org:1511") == 0;
});

/* Bracketed IPv6 literal without a port -> port appended after the bracket. */
EXO_TEST(regserver_hh_ipv6_add_port, {
	return regserver_hub_url("adc://[2001:db8::1]", 0, 1511, hh, sizeof(hh))
		&& strcmp(hh, "adc://[2001:db8::1]:1511") == 0;
});

/* Bracketed IPv6 literal that already has a port is left alone (colons inside
 * the brackets must not be mistaken for a port separator). */
EXO_TEST(regserver_hh_ipv6_keep_port, {
	return regserver_hub_url("adcs://[2001:db8::1]:1511", 0, 411, hh, sizeof(hh))
		&& strcmp(hh, "adcs://[2001:db8::1]:1511") == 0;
});

/* Empty / NULL hub_address -> no address to advertise. */
EXO_TEST(regserver_hh_empty, {
	return regserver_hub_url("", 0, 1511, hh, sizeof(hh)) == 0
		&& regserver_hub_url(NULL, 0, 1511, hh, sizeof(hh)) == 0;
});

/* A non-ADC scheme is refused rather than advertised verbatim. */
EXO_TEST(regserver_hh_reject_foreign_scheme, {
	return regserver_hub_url("http://hub.example.org:80", 0, 1511, hh, sizeof(hh)) == 0
		&& regserver_hub_url("dchub://hub.example.org:411", 0, 1511, hh, sizeof(hh)) == 0;
});

/* When a port must be synthesized, an out-of-range server_port is rejected. */
EXO_TEST(regserver_hh_reject_bad_port, {
	return regserver_hub_url("hub.example.org", 0, 0, hh, sizeof(hh)) == 0
		&& regserver_hub_url("hub.example.org", 0, 70000, hh, sizeof(hh)) == 0;
});

/* A result that does not fit the destination buffer is rejected, not truncated. */
EXO_TEST(regserver_hh_reject_overflow, {
	char small[8];
	return regserver_hub_url("adc://hub.example.org:1511", 0, 411, small, sizeof(small)) == 0;
});
