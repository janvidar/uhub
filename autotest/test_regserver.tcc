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
