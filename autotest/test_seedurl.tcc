#include "system.h"
#include "network/ipcalc.h"
#include "network/network.h"
#include "seeder/url.h"

static struct seed_url bu;
static struct seed_url bu2;
static struct seed_addr_policy* bpolicy = NULL;
static struct seed_addr_policy* bpolicy_private = NULL;

/* -1 conversion failed, 0 denied, 1 permitted. */
static int seedurl_check_addr(struct seed_addr_policy* policy, const char* address)
{
	struct ip_addr_encap ip;
	memset(&ip, 0, sizeof(ip));
	if (ip_convert_to_binary(address, &ip) == -1)
		return -1;
	return seed_addr_is_permitted(policy, &ip);
}

static int seedurl_denied(const char* address)
{
	return seedurl_check_addr(bpolicy, address) == 0;
}

static int seedurl_allowed(const char* address)
{
	return seedurl_check_addr(bpolicy, address) == 1;
}

EXO_TEST(seedurl_prepare_network, {
	return net_initialize() == 0;
});

/* ---------------------------------------------------------------- parser: accept */

EXO_TEST(seedurl_accept_plain, {
	return seed_url_parse("http://example.org/", NULL, &bu) == SEED_URL_OK
		&& bu.tls == 0
		&& bu.port == 80
		&& strcmp(bu.host, "example.org") == 0
		&& strcmp(bu.path, "/") == 0;
});

EXO_TEST(seedurl_accept_https_query, {
	return seed_url_parse("https://example.org:443/a/b?c=d", NULL, &bu) == SEED_URL_OK
		&& bu.tls == 1
		&& bu.port == 443
		&& strcmp(bu.host, "example.org") == 0
		&& strcmp(bu.path, "/a/b?c=d") == 0;
});

EXO_TEST(seedurl_accept_ipv6_literal, {
	return seed_url_parse("http://[2001:db8::1]/x", NULL, &bu) == SEED_URL_OK
		&& bu.tls == 0
		&& bu.port == 80
		&& strcmp(bu.host, "2001:db8::1") == 0
		&& strcmp(bu.path, "/x") == 0;
});

EXO_TEST(seedurl_accept_ipv6_literal_with_port, {
	return seed_url_parse("http://[2001:db8::1]:8080/x", NULL, &bu) == SEED_URL_OK
		&& bu.port == 8080
		&& strcmp(bu.host, "2001:db8::1") == 0
		&& strcmp(bu.path, "/x") == 0;
});

EXO_TEST(seedurl_accept_ipv4_literal, {
	return seed_url_parse("http://1.2.3.4:80/", NULL, &bu) == SEED_URL_OK
		&& bu.port == 80
		&& strcmp(bu.host, "1.2.3.4") == 0
		&& strcmp(bu.path, "/") == 0;
});

EXO_TEST(seedurl_accept_no_path_becomes_slash, {
	return seed_url_parse("http://example.org", NULL, &bu) == SEED_URL_OK
		&& strcmp(bu.path, "/") == 0;
});

EXO_TEST(seedurl_accept_scheme_case_insensitive, {
	return seed_url_parse("HtTpS://Example.ORG/A", NULL, &bu) == SEED_URL_OK
		&& bu.tls == 1
		&& bu.port == 443
		&& strcmp(bu.host, "example.org") == 0   /* host lowercased */
		&& strcmp(bu.path, "/A") == 0;           /* path is not */
});

EXO_TEST(seedurl_accept_fragment_stripped, {
	return seed_url_parse("http://example.org/a?b=c#frag", NULL, &bu) == SEED_URL_OK
		&& strcmp(bu.path, "/a?b=c") == 0;
});

EXO_TEST(seedurl_accept_fragment_only, {
	return seed_url_parse("http://example.org#frag", NULL, &bu) == SEED_URL_OK
		&& strcmp(bu.path, "/") == 0;
});

EXO_TEST(seedurl_accept_query_without_path, {
	return seed_url_parse("http://example.org?q=1", NULL, &bu) == SEED_URL_OK
		&& strcmp(bu.path, "/?q=1") == 0;
});

EXO_TEST(seedurl_accept_port_in_allow_list, {
	return seed_url_parse("http://example.org:8080/", "80,443,8080", &bu) == SEED_URL_OK
		&& bu.port == 8080;
});

EXO_TEST(seedurl_accept_default_port_in_allow_list, {
	return seed_url_parse("https://example.org/", "80, 443", &bu) == SEED_URL_OK
		&& bu.port == 443;
});

EXO_TEST(seedurl_accept_empty_allow_list_allows_any_port, {
	return seed_url_parse("http://example.org:31337/", "", &bu) == SEED_URL_OK
		&& bu.port == 31337;
});

/* ---------------------------------------------------------------- parser: reject */

EXO_TEST(seedurl_reject_file_scheme, {
	return seed_url_parse("file:///etc/passwd", NULL, &bu) == SEED_URL_ERR_SCHEME;
});

EXO_TEST(seedurl_reject_gopher_scheme, {
	return seed_url_parse("gopher://x/", NULL, &bu) == SEED_URL_ERR_SCHEME;
});

EXO_TEST(seedurl_reject_ftp_scheme, {
	return seed_url_parse("ftp://x/", NULL, &bu) == SEED_URL_ERR_SCHEME;
});

EXO_TEST(seedurl_reject_data_scheme, {
	return seed_url_parse("data:text/plain,hello", NULL, &bu) == SEED_URL_ERR_SCHEME;
});

EXO_TEST(seedurl_reject_scheme_relative, {
	return seed_url_parse("//example.org/x", NULL, &bu) == SEED_URL_ERR_SCHEME;
});

EXO_TEST(seedurl_reject_empty_string, {
	return seed_url_parse("", NULL, &bu) == SEED_URL_ERR_SCHEME;
});

EXO_TEST(seedurl_reject_null_url, {
	return seed_url_parse(NULL, NULL, &bu) == SEED_URL_ERR_SYNTAX;
});

EXO_TEST(seedurl_reject_userinfo, {
	return seed_url_parse("http://user:pass@example.org/", NULL, &bu) == SEED_URL_ERR_USERINFO;
});

EXO_TEST(seedurl_reject_userinfo_bare_at, {
	return seed_url_parse("http://evil.example.net@127.0.0.1/", NULL, &bu) == SEED_URL_ERR_USERINFO;
});

EXO_TEST(seedurl_accept_at_in_path, {
	/* '@' only means userinfo inside the authority. */
	return seed_url_parse("http://example.org/a@b", NULL, &bu) == SEED_URL_OK
		&& strcmp(bu.path, "/a@b") == 0;
});

EXO_TEST(seedurl_reject_port_not_allowed, {
	return seed_url_parse("http://example.org:22/", "80,443", &bu) == SEED_URL_ERR_PORT;
});

EXO_TEST(seedurl_reject_port_zero, {
	return seed_url_parse("http://example.org:0/", NULL, &bu) == SEED_URL_ERR_PORT;
});

EXO_TEST(seedurl_reject_port_too_big, {
	return seed_url_parse("http://example.org:65536/", NULL, &bu) == SEED_URL_ERR_PORT;
});

EXO_TEST(seedurl_reject_port_empty, {
	return seed_url_parse("http://example.org:/x", NULL, &bu) == SEED_URL_ERR_PORT;
});

EXO_TEST(seedurl_reject_port_not_numeric, {
	return seed_url_parse("http://example.org:80a/", NULL, &bu) == SEED_URL_ERR_PORT;
});

EXO_TEST(seedurl_reject_too_long, {
	static char big[5000];
	memset(big, 0, sizeof(big));
	memcpy(big, "http://example.org/", 19);
	memset(big + 19, 'a', 4096 - 19);
	return seed_url_parse(big, NULL, &bu) == SEED_URL_ERR_TOO_LONG;
});

EXO_TEST(seedurl_reject_long_host, {
	static char big[SEED_URL_MAX_HOST + 64];
	memset(big, 0, sizeof(big));
	memcpy(big, "http://", 7);
	memset(big + 7, 'a', SEED_URL_MAX_HOST + 8);
	memcpy(big + 7 + SEED_URL_MAX_HOST + 8, "/", 2);
	return seed_url_parse(big, NULL, &bu) == SEED_URL_ERR_TOO_LONG;
});

EXO_TEST(seedurl_reject_long_path, {
	static char big[SEED_URL_MAX_PATH + 64];
	memset(big, 0, sizeof(big));
	memcpy(big, "http://example.org", 18);
	memset(big + 18, '/', SEED_URL_MAX_PATH + 4);
	return seed_url_parse(big, NULL, &bu) == SEED_URL_ERR_TOO_LONG;
});

/*
 * A C string cannot carry an embedded NUL past the API boundary: parsing stops
 * there. Both halves of that contract are checked - a NUL that truncates the
 * authority is a syntax error, and no byte after a NUL can reach the output.
 */
EXO_TEST(seedurl_reject_embedded_nul_truncates_host, {
	return seed_url_parse("http://\0example.org/", NULL, &bu) == SEED_URL_ERR_SYNTAX;
});

EXO_TEST(seedurl_embedded_nul_does_not_leak_into_path, {
	return seed_url_parse("http://example.org/a\0/evil", NULL, &bu) == SEED_URL_OK
		&& strcmp(bu.path, "/a") == 0;
});

EXO_TEST(seedurl_reject_space_in_host, {
	return seed_url_parse("http://exa mple.org/", NULL, &bu) == SEED_URL_ERR_SYNTAX;
});

EXO_TEST(seedurl_reject_tab_and_newline, {
	return seed_url_parse("http://example.org/\tx", NULL, &bu) == SEED_URL_ERR_SYNTAX
		&& seed_url_parse("http://example.org/\nx", NULL, &bu) == SEED_URL_ERR_SYNTAX
		&& seed_url_parse("http://example.org/\rx", NULL, &bu) == SEED_URL_ERR_SYNTAX;
});

EXO_TEST(seedurl_reject_non_ascii, {
	return seed_url_parse("http://ex\xc3\xa4mple.org/", NULL, &bu) == SEED_URL_ERR_SYNTAX;
});

EXO_TEST(seedurl_reject_no_host, {
	return seed_url_parse("http://", NULL, &bu) == SEED_URL_ERR_SYNTAX;
});

EXO_TEST(seedurl_reject_empty_host_with_path, {
	return seed_url_parse("http:///path", NULL, &bu) == SEED_URL_ERR_SYNTAX;
});

EXO_TEST(seedurl_reject_percent_encoded_host, {
	return seed_url_parse("http://exa%6dple.org/", NULL, &bu) == SEED_URL_ERR_SYNTAX;
});

EXO_TEST(seedurl_reject_trailing_dot_host, {
	/* "example.org." resolves like "example.org" but defeats suffix matching. */
	return seed_url_parse("http://example.org./", NULL, &bu) == SEED_URL_ERR_SYNTAX;
});

EXO_TEST(seedurl_reject_empty_label_host, {
	return seed_url_parse("http://example..org/", NULL, &bu) == SEED_URL_ERR_SYNTAX;
});

EXO_TEST(seedurl_reject_unterminated_bracket, {
	return seed_url_parse("http://[2001:db8::1/x", NULL, &bu) == SEED_URL_ERR_SYNTAX;
});

EXO_TEST(seedurl_reject_bracketed_name, {
	return seed_url_parse("http://[example.org]/x", NULL, &bu) == SEED_URL_ERR_SYNTAX;
});

EXO_TEST(seedurl_reject_junk_after_bracket, {
	return seed_url_parse("http://[::1]zz/x", NULL, &bu) == SEED_URL_ERR_SYNTAX;
});

EXO_TEST(seedurl_reject_backslash_host, {
	return seed_url_parse("http://example.org\\@127.0.0.1/", NULL, &bu) == SEED_URL_ERR_USERINFO;
});

EXO_TEST(seedurl_error_strings, {
	return strcmp(seed_url_error_string(SEED_URL_OK), "ok") == 0
		&& seed_url_error_string(SEED_URL_ERR_SCHEME) != NULL
		&& seed_url_error_string(SEED_URL_ERR_SYNTAX) != NULL
		&& seed_url_error_string(SEED_URL_ERR_USERINFO) != NULL
		&& seed_url_error_string(SEED_URL_ERR_PORT) != NULL
		&& seed_url_error_string(SEED_URL_ERR_TOO_LONG) != NULL;
});

/* ---------------------------------------------------------------- address policy */

EXO_TEST(seedurl_policy_create, {
	bpolicy = seed_addr_policy_create(0);
	bpolicy_private = seed_addr_policy_create(1);
	return bpolicy != NULL && bpolicy_private != NULL;
});

EXO_TEST(seedurl_policy_null_fails_closed, {
	struct ip_addr_encap ip;
	memset(&ip, 0, sizeof(ip));
	return seed_addr_is_permitted(NULL, &ip) == 0
		&& seed_addr_is_permitted(bpolicy, NULL) == 0;
});

EXO_TEST(seedurl_deny_loopback_v4, {
	return seedurl_denied("127.0.0.1") && seedurl_denied("127.255.255.254");
});

EXO_TEST(seedurl_deny_rfc1918_10, {
	return seedurl_denied("10.1.2.3");
});

EXO_TEST(seedurl_deny_rfc1918_172, {
	return seedurl_denied("172.16.0.1") && seedurl_denied("172.31.255.255");
});

EXO_TEST(seedurl_deny_rfc1918_192, {
	return seedurl_denied("192.168.1.1");
});

EXO_TEST(seedurl_deny_link_local_metadata, {
	return seedurl_denied("169.254.169.254");
});

EXO_TEST(seedurl_deny_cgnat, {
	return seedurl_denied("100.64.0.1") && seedurl_denied("100.127.255.255");
});

EXO_TEST(seedurl_deny_this_network, {
	return seedurl_denied("0.0.0.0");
});

EXO_TEST(seedurl_deny_broadcast, {
	return seedurl_denied("255.255.255.255");
});

EXO_TEST(seedurl_deny_multicast_v4, {
	return seedurl_denied("224.0.0.1") && seedurl_denied("239.255.255.255");
});

EXO_TEST(seedurl_deny_documentation_v4, {
	return seedurl_denied("192.0.2.1") && seedurl_denied("198.51.100.1") && seedurl_denied("203.0.113.1");
});

EXO_TEST(seedurl_deny_misc_reserved_v4, {
	return seedurl_denied("192.0.0.1") && seedurl_denied("192.88.99.1")
		&& seedurl_denied("198.18.0.1") && seedurl_denied("198.19.255.255")
		&& seedurl_denied("240.0.0.1");
});

EXO_TEST(seedurl_deny_loopback_v6, {
	return seedurl_denied("::1");
});

EXO_TEST(seedurl_deny_unspecified_v6, {
	return seedurl_denied("::");
});

EXO_TEST(seedurl_deny_v4_mapped_loopback, {
	return seedurl_denied("::ffff:127.0.0.1");
});

EXO_TEST(seedurl_deny_v4_mapped_public, {
	/* The whole ::ffff:0:0/96 block is denied: reaching a public host through
	 * the mapped form has no legitimate use and is a known filter bypass. */
	return seedurl_denied("::ffff:8.8.8.8");
});

EXO_TEST(seedurl_deny_link_local_v6, {
	return seedurl_denied("fe80::1") && seedurl_denied("febf:ffff::1");
});

EXO_TEST(seedurl_deny_unique_local_v6, {
	return seedurl_denied("fc00::1") && seedurl_denied("fdff::1");
});

EXO_TEST(seedurl_deny_documentation_v6, {
	return seedurl_denied("2001:db8::1");
});

EXO_TEST(seedurl_deny_multicast_v6, {
	return seedurl_denied("ff02::1");
});

EXO_TEST(seedurl_deny_misc_reserved_v6, {
	return seedurl_denied("64:ff9b::1") && seedurl_denied("100::1") && seedurl_denied("2002::1");
});

/* Boundary cases: these catch an off-by-one in the CIDR arithmetic. */

EXO_TEST(seedurl_allow_just_past_172_12, {
	return seedurl_allowed("172.32.0.1");
});

EXO_TEST(seedurl_allow_just_before_172_12, {
	return seedurl_allowed("172.15.255.255");
});

EXO_TEST(seedurl_allow_just_past_cgnat_10, {
	return seedurl_allowed("100.128.0.1");
});

EXO_TEST(seedurl_allow_just_before_cgnat_10, {
	return seedurl_allowed("100.63.255.255");
});

EXO_TEST(seedurl_allow_just_past_link_local_v4, {
	return seedurl_allowed("169.255.0.1");
});

EXO_TEST(seedurl_allow_just_before_multicast_v4, {
	return seedurl_allowed("223.255.255.255");
});

EXO_TEST(seedurl_allow_public_v4, {
	return seedurl_allowed("8.8.8.8") && seedurl_allowed("1.1.1.1");
});

EXO_TEST(seedurl_allow_just_before_link_local_v6, {
	/* fe80::/10 is fe80:: .. febf:ffff:..., so fe00::1 is genuinely outside. */
	return seedurl_allowed("fe00::1");
});

EXO_TEST(seedurl_allow_just_before_unique_local_v6, {
	return seedurl_allowed("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
});

EXO_TEST(seedurl_allow_public_v6, {
	return seedurl_allowed("2606:4700::1");
});

EXO_TEST(seedurl_allow_just_past_documentation_v6, {
	return seedurl_allowed("2001:db9::1");
});

EXO_TEST(seedurl_allow_private_permits_loopback, {
	return seedurl_check_addr(bpolicy_private, "127.0.0.1") == 1
		&& seedurl_check_addr(bpolicy_private, "169.254.169.254") == 1
		&& seedurl_check_addr(bpolicy_private, "::1") == 1;
});

/* ---------------------------------------------------------------- redirects */

EXO_TEST(seedurl_redirect_setup, {
	return seed_url_parse("http://a.example.org/one", NULL, &bu) == SEED_URL_OK
		&& seed_url_parse("http://b.example.org/two", NULL, &bu2) == SEED_URL_OK;
});

EXO_TEST(seedurl_redirect_first_hop_ok, {
	return seed_url_redirect_ok(&bu, &bu2, 0, 3) == 1;
});

EXO_TEST(seedurl_redirect_last_hop_ok, {
	return seed_url_redirect_ok(&bu, &bu2, 2, 3) == 1;
});

EXO_TEST(seedurl_redirect_hop_limit, {
	return seed_url_redirect_ok(&bu, &bu2, 3, 3) == 0
		&& seed_url_redirect_ok(&bu, &bu2, 4, 3) == 0;
});

EXO_TEST(seedurl_redirect_zero_max, {
	return seed_url_redirect_ok(&bu, &bu2, 0, 0) == 0;
});

EXO_TEST(seedurl_redirect_null, {
	return seed_url_redirect_ok(NULL, &bu2, 0, 3) == 0
		&& seed_url_redirect_ok(&bu, NULL, 0, 3) == 0;
});

EXO_TEST(seedurl_redirect_self_loop_refused, {
	struct seed_url a;
	struct seed_url b;
	return seed_url_parse("http://a.example.org/one", NULL, &a) == SEED_URL_OK
		&& seed_url_parse("http://a.example.org/one", NULL, &b) == SEED_URL_OK
		&& seed_url_redirect_ok(&a, &b, 0, 3) == 0;
});

EXO_TEST(seedurl_redirect_same_host_other_path_ok, {
	struct seed_url a;
	struct seed_url b;
	return seed_url_parse("http://a.example.org/one", NULL, &a) == SEED_URL_OK
		&& seed_url_parse("http://a.example.org/two", NULL, &b) == SEED_URL_OK
		&& seed_url_redirect_ok(&a, &b, 0, 3) == 1;
});

EXO_TEST(seedurl_redirect_downgrade_refused, {
	struct seed_url a;
	struct seed_url b;
	return seed_url_parse("https://a.example.org/one", NULL, &a) == SEED_URL_OK
		&& seed_url_parse("http://b.example.org/two", NULL, &b) == SEED_URL_OK
		&& seed_url_redirect_ok(&a, &b, 0, 3) == 0;
});

EXO_TEST(seedurl_redirect_upgrade_allowed, {
	struct seed_url a;
	struct seed_url b;
	return seed_url_parse("http://a.example.org/one", NULL, &a) == SEED_URL_OK
		&& seed_url_parse("https://a.example.org/one", NULL, &b) == SEED_URL_OK
		&& seed_url_redirect_ok(&a, &b, 0, 3) == 1;
});

/* ---------------------------------------------------------------- host lists */

EXO_TEST(seedurl_host_list_exact, {
	return seed_host_matches_list("example.com", "example.com") == 1;
});

EXO_TEST(seedurl_host_list_subdomain, {
	return seed_host_matches_list("a.example.com", "example.com") == 1
		&& seed_host_matches_list("a.b.example.com", "example.com") == 1;
});

EXO_TEST(seedurl_host_list_prefix_is_not_a_match, {
	return seed_host_matches_list("notexample.com", "example.com") == 0;
});

EXO_TEST(seedurl_host_list_suffix_is_not_a_match, {
	return seed_host_matches_list("example.com.evil.net", "example.com") == 0;
});

EXO_TEST(seedurl_host_list_empty_matches_nothing, {
	return seed_host_matches_list("example.com", "") == 0
		&& seed_host_matches_list("example.com", ",,") == 0
		&& seed_host_matches_list("example.com", NULL) == 0;
});

EXO_TEST(seedurl_host_list_empty_host, {
	return seed_host_matches_list("", "example.com") == 0
		&& seed_host_matches_list(NULL, "example.com") == 0;
});

EXO_TEST(seedurl_host_list_multi_entry, {
	const char* list = "example.com, cdn.example.net ,images.org";
	return seed_host_matches_list("a.example.com", list) == 1
		&& seed_host_matches_list("cdn.example.net", list) == 1
		&& seed_host_matches_list("x.cdn.example.net", list) == 1
		&& seed_host_matches_list("images.org", list) == 1
		&& seed_host_matches_list("example.net", list) == 0
		&& seed_host_matches_list("evil.net", list) == 0;
});

EXO_TEST(seedurl_host_list_case_insensitive, {
	return seed_host_matches_list("A.Example.COM", "example.com") == 1
		&& seed_host_matches_list("a.example.com", "EXAMPLE.COM") == 1;
});

EXO_TEST(seedurl_host_list_leading_dot_entry, {
	return seed_host_matches_list("a.example.com", ".example.com") == 1
		&& seed_host_matches_list("example.com", ".example.com") == 1;
});

EXO_TEST(seedurl_host_list_shorter_than_entry, {
	return seed_host_matches_list("com", "example.com") == 0;
});

/* Pairs with seedurl_prepare_network above. net_initialize() fails if the
   network is already up, so a file that leaves it initialized fails whichever
   test file happens to sort after it. */
EXO_TEST(seedurl_policy_destroy, {
	seed_addr_policy_destroy(bpolicy);
	seed_addr_policy_destroy(bpolicy_private);
	seed_addr_policy_destroy(NULL);
	bpolicy = NULL;
	bpolicy_private = NULL;
	net_destroy();
	return 1;
});
