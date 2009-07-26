#include <uhub.h>

static int ipv6 = 0;

static struct ip_addr_encap ip4_a;
static struct ip_addr_encap ip4_b;
static struct ip_addr_encap ip4_c;
static struct ip_addr_encap ip6_a;
static struct ip_addr_encap ip6_b;
static struct ip_addr_encap ip6_c;
static struct ip_addr_encap mask;
static struct ip_range ban6;
static struct ip_range ban4;

EXO_TEST(prepare_network, {
    return net_initialize() == 0;
});

EXO_TEST(check_ipv6, {
	ipv6 = net_is_ipv6_supported();
	return ipv6 != -1;
});

EXO_TEST(create_addresses_1, {
	return
		ip_convert_to_binary("192.168.0.0",     &ip4_a) &&
		ip_convert_to_binary("192.168.255.255", &ip4_b) &&
		ip_convert_to_binary("192.168.0.1",     &ip4_c);
});

EXO_TEST(create_addresses_2, {
	return
		ip_convert_to_binary("2001::201:2ff:fefa:0",    &ip6_a) &&
		ip_convert_to_binary("2001::201:2ff:fefa:ffff", &ip6_b) &&
		ip_convert_to_binary("2001::201:2ff:fefa:fffe", &ip6_c);
});

EXO_TEST(ip_is_valid_ipv4_1, {
	return ip_is_valid_ipv4("127.0.0.1");
});

EXO_TEST(ip_is_valid_ipv4_2, {
	return ip_is_valid_ipv4("10.18.1.178");
});

EXO_TEST(ip_is_valid_ipv4_3, {
	return ip_is_valid_ipv4("10.18.1.178");
});

EXO_TEST(ip_is_valid_ipv4_4, {
	return ip_is_valid_ipv4("224.0.0.1");
});

EXO_TEST(ip_is_valid_ipv4_5, {
	return !ip_is_valid_ipv4("224.0.0.");
});

EXO_TEST(ip_is_valid_ipv4_6, {
	return !ip_is_valid_ipv4("invalid");
});

EXO_TEST(ip_is_valid_ipv4_7, {
	return !ip_is_valid_ipv4("localhost");
});

EXO_TEST(ip_is_valid_ipv4_8, {
	return !ip_is_valid_ipv4("123.45.67.890");
});

EXO_TEST(ip_is_valid_ipv4_9, {
	return !ip_is_valid_ipv4("777.777.777.777");
});

EXO_TEST(ip_is_valid_ipv6_1, {
	if (!ipv6) return 1;
	return ip_is_valid_ipv6("::");
});

EXO_TEST(ip_is_valid_ipv6_2, {
	if (!ipv6) return 1;
	return ip_is_valid_ipv6("::1");
});

EXO_TEST(ip_is_valid_ipv6_3, {
	if (!ipv6) return 1;
	return ip_is_valid_ipv6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
});

EXO_TEST(ip4_compare_1, {
	return ip_compare(&ip4_a, &ip4_b) < 0;
});

EXO_TEST(ip4_compare_2, {
	return ip_compare(&ip4_a, &ip4_c) < 0;
});

EXO_TEST(ip4_compare_3, {
	return ip_compare(&ip4_b, &ip4_c) > 0;
});

EXO_TEST(ip4_compare_4, {
	return ip_compare(&ip4_b, &ip4_a) > 0;
});

EXO_TEST(ip4_compare_5, {
	return ip_compare(&ip4_c, &ip4_a) > 0;
});

EXO_TEST(ip4_compare_6, {
	if (!ipv6) return 1;
	return ip_compare(&ip4_c, &ip4_c) == 0;
});

EXO_TEST(ip6_compare_1, {
	if (!ipv6) return 1;
	return ip_compare(&ip6_a, &ip6_b) < 0;
});

EXO_TEST(ip6_compare_2, {
	if (!ipv6) return 1;
	return ip_compare(&ip6_a, &ip6_c) < 0;
});

EXO_TEST(ip6_compare_3, {
	if (!ipv6) return 1;
	return ip_compare(&ip6_b, &ip6_c) > 0;
});

EXO_TEST(ip6_compare_4, {
	if (!ipv6) return 1;
	return ip_compare(&ip6_b, &ip6_a) > 0;
});

EXO_TEST(ip6_compare_5, {
	if (!ipv6) return 1;
	return ip_compare(&ip6_c, &ip6_a) > 0;
});

EXO_TEST(ip6_compare_6, {
	if (!ipv6) return 1;
	return ip_compare(&ip6_c, &ip6_c) == 0;
});

static int compare_str(const char* s1, const char* s2)
{
	int ok = strcmp(s1, s2);
#ifdef DEBUG_TESTS
	if (ok)
	{
		printf("compare_str fail: s1='%s', s2='%s'\n", s1, s2);
	}
#endif
	return ok;
}

#define LMASK4(bits)    !ip_mask_create_left (AF_INET,  bits, &mask)
#define LMASK6(bits)    (ipv6 ? !ip_mask_create_left (AF_INET6, bits, &mask) : 1)
#define RMASK4(bits)    !ip_mask_create_right(AF_INET,  bits, &mask)
#define RMASK6(bits)    (ipv6 ? !ip_mask_create_right(AF_INET6, bits, &mask) : 1)
#define CHECK4(expect)   !compare_str(ip_convert_to_string(&mask), expect)
#define CHECK6(expect)  (ipv6 ? !compare_str(ip_convert_to_string(&mask), expect) : 1)

/* Check IPv4 masks */
EXO_TEST(ipv4_lmask_create_0,  { return LMASK4( 0) && CHECK4("0.0.0.0"); });
EXO_TEST(ipv4_lmask_create_1,  { return LMASK4( 1) && CHECK4("128.0.0.0"); });
EXO_TEST(ipv4_lmask_create_2,  { return LMASK4( 2) && CHECK4("192.0.0.0"); });
EXO_TEST(ipv4_lmask_create_3,  { return LMASK4( 3) && CHECK4("224.0.0.0"); });
EXO_TEST(ipv4_lmask_create_4,  { return LMASK4( 4) && CHECK4("240.0.0.0"); });
EXO_TEST(ipv4_lmask_create_5,  { return LMASK4( 5) && CHECK4("248.0.0.0"); });
EXO_TEST(ipv4_lmask_create_6,  { return LMASK4( 6) && CHECK4("252.0.0.0"); });
EXO_TEST(ipv4_lmask_create_7,  { return LMASK4( 7) && CHECK4("254.0.0.0"); });
EXO_TEST(ipv4_lmask_create_8,  { return LMASK4( 8) && CHECK4("255.0.0.0"); });
EXO_TEST(ipv4_lmask_create_9,  { return LMASK4( 9) && CHECK4("255.128.0.0"); });
EXO_TEST(ipv4_lmask_create_10, { return LMASK4(10) && CHECK4("255.192.0.0"); });
EXO_TEST(ipv4_lmask_create_11, { return LMASK4(11) && CHECK4("255.224.0.0"); });
EXO_TEST(ipv4_lmask_create_12, { return LMASK4(12) && CHECK4("255.240.0.0"); });
EXO_TEST(ipv4_lmask_create_13, { return LMASK4(13) && CHECK4("255.248.0.0"); });
EXO_TEST(ipv4_lmask_create_14, { return LMASK4(14) && CHECK4("255.252.0.0"); });
EXO_TEST(ipv4_lmask_create_15, { return LMASK4(15) && CHECK4("255.254.0.0"); });
EXO_TEST(ipv4_lmask_create_16, { return LMASK4(16) && CHECK4("255.255.0.0"); });
EXO_TEST(ipv4_lmask_create_17, { return LMASK4(17) && CHECK4("255.255.128.0"); });
EXO_TEST(ipv4_lmask_create_18, { return LMASK4(18) && CHECK4("255.255.192.0"); });
EXO_TEST(ipv4_lmask_create_19, { return LMASK4(19) && CHECK4("255.255.224.0"); });
EXO_TEST(ipv4_lmask_create_20, { return LMASK4(20) && CHECK4("255.255.240.0"); });
EXO_TEST(ipv4_lmask_create_21, { return LMASK4(21) && CHECK4("255.255.248.0"); });
EXO_TEST(ipv4_lmask_create_22, { return LMASK4(22) && CHECK4("255.255.252.0"); });
EXO_TEST(ipv4_lmask_create_23, { return LMASK4(23) && CHECK4("255.255.254.0"); });
EXO_TEST(ipv4_lmask_create_24, { return LMASK4(24) && CHECK4("255.255.255.0"); });
EXO_TEST(ipv4_lmask_create_25, { return LMASK4(25) && CHECK4("255.255.255.128"); });
EXO_TEST(ipv4_lmask_create_26, { return LMASK4(26) && CHECK4("255.255.255.192"); });
EXO_TEST(ipv4_lmask_create_27, { return LMASK4(27) && CHECK4("255.255.255.224"); });
EXO_TEST(ipv4_lmask_create_28, { return LMASK4(28) && CHECK4("255.255.255.240"); });
EXO_TEST(ipv4_lmask_create_29, { return LMASK4(29) && CHECK4("255.255.255.248"); });
EXO_TEST(ipv4_lmask_create_30, { return LMASK4(30) && CHECK4("255.255.255.252"); });
EXO_TEST(ipv4_lmask_create_31, { return LMASK4(31) && CHECK4("255.255.255.254"); });
EXO_TEST(ipv4_lmask_create_32, { return LMASK4(32) && CHECK4("255.255.255.255"); });

/* Check IPv4 right to left mask */
EXO_TEST(ipv4_rmask_create_0,  { return RMASK4( 0) && CHECK4("0.0.0.0"); });
EXO_TEST(ipv4_rmask_create_1,  { return RMASK4( 1) && CHECK4("0.0.0.1"); });
EXO_TEST(ipv4_rmask_create_2,  { return RMASK4( 2) && CHECK4("0.0.0.3"); });
EXO_TEST(ipv4_rmask_create_3,  { return RMASK4( 3) && CHECK4("0.0.0.7"); });
EXO_TEST(ipv4_rmask_create_4,  { return RMASK4( 4) && CHECK4("0.0.0.15"); });
EXO_TEST(ipv4_rmask_create_5,  { return RMASK4( 5) && CHECK4("0.0.0.31"); });
EXO_TEST(ipv4_rmask_create_6,  { return RMASK4( 6) && CHECK4("0.0.0.63"); });
EXO_TEST(ipv4_rmask_create_7,  { return RMASK4( 7) && CHECK4("0.0.0.127"); });
EXO_TEST(ipv4_rmask_create_8,  { return RMASK4( 8) && CHECK4("0.0.0.255"); });
EXO_TEST(ipv4_rmask_create_9,  { return RMASK4( 9) && CHECK4("0.0.1.255"); });
EXO_TEST(ipv4_rmask_create_10, { return RMASK4(10) && CHECK4("0.0.3.255"); });
EXO_TEST(ipv4_rmask_create_11, { return RMASK4(11) && CHECK4("0.0.7.255"); });
EXO_TEST(ipv4_rmask_create_12, { return RMASK4(12) && CHECK4("0.0.15.255"); });
EXO_TEST(ipv4_rmask_create_13, { return RMASK4(13) && CHECK4("0.0.31.255"); });
EXO_TEST(ipv4_rmask_create_14, { return RMASK4(14) && CHECK4("0.0.63.255"); });
EXO_TEST(ipv4_rmask_create_15, { return RMASK4(15) && CHECK4("0.0.127.255"); });
EXO_TEST(ipv4_rmask_create_16, { return RMASK4(16) && CHECK4("0.0.255.255"); });
EXO_TEST(ipv4_rmask_create_17, { return RMASK4(17) && CHECK4("0.1.255.255"); });
EXO_TEST(ipv4_rmask_create_18, { return RMASK4(18) && CHECK4("0.3.255.255"); });
EXO_TEST(ipv4_rmask_create_19, { return RMASK4(19) && CHECK4("0.7.255.255"); });
EXO_TEST(ipv4_rmask_create_20, { return RMASK4(20) && CHECK4("0.15.255.255"); });
EXO_TEST(ipv4_rmask_create_21, { return RMASK4(21) && CHECK4("0.31.255.255"); });
EXO_TEST(ipv4_rmask_create_22, { return RMASK4(22) && CHECK4("0.63.255.255"); });
EXO_TEST(ipv4_rmask_create_23, { return RMASK4(23) && CHECK4("0.127.255.255"); });
EXO_TEST(ipv4_rmask_create_24, { return RMASK4(24) && CHECK4("0.255.255.255"); });
EXO_TEST(ipv4_rmask_create_25, { return RMASK4(25) && CHECK4("1.255.255.255"); });
EXO_TEST(ipv4_rmask_create_26, { return RMASK4(26) && CHECK4("3.255.255.255"); });
EXO_TEST(ipv4_rmask_create_27, { return RMASK4(27) && CHECK4("7.255.255.255"); });
EXO_TEST(ipv4_rmask_create_28, { return RMASK4(28) && CHECK4("15.255.255.255"); });
EXO_TEST(ipv4_rmask_create_29, { return RMASK4(29) && CHECK4("31.255.255.255"); });
EXO_TEST(ipv4_rmask_create_30, { return RMASK4(30) && CHECK4("63.255.255.255"); });
EXO_TEST(ipv4_rmask_create_31, { return RMASK4(31) && CHECK4("127.255.255.255"); });
EXO_TEST(ipv4_rmask_create_32, { return RMASK4(32) && CHECK4("255.255.255.255"); });


/* Check IPv6 masks */
EXO_TEST(ip6_lmask_create_0,   { return LMASK6(  0) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_lmask_create_1,   { return LMASK6(  1) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"); });
EXO_TEST(ip6_lmask_create_2,   { return LMASK6(  2) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc"); });
EXO_TEST(ip6_lmask_create_3,   { return LMASK6(  3) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff8"); });
EXO_TEST(ip6_lmask_create_4,   { return LMASK6(  4) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0"); });
EXO_TEST(ip6_lmask_create_5,   { return LMASK6(  5) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffe0"); });
EXO_TEST(ip6_lmask_create_6,   { return LMASK6(  6) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffc0"); });
EXO_TEST(ip6_lmask_create_7,   { return LMASK6(  7) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff80"); });
EXO_TEST(ip6_lmask_create_8,   { return LMASK6(  8) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"); });
EXO_TEST(ip6_lmask_create_9,   { return LMASK6(  9) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fe00"); });
EXO_TEST(ip6_lmask_create_10,  { return LMASK6( 10) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fc00"); });
EXO_TEST(ip6_lmask_create_11,  { return LMASK6( 11) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:f800"); });
EXO_TEST(ip6_lmask_create_12,  { return LMASK6( 12) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:f000"); });
EXO_TEST(ip6_lmask_create_13,  { return LMASK6( 13) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:e000"); });
EXO_TEST(ip6_lmask_create_14,  { return LMASK6( 14) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:c000"); });
EXO_TEST(ip6_lmask_create_15,  { return LMASK6( 15) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:8000"); });
EXO_TEST(ip6_lmask_create_16,  { return LMASK6( 16) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff::")); });
EXO_TEST(ip6_lmask_create_17,  { return LMASK6( 17) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:fffe:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:fffe::")); });
EXO_TEST(ip6_lmask_create_18,  { return LMASK6( 18) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:fffc:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:fffc::")); });
EXO_TEST(ip6_lmask_create_19,  { return LMASK6( 19) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:fff8:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:fff8::")); });
EXO_TEST(ip6_lmask_create_20,  { return LMASK6( 20) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:fff0:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:fff0::")); });
EXO_TEST(ip6_lmask_create_21,  { return LMASK6( 21) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffe0:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffe0::")); });
EXO_TEST(ip6_lmask_create_22,  { return LMASK6( 22) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffc0:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffc0::")); });
EXO_TEST(ip6_lmask_create_23,  { return LMASK6( 23) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ff80:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ff80::")); });
EXO_TEST(ip6_lmask_create_24,  { return LMASK6( 24) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ff00:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ff00::")); });
EXO_TEST(ip6_lmask_create_25,  { return LMASK6( 25) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:fe00:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:fe00::")); });
EXO_TEST(ip6_lmask_create_26,  { return LMASK6( 26) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:fc00:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:fc00::")); });
EXO_TEST(ip6_lmask_create_27,  { return LMASK6( 27) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:f800:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:f800::")); });
EXO_TEST(ip6_lmask_create_28,  { return LMASK6( 28) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:f000:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:f000::")); });
EXO_TEST(ip6_lmask_create_29,  { return LMASK6( 29) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:e000:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:e000::")); });
EXO_TEST(ip6_lmask_create_30,  { return LMASK6( 30) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:c000:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:c000::")); });
EXO_TEST(ip6_lmask_create_31,  { return LMASK6( 31) && (CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:8000:0") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:8000::")); });
EXO_TEST(ip6_lmask_create_32,  { return LMASK6( 32) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff::"); });
EXO_TEST(ip6_lmask_create_33,  { return LMASK6( 33) && CHECK6("ffff:ffff:ffff:ffff:ffff:fffe::"); });
EXO_TEST(ip6_lmask_create_34,  { return LMASK6( 34) && CHECK6("ffff:ffff:ffff:ffff:ffff:fffc::"); });
EXO_TEST(ip6_lmask_create_35,  { return LMASK6( 35) && CHECK6("ffff:ffff:ffff:ffff:ffff:fff8::"); });
EXO_TEST(ip6_lmask_create_36,  { return LMASK6( 36) && CHECK6("ffff:ffff:ffff:ffff:ffff:fff0::"); });
EXO_TEST(ip6_lmask_create_37,  { return LMASK6( 37) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffe0::"); });
EXO_TEST(ip6_lmask_create_38,  { return LMASK6( 38) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffc0::"); });
EXO_TEST(ip6_lmask_create_39,  { return LMASK6( 39) && CHECK6("ffff:ffff:ffff:ffff:ffff:ff80::"); });
EXO_TEST(ip6_lmask_create_40,  { return LMASK6( 40) && CHECK6("ffff:ffff:ffff:ffff:ffff:ff00::"); });
EXO_TEST(ip6_lmask_create_41,  { return LMASK6( 41) && CHECK6("ffff:ffff:ffff:ffff:ffff:fe00::"); });
EXO_TEST(ip6_lmask_create_42,  { return LMASK6( 42) && CHECK6("ffff:ffff:ffff:ffff:ffff:fc00::"); });
EXO_TEST(ip6_lmask_create_43,  { return LMASK6( 43) && CHECK6("ffff:ffff:ffff:ffff:ffff:f800::"); });
EXO_TEST(ip6_lmask_create_44,  { return LMASK6( 44) && CHECK6("ffff:ffff:ffff:ffff:ffff:f000::"); });
EXO_TEST(ip6_lmask_create_45,  { return LMASK6( 45) && CHECK6("ffff:ffff:ffff:ffff:ffff:e000::"); });
EXO_TEST(ip6_lmask_create_46,  { return LMASK6( 46) && CHECK6("ffff:ffff:ffff:ffff:ffff:c000::"); });
EXO_TEST(ip6_lmask_create_47,  { return LMASK6( 47) && CHECK6("ffff:ffff:ffff:ffff:ffff:8000::"); });
EXO_TEST(ip6_lmask_create_48,  { return LMASK6( 48) && CHECK6("ffff:ffff:ffff:ffff:ffff::"); });
EXO_TEST(ip6_lmask_create_49,  { return LMASK6( 49) && CHECK6("ffff:ffff:ffff:ffff:fffe::"); });
EXO_TEST(ip6_lmask_create_50,  { return LMASK6( 50) && CHECK6("ffff:ffff:ffff:ffff:fffc::"); });
EXO_TEST(ip6_lmask_create_51,  { return LMASK6( 51) && CHECK6("ffff:ffff:ffff:ffff:fff8::"); });
EXO_TEST(ip6_lmask_create_52,  { return LMASK6( 52) && CHECK6("ffff:ffff:ffff:ffff:fff0::"); });
EXO_TEST(ip6_lmask_create_53,  { return LMASK6( 53) && CHECK6("ffff:ffff:ffff:ffff:ffe0::"); });
EXO_TEST(ip6_lmask_create_54,  { return LMASK6( 54) && CHECK6("ffff:ffff:ffff:ffff:ffc0::"); });
EXO_TEST(ip6_lmask_create_55,  { return LMASK6( 55) && CHECK6("ffff:ffff:ffff:ffff:ff80::"); });
EXO_TEST(ip6_lmask_create_56,  { return LMASK6( 56) && CHECK6("ffff:ffff:ffff:ffff:ff00::"); });
EXO_TEST(ip6_lmask_create_57,  { return LMASK6( 57) && CHECK6("ffff:ffff:ffff:ffff:fe00::"); });
EXO_TEST(ip6_lmask_create_58,  { return LMASK6( 58) && CHECK6("ffff:ffff:ffff:ffff:fc00::"); });
EXO_TEST(ip6_lmask_create_59,  { return LMASK6( 59) && CHECK6("ffff:ffff:ffff:ffff:f800::"); });
EXO_TEST(ip6_lmask_create_60,  { return LMASK6( 60) && CHECK6("ffff:ffff:ffff:ffff:f000::"); });
EXO_TEST(ip6_lmask_create_61,  { return LMASK6( 61) && CHECK6("ffff:ffff:ffff:ffff:e000::"); });
EXO_TEST(ip6_lmask_create_62,  { return LMASK6( 62) && CHECK6("ffff:ffff:ffff:ffff:c000::"); });
EXO_TEST(ip6_lmask_create_63,  { return LMASK6( 63) && CHECK6("ffff:ffff:ffff:ffff:8000::"); });
EXO_TEST(ip6_lmask_create_64,  { return LMASK6( 64) && CHECK6("ffff:ffff:ffff:ffff::"); });
EXO_TEST(ip6_lmask_create_65,  { return LMASK6( 65) && CHECK6("ffff:ffff:ffff:fffe::"); });
EXO_TEST(ip6_lmask_create_66,  { return LMASK6( 66) && CHECK6("ffff:ffff:ffff:fffc::"); });
EXO_TEST(ip6_lmask_create_67,  { return LMASK6( 67) && CHECK6("ffff:ffff:ffff:fff8::"); });
EXO_TEST(ip6_lmask_create_68,  { return LMASK6( 68) && CHECK6("ffff:ffff:ffff:fff0::"); });
EXO_TEST(ip6_lmask_create_69,  { return LMASK6( 69) && CHECK6("ffff:ffff:ffff:ffe0::"); });
EXO_TEST(ip6_lmask_create_70,  { return LMASK6( 70) && CHECK6("ffff:ffff:ffff:ffc0::"); });
EXO_TEST(ip6_lmask_create_71,  { return LMASK6( 71) && CHECK6("ffff:ffff:ffff:ff80::"); });
EXO_TEST(ip6_lmask_create_72,  { return LMASK6( 72) && CHECK6("ffff:ffff:ffff:ff00::"); });
EXO_TEST(ip6_lmask_create_73,  { return LMASK6( 73) && CHECK6("ffff:ffff:ffff:fe00::"); });
EXO_TEST(ip6_lmask_create_74,  { return LMASK6( 74) && CHECK6("ffff:ffff:ffff:fc00::"); });
EXO_TEST(ip6_lmask_create_75,  { return LMASK6( 75) && CHECK6("ffff:ffff:ffff:f800::"); });
EXO_TEST(ip6_lmask_create_76,  { return LMASK6( 76) && CHECK6("ffff:ffff:ffff:f000::"); });
EXO_TEST(ip6_lmask_create_77,  { return LMASK6( 77) && CHECK6("ffff:ffff:ffff:e000::"); });
EXO_TEST(ip6_lmask_create_78,  { return LMASK6( 78) && CHECK6("ffff:ffff:ffff:c000::"); });
EXO_TEST(ip6_lmask_create_79,  { return LMASK6( 79) && CHECK6("ffff:ffff:ffff:8000::"); });
EXO_TEST(ip6_lmask_create_80,  { return LMASK6( 80) && CHECK6("ffff:ffff:ffff::"); });
EXO_TEST(ip6_lmask_create_81,  { return LMASK6( 81) && CHECK6("ffff:ffff:fffe::"); });
EXO_TEST(ip6_lmask_create_82,  { return LMASK6( 82) && CHECK6("ffff:ffff:fffc::"); });
EXO_TEST(ip6_lmask_create_83,  { return LMASK6( 83) && CHECK6("ffff:ffff:fff8::"); });
EXO_TEST(ip6_lmask_create_84,  { return LMASK6( 84) && CHECK6("ffff:ffff:fff0::"); });
EXO_TEST(ip6_lmask_create_85,  { return LMASK6( 85) && CHECK6("ffff:ffff:ffe0::"); });
EXO_TEST(ip6_lmask_create_86,  { return LMASK6( 86) && CHECK6("ffff:ffff:ffc0::"); });
EXO_TEST(ip6_lmask_create_87,  { return LMASK6( 87) && CHECK6("ffff:ffff:ff80::"); });
EXO_TEST(ip6_lmask_create_88,  { return LMASK6( 88) && CHECK6("ffff:ffff:ff00::"); });
EXO_TEST(ip6_lmask_create_89,  { return LMASK6( 89) && CHECK6("ffff:ffff:fe00::"); });
EXO_TEST(ip6_lmask_create_90,  { return LMASK6( 90) && CHECK6("ffff:ffff:fc00::"); });
EXO_TEST(ip6_lmask_create_91,  { return LMASK6( 91) && CHECK6("ffff:ffff:f800::"); });
EXO_TEST(ip6_lmask_create_92,  { return LMASK6( 92) && CHECK6("ffff:ffff:f000::"); });
EXO_TEST(ip6_lmask_create_93,  { return LMASK6( 93) && CHECK6("ffff:ffff:e000::"); });
EXO_TEST(ip6_lmask_create_94,  { return LMASK6( 94) && CHECK6("ffff:ffff:c000::"); });
EXO_TEST(ip6_lmask_create_95,  { return LMASK6( 95) && CHECK6("ffff:ffff:8000::"); });
EXO_TEST(ip6_lmask_create_96,  { return LMASK6( 96) && CHECK6("ffff:ffff::"); });
EXO_TEST(ip6_lmask_create_97,  { return LMASK6( 97) && CHECK6("ffff:fffe::"); });
EXO_TEST(ip6_lmask_create_98,  { return LMASK6( 98) && CHECK6("ffff:fffc::"); });
EXO_TEST(ip6_lmask_create_99,  { return LMASK6( 99) && CHECK6("ffff:fff8::"); });
EXO_TEST(ip6_lmask_create_100, { return LMASK6(100) && CHECK6("ffff:fff0::"); });
EXO_TEST(ip6_lmask_create_101, { return LMASK6(101) && CHECK6("ffff:ffe0::"); });
EXO_TEST(ip6_lmask_create_102, { return LMASK6(102) && CHECK6("ffff:ffc0::"); });
EXO_TEST(ip6_lmask_create_103, { return LMASK6(103) && CHECK6("ffff:ff80::"); });
EXO_TEST(ip6_lmask_create_104, { return LMASK6(104) && CHECK6("ffff:ff00::"); });
EXO_TEST(ip6_lmask_create_105, { return LMASK6(105) && CHECK6("ffff:fe00::"); });
EXO_TEST(ip6_lmask_create_106, { return LMASK6(106) && CHECK6("ffff:fc00::"); });
EXO_TEST(ip6_lmask_create_107, { return LMASK6(107) && CHECK6("ffff:f800::"); });
EXO_TEST(ip6_lmask_create_108, { return LMASK6(108) && CHECK6("ffff:f000::"); });
EXO_TEST(ip6_lmask_create_109, { return LMASK6(109) && CHECK6("ffff:e000::"); });
EXO_TEST(ip6_lmask_create_110, { return LMASK6(110) && CHECK6("ffff:c000::"); });
EXO_TEST(ip6_lmask_create_111, { return LMASK6(111) && CHECK6("ffff:8000::"); });
EXO_TEST(ip6_lmask_create_112, { return LMASK6(112) && CHECK6("ffff::"); });
EXO_TEST(ip6_lmask_create_113, { return LMASK6(113) && CHECK6("fffe::"); });
EXO_TEST(ip6_lmask_create_114, { return LMASK6(114) && CHECK6("fffc::"); });
EXO_TEST(ip6_lmask_create_115, { return LMASK6(115) && CHECK6("fff8::"); });
EXO_TEST(ip6_lmask_create_116, { return LMASK6(116) && CHECK6("fff0::"); });
EXO_TEST(ip6_lmask_create_117, { return LMASK6(117) && CHECK6("ffe0::"); });
EXO_TEST(ip6_lmask_create_118, { return LMASK6(118) && CHECK6("ffc0::"); });
EXO_TEST(ip6_lmask_create_119, { return LMASK6(119) && CHECK6("ff80::"); });
EXO_TEST(ip6_lmask_create_120, { return LMASK6(120) && CHECK6("ff00::"); });
EXO_TEST(ip6_lmask_create_121, { return LMASK6(121) && CHECK6("fe00::"); });
EXO_TEST(ip6_lmask_create_122, { return LMASK6(122) && CHECK6("fc00::"); });
EXO_TEST(ip6_lmask_create_123, { return LMASK6(123) && CHECK6("f800::"); });
EXO_TEST(ip6_lmask_create_124, { return LMASK6(124) && CHECK6("f000::"); });
EXO_TEST(ip6_lmask_create_125, { return LMASK6(125) && CHECK6("e000::"); });
EXO_TEST(ip6_lmask_create_126, { return LMASK6(126) && CHECK6("c000::"); });
EXO_TEST(ip6_lmask_create_127, { return LMASK6(127) && CHECK6("8000::"); });
EXO_TEST(ip6_lmask_create_128, { return LMASK6(128) && CHECK6("::"); });

/* Check IPv6 right to left masks */
EXO_TEST(ip6_rmask_create_0,   { return RMASK6(  0) && CHECK6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_1,   { return RMASK6(  1) && CHECK6("7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_2,   { return RMASK6(  2) && CHECK6("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_3,   { return RMASK6(  3) && CHECK6("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_4,   { return RMASK6(  4) && CHECK6("fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_5,   { return RMASK6(  5) && CHECK6("7ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_6,   { return RMASK6(  6) && CHECK6("3ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_7,   { return RMASK6(  7) && CHECK6("1ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_8,   { return RMASK6(  8) && CHECK6("ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_9,   { return RMASK6(  9) && CHECK6("7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_10,  { return RMASK6( 10) && CHECK6("3f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_11,  { return RMASK6( 11) && CHECK6("1f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_12,  { return RMASK6( 12) && CHECK6("f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_13,  { return RMASK6( 13) && CHECK6("7:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_14,  { return RMASK6( 14) && CHECK6("3:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_15,  { return RMASK6( 15) && CHECK6("1:ffff:ffff:ffff:ffff:ffff:ffff:ffff"); });
EXO_TEST(ip6_rmask_create_16,  { return RMASK6( 16) && (CHECK6("0:ffff:ffff:ffff:ffff:ffff:ffff:ffff") || CHECK6("::ffff:ffff:ffff:ffff:ffff:ffff:ffff") || CHECK6("ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_17,  { return RMASK6( 17) && (CHECK6("0:7fff:ffff:ffff:ffff:ffff:ffff:ffff") || CHECK6("::7fff:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_18,  { return RMASK6( 18) && (CHECK6("0:3fff:ffff:ffff:ffff:ffff:ffff:ffff") || CHECK6("::3fff:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_19,  { return RMASK6( 19) && (CHECK6("0:1fff:ffff:ffff:ffff:ffff:ffff:ffff") || CHECK6("::1fff:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_20,  { return RMASK6( 20) && (CHECK6("0:fff:ffff:ffff:ffff:ffff:ffff:ffff")  || CHECK6("::fff:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_21,  { return RMASK6( 21) && (CHECK6("0:7ff:ffff:ffff:ffff:ffff:ffff:ffff")  || CHECK6("::7ff:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_22,  { return RMASK6( 22) && (CHECK6("0:3ff:ffff:ffff:ffff:ffff:ffff:ffff")  || CHECK6("::3ff:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_23,  { return RMASK6( 23) && (CHECK6("0:1ff:ffff:ffff:ffff:ffff:ffff:ffff")  || CHECK6("::1ff:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_24,  { return RMASK6( 24) && (CHECK6("0:ff:ffff:ffff:ffff:ffff:ffff:ffff")   || CHECK6("::ff:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_25,  { return RMASK6( 25) && (CHECK6("0:7f:ffff:ffff:ffff:ffff:ffff:ffff")   || CHECK6("::7f:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_26,  { return RMASK6( 26) && (CHECK6("0:3f:ffff:ffff:ffff:ffff:ffff:ffff")   || CHECK6("::3f:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_27,  { return RMASK6( 27) && (CHECK6("0:1f:ffff:ffff:ffff:ffff:ffff:ffff")   || CHECK6("::1f:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_28,  { return RMASK6( 28) && (CHECK6("0:f:ffff:ffff:ffff:ffff:ffff:ffff")    || CHECK6("::f:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_29,  { return RMASK6( 29) && (CHECK6("0:7:ffff:ffff:ffff:ffff:ffff:ffff")    || CHECK6("::7:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_30,  { return RMASK6( 30) && (CHECK6("0:3:ffff:ffff:ffff:ffff:ffff:ffff")    || CHECK6("::3:ffff:ffff:ffff:ffff:ffff:ffff")); });
EXO_TEST(ip6_rmask_create_31,  { return RMASK6( 31) && (CHECK6("0:1:ffff:ffff:ffff:ffff:ffff:ffff")    || CHECK6("::1:ffff:ffff:ffff:ffff:ffff:ffff")); });

EXO_TEST(check_ban_setup_1, {
	return	ip_convert_to_binary("2001::201:2ff:fefa:0",    &ban6.lo) &&
			ip_convert_to_binary("2001::201:2ff:fefa:ffff", &ban6.hi) &&
			ip_convert_to_binary("192.168.0.0",             &ban4.lo) &&
			ip_convert_to_binary("192.168.0.255",           &ban4.hi);
});

EXO_TEST(check_ban_ipv4_1, {
	struct ip_addr_encap addr; ip_convert_to_binary("192.168.0.0", &addr);
	return ip_in_range(&addr, &ban4);
});

EXO_TEST(check_ban_ipv4_2, {
	struct ip_addr_encap addr; ip_convert_to_binary("192.168.0.1", &addr);
	return ip_in_range(&addr, &ban4);
});

EXO_TEST(check_ban_ipv4_3, {
	struct ip_addr_encap addr; ip_convert_to_binary("192.168.0.255", &addr);
	return ip_in_range(&addr, &ban4);
});

EXO_TEST(check_ban_ipv4_4, {
	struct ip_addr_encap addr; ip_convert_to_binary("192.168.1.0", &addr);
	return !ip_in_range(&addr, &ban4);
});

EXO_TEST(check_ban_ipv4_5, {
	struct ip_addr_encap addr; ip_convert_to_binary("192.167.255.255", &addr);
	return !ip_in_range(&addr, &ban4);
});

EXO_TEST(check_ban_ipv6_1, {
	if (!ipv6) return 1;
	struct ip_addr_encap addr; ip_convert_to_binary("2001::201:2ff:fefa:0", &addr);
	return ip_in_range(&addr, &ban6);
});

EXO_TEST(check_ban_ipv6_2, {
	if (!ipv6) return 1;
	struct ip_addr_encap addr; ip_convert_to_binary("2001::201:2ff:fefa:1", &addr);
	return ip_in_range(&addr, &ban6);
});

EXO_TEST(check_ban_ipv6_3, {
	if (!ipv6) return 1;
	struct ip_addr_encap addr; ip_convert_to_binary("2001::201:2ff:fefa:fffe", &addr);
	return ip_in_range(&addr, &ban6);
});

EXO_TEST(check_ban_ipv6_4, {
	if (!ipv6) return 1;
	struct ip_addr_encap addr; ip_convert_to_binary("2001::201:2ff:fefa:ffff", &addr);
	return ip_in_range(&addr, &ban6);
});

EXO_TEST(check_ban_ipv6_5, {
	if (!ipv6) return 1;
	struct ip_addr_encap addr; ip_convert_to_binary("2001::201:2ff:fefb:0", &addr);
	return !ip_in_range(&addr, &ban6);
});

EXO_TEST(check_ban_ipv6_6, {
	if (!ipv6) return 1;
	struct ip_addr_encap addr; ip_convert_to_binary("2001::201:2ff:fef9:ffff", &addr);
	return !ip_in_range(&addr, &ban6);
});

EXO_TEST(check_ban_afmix_1, {
	if (!ipv6) return 1;
	struct ip_addr_encap addr; ip_convert_to_binary("2001::201:2ff:fef9:ffff", &addr);
	return !ip_in_range(&addr, &ban4);
});

EXO_TEST(check_ban_afmix_2, {
	struct ip_addr_encap addr; ip_convert_to_binary("10.20.30.40", &addr);
	return !ip_in_range(&addr, &ban6);
});

EXO_TEST(ip4_bitwise_AND_1, {
	ip_convert_to_binary("255.255.255.255", &ip4_a);
	ip_convert_to_binary("255.255.255.0",   &ip4_b);
	ip_mask_apply_AND(&ip4_a, &ip4_b, &ip4_c);
	return !strcmp(ip_convert_to_string(&ip4_c), "255.255.255.0");
});

EXO_TEST(ip4_bitwise_AND_2, {
	ip_convert_to_binary("192.168.217.113", &ip4_a);
	ip_convert_to_binary("255.255.255.0",   &ip4_b);
	ip_mask_apply_AND(&ip4_a, &ip4_b, &ip4_c);
	return !strcmp(ip_convert_to_string(&ip4_c), "192.168.217.0");
});

EXO_TEST(ip4_bitwise_AND_3, {
	ip_convert_to_binary("192.168.217.113", &ip4_a);
	ip_convert_to_binary("255.255.0.0",     &ip4_b);
	ip_mask_apply_AND(&ip4_a, &ip4_b, &ip4_c);
	return !strcmp(ip_convert_to_string(&ip4_c), "192.168.0.0");
});

EXO_TEST(ip4_bitwise_AND_4, {
	ip_convert_to_binary("192.168.217.113", &ip4_a);
	ip_convert_to_binary("255.0.0.0",       &ip4_b);
	ip_mask_apply_AND(&ip4_a, &ip4_b, &ip4_c);
	return !strcmp(ip_convert_to_string(&ip4_c), "192.0.0.0");
});

EXO_TEST(ip4_bitwise_AND_5, {
	ip_convert_to_binary("192.168.217.113", &ip4_a);
	ip_convert_to_binary("0.0.0.0",   &ip4_b);
	ip_mask_apply_AND(&ip4_a, &ip4_b, &ip4_c);
	return !strcmp(ip_convert_to_string(&ip4_c), "0.0.0.0");
});

EXO_TEST(ip4_bitwise_OR_1, {
	ip_convert_to_binary("255.255.255.255", &ip4_a);
	ip_convert_to_binary("255.255.255.0",   &ip4_b);
	ip_mask_apply_OR(&ip4_a, &ip4_b, &ip4_c);
	return !strcmp(ip_convert_to_string(&ip4_c), "255.255.255.255");
});

EXO_TEST(ip4_bitwise_OR_2, {
	ip_convert_to_binary("192.168.217.113", &ip4_a);
	ip_convert_to_binary("255.255.255.0",   &ip4_b);
	ip_mask_apply_OR(&ip4_a, &ip4_b, &ip4_c);
	return !strcmp(ip_convert_to_string(&ip4_c), "255.255.255.113");
});

EXO_TEST(ip4_bitwise_OR_3, {
	ip_convert_to_binary("192.168.217.113", &ip4_a);
	ip_convert_to_binary("255.255.0.0",     &ip4_b);
	ip_mask_apply_OR(&ip4_a, &ip4_b, &ip4_c);
	return !strcmp(ip_convert_to_string(&ip4_c), "255.255.217.113");
});

EXO_TEST(ip4_bitwise_OR_4, {
	ip_convert_to_binary("192.168.217.113", &ip4_a);
	ip_convert_to_binary("255.0.0.0",       &ip4_b);
	ip_mask_apply_OR(&ip4_a, &ip4_b, &ip4_c);
	return !strcmp(ip_convert_to_string(&ip4_c), "255.168.217.113");
});

EXO_TEST(ip4_bitwise_OR_5, {
	ip_convert_to_binary("192.168.217.113", &ip4_a);
	ip_convert_to_binary("0.0.0.0",         &ip4_b);
	ip_mask_apply_OR(&ip4_a, &ip4_b, &ip4_c);
	return !strcmp(ip_convert_to_string(&ip4_c), "192.168.217.113");
});

EXO_TEST(ip6_bitwise_AND_1, {
	if (!ipv6) return 1;
	ip_convert_to_binary("7f7f:ffff:ffff:3f3f:ffff:ffff:ffff:ffff", &ip6_a);
	ip_convert_to_binary("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0",    &ip6_b);
	ip_mask_apply_AND(&ip6_a, &ip6_b, &ip6_c);
	return  !strcmp(ip_convert_to_string(&ip6_c), "7f7f:ffff:ffff:3f3f:ffff:ffff:ffff:0") ||
			!strcmp(ip_convert_to_string(&ip6_c), "7f7f:ffff:ffff:3f3f:ffff:ffff:ffff::");
});

EXO_TEST(ip6_bitwise_AND_2, {
	if (!ipv6) return 1;
	ip_convert_to_binary("7777:cccc:3333:1111:ffff:ffff:ffff:ffff", &ip6_a);
	ip_convert_to_binary("ffff:ffff:ffff:ffff::",    &ip6_b);
	ip_mask_apply_AND(&ip6_a, &ip6_b, &ip6_c);
	return !strcmp(ip_convert_to_string(&ip6_c), "7777:cccc:3333:1111::");
});

EXO_TEST(ip6_bitwise_AND_3, {
	if (!ipv6) return 1;
	ip_convert_to_binary("7777:cccc:3333:1111:ffff:ffff:ffff:ffff", &ip6_a);
	ip_convert_to_binary("::",    &ip6_b);
	ip_mask_apply_AND(&ip6_a, &ip6_b, &ip6_c);
	return !strcmp(ip_convert_to_string(&ip6_c), "::");
});

EXO_TEST(ip6_bitwise_OR_1, {
	if (!ipv6) return 1;
	ip_convert_to_binary("7f7f:ffff:ffff:3f3f:ffff:ffff:ffff:ffff", &ip6_a);
	ip_convert_to_binary("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0",    &ip6_b);
	ip_mask_apply_OR(&ip6_a, &ip6_b, &ip6_c);
	return !strcmp(ip_convert_to_string(&ip6_c), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
});

EXO_TEST(ip6_bitwise_OR_2, {
	if (!ipv6) return 1;
	ip_convert_to_binary("7777:cccc:3333:1111:ffff:ffff:ffff:ffff", &ip6_a);
	ip_convert_to_binary("ffff:ffff:ffff:ffff:ffff:ffff:ffff:0",    &ip6_b);
	ip_mask_apply_OR(&ip6_a, &ip6_b, &ip6_c);
	return !strcmp(ip_convert_to_string(&ip6_c), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
});

EXO_TEST(ip6_bitwise_OR_3, {
	if (!ipv6) return 1;
	ip_convert_to_binary("7777:cccc:3333:1111:ffff:ffff:ffff:1c1c", &ip6_a);
	ip_convert_to_binary("::",    &ip6_b);
	ip_mask_apply_OR(&ip6_a, &ip6_b, &ip6_c);
	return !strcmp(ip_convert_to_string(&ip6_c), "7777:cccc:3333:1111:ffff:ffff:ffff:1c1c");
});

EXO_TEST(ip_range_1, {
	struct ip_range range; memset(&range, 0, sizeof(range));
	return ip_convert_address_to_range("192.168.0.1", &range) && memcmp(&range.lo, &range.hi, sizeof(struct ip_addr_encap)) == 0;
});

EXO_TEST(ip_range_2, {
	struct ip_range range; memset(&range, 0, sizeof(range));
	return ip_convert_address_to_range("192.168.0.0-192.168.255.255", &range) && range.lo.af == range.hi.af && memcmp(&range.lo, &range.hi, sizeof(struct ip_addr_encap)) != 0;
});

EXO_TEST(ip_range_3, {
	struct ip_range range; memset(&range, 0, sizeof(range));
	return ip_convert_address_to_range("192.168.0.0/24", &range) && range.lo.af == range.hi.af && memcmp(&range.lo, &range.hi, sizeof(struct ip_addr_encap)) != 0;
});

EXO_TEST(ip_range_4, {
	struct ip_range range1; memset(&range1, 0, sizeof(range1));
	struct ip_range range2; memset(&range2, 0, sizeof(range2));
	return ip_convert_address_to_range("192.168.0.0/24", &range1) && ip_convert_address_to_range("192.168.0.0-192.168.255.255", &range2) && memcmp(&range1, &range2, sizeof(struct ip_range)) == 0;
});


EXO_TEST(shutdown_network, {
    return net_destroy() == 0;
});
