#include "system.h"
#include "core/probe.h"

/*
 * Unit tests for the pre-authentication protocol demux (probe_classify in
 * core/probe.c). This decides, from the first bytes peeked off a fresh
 * connection, whether it is TLS, ADC, a hub link, HTTP (metrics), or
 * unsupported -- attacker-controlled input on a brand-new socket, so the
 * classification is worth pinning down directly.
 */

EXO_TEST(probe_incomplete_short, { return probe_classify("HS", 2) == probe_protocol_incomplete; });
EXO_TEST(probe_incomplete_empty, { return probe_classify("", 0) == probe_protocol_incomplete; });

EXO_TEST(probe_adc_hsup, { return probe_classify("HSUP ADBASE ADTIGR\n", 19) == probe_protocol_adc; });
EXO_TEST(probe_adc_htcp, { return probe_classify("HTCP AAAA\n", 10) == probe_protocol_adc; });

EXO_TEST(probe_link_lcha, { return probe_classify("LCHA hub\n", 9) == probe_protocol_link; });

EXO_TEST(probe_http_get,  { return probe_classify("GET /metrics HTTP/1.1", 21) == probe_protocol_http; });
EXO_TEST(probe_http_post, { return probe_classify("POST / HTTP/1.1", 15) == probe_protocol_http; });
EXO_TEST(probe_http_head, { return probe_classify("HEAD / HTTP/1.1", 15) == probe_protocol_http; });

EXO_TEST(probe_unsupported, { return probe_classify("ABCD junk", 9) == probe_protocol_unsupported; });

/* The 4-byte prefixes are matched case-sensitively, so lowercase is not ADC. */
EXO_TEST(probe_case_sensitive, { return probe_classify("hsup rest", 9) == probe_protocol_unsupported; });

/* A well-formed TLS ClientHello record header: type 22, version 3.x, the
   handshake message type client_hello (1) at offset 5, version echoed at 9. */
EXO_TEST(probe_tls_clienthello, {
	unsigned char b[16];
	memset(b, 0, sizeof(b));
	b[0] = 22;
	b[1] = 3;
	b[5] = 1;
	b[9] = 3;
	return probe_classify((const char*) b, sizeof(b)) == probe_protocol_tls;
});

/* The TLS pattern needs 11 bytes; a shorter buffer cannot be classified as TLS
   and, matching no ASCII prefix, is unsupported. */
EXO_TEST(probe_tls_too_short, {
	unsigned char b[10];
	memset(b, 0, sizeof(b));
	b[0] = 22;
	b[1] = 3;
	b[5] = 1;
	b[9] = 3;
	return probe_classify((const char*) b, sizeof(b)) == probe_protocol_unsupported;
});

/* Wrong handshake message type (not client_hello) is not classified as TLS. */
EXO_TEST(probe_tls_wrong_type, {
	unsigned char b[16];
	memset(b, 0, sizeof(b));
	b[0] = 22;
	b[1] = 3;
	b[5] = 2; /* not client_hello */
	b[9] = 3;
	return probe_classify((const char*) b, sizeof(b)) == probe_protocol_unsupported;
});
