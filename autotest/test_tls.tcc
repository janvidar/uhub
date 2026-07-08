#include "system.h"
#include "network/tls.h"

/*
 * Unit tests for the TLS backend (network/openssl.c) -- the parts that do not
 * need a live handshake or the reactor: library init, provider string, SSL
 * context creation with tls_version/cipher enforcement, certificate/key
 * loading, and the ADC KEYP keyprint (SHA-256 of the DER certificate, base32).
 *
 * Uses a checked-in self-signed test certificate under autotest/. UHUB_TEST_DIR
 * is the absolute path to that directory, injected by CMake, so the fixtures
 * resolve regardless of the working directory. Cert loading and the keyprint do
 * not verify the certificate chain or expiry, so the fixture never goes stale.
 */

#define TLS_CERT UHUB_TEST_DIR "/tls-test-cert.pem"
#define TLS_KEY  UHUB_TEST_DIR "/tls-test-key.pem"
/* SHA-256 of the DER encoding of tls-test-cert.pem, base32 (RFC 4648). */
#define TLS_CERT_KEYPRINT "SHA256/7LTBHRI6DRARELTAMUCE3MXHGRZQRZHCIKYE4GHP4S3GV4LETMZQ"

/* A cipher list valid on both OpenSSL and LibreSSL (an empty list would make
   SSL_CTX_set_cipher_list fail and the context creation return NULL). */
#define TLS_CIPHERS "DEFAULT"

EXO_TEST(tls_library_init, { return net_ssl_library_init() == 1; });

EXO_TEST(tls_provider_nonempty, {
	const char* p = net_ssl_get_provider();
	return p && *p;
});

/* --- context creation + tls_version enforcement ------------------------- */

EXO_TEST(tls_ctx_version_1_2, {
	struct ssl_context_handle* c = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	int ok = (c != NULL);
	if (c) net_ssl_context_destroy(c);
	return ok;
});

EXO_TEST(tls_ctx_version_1_3, {
	struct ssl_context_handle* c = net_ssl_context_create("1.3", TLS_CIPHERS, "");
	int ok = (c != NULL);
	if (c) net_ssl_context_destroy(c);
	return ok;
});

/* TLS 1.0/1.1 are not selectable; empty/unknown versions are rejected. */
EXO_TEST(tls_ctx_version_1_1_rejected, {
	return net_ssl_context_create("1.1", TLS_CIPHERS, "") == NULL;
});
EXO_TEST(tls_ctx_version_empty_rejected, {
	return net_ssl_context_create("", TLS_CIPHERS, "") == NULL;
});
EXO_TEST(tls_ctx_version_junk_rejected, {
	return net_ssl_context_create("nope", TLS_CIPHERS, "") == NULL;
});

/* An unusable cipher list is rejected. */
EXO_TEST(tls_ctx_bad_cipher_rejected, {
	return net_ssl_context_create("1.2", "this-is-not-a-cipher", "") == NULL;
});

/* --- certificate / key loading ------------------------------------------ */

EXO_TEST(tls_load_cert_and_key, {
	struct ssl_context_handle* c = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	int ok = c
		&& ssl_load_certificate(c, TLS_CERT) == 1
		&& ssl_load_private_key(c, TLS_KEY) == 1
		&& ssl_check_private_key(c) == 1;
	if (c) net_ssl_context_destroy(c);
	return ok;
});

EXO_TEST(tls_load_cert_missing_file, {
	struct ssl_context_handle* c = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	int r = c ? ssl_load_certificate(c, UHUB_TEST_DIR "/no-such-cert.pem") : 1;
	if (c) net_ssl_context_destroy(c);
	return r == 0;
});

/* --- KEYP keyprint ------------------------------------------------------ */

EXO_TEST(tls_keyprint_exact, {
	struct ssl_context_handle* c = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	char kp[128];
	int ok = c
		&& ssl_load_certificate(c, TLS_CERT) == 1
		&& net_ssl_get_keyprint(c, kp, sizeof(kp)) == 1
		&& !strcmp(kp, TLS_CERT_KEYPRINT);
	if (c) net_ssl_context_destroy(c);
	return ok;
});

/* No certificate loaded -> keyprint fails cleanly (not a crash). */
EXO_TEST(tls_keyprint_no_cert, {
	struct ssl_context_handle* c = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	char kp[128];
	int r = c ? net_ssl_get_keyprint(c, kp, sizeof(kp)) : -1;
	if (c) net_ssl_context_destroy(c);
	return r == 0;
});

/* Output buffer too small for "SHA256/" + 52 chars -> fails, no truncation. */
EXO_TEST(tls_keyprint_small_buffer, {
	struct ssl_context_handle* c = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	char kp[8];
	int r = -1;
	if (c && ssl_load_certificate(c, TLS_CERT) == 1)
		r = net_ssl_get_keyprint(c, kp, sizeof(kp));
	if (c) net_ssl_context_destroy(c);
	return r == 0;
});
