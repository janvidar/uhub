#include "system.h"
#include "network/tls.h"
#include "network/network.h"
#include "network/connection.h"
#include "network/backend.h"
#include <sys/socket.h>

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
/* The same keyprint written in lower case: base32 and the hash name are both
   case-insensitive, so this must compare equal to the one above. */
#define TLS_CERT_KEYPRINT_LC "sha256/7ltbhri6drareltamuce3mxhgrzqrzhcikye4ghp4s3gv4letmzq"

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

/* --- outbound (client) certificate verification -------------------------- */

/* A DNS name is accepted as the identity the peer must present. */
EXO_TEST(tls_client_verify_hostname, {
	struct ssl_context_handle* c = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	int ok;
	if (!c) return 0;
	ok = net_ssl_context_set_client_verify(c, "images.example.org") == 1;
	net_ssl_context_destroy(c);
	return ok;
});

/* So is an IP literal, which is matched against the iPAddress SANs instead. */
EXO_TEST(tls_client_verify_ipv4_literal, {
	struct ssl_context_handle* c = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	int ok;
	if (!c) return 0;
	ok = net_ssl_context_set_client_verify(c, "192.0.2.10") == 1;
	net_ssl_context_destroy(c);
	return ok;
});

EXO_TEST(tls_client_verify_ipv6_literal, {
	struct ssl_context_handle* c = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	int ok;
	if (!c) return 0;
	ok = net_ssl_context_set_client_verify(c, "2001:db8::1") == 1;
	net_ssl_context_destroy(c);
	return ok;
});

/* Fails closed: with no identity there is nothing to verify against. */
EXO_TEST(tls_client_verify_requires_identity, {
	struct ssl_context_handle* c = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	int ok;
	if (!c) return 0;
	ok = net_ssl_context_set_client_verify(c, NULL) == 0
		&& net_ssl_context_set_client_verify(c, "") == 0;
	net_ssl_context_destroy(c);
	return ok;
});

EXO_TEST(tls_client_verify_null_context, {
	return net_ssl_context_set_client_verify(NULL, "example.org") == 0;
});

/* Setting it twice replaces the identity rather than leaking the first. */
EXO_TEST(tls_client_verify_replaces, {
	struct ssl_context_handle* c = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	int ok;
	if (!c) return 0;
	ok = net_ssl_context_set_client_verify(c, "a.example.org") == 1
		&& net_ssl_context_set_client_verify(c, "b.example.org") == 1;
	net_ssl_context_destroy(c);
	return ok;
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

/* --- keyprint comparison ------------------------------------------------ */

/* Base32 (and the hash name) are case-insensitive, so a keyprint copied out of
   a hub's config in either case pins the same certificate. */
EXO_TEST(tls_keyprint_equal_same_case, {
	return net_ssl_keyprint_equal(TLS_CERT_KEYPRINT, TLS_CERT_KEYPRINT) == 1;
});

EXO_TEST(tls_keyprint_equal_ignores_case, {
	return net_ssl_keyprint_equal(TLS_CERT_KEYPRINT, TLS_CERT_KEYPRINT_LC) == 1
		&& net_ssl_keyprint_equal(TLS_CERT_KEYPRINT_LC, TLS_CERT_KEYPRINT) == 1;
});

/* Only ASCII letters fold: the digits and the '/' must survive untouched, so a
   keyprint differing only in a digit is still a different keyprint. */
EXO_TEST(tls_keyprint_equal_digits_are_not_folded, {
	return net_ssl_keyprint_equal("SHA256/22222", "SHA256/22223") == 0;
});

/*
 * The comparison has no early exit to observe: a difference in the very first
 * character and a difference in the very last are both simply "not equal", and
 * the loop runs the full length either way. Position-independence is the
 * testable shape of the constant-time property.
 */
EXO_TEST(tls_keyprint_equal_difference_anywhere, {
	char first[128];
	char last[128];
	size_t len;

	snprintf(first, sizeof(first), "%s", TLS_CERT_KEYPRINT);
	snprintf(last, sizeof(last), "%s", TLS_CERT_KEYPRINT);
	len = strlen(first);

	/* 'S' -> 'T' and the trailing 'Q' -> 'R': both inside the base32/name
	   alphabet, so nothing but the position of the change differs. */
	first[0] = 'T';
	last[len - 1] = 'R';

	return net_ssl_keyprint_equal(first, TLS_CERT_KEYPRINT) == 0
		&& net_ssl_keyprint_equal(last, TLS_CERT_KEYPRINT) == 0
		&& net_ssl_keyprint_equal(TLS_CERT_KEYPRINT, first) == 0
		&& net_ssl_keyprint_equal(TLS_CERT_KEYPRINT, last) == 0;
});

/* A prefix is not a match, in either direction. */
EXO_TEST(tls_keyprint_equal_length_differs, {
	return net_ssl_keyprint_equal("SHA256/ABCD", "SHA256/ABC") == 0
		&& net_ssl_keyprint_equal("SHA256/ABC", "SHA256/ABCD") == 0;
});

/* Nothing compares equal to nothing: an absent keyprint is not a pass. */
EXO_TEST(tls_keyprint_equal_empty_and_null, {
	return net_ssl_keyprint_equal("", "") == 0
		&& net_ssl_keyprint_equal(NULL, TLS_CERT_KEYPRINT) == 0
		&& net_ssl_keyprint_equal(TLS_CERT_KEYPRINT, NULL) == 0
		&& net_ssl_keyprint_equal(NULL, NULL) == 0;
});

/* --- peer keyprint ------------------------------------------------------ */

EXO_TEST(tls_peer_keyprint_null_connection, {
	char kp[128];
	return net_ssl_get_peer_keyprint(NULL, kp, sizeof(kp)) == 0;
});

/* --- full handshake + encrypted round-trip ------------------------------ */

struct tls_ep { int connected; int error; };

/* net_ssl_callback forwards to this once the handshake completes (READ) or
   fails (ERROR); it is not called during the handshake itself. */
static void tls_hs_cb(struct net_connection* con, int events, void* ptr)
{
	struct tls_ep* ep = (struct tls_ep*) ptr;
	(void) con;
	if (events & (NET_EVENT_ERROR | NET_EVENT_TIMEOUT))
		ep->error = 1;
	else
		ep->connected = 1;
}

/*
 * Drive a real TLS handshake between two net_connections over a socketpair,
 * through the reactor, then send an encrypted message each way. Exercises the
 * handshake state machine (net_con_ssl_handshake / net_con_ssl_accept /
 * net_con_ssl_connect / net_ssl_callback) and net_ssl_send / net_ssl_recv --
 * the functional path the context/keyprint tests above do not reach.
 */
EXO_TEST(tls_handshake_and_data, {
	struct ssl_context_handle* sctx = 0;
	struct ssl_context_handle* cctx = 0;
	struct net_connection* scon = 0;
	struct net_connection* ccon = 0;
	struct tls_ep sep;
	struct tls_ep cep;
	int fds[2];
	int ok = 0;
	int i;
	char buf[64];
	const char* c2s = "client->server";
	const char* s2c = "server->client";
	ssize_t n;
	const char* ver;

	/* Brace initializers are avoided above: a top-level comma inside an
	   EXO_TEST() body would be parsed as a macro-argument separator. */
	memset(&sep, 0, sizeof(sep));
	memset(&cep, 0, sizeof(cep));
	fds[0] = -1;
	fds[1] = -1;

	if (net_initialize() != 0)
		return 0;

	sctx = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	cctx = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	if (!sctx || !cctx)
		goto done;
	if (ssl_load_certificate(sctx, TLS_CERT) != 1 || ssl_load_private_key(sctx, TLS_KEY) != 1)
		goto done;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		goto done;
	net_set_nonblocking(fds[0], 1);
	net_set_nonblocking(fds[1], 1);

	scon = net_con_create();
	ccon = net_con_create();
	if (!scon || !ccon)
		goto done;
	net_con_initialize(scon, fds[0], tls_hs_cb, &sep, NET_EVENT_READ);
	net_con_initialize(ccon, fds[1], tls_hs_cb, &cep, NET_EVENT_READ);
	fds[0] = fds[1] = -1; /* the connections own the descriptors now */

	net_con_ssl_handshake(scon, net_con_ssl_mode_server, sctx);
	net_con_ssl_handshake(ccon, net_con_ssl_mode_client, cctx);

	/* Pump until both ends finish the handshake (bounded so a regression that
	   never completes fails the assertion instead of hanging forever). */
	for (i = 0; i < 500 && !(sep.connected && cep.connected) && !sep.error && !cep.error; i++)
		net_backend_process();
	if (!(sep.connected && cep.connected))
		goto done;

	ver = net_ssl_get_tls_version(scon);
	if (!ver || strncmp(ver, "TLSv1.", 6) != 0)
		goto done;

	/* client -> server */
	if (net_ssl_send(ccon, c2s, strlen(c2s)) != (ssize_t) strlen(c2s))
		goto done;
	n = 0;
	for (i = 0; i < 500 && n <= 0; i++)
	{
		net_backend_process();
		n = net_ssl_recv(scon, buf, sizeof(buf));
	}
	if (n != (ssize_t) strlen(c2s) || memcmp(buf, c2s, strlen(c2s)) != 0)
		goto done;

	/* server -> client */
	if (net_ssl_send(scon, s2c, strlen(s2c)) != (ssize_t) strlen(s2c))
		goto done;
	n = 0;
	for (i = 0; i < 500 && n <= 0; i++)
	{
		net_backend_process();
		n = net_ssl_recv(ccon, buf, sizeof(buf));
	}
	if (n != (ssize_t) strlen(s2c) || memcmp(buf, s2c, strlen(s2c)) != 0)
		goto done;

	ok = 1;

done:
	/* net_con_close() defers the free; net_destroy() -> net_backend_shutdown()
	   -> net_cleanup_process() runs it. Pumping net_backend_process() here
	   instead would block: with no pending event the poll waits up to
	   TIMEOUT_QUEUE_MAX seconds. */
	if (scon) net_con_close(scon);
	if (ccon) net_con_close(ccon);
	if (fds[0] >= 0) close(fds[0]);
	if (fds[1] >= 0) close(fds[1]);
	if (sctx) net_ssl_context_destroy(sctx);
	if (cctx) net_ssl_context_destroy(cctx);
	net_destroy();
	return ok;
});

/*
 * The peer accessor over a real handshake: the client must fingerprint the
 * server's certificate to exactly the keyprint the server's own context
 * advertises, since that is the whole basis of pinning "?kp=" from a hub URL.
 * The server end of the same handshake asked for no client certificate, so it
 * must report 0 -- "no peer certificate" is not an empty string to compare
 * against but a failure to verify.
 */
EXO_TEST(tls_peer_keyprint_handshake, {
	struct ssl_context_handle* sctx = 0;
	struct ssl_context_handle* cctx = 0;
	struct net_connection* scon = 0;
	struct net_connection* ccon = 0;
	struct net_connection* plain = 0;
	struct tls_ep sep;
	struct tls_ep cep;
	int fds[2];
	int pfds[2];
	int ok = 0;
	int i;
	char kp[128];
	char small[8];

	memset(&sep, 0, sizeof(sep));
	memset(&cep, 0, sizeof(cep));
	fds[0] = fds[1] = -1;
	pfds[0] = pfds[1] = -1;

	if (net_initialize() != 0)
		return 0;

	sctx = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	cctx = net_ssl_context_create("1.2", TLS_CIPHERS, "");
	if (!sctx || !cctx)
		goto done;
	if (ssl_load_certificate(sctx, TLS_CERT) != 1 || ssl_load_private_key(sctx, TLS_KEY) != 1)
		goto done;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
		goto done;
	net_set_nonblocking(fds[0], 1);
	net_set_nonblocking(fds[1], 1);

	scon = net_con_create();
	ccon = net_con_create();
	if (!scon || !ccon)
		goto done;
	net_con_initialize(scon, fds[0], tls_hs_cb, &sep, NET_EVENT_READ);
	net_con_initialize(ccon, fds[1], tls_hs_cb, &cep, NET_EVENT_READ);
	fds[0] = fds[1] = -1;

	/* A connection that never handshakes has no peer certificate either. */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pfds) != 0)
		goto done;
	net_set_nonblocking(pfds[0], 1);
	plain = net_con_create();
	if (!plain)
		goto done;
	net_con_initialize(plain, pfds[0], tls_hs_cb, &sep, NET_EVENT_READ);
	pfds[0] = -1;
	if (net_ssl_get_peer_keyprint(plain, kp, sizeof(kp)) != 0)
		goto done;

	net_con_ssl_handshake(scon, net_con_ssl_mode_server, sctx);
	net_con_ssl_handshake(ccon, net_con_ssl_mode_client, cctx);

	for (i = 0; i < 500 && !(sep.connected && cep.connected) && !sep.error && !cep.error; i++)
		net_backend_process();
	if (!(sep.connected && cep.connected))
		goto done;

	/* What the client saw is what the server's context advertises. */
	if (net_ssl_get_peer_keyprint(ccon, kp, sizeof(kp)) != 1)
		goto done;
	if (strcmp(kp, TLS_CERT_KEYPRINT) != 0)
		goto done;
	if (!net_ssl_keyprint_equal(kp, TLS_CERT_KEYPRINT_LC))
		goto done;

	/* Too small for "SHA256/" + 52 characters: refused, never truncated (a
	   truncated keyprint would compare unequal and look like an attack). */
	if (net_ssl_get_peer_keyprint(ccon, small, sizeof(small)) != 0)
		goto done;

	/* No client certificate was requested or sent. */
	if (net_ssl_get_peer_keyprint(scon, kp, sizeof(kp)) != 0)
		goto done;

	ok = 1;

done:
	if (scon) net_con_close(scon);
	if (ccon) net_con_close(ccon);
	if (plain) net_con_close(plain);
	if (fds[0] >= 0) close(fds[0]);
	if (fds[1] >= 0) close(fds[1]);
	if (pfds[0] >= 0) close(pfds[0]);
	if (pfds[1] >= 0) close(pfds[1]);
	if (sctx) net_ssl_context_destroy(sctx);
	if (cctx) net_ssl_context_destroy(cctx);
	net_destroy();
	return ok;
});
