#include "system.h"
#include "util/memory.h"
#include "core/link.h"

EXO_TEST(link_auth_response_len, {
	char out[LINK_AUTH_RESPONSE_LEN + 1];
	link_auth_response("s3cr3t", "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJK", out);
	return strlen(out) == LINK_AUTH_RESPONSE_LEN;
});

EXO_TEST(link_auth_response_deterministic, {
	char a[LINK_AUTH_RESPONSE_LEN + 1];
	char b[LINK_AUTH_RESPONSE_LEN + 1];
	link_auth_response("s3cr3t", "nonce123", a);
	link_auth_response("s3cr3t", "nonce123", b);
	return strcmp(a, b) == 0;
});

EXO_TEST(link_auth_response_nonce_sensitive, {
	char a[LINK_AUTH_RESPONSE_LEN + 1];
	char b[LINK_AUTH_RESPONSE_LEN + 1];
	link_auth_response("s3cr3t", "nonceAAA", a);
	link_auth_response("s3cr3t", "nonceBBB", b);
	return strcmp(a, b) != 0;
});

EXO_TEST(link_auth_response_secret_sensitive, {
	char a[LINK_AUTH_RESPONSE_LEN + 1];
	char b[LINK_AUTH_RESPONSE_LEN + 1];
	link_auth_response("secretA", "nonce", a);
	link_auth_response("secretB", "nonce", b);
	return strcmp(a, b) != 0;
});

EXO_TEST(link_auth_verify_accepts, {
	char resp[LINK_AUTH_RESPONSE_LEN + 1];
	link_auth_response("s3cr3t", "noncexyz", resp);
	return link_auth_verify("s3cr3t", "noncexyz", resp) == 1;
});

EXO_TEST(link_auth_verify_rejects_wrong_secret, {
	char resp[LINK_AUTH_RESPONSE_LEN + 1];
	link_auth_response("s3cr3t", "noncexyz", resp);
	return link_auth_verify("wrong", "noncexyz", resp) == 0;
});

EXO_TEST(link_auth_verify_rejects_wrong_nonce, {
	char resp[LINK_AUTH_RESPONSE_LEN + 1];
	link_auth_response("s3cr3t", "noncexyz", resp);
	return link_auth_verify("s3cr3t", "different", resp) == 0;
});

EXO_TEST(link_auth_verify_rejects_bad_length, {
	return link_auth_verify("s3cr3t", "nonce", "tooshort") == 0;
});

EXO_TEST(link_auth_verify_rejects_null, {
	return link_auth_verify("s3cr3t", "nonce", NULL) == 0;
});

EXO_TEST(link_make_nonce_format, {
	char n[LINK_NONCE_LEN + 1];
	int ok = link_make_nonce(n);
	return ok == 1 && strlen(n) == LINK_NONCE_LEN;
});

EXO_TEST(link_make_nonce_unique, {
	char a[LINK_NONCE_LEN + 1];
	char b[LINK_NONCE_LEN + 1];
	link_make_nonce(a);
	link_make_nonce(b);
	return strcmp(a, b) != 0;
});
