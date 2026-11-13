#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "system.h"
#include "util/memory.h"
#include "util/list.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "network/network.h"
#include "network/connection.h"
#include "core/auth.h"
#include "core/config.h"
#include "core/eventid.h"
#include "core/eventqueue.h"
#include "core/hub.h"
#include "core/link.h"
#include "core/pluginloader.h"
#include "core/route.h"
#include "core/user.h"
#include "core/usermanager.h"
#include "plugin_api/handle.h"
#include "testutil_net.h"
#include "testutil_user.h"

/*
 * The hub-to-hub link: its authentication primitives, the handshake state
 * machine on both sides, and every path that writes a field received from a
 * client or an operator onto the line-based link protocol.
 *
 * The handshake tests drive a real link over a socketpair: link_adopt() takes
 * one end, the test plays the peer on the other and calls net_con_callback()
 * after each line, so nothing here goes through the shared event loop. The
 * link announces LELC once established (this node is node 0), which is how a
 * test tells that the handshake completed; a refused peer sees the socket
 * close.
 */

#define LT_SECRET "s3cr3t"
#define LT_CLIENT_NONCE "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define LT_SERVER_NONCE "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
#define LT_OTHER_NONCE  "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"
#define LT_PEER_NONCE   "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA"
#define LT_CID          "GNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI"

/* -------------------------------------------------------------------------
 * Authentication primitives
 * ------------------------------------------------------------------------- */

EXO_TEST(link_auth_mutual, {
	char client[LINK_AUTH_RESPONSE_LEN + 1];
	char server[LINK_AUTH_RESPONSE_LEN + 1];
	link_auth_response(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, client);
	link_auth_response(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 0, server);
	return strlen(client) == LINK_AUTH_RESPONSE_LEN
		&& strlen(server) == LINK_AUTH_RESPONSE_LEN
		&& link_auth_verify(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, client)
		&& link_auth_verify(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 0, server);
});

EXO_TEST(link_auth_deterministic, {
	char a[LINK_AUTH_RESPONSE_LEN + 1];
	char b[LINK_AUTH_RESPONSE_LEN + 1];
	link_auth_response(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, a);
	link_auth_response(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, b);
	return strcmp(a, b) == 0;
});

/* The heart of the reflection fix: the two directions differ, so neither
   side's answer can be passed off as the other's. */
EXO_TEST(link_auth_rejects_reflection, {
	char server[LINK_AUTH_RESPONSE_LEN + 1];
	link_auth_response(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 0, server);
	return !link_auth_verify(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, server)
		&& !link_auth_verify(LT_SECRET, LT_SERVER_NONCE, LT_CLIENT_NONCE, 1, server)
		&& !link_auth_verify(LT_SECRET, LT_SERVER_NONCE, LT_CLIENT_NONCE, 0, server);
});

EXO_TEST(link_auth_binds_both_nonces, {
	char resp[LINK_AUTH_RESPONSE_LEN + 1];
	link_auth_response(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, resp);
	return !link_auth_verify(LT_SECRET, LT_OTHER_NONCE, LT_SERVER_NONCE, 1, resp)
		&& !link_auth_verify(LT_SECRET, LT_CLIENT_NONCE, LT_OTHER_NONCE, 1, resp);
});

EXO_TEST(link_auth_rejects_wrong_secret, {
	char resp[LINK_AUTH_RESPONSE_LEN + 1];
	link_auth_response(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, resp);
	return !link_auth_verify("wrong", LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, resp);
});

EXO_TEST(link_auth_rejects_bad_response, {
	return !link_auth_verify(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, NULL)
		&& !link_auth_verify(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, "tooshort")
		&& !link_auth_verify(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, "");
});

/* Invalid input yields no response at all, and nothing verifies against it --
   in particular an empty response must not match an empty expectation. */
EXO_TEST(link_auth_rejects_invalid_input, {
	char resp[LINK_AUTH_RESPONSE_LEN + 1];
	char out[LINK_AUTH_RESPONSE_LEN + 1];
	link_auth_response(LT_SECRET, LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, resp);
	link_auth_response("", LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, out);
	if (out[0]) return 0;
	link_auth_response(NULL, LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, out);
	if (out[0]) return 0;
	link_auth_response(LT_SECRET, LT_CLIENT_NONCE, LT_CLIENT_NONCE, 1, out);
	if (out[0]) return 0;
	return !link_auth_verify("", LT_CLIENT_NONCE, LT_SERVER_NONCE, 1, resp)
		&& !link_auth_verify(LT_SECRET, NULL, LT_SERVER_NONCE, 1, resp)
		&& !link_auth_verify(LT_SECRET, LT_CLIENT_NONCE, NULL, 1, resp)
		&& !link_auth_verify(LT_SECRET, "short", LT_SERVER_NONCE, 1, resp)
		&& !link_auth_verify(LT_SECRET, LT_CLIENT_NONCE, LT_CLIENT_NONCE, 1, resp);
});

EXO_TEST(link_nonce_valid_checks, {
	return link_nonce_valid(LT_CLIENT_NONCE)
		&& !link_nonce_valid(NULL)
		&& !link_nonce_valid("")
		&& !link_nonce_valid("AAAA")
		&& !link_nonce_valid(LT_CLIENT_NONCE "A")                     /* too long */
		&& !link_nonce_valid("aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")  /* lower case */
		&& !link_nonce_valid("1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")  /* not base32 */
		&& !link_nonce_valid("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ");
});

EXO_TEST(link_make_nonce_format, {
	char n[LINK_NONCE_LEN + 1];
	return link_make_nonce(n) == 1 && strlen(n) == LINK_NONCE_LEN && link_nonce_valid(n);
});

EXO_TEST(link_make_nonce_unique, {
	char a[LINK_NONCE_LEN + 1];
	char b[LINK_NONCE_LEN + 1];
	return link_make_nonce(a) && link_make_nonce(b) && strcmp(a, b) != 0;
});

/* -------------------------------------------------------------------------
 * A hub with linking enabled, and a peer on the far end of a socketpair
 * ------------------------------------------------------------------------- */

static struct hub_info* lt_hub = 0;

struct lt_peer
{
	int fd;                       /* our end */
	struct net_connection* con;   /* the link's end, owned by the link */
	int closed;                   /* the link closed its end */
	char out[8192];               /* everything the link sent us */
	size_t outlen;
};

static struct lt_peer lt_p = { -1, 0, 0, {0}, 0 };

static void lt_peer_close(void)
{
	if (lt_p.fd != -1)
		close(lt_p.fd);
	memset(&lt_p, 0, sizeof(lt_p));
	lt_p.fd = -1;
}

EXO_SETUP({
	if (!test_net_acquire())
		return 0;
	lt_hub = (struct hub_info*) hub_malloc_zero(sizeof(struct hub_info));
	if (!lt_hub)
		return 0;
	lt_hub->users = uman_init(0, 1);
	lt_hub->acl = (struct acl_handle*) hub_malloc_zero(sizeof(struct acl_handle));
	lt_hub->config = (struct hub_config*) hub_malloc_zero(sizeof(struct hub_config));
	if (!lt_hub->users || !lt_hub->acl || !lt_hub->config)
		return 0;
	config_defaults(lt_hub->config);
	acl_initialize(lt_hub->config, lt_hub->acl);
	lt_hub->write_queue = list_create();
	return lt_hub->write_queue != 0;
});

EXO_TEARDOWN({
	link_stop(lt_hub);
	lt_peer_close();
	if (lt_hub)
	{
		uman_shutdown(lt_hub->users);
		list_destroy(lt_hub->write_queue);
		acl_shutdown(lt_hub->acl);
		free_config(lt_hub->config);
		hub_free(lt_hub->acl);
		hub_free(lt_hub->config);
		hub_free(lt_hub);
		lt_hub = 0;
	}
	test_net_release();
	return 1;
});

/* The node_id the next lt_fresh() configures; a test that changes it puts the
   default back. */
static int lt_node_id = 0;

/* Every link test starts here: no links, a fresh ACL, no plugins, and the
   shared secret configured. */
static void lt_fresh(void)
{
	link_stop(lt_hub);
	lt_peer_close();
	lt_hub->plugins = NULL;
	acl_shutdown(lt_hub->acl);
	free_config(lt_hub->config);
	config_defaults(lt_hub->config);
	hub_free(lt_hub->config->link_secret);
	lt_hub->config->link_secret = hub_strdup(LT_SECRET);
	lt_hub->config->node_count = 2;
	lt_hub->config->node_id = lt_node_id;
	acl_initialize(lt_hub->config, lt_hub->acl);
	link_start(lt_hub);
}

/* Collect whatever the link has written; notice when it closes. */
static void lt_drain(void)
{
	for (;;)
	{
		ssize_t n;
		if (lt_p.outlen >= sizeof(lt_p.out) - 1)
			return;
		n = read(lt_p.fd, lt_p.out + lt_p.outlen, sizeof(lt_p.out) - 1 - lt_p.outlen);
		if (n > 0)
		{
			lt_p.outlen += (size_t) n;
			lt_p.out[lt_p.outlen] = 0;
			continue;
		}
		/* EOF, or a reset when the link closed with our data still unread. */
		if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
			lt_p.closed = 1;
		return;
	}
}

static void lt_clear(void)
{
	lt_p.outlen = 0;
	lt_p.out[0] = 0;
}

/* Hand a socketpair end to the link as the given side. */
static int lt_attach(int is_client)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return 0;
	net_set_nonblocking(sv[0], 1);
	fcntl(sv[1], F_SETFL, fcntl(sv[1], F_GETFL) | O_NONBLOCK);
	lt_p.fd = sv[1];
	lt_p.con = net_con_create();
	if (!lt_p.con)
		return 0;
	net_con_initialize(lt_p.con, sv[0], NULL, NULL, 0);
	if (!link_adopt(lt_hub, lt_p.con, is_client, "test-peer"))
		return 0;
	lt_drain();
	return 1;
}

/* Send one or more lines as the peer and let the link process them. */
static void lt_send(const char* data)
{
	if (lt_p.closed)
		return;
	if (write(lt_p.fd, data, strlen(data)) != (ssize_t) strlen(data))
		return;
	net_con_callback(lt_p.con, NET_EVENT_READ);
	lt_drain();
}

/* Find the first line the link sent that starts with prefix, and copy the
   rest of it (without the newline) to out. */
static int lt_find(const char* prefix, char* out, size_t outsz)
{
	const char* p = lt_p.out;
	size_t plen = strlen(prefix);
	while (p && *p)
	{
		const char* nl = strchr(p, '\n');
		size_t len = nl ? (size_t) (nl - p) : strlen(p);
		if (len >= plen && !strncmp(p, prefix, plen))
		{
			size_t rest = len - plen;
			if (out)
			{
				if (rest >= outsz)
					rest = outsz - 1;
				memcpy(out, p + plen, rest);
				out[rest] = 0;
			}
			return 1;
		}
		p = nl ? nl + 1 : NULL;
	}
	return 0;
}

static int lt_established(void)
{
	/* An electing or coordinating node announces LELC once established; a
	   static member (node_id > 0) announces nothing, so its LACK is the sign. */
	if (lt_hub->config->node_id > 0)
		return !lt_p.closed && lt_find("LACK", NULL, 0);
	return !lt_p.closed && lt_find("LELC ", NULL, 0);
}

static void lt_sendf(const char* fmt, const char* a)
{
	char line[256];
	snprintf(line, sizeof(line), fmt, a);
	lt_send(line);
}

/* The hub accepts the connection; the test is the connecting peer. Adds a
   link to whatever is already there. */
static int lt_server_handshake_add(void)
{
	char server_nonce[LINK_NONCE_LEN + 8];
	char resp[LINK_AUTH_RESPONSE_LEN + 8];
	char expect[LINK_AUTH_RESPONSE_LEN + 1];

	if (!lt_attach(0) || !lt_find("LCHA ", server_nonce, sizeof(server_nonce)))
		return 0;
	lt_sendf("LCHA %s\n", LT_CLIENT_NONCE);
	link_auth_response(LT_SECRET, LT_CLIENT_NONCE, server_nonce, 0, expect);
	if (!lt_find("LRES ", resp, sizeof(resp)) || strcmp(resp, expect))
		return 0;
	link_auth_response(LT_SECRET, LT_CLIENT_NONCE, server_nonce, 1, resp);
	lt_sendf("LRES %s\n", resp);
	if (!lt_find("LACK", NULL, 0))
		return 0;
	lt_send("LACK\n");
	if (!lt_established())
		return 0;
	lt_clear();
	return 1;
}

static int lt_server_handshake(void)
{
	lt_fresh();
	return lt_server_handshake_add();
}

/* Exchange the current peer with another, to drive two links at once. */
static void lt_swap(struct lt_peer* other)
{
	struct lt_peer tmp = lt_p;
	lt_p = *other;
	*other = tmp;
}

/* The hub opened the connection; the test is the accepting peer. Adds a link
   to whatever is already there. */
static int lt_client_handshake_add(void)
{
	char client_nonce[LINK_NONCE_LEN + 8];
	char resp[LINK_AUTH_RESPONSE_LEN + 8];
	char expect[LINK_AUTH_RESPONSE_LEN + 1];

	if (!lt_attach(1) || !lt_find("LCHA ", client_nonce, sizeof(client_nonce)))
		return 0;
	lt_sendf("LCHA %s\n", LT_PEER_NONCE);
	link_auth_response(LT_SECRET, client_nonce, LT_PEER_NONCE, 1, expect);
	if (!lt_find("LRES ", resp, sizeof(resp)) || strcmp(resp, expect))
		return 0;
	link_auth_response(LT_SECRET, client_nonce, LT_PEER_NONCE, 0, resp);
	lt_sendf("LRES %s\n", resp);
	if (!lt_find("LACK", NULL, 0))
		return 0;
	lt_send("LACK\n");
	if (!lt_established())
		return 0;
	lt_clear();
	return 1;
}

static int lt_client_handshake(void)
{
	lt_fresh();
	return lt_client_handshake_add();
}

/* -------------------------------------------------------------------------
 * Handshake
 * ------------------------------------------------------------------------- */

EXO_TEST(link_hs_server_established, { return lt_server_handshake(); });
EXO_TEST(link_hs_client_established, { return lt_client_handshake(); });

EXO_TEST(link_hs_no_secret_rejected, {
	int sv[2];
	struct net_connection* con;
	int taken;
	lt_fresh();
	hub_free(lt_hub->config->link_secret);
	lt_hub->config->link_secret = hub_strdup("");
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return 0;
	con = net_con_create();
	net_con_initialize(con, sv[0], NULL, NULL, 0);
	taken = link_adopt(lt_hub, con, 0, "test-peer");
	if (!taken)
		net_con_close(con);
	close(sv[1]);
	return taken == 0;
});

/* Issue #127: echoing the hub's own challenge back at it. */
EXO_TEST(link_hs_own_challenge_rejected, {
	char server_nonce[LINK_NONCE_LEN + 8];
	lt_fresh();
	if (!lt_attach(0) || !lt_find("LCHA ", server_nonce, sizeof(server_nonce)))
		return 0;
	lt_sendf("LCHA %s\n", server_nonce);
	return lt_p.closed && !lt_find("LRES ", NULL, 0);
});

/* Issue #127 exactly as reported: a first, arbitrary challenge, then the hub's
   own one to make it compute the answer to its own challenge. */
EXO_TEST(link_hs_second_challenge_rejected, {
	char server_nonce[LINK_NONCE_LEN + 8];
	lt_fresh();
	if (!lt_attach(0) || !lt_find("LCHA ", server_nonce, sizeof(server_nonce)))
		return 0;
	lt_sendf("LCHA %s\n", LT_CLIENT_NONCE);
	if (lt_p.closed)
		return 0;
	lt_clear();
	lt_sendf("LCHA %s\n", server_nonce);
	return lt_p.closed && !lt_find("LRES ", NULL, 0);
});

/* The hub's own answer, played back to it, is for the wrong role. */
EXO_TEST(link_hs_reflected_response_rejected, {
	char resp[LINK_AUTH_RESPONSE_LEN + 8];
	lt_fresh();
	if (!lt_attach(0))
		return 0;
	lt_sendf("LCHA %s\n", LT_CLIENT_NONCE);
	if (!lt_find("LRES ", resp, sizeof(resp)))
		return 0;
	lt_sendf("LRES %s\n", resp);
	lt_send("LACK\n");
	return lt_p.closed && lt_find("LERR", NULL, 0) && !lt_find("LACK", NULL, 0)
		&& !lt_find("LELC ", NULL, 0);
});

/* The same two reflections against the side that opened the connection. */
EXO_TEST(link_hs_client_own_challenge_rejected, {
	char client_nonce[LINK_NONCE_LEN + 8];
	lt_fresh();
	if (!lt_attach(1) || !lt_find("LCHA ", client_nonce, sizeof(client_nonce)))
		return 0;
	lt_sendf("LCHA %s\n", client_nonce);
	return lt_p.closed && !lt_find("LRES ", NULL, 0);
});

EXO_TEST(link_hs_client_reflected_response_rejected, {
	char resp[LINK_AUTH_RESPONSE_LEN + 8];
	lt_fresh();
	if (!lt_attach(1))
		return 0;
	lt_sendf("LCHA %s\n", LT_PEER_NONCE);
	if (!lt_find("LRES ", resp, sizeof(resp)))
		return 0;
	lt_sendf("LRES %s\n", resp);
	return lt_p.closed && lt_find("LERR", NULL, 0) && !lt_find("LACK", NULL, 0);
});

EXO_TEST(link_hs_wrong_secret_rejected, {
	char server_nonce[LINK_NONCE_LEN + 8];
	char resp[LINK_AUTH_RESPONSE_LEN + 1];
	lt_fresh();
	if (!lt_attach(0) || !lt_find("LCHA ", server_nonce, sizeof(server_nonce)))
		return 0;
	lt_sendf("LCHA %s\n", LT_CLIENT_NONCE);
	link_auth_response("wrong", LT_CLIENT_NONCE, server_nonce, 1, resp);
	lt_sendf("LRES %s\n", resp);
	return lt_p.closed && lt_find("LERR", NULL, 0);
});

EXO_TEST(link_hs_malformed_challenge_rejected, {
	lt_fresh();
	if (!lt_attach(0))
		return 0;
	lt_send("LCHA short\n");
	return lt_p.closed && !lt_find("LRES ", NULL, 0);
});

EXO_TEST(link_hs_lowercase_challenge_rejected, {
	lt_fresh();
	if (!lt_attach(0))
		return 0;
	lt_send("LCHA aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
	return lt_p.closed;
});

/* An answer is meaningless before the peer's challenge: the response binds
   both nonces, so there is nothing yet to check it against. */
EXO_TEST(link_hs_response_before_challenge_rejected, {
	char server_nonce[LINK_NONCE_LEN + 8];
	char resp[LINK_AUTH_RESPONSE_LEN + 1];
	lt_fresh();
	if (!lt_attach(0) || !lt_find("LCHA ", server_nonce, sizeof(server_nonce)))
		return 0;
	link_auth_response(LT_SECRET, LT_CLIENT_NONCE, server_nonce, 1, resp);
	lt_sendf("LRES %s\n", resp);
	return lt_p.closed && lt_find("LERR", NULL, 0);
});

EXO_TEST(link_hs_ack_before_response_rejected, {
	lt_fresh();
	if (!lt_attach(0))
		return 0;
	lt_sendf("LCHA %s\n", LT_CLIENT_NONCE);
	lt_send("LACK\n");
	return lt_p.closed && !lt_find("LACK", NULL, 0);
});

EXO_TEST(link_hs_duplicate_response_rejected, {
	char server_nonce[LINK_NONCE_LEN + 8];
	char resp[LINK_AUTH_RESPONSE_LEN + 1];
	lt_fresh();
	if (!lt_attach(0) || !lt_find("LCHA ", server_nonce, sizeof(server_nonce)))
		return 0;
	lt_sendf("LCHA %s\n", LT_CLIENT_NONCE);
	link_auth_response(LT_SECRET, LT_CLIENT_NONCE, server_nonce, 1, resp);
	lt_sendf("LRES %s\n", resp);
	if (lt_p.closed || !lt_find("LACK", NULL, 0))
		return 0;
	lt_sendf("LRES %s\n", resp);
	return lt_p.closed;
});

EXO_TEST(link_hs_peer_error_closes, {
	lt_fresh();
	if (!lt_attach(0))
		return 0;
	lt_send("LERR\n");
	return lt_p.closed;
});

EXO_TEST(link_hs_unknown_message_closes, {
	lt_fresh();
	if (!lt_attach(0))
		return 0;
	lt_send("LXYZ\n");
	return lt_p.closed;
});

/* An established-only command before authentication closes the link. */
EXO_TEST(link_hs_command_before_auth_closes, {
	lt_fresh();
	if (!lt_attach(0))
		return 0;
	lt_send("LUBN victim\n");
	return lt_p.closed;
});

/* After establishment the handshake is over: no challenge is answered (an
   answering oracle on a live link), and no handshake message is accepted. */
EXO_TEST(link_hs_challenge_after_established_closes, {
	if (!lt_server_handshake())
		return 0;
	lt_sendf("LCHA %s\n", LT_OTHER_NONCE);
	return lt_p.closed && !lt_find("LRES ", NULL, 0);
});

EXO_TEST(link_hs_ack_after_established_closes, {
	if (!lt_server_handshake())
		return 0;
	lt_send("LACK\n");
	return lt_p.closed;
});

/* Starting the link layer again replaces what was there: the old link is
   dropped (not leaked), and a new one can still be established. A second
   hub_start_service() in the same process does exactly this. */
EXO_TEST(link_restart_replaces_state, {
	if (!lt_server_handshake())
		return 0;
	link_start(lt_hub);
	lt_drain();
	if (!lt_p.closed)
		return 0;
	lt_peer_close();
	return lt_server_handshake_add();
});

EXO_TEST(link_hs_oversized_line_closes, {
	char big[1100];
	lt_fresh();
	if (!lt_attach(0))
		return 0;
	memset(big, 'A', sizeof(big) - 1);
	big[sizeof(big) - 1] = 0;
	lt_send(big);
	return lt_p.closed;
});

/* -------------------------------------------------------------------------
 * Nothing may put a CR/LF inside a link line (issues #128, #129)
 * ------------------------------------------------------------------------- */

/* Issue #129: !unban hands its argument to the link as the rest of a line. */
EXO_TEST(link_unban_crlf_not_sent, {
	if (!lt_server_handshake())
		return 0;
	link_broadcast_unban(lt_hub, "victim\nLBAN 0 " LT_CID " Admin x");
	link_broadcast_unban(lt_hub, "victim\rLBAN 0 " LT_CID " Admin x");
	link_broadcast_unban(lt_hub, "");
	link_broadcast_unban(lt_hub, NULL);
	lt_drain();
	return lt_p.outlen == 0 && !lt_p.closed;
});

EXO_TEST(link_unban_sent, {
	if (!lt_server_handshake())
		return 0;
	link_broadcast_unban(lt_hub, "Two Words");
	lt_drain();
	return !strcmp(lt_p.out, "LUBN Two Words\n");
});

EXO_TEST(link_description_crlf_not_sent, {
	if (!lt_server_handshake())
		return 0;
	link_broadcast_description(lt_hub, "topic\nLUBN victim");
	link_broadcast_description(lt_hub, NULL);
	lt_drain();
	if (lt_p.outlen)
		return 0;
	link_broadcast_description(lt_hub, "new\\stopic");
	lt_drain();
	return !strcmp(lt_p.out, "LDSC new\\stopic\n");
});

/* The ban reason may contain anything; a CR/LF in it becomes a space. */
EXO_TEST(link_ban_reason_crlf_flattened, {
	if (!lt_server_handshake())
		return 0;
	link_broadcast_ban(lt_hub, LT_CID, "victim", 0, "bad\nLUBN x\rmore");
	lt_drain();
	return !strcmp(lt_p.out, "LBAN 0 " LT_CID " victim bad LUBN x more\n");
});

/* A nick may contain spaces; sent bare it would shift the field boundary and
   ban "Admin" on the peer instead of "Admin x". */
EXO_TEST(link_ban_nick_escaped, {
	if (!lt_server_handshake())
		return 0;
	link_broadcast_ban(lt_hub, LT_CID, "Admin x", 0, "reason here");
	lt_drain();
	return !strcmp(lt_p.out, "LBAN 0 " LT_CID " Admin\\sx reason here\n");
});

EXO_TEST(link_ban_nick_received, {
	if (!lt_server_handshake())
		return 0;
	lt_send("LBAN 0 " LT_CID " Admin\\sx because\n");
	return !lt_p.closed
		&& acl_is_user_banned(lt_hub->acl, "Admin x")
		&& !acl_is_user_banned(lt_hub->acl, "Admin")
		&& acl_is_cid_banned(lt_hub->acl, LT_CID);
});

/* An over-long field is not cut down to size: a truncated CID or nick would
   name somebody else. The ban is dropped; the link stays up. */
EXO_TEST(link_ban_overlong_ignored, {
	char nick[MAX_NICK_LEN + 2];
	char line[256];
	if (!lt_server_handshake())
		return 0;
	lt_send("LBAN 0 " LT_CID "X victim reason\n");
	if (lt_p.closed || acl_is_cid_banned(lt_hub->acl, LT_CID) || acl_is_user_banned(lt_hub->acl, "victim"))
		return 0;
	memset(nick, 'n', sizeof(nick) - 1);
	nick[sizeof(nick) - 1] = 0;
	snprintf(line, sizeof(line), "LBAN 0 %s %s reason\n", LT_CID, nick);
	lt_send(line);
	nick[MAX_NICK_LEN] = 0;
	return !lt_p.closed && !acl_is_cid_banned(lt_hub->acl, LT_CID)
		&& !acl_is_user_banned(lt_hub->acl, nick);
});

/* A routed message is a whole ADC line; one that somehow holds a second line
   is refused rather than passed through. */
EXO_TEST(link_route_one_line_only, {
	struct hub_link* link;
	struct adc_message* msg;
	if (!lt_server_handshake())
		return 0;
	link = (struct hub_link*) net_con_get_ptr(lt_p.con);
	msg = adc_msg_create("EMSG AAAB AAAC hello\n");
	if (!msg || !msg->cache || msg->length < 10)
		return 0;
	link_forward_message(link, msg);
	lt_drain();
	if (strcmp(lt_p.out, "LRTE EMSG AAAB AAAC hello\n"))
	{
		adc_msg_free(msg);
		return 0;
	}
	lt_clear();
	msg->cache[9] = '\n'; /* "EMSG AAAB\nAAAC hello\n" */
	link_forward_message(link, msg);
	adc_msg_free(msg);
	lt_drain();
	return lt_p.outlen == 0 && !lt_p.closed;
});

/* -------------------------------------------------------------------------
 * Master-slave auth over the link, slave side (issue #128)
 * ------------------------------------------------------------------------- */

static struct hub_user lt_user;

static struct hub_user* lt_pending_user(void)
{
	memset(&lt_user, 0, sizeof(lt_user));
	lt_user.id.sid = string_to_sid("AAAB");
	return &lt_user;
}

/* No master link: nothing to ask, the caller logs in locally. */
EXO_TEST(link_acq_no_master, {
	lt_fresh();
	return link_auth_query(lt_hub, lt_pending_user(), "nick") == 0;
});

/* A link we accepted is not a master; only one we opened is. */
EXO_TEST(link_acq_inbound_not_master, {
	if (!lt_server_handshake())
		return 0;
	return link_auth_query(lt_hub, lt_pending_user(), "nick") == 0;
});

EXO_TEST(link_acq_sent, {
	struct hub_user* u;
	int sent;
	if (!lt_client_handshake())
		return 0;
	u = lt_pending_user();
	sent = link_auth_query(lt_hub, u, "Good Nick");
	link_auth_pending_forget(u);
	lt_drain();
	return sent == 1 && !strcmp(lt_p.out, "LACQ AAAB Good Nick\n");
});

EXO_TEST(link_acq_crlf_not_sent, {
	struct hub_user* u;
	int sent;
	if (!lt_client_handshake())
		return 0;
	u = lt_pending_user();
	sent = link_auth_query(lt_hub, u, "evil\nLUBN victim")
		+ link_auth_query(lt_hub, u, "evil\rLUBN victim")
		+ link_auth_query(lt_hub, u, "")
		+ link_auth_query(lt_hub, u, NULL);
	link_auth_pending_forget(u);
	lt_drain();
	return sent == 0 && lt_p.outlen == 0 && !lt_p.closed;
});

/* The longest nick still fits an LVFY line (it did not, in a 128-byte buffer:
   the request was dropped and the login hung). */
EXO_TEST(link_vfy_long_nick_sent, {
	const char* chal = "CHALLENGECHALLENGECHALLENGECHALLENGECHA";
	const char* resp = "RESPONSERESPONSERESPONSERESPONSERESPONS";
	struct hub_user* u;
	char expect[256];
	int sent;
	if (!lt_client_handshake())
		return 0;
	u = lt_pending_user();
	memset(u->id.nick, 'n', MAX_NICK_LEN);
	u->id.nick[MAX_NICK_LEN] = 0;
	sent = link_auth_proxy_verify(lt_hub, u, chal, resp);
	link_auth_pending_forget(u);
	lt_drain();
	snprintf(expect, sizeof(expect), "LVFY AAAB %s %s %s\n", chal, resp, u->id.nick);
	return sent == 1 && !strcmp(lt_p.out, expect);
});

/* The response is a middle field: a space would shift the nick, a CR/LF would
   inject. Either way it is not sent, and the login fails rather than waits. */
EXO_TEST(link_vfy_bad_response_not_sent, {
	struct hub_user* u;
	int sent;
	if (!lt_client_handshake())
		return 0;
	u = lt_pending_user();
	strcpy(u->id.nick, "nick");
	sent = link_auth_proxy_verify(lt_hub, u, "CHAL", "RE SP")
		+ link_auth_proxy_verify(lt_hub, u, "CHAL", "RESP\nLUBN victim")
		+ link_auth_proxy_verify(lt_hub, u, "CH\nAL", "RESP")
		+ link_auth_proxy_verify(lt_hub, u, NULL, "RESP")
		+ link_auth_proxy_verify(lt_hub, u, "CHAL", NULL);
	link_auth_pending_forget(u);
	lt_drain();
	return sent == 0 && lt_p.outlen == 0;
});

/* -------------------------------------------------------------------------
 * hub_apply_unban (issue #129)
 * ------------------------------------------------------------------------- */

static struct ban_info lt_unban_record;
static int lt_unban_calls;

static plugin_st lt_capture_unban(struct plugin_handle* plugin, const struct ban_info* ban)
{
	(void) plugin;
	lt_unban_record = *ban;
	lt_unban_calls++;
	return st_allow;
}

/* Run hub_apply_unban against a storage plugin that records what it was
   asked to delete. */
static int lt_unban(const char* target, int propagate)
{
	struct uhub_plugins plugins;
	struct plugin_handle plugin;
	int removed;
	memset(&plugins, 0, sizeof(plugins));
	memset(&plugin, 0, sizeof(plugin));
	memset(&lt_unban_record, 0, sizeof(lt_unban_record));
	lt_unban_calls = 0;
	plugins.loaded = list_create();
	if (!plugins.loaded)
		return -1;
	plugin.funcs.auth_ban_del = lt_capture_unban;
	list_append(plugins.loaded, &plugin);
	lt_hub->plugins = &plugins;
	removed = hub_apply_unban(lt_hub, target, propagate);
	lt_hub->plugins = NULL;
	list_clear(plugins.loaded, NULL);
	list_destroy(plugins.loaded);
	return removed;
}

/* Nothing is deleted, locally or in storage, and nothing propagates. */
EXO_TEST(link_unban_rejects_line_breaks, {
	if (!lt_server_handshake())
		return 0;
	acl_ban_add(lt_hub->acl, LT_CID, NULL, 0, NULL);
	if (lt_unban(LT_CID "\nLBAN 0 " LT_CID " Admin x", 1) != 0 || lt_unban_calls)
		return 0;
	if (lt_unban(LT_CID "\rLBAN 0 " LT_CID " Admin x", 1) != 0 || lt_unban_calls)
		return 0;
	lt_drain();
	return lt_p.outlen == 0 && acl_is_cid_banned(lt_hub->acl, LT_CID);
});

/* A target one character longer than a CID is not that CID. */
EXO_TEST(link_unban_does_not_truncate_cid, {
	lt_fresh();
	acl_ban_add(lt_hub->acl, LT_CID, NULL, 0, NULL);
	lt_unban(LT_CID "X", 0);
	return lt_unban_calls == 1
		&& lt_unban_record.flags == ban_nickname
		&& !strcmp(lt_unban_record.nickname, LT_CID "X")
		&& !lt_unban_record.cid[0]
		&& acl_is_cid_banned(lt_hub->acl, LT_CID);
});

EXO_TEST(link_unban_does_not_truncate_nick, {
	char target[MAX_NICK_LEN + 2];
	lt_fresh();
	memset(target, 'x', sizeof(target) - 1);
	target[sizeof(target) - 1] = 0;
	return lt_unban(target, 0) == 0 && lt_unban_calls == 0;
});

EXO_TEST(link_unban_exact_cid, {
	lt_fresh();
	acl_ban_add(lt_hub->acl, LT_CID, NULL, 0, NULL);
	return lt_unban(LT_CID, 0) > 0 && lt_unban_calls == 1
		&& lt_unban_record.flags == (ban_nickname | ban_cid)
		&& !strcmp(lt_unban_record.cid, LT_CID)
		&& !acl_is_cid_banned(lt_hub->acl, LT_CID);
});

/* Not base32, so not offered as a CID even at CID length. */
EXO_TEST(link_unban_cid_length_nick, {
	const char* target = "abcdefghijklmnopqrstuvwxyzabcdefghijklm";
	lt_fresh();
	lt_unban(target, 0);
	return strlen(target) == MAX_CID_LEN && lt_unban_calls == 1
		&& lt_unban_record.flags == ban_nickname;
});

EXO_TEST(link_unban_nick_with_spaces_propagates, {
	if (!lt_server_handshake())
		return 0;
	acl_ban_add(lt_hub->acl, NULL, "Two Words", 0, NULL);
	if (lt_unban("Two Words", 1) <= 0 || lt_unban_calls != 1
		|| lt_unban_record.flags != ban_nickname
		|| strcmp(lt_unban_record.nickname, "Two Words"))
		return 0;
	lt_drain();
	return !strcmp(lt_p.out, "LUBN Two Words\n")
		&& !acl_is_user_banned(lt_hub->acl, "Two Words");
});

/* -------------------------------------------------------------------------
 * A peer speaks only for what it owns
 * ------------------------------------------------------------------------- */

#define LT_REMOTE_INF "LINF BINF AAAD IDBN7ZMSLIEBL53OPTM7WXGSTXUS3XOY6KQS5LBGX NIremote\n"

/* Local users AAAB (the recipient) and AAAE (an operator), routable by SID. */
static struct hub_user* lt_local_target = 0;
static struct hub_user* lt_local_op = 0;

static int lt_add_local_users(void)
{
	lt_local_target = tu_user_create(lt_hub, string_to_sid("AAAB"), "target",
		"AN7ZMSLIEBL53OPTM7WXGSTXUS3XOY6KQS5LBGX", auth_cred_user);
	lt_local_op = tu_user_create(lt_hub, string_to_sid("AAAE"), "operator",
		"CN7ZMSLIEBL53OPTM7WXGSTXUS3XOY6KQS5LBGX", auth_cred_operator);
	if (!lt_local_target || !lt_local_op
		|| !sid_pool_insert(lt_hub->users->sids, lt_local_target->id.sid, lt_local_target)
		|| !sid_pool_insert(lt_hub->users->sids, lt_local_op->id.sid, lt_local_op))
		return 0;
	uman_add(lt_hub->users, lt_local_target);
	uman_add(lt_hub->users, lt_local_op);
	return 1;
}

/* Whether a queued line for the user starts with prefix (a relayed DMSG may
   have gained a timestamp). */
static int lt_queued(struct hub_user* user, const char* prefix)
{
	size_t i;
	for (i = 0; i < tu_queue_count(user); i++)
	{
		const char* line = tu_queue_line(user, i);
		if (line && !strncmp(line, prefix, strlen(prefix)))
			return 1;
	}
	return 0;
}

static void lt_remove_local_users(void)
{
	struct hub_user** u[] = { &lt_local_target, &lt_local_op };
	size_t i;
	for (i = 0; i < sizeof(u) / sizeof(u[0]); i++)
	{
		if (!*u[i])
			continue;
		sid_free(lt_hub->users->sids, (*u[i])->id.sid);
		uman_remove(lt_hub->users, *u[i]);
		tu_user_destroy(*u[i]);
		*u[i] = 0;
	}
}

/* A message from a remote user the peer told us about is delivered... */
EXO_TEST(link_route_from_owned_user_delivered, {
	int ok;
	if (!lt_server_handshake() || !lt_add_local_users())
	{
		lt_remove_local_users();
		return 0;
	}
	lt_send(LT_REMOTE_INF);
	lt_send("LRTE DMSG AAAD AAAB hello\n");
	ok = !lt_p.closed && lt_queued(lt_local_target, "DMSG AAAD AAAB hello");
	link_stop(lt_hub); /* drops the remote user while the local ones exist */
	lt_remove_local_users();
	return ok;
});

/* ... but one claiming to come from one of our own users is not: the peer
   would be putting words in a local operator's mouth. */
EXO_TEST(link_route_spoofed_local_sender_dropped, {
	int ok;
	if (!lt_server_handshake() || !lt_add_local_users())
	{
		lt_remove_local_users();
		return 0;
	}
	lt_send("LRTE DMSG AAAE AAAB unblock\n");
	ok = !lt_p.closed && !lt_queued(lt_local_target, "DMSG");
	lt_remove_local_users();
	return ok;
});

/* Nor one from a user another link owns. */
EXO_TEST(link_route_other_links_user_dropped, {
	struct lt_peer first;
	int ok;
	memset(&first, 0, sizeof(first));
	first.fd = -1;
	if (!lt_server_handshake() || !lt_add_local_users())
	{
		lt_remove_local_users();
		return 0;
	}
	lt_send(LT_REMOTE_INF);          /* AAAD belongs to the first link */
	lt_swap(&first);
	if (!lt_server_handshake_add())
		ok = 0;
	else
	{
		lt_send("LRTE DMSG AAAD AAAB hello\n");
		ok = !lt_p.closed && !lt_queued(lt_local_target, "DMSG");
	}
	link_stop(lt_hub);
	lt_remove_local_users();
	if (first.fd != -1)
		close(first.fd);
	return ok;
});

/* A description is one escaped token; a space would add fields to the hub
   INF that every client receives. */
EXO_TEST(link_description_with_space_ignored, {
	char* de;
	int ok;
	if (!lt_server_handshake())
		return 0;
	lt_hub->command_info = adc_msg_create("IINF DEold\n");
	if (!lt_hub->command_info)
		return 0;
	lt_send("LDSC evil CT32 OP1\n");
	de = adc_msg_get_named_argument(lt_hub->command_info, ADC_INF_FLAG_DESCRIPTION);
	ok = !lt_p.closed && de && !strcmp(de, "old")
		&& !adc_msg_has_named_argument(lt_hub->command_info, "CT");
	hub_free(de);
	if (ok)
	{
		lt_send("LDSC new\\stopic\n");
		de = adc_msg_get_named_argument(lt_hub->command_info, ADC_INF_FLAG_DESCRIPTION);
		ok = de && !strcmp(de, "new\\stopic");
		hub_free(de);
	}
	adc_msg_free(lt_hub->command_info);
	lt_hub->command_info = 0;
	return ok;
});

/* Only the auth master answers for a pending login. A reply from any other
   peer -- here one that connected to us -- is ignored, and the master's real
   answer still settles it. */
EXO_TEST(link_auth_reply_only_from_master, {
	struct lt_peer master;
	struct hub_user* u;
	int ok;
	memset(&master, 0, sizeof(master));
	master.fd = -1;
	if (!lt_client_handshake())
		return 0;
	u = lt_pending_user();
	if (link_auth_query(lt_hub, u, "victim") != 1)
		return 0;
	lt_swap(&master);                 /* keep the master; open an inbound link */
	ok = lt_server_handshake_add();
	if (ok)
	{
		lt_send("LACR AAAB admin\n");
		lt_send("LVRS AAAB 1 admin\n");
		ok = !lt_p.closed && !u->auth_proxy_resolved;
	}
	lt_swap(&master);
	if (ok)
	{
		lt_send("LACR AAAB user\n");
		ok = u->auth_proxy_resolved && u->auth_proxy_cred == auth_cred_user;
	}
	link_auth_pending_forget(u);
	link_stop(lt_hub);
	if (master.fd != -1)
		close(master.fd);
	return ok;
});

/* -------------------------------------------------------------------------
 * A refused nick stays refused across auth_proxy (issue #130)
 * ------------------------------------------------------------------------- */

static plugin_st lt_auth_get_user(struct plugin_handle* plugin, const char* nick, struct auth_info* info)
{
	(void) plugin;
	memset(info, 0, sizeof(*info));
	if (!strcmp(nick, "Boss"))
	{
		strcpy(info->nickname, "Boss");
		info->credentials = auth_cred_operator;
		return st_allow;
	}
	if (!strcmp(nick, "stranger"))
		return st_default;
	return st_deny; /* exclusive: everyone else */
}

/* Master: answer a slave's LACQ through an exclusive auth plugin. */
EXO_TEST(link_acq_master_reply, {
	struct uhub_plugins plugins;
	struct plugin_handle plugin;
	char reply[64];
	int ok;
	if (!lt_server_handshake())
		return 0;
	memset(&plugins, 0, sizeof(plugins));
	memset(&plugin, 0, sizeof(plugin));
	plugins.loaded = list_create();
	if (!plugins.loaded)
		return 0;
	plugin.funcs.auth_get_user = lt_auth_get_user;
	list_append(plugins.loaded, &plugin);
	lt_hub->plugins = &plugins;

	lt_send("LACQ AAAB Boss\n");
	ok = lt_find("LACR AAAB ", reply, sizeof(reply)) && !strcmp(reply, "operator");
	lt_clear();
	lt_send("LACQ AAAC stranger\n");
	ok = ok && lt_find("LACR AAAC ", reply, sizeof(reply)) && !strcmp(reply, "guest");
	lt_clear();
	lt_send("LACQ AAAD intruder\n");
	ok = ok && lt_find("LACR AAAD ", reply, sizeof(reply)) && !strcmp(reply, "none");

	lt_hub->plugins = NULL;
	list_clear(plugins.loaded, NULL);
	list_destroy(plugins.loaded);
	return ok;
});

/* Slave: "none" is a refusal, and so is a reply it cannot read -- neither
   may become a guest login. */
static int lt_slave_resolves(const char* reply, enum auth_credentials expect)
{
	struct hub_user* u;
	char line[64];
	int ok;
	if (!lt_client_handshake())
		return 0;
	u = lt_pending_user();
	if (link_auth_query(lt_hub, u, "nick") != 1)
		return 0;
	snprintf(line, sizeof(line), "LACR AAAB %s\n", reply);
	lt_send(line);
	ok = u->auth_proxy_resolved && u->auth_proxy_cred == expect;
	link_auth_pending_forget(u);
	return ok;
}

EXO_TEST(link_acr_none_refused,   { return lt_slave_resolves("none", auth_cred_none); });
EXO_TEST(link_acr_bogus_refused,  { return lt_slave_resolves("bogus", auth_cred_none); });
EXO_TEST(link_acr_guest,          { return lt_slave_resolves("guest", auth_cred_guest); });
EXO_TEST(link_acr_account,        { return lt_slave_resolves("admin", auth_cred_admin); });

/* A client can repeat HPAS (or the login re-query) while the master has yet to
   answer. It is registered once: the disconnect forgets it once, so a second
   entry would outlive the user and a late reply would land on freed memory. */
static int lt_repeat_then_forget(int verify)
{
	struct hub_user* u;
	int sent;
	if (!lt_client_handshake())
		return 0;
	u = lt_pending_user();
	strcpy(u->id.nick, "nick");
	if (verify)
		sent = link_auth_proxy_verify(lt_hub, u, "CHAL", "RESP")
			+ link_auth_proxy_verify(lt_hub, u, "CHAL", "RESP");
	else
		sent = link_auth_query(lt_hub, u, "nick")
			+ link_auth_query(lt_hub, u, "nick");
	link_auth_pending_forget(u);
	lt_send("LACR AAAB admin\n");
	return sent == 2 && !lt_p.closed && !u->auth_proxy_resolved;
}

EXO_TEST(link_vfy_repeated_forgotten, { return lt_repeat_then_forget(1); });
EXO_TEST(link_acq_repeated_forgotten, { return lt_repeat_then_forget(0); });

/* ... and the first reply settles it, the second finds nothing. */
EXO_TEST(link_acq_repeated_answered_once, {
	struct hub_user* u;
	int ok;
	if (!lt_client_handshake())
		return 0;
	u = lt_pending_user();
	if (link_auth_query(lt_hub, u, "nick") + link_auth_query(lt_hub, u, "nick") != 2)
		return 0;
	lt_send("LACR AAAB admin\n");
	ok = u->auth_proxy_resolved && u->auth_proxy_cred == auth_cred_admin;
	u->auth_proxy_resolved = 0;
	lt_send("LACR AAAB user\n");
	ok = ok && !u->auth_proxy_resolved;
	link_auth_pending_forget(u);
	return ok;
});

/* -------------------------------------------------------------------------
 * A remote user disconnected on this hub
 * ------------------------------------------------------------------------- */

/* The parts of hub_event_dispatcher() that free users. */
static void lt_dispatch(void* data, struct event_data* ev)
{
	struct hub_info* hub = (struct hub_info*) data;
	struct hub_user* user = (struct hub_user*) ev->ptr;
	if (ev->id == UHUB_EVENT_USER_QUIT)
	{
		uman_remove(hub->users, user);
		hub_schedule_destroy_user(hub, user);
	}
	else if (ev->id == UHUB_EVENT_USER_DESTROY)
	{
		route_clear_dirty(hub, user);
		user_destroy(user);
	}
}

/* Kick the remote user AAAD here (an operator's !kick, a plugin's
   user_disconnect), then let the peer report it gone -- `after`, or the link
   dropping if NULL -- before the event queue runs. The link frees remote users
   on the spot, so the kick must already have unlinked it: otherwise the queued
   events unlink and free it a second time. */
static int lt_kick_remote(const char* after)
{
	struct hub_user* remote;
	int ok;
	if (!lt_server_handshake() || !lt_add_local_users()
		|| event_queue_initialize(&lt_hub->queue, lt_dispatch, lt_hub) == -1)
	{
		lt_remove_local_users();
		return 0;
	}
	lt_hub->status = hub_status_running;
	lt_send(LT_REMOTE_INF);
	remote = uman_get_user_by_sid(lt_hub->users, string_to_sid("AAAD"));
	ok = remote && user_is_remote(remote);
	if (ok)
	{
		hub_disconnect_user(lt_hub, remote, quit_kicked);
		ok = !uman_get_user_by_sid(lt_hub->users, string_to_sid("AAAD"))
			&& !uman_get_user_by_nick(lt_hub->users, "remote")
			&& lt_queued(lt_local_target, "IQUI AAAD");
		if (after)
			lt_send(after);
		else
			link_stop(lt_hub);
		ok = ok && (!after || !lt_p.closed);
	}
	event_queue_process(lt_hub->queue);
	ok = ok && event_queue_size(lt_hub->queue) == 0;
	event_queue_shutdown(lt_hub->queue);
	lt_hub->queue = 0;
	lt_hub->status = hub_status_uninitialized;
	link_stop(lt_hub);
	lt_remove_local_users();
	return ok;
}

EXO_TEST(link_kicked_remote_then_quit, { return lt_kick_remote("LQUI AAAD\n"); });
EXO_TEST(link_kicked_remote_then_link_lost, { return lt_kick_remote(NULL); });

/* -------------------------------------------------------------------------
 * SID window lease, member side (node_id = -1)
 * ------------------------------------------------------------------------- */

static struct hub_user_manager* lt_saved_users = 0;

/* A node that leases its window: no window until a coordinator grants one.
   The test plays the peer the hub connected out to. */
static int lt_member_handshake(void)
{
	lt_saved_users = lt_hub->users;
	lt_hub->users = uman_init(-1, 2);
	if (!lt_hub->users)
	{
		lt_hub->users = lt_saved_users;
		lt_saved_users = 0;
		return 0;
	}
	lt_node_id = -1;
	return lt_client_handshake();
}

static void lt_member_done(void)
{
	link_stop(lt_hub);
	lt_node_id = 0;
	if (lt_saved_users)
	{
		uman_shutdown(lt_hub->users);
		lt_hub->users = lt_saved_users;
		lt_saved_users = 0;
	}
}

/* The SID the next local user would get (0: none), handed straight back. */
static sid_t lt_next_sid(void)
{
	struct hub_user u;
	sid_t sid;
	memset(&u, 0, sizeof(u));
	sid = uman_get_free_sid(lt_hub->users, &u);
	if (sid)
		sid_free(lt_hub->users->sids, sid);
	return sid;
}

/* A grant nobody asked for is refused, and the window stays empty. */
EXO_TEST(link_window_unrequested_refused, {
	int ok;
	if (!lt_member_handshake())
	{
		lt_member_done();
		return 0;
	}
	lt_send("LWIN 1000 1999\n");
	ok = lt_p.closed && lt_next_sid() == 0;
	lt_member_done();
	return ok;
});

/* Losing the election asks the winner for a window, and its answer is
   applied -- once. A second grant would move the window under live users. */
EXO_TEST(link_window_requested_applied_once, {
	sid_t sid;
	int ok;
	if (!lt_member_handshake())
	{
		lt_member_done();
		return 0;
	}
	lt_send("LELC 0000000000000000\n"); /* a forced coordinator: we lose */
	ok = lt_find("LWRQ", NULL, 0);
	lt_send("LWIN 1000 1999\n");
	sid = lt_next_sid();
	ok = ok && !lt_p.closed && sid >= 1000 && sid <= 1999;
	lt_send("LWIN 3000 3999\n");
	sid = lt_next_sid();
	ok = ok && lt_p.closed && sid >= 1000 && sid <= 1999;
	lt_member_done();
	return ok;
});

/* A static node (node_id > 0) takes no part in the election. Its election id
   is 0, so it used to win every LELC and start granting windows of its own --
   overlapping the static ones. */
EXO_TEST(link_static_node_does_not_coordinate, {
	int ok;
	lt_node_id = 1;
	ok = lt_client_handshake();
	if (ok)
	{
		lt_send("LELC ffffffffffffffff\n");
		lt_send("LWRQ\n");
		ok = !lt_p.closed && !lt_find("LWIN ", NULL, 0) && !lt_find("LERR", NULL, 0);
	}
	link_stop(lt_hub);
	lt_node_id = 0;
	return ok;
});

/* A member that leased its window does not coordinate when it wins a later
   election against another pending node: that node leases from the real
   coordinator, and the member neither grants nor drops the link. */
EXO_TEST(link_member_does_not_coordinate, {
	struct lt_peer coordinator;
	int ok;
	memset(&coordinator, 0, sizeof(coordinator));
	coordinator.fd = -1;
	ok = lt_member_handshake();
	if (ok)
	{
		lt_send("LELC 0000000000000000\n");
		lt_send("LWIN 1000 1999\n");
		ok = !lt_p.closed && lt_next_sid() >= 1000;
	}
	lt_swap(&coordinator);             /* keep it; a pending node connects to us */
	ok = ok && lt_server_handshake_add();
	if (ok)
	{
		lt_send("LELC ffffffffffffffff\n"); /* we win this one */
		lt_send("LWRQ\n");
		ok = !lt_p.closed && !lt_find("LWIN ", NULL, 0) && !lt_find("LERR", NULL, 0);
	}
	lt_member_done();
	if (coordinator.fd != -1)
		close(coordinator.fd);
	return ok;
});

/* -------------------------------------------------------------------------
 * SID window lease, coordinator side (node_id = 0)
 * ------------------------------------------------------------------------- */

/* Count the lines the link sent that start with prefix. */
static int lt_count(const char* prefix)
{
	const char* p = lt_p.out;
	size_t plen = strlen(prefix);
	int n = 0;
	while (p && *p)
	{
		const char* nl = strchr(p, '\n');
		if (!strncmp(p, prefix, plen))
			n++;
		p = nl ? nl + 1 : NULL;
	}
	return n;
}

/* A link holds one lease. A repeated request is ignored; it used to take a
   second window and lose track of the first, which then never returned to the
   pool. With node_count 2 there is one window to lease, so the second grant
   was a refusal that closed the link. */
EXO_TEST(link_window_one_lease_per_link, {
	if (!lt_server_handshake())
		return 0;
	lt_send("LWRQ\n");
	lt_send("LWRQ\n");
	return !lt_p.closed && lt_count("LWIN ") == 1 && !lt_find("LERR", NULL, 0);
});

/* With node_count 2 the one window a coordinator leases is window 1. */
#define LT_W1_LO "524288"
#define LT_W1_HI "1048575"

/* A member that held window 1 before the coordinator lost track of it (the
   link dropped, or the coordinator restarted) reclaims it, and it is not
   leased to anyone else. */
EXO_TEST(link_window_reclaimed, {
	struct lt_peer member;
	int ok;
	memset(&member, 0, sizeof(member));
	member.fd = -1;
	if (!lt_server_handshake())
		return 0;
	lt_send("LWRQ " LT_W1_LO " " LT_W1_HI "\n");
	ok = !lt_p.closed && !lt_find("LERR", NULL, 0);
	lt_swap(&member);                 /* keep it; a pending node asks for one */
	ok = ok && lt_server_handshake_add();
	if (ok)
	{
		lt_send("LWRQ\n");
		ok = !lt_find("LWIN ", NULL, 0) && lt_find("LERR", NULL, 0);
	}
	link_stop(lt_hub);
	if (member.fd != -1)
		close(member.fd);
	return ok;
});

/* A window already leased to another node cannot be claimed: the link is
   refused rather than two nodes handing out the same SIDs. */
EXO_TEST(link_window_reclaim_conflict_refused, {
	struct lt_peer first;
	int ok;
	memset(&first, 0, sizeof(first));
	first.fd = -1;
	if (!lt_server_handshake())
		return 0;
	lt_send("LWRQ\n");
	ok = lt_find("LWIN " LT_W1_LO " " LT_W1_HI, NULL, 0);
	lt_swap(&first);
	ok = ok && lt_server_handshake_add();
	if (ok)
	{
		lt_send("LWRQ " LT_W1_LO " " LT_W1_HI "\n");
		ok = lt_p.closed;
	}
	link_stop(lt_hub);
	if (first.fd != -1)
		close(first.fd);
	return ok;
});

/* A claim that is not exactly a leasable window is refused too. */
EXO_TEST(link_window_reclaim_misaligned_refused, {
	if (!lt_server_handshake())
		return 0;
	lt_send("LWRQ 1 524287\n");      /* window 0: the coordinator's own */
	return lt_p.closed;
});

/* Member side: linking to a coordinator again, a node holding a leased window
   says which one, instead of asking for another or saying nothing. */
EXO_TEST(link_member_reclaims_its_window, {
	struct lt_peer first;
	char claim[64];
	int ok;
	memset(&first, 0, sizeof(first));
	first.fd = -1;
	ok = lt_member_handshake();
	if (ok)
	{
		lt_send("LELC 0000000000000000\n");
		lt_send("LWIN " LT_W1_LO " " LT_W1_HI "\n");
		ok = !lt_p.closed;
	}
	lt_swap(&first);                  /* the coordinator again, over a new link */
	ok = ok && lt_client_handshake_add();
	if (ok)
	{
		lt_send("LELC 0000000000000000\n");
		ok = lt_find("LWRQ ", claim, sizeof(claim)) && !strcmp(claim, LT_W1_LO " " LT_W1_HI);
	}
	lt_member_done();
	if (first.fd != -1)
		close(first.fd);
	return ok;
});

/* Two coordinators meeting -- here the forced one, outbound, losing the tie to
   another forced one -- would both hand out window 0 and every window after
   it. The link is refused instead. */
EXO_TEST(link_second_coordinator_refused, {
	int ok;
	if (!lt_client_handshake())
		return 0;
	lt_send("LELC 0000000000000000\n");
	ok = lt_p.closed && lt_find("LERR", NULL, 0);
	link_stop(lt_hub);
	return ok;
});

/* A pending node that won elsewhere first and now meets a lower id: the same. */
EXO_TEST(link_pending_coordinator_refused, {
	struct lt_peer first;
	int ok;
	memset(&first, 0, sizeof(first));
	first.fd = -1;
	ok = lt_member_handshake();
	if (ok)
	{
		lt_send("LELC ffffffffffffffff\n"); /* we win: coordinator, window 0 */
		ok = !lt_p.closed && lt_next_sid() != 0;
	}
	lt_swap(&first);
	ok = ok && lt_client_handshake_add();
	if (ok)
	{
		lt_send("LELC 0000000000000000\n"); /* the forced coordinator */
		ok = lt_p.closed;
	}
	lt_member_done();
	if (first.fd != -1)
		close(first.fd);
	return ok;
});
