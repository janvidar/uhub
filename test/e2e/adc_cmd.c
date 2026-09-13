/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

/*
 * A tiny scriptable ADC client for end-to-end testing (see run_ban_e2e.sh).
 * It logs in to a hub as a given nick (optionally with a password), optionally
 * sends one or more chat lines (used to drive !commands), lingers briefly, and
 * exits with a status that reflects whether login succeeded or was rejected.
 *
 * Built on the hub's own libadcclient, so the ADC handshake and the Tiger
 * password challenge are handled for us.
 *
 * Usage:
 *   adc_cmd <adc://host:port> --nick N [--password P]
 *           [--send "text"]... [--raw "LINE"]... [--sup ADXXXX]...
 *           [--inf FIELD]... [--hbri] [--hbri-abandon]
 *           [--expect-line GLOB]... [--dump]
 *           [--linger SECONDS] [--timeout SECONDS] [--expect ok|fail]
 *
 * --raw sends a line verbatim after login, for driving extensions this client
 * does not model (BBS0's HBBL and HBBP, say). --inf does the same for the
 * login INF ("--inf I6::1"). --expect-line matches received lines against a
 * glob and fails the run if any pattern goes unmatched, which is how a test
 * asserts on what the hub sent back.
 *
 * --hbri-abandon leaves as soon as the challenge arrives, without answering it,
 * so the session lasts milliseconds rather than --linger seconds.
 *
 * --hbri answers an HBRI challenge: when the hub sends ITCP, connect to the
 * address and port it names and send the token back as the first line of that
 * connection -- over TLS when the hub address is adcs://, since the hub demuxes
 * that connection exactly as it demuxes a login. That second connection is the whole point of HBRI -- it is how
 * the hub observes an address on the other protocol family instead of taking
 * the client's word for it -- so a test cannot fake it in the primary session.
 *
 * Exit codes: 0 = expectation met, 1 = expectation not met, 2 = usage/timeout.
 */

#include "adcclient.h"
#include <fnmatch.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>

#define MAX_SEND 8
#define MAX_RAW 16
#define MAX_SUP 8
#define MAX_INF 8
#define MAX_EXPECT 16

static int running = 1;
static int logged_in = 0;
static int login_error = 0;
static int timed_out = 0;

static const char* opt_send[MAX_SEND];
static int opt_send_n = 0;
static const char* opt_raw[MAX_RAW];
static int opt_raw_n = 0;
static const char* opt_sup[MAX_SUP];
static int opt_sup_n = 0;
static const char* opt_inf[MAX_INF];
static int opt_inf_n = 0;
static int opt_hbri = 0;
static int opt_hbri_tls = 0;   /* set when the hub URL is adcs:// */
static int opt_hbri_abandon = 0;
static int hbri_answered = 0;
static const char* opt_expect_line[MAX_EXPECT];
static int opt_expect_line_seen[MAX_EXPECT];
static int opt_expect_line_n = 0;
static int opt_dump = 0;
static int opt_linger = 1;   /* seconds to stay connected after login */

/*
 * Send a line to the hub verbatim. adc_msg_create() takes the line as-is, so
 * whatever the caller wrote is what goes on the wire -- the point of --raw.
 *
 * The one substitution is "%SID%", which becomes this client's own session id.
 * A D-type message carries its source SID and the hub verifies it, so without
 * this there is no way to script one: the SID is only known at run time.
 */
static void send_raw(struct ADC_client* client, const char* line)
{
	char buf[MAX_ADC_CMD_LEN];
	struct adc_message* cmd;
	const char* mark = strstr(line, "%SID%");

	if (mark)
	{
		snprintf(buf, sizeof(buf), "%.*s%s%s\n", (int) (mark - line), line,
			sid_to_string(ADC_client_get_sid(client)), mark + 5);
		cmd = adc_msg_create(buf);
		if (!cmd)
		{
			printf("RAW-INVALID: %s\n", buf);
			return;
		}
		ADC_client_send(client, cmd);
		adc_msg_free(cmd);
		printf("RAW: %s", buf);
		return;
	}

	snprintf(buf, sizeof(buf), "%s\n", line);
	cmd = adc_msg_create(buf);
	if (!cmd)
	{
		printf("RAW-INVALID: %s\n", line);
		return;
	}
	ADC_client_send(client, cmd);
	adc_msg_free(cmd);
	printf("RAW: %s\n", line);
}

/*
 * Write the validation reply, over TLS when the hub is a TLS hub. probe.c
 * demuxes the validation connection the same way it demuxes a login, so on a
 * TLS hub this one must be encrypted too -- and on a tls_require hub a
 * plaintext one is refused outright.
 *
 * No certificate check: the hub under test signs its own, and what is being
 * tested is the hub's side. A real client pins the keyprint instead.
 */
static int hbri_write_reply(int fd, const char* reply)
{
	size_t len = strlen(reply);
	SSL_CTX* ctx;
	SSL* ssl;
	int ok;

	if (!opt_hbri_tls)
		return write(fd, reply, len) == (ssize_t) len;

	ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx)
		return 0;

	ssl = SSL_new(ctx);
	if (!ssl)
	{
		SSL_CTX_free(ctx);
		return 0;
	}

	ok = SSL_set_fd(ssl, fd) == 1
	  && SSL_connect(ssl) == 1
	  && SSL_write(ssl, reply, (int) len) == (int) len;

	if (ok)
		SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	return ok;
}

/*
 * Answer an HBRI challenge.
 *
 * ITCP names where to reach the hub on the other protocol family (I4/I6 plus
 * P4/P6) and carries the token. The reply goes on a fresh connection to that
 * address, as its very first line and with no HSUP before it -- the hub takes
 * the peer address it sees there as the proven one. The connection is closed
 * from the hub's side either way, so nothing is read back.
 *
 * Blocking sockets are fine here: this is a test client, and the alarm() that
 * bounds the whole run still applies.
 */
static void hbri_respond(const char* line)
{
	char addr[128] = "";
	char port[16] = "";
	char token[128] = "";
	char reply[256];
	struct addrinfo hints;
	struct addrinfo* res = NULL;
	struct addrinfo* ai;
	const char* p = line;
	int fd = -1;

	/* Fields are space separated; take the ones we need whichever family. */
	while ((p = strchr(p, ' ')) != NULL)
	{
		p++;
		if ((!strncmp(p, "I4", 2) || !strncmp(p, "I6", 2)) && !*addr)
			sscanf(p + 2, "%127[^ ]", addr);
		else if ((!strncmp(p, "P4", 2) || !strncmp(p, "P6", 2)) && !*port)
			sscanf(p + 2, "%15[^ ]", port);
		else if (!strncmp(p, "TO", 2) && !*token)
			sscanf(p + 2, "%127[^ ]", token);
	}

	if (!*addr || !*port || !*token)
	{
		printf("HBRI-BAD-CHALLENGE: %s\n", line);
		return;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(addr, port, &hints, &res) != 0)
	{
		printf("HBRI-RESOLVE-FAILED: %s:%s\n", addr, port);
		return;
	}

	for (ai = res; ai; ai = ai->ai_next)
	{
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);

	if (fd < 0)
	{
		printf("HBRI-CONNECT-FAILED: %s:%s\n", addr, port);
		return;
	}

	snprintf(reply, sizeof(reply), "HTCP TO%s\n", token);
	if (!hbri_write_reply(fd, reply))
		printf("HBRI-WRITE-FAILED\n");
	else
	{
		hbri_answered = 1;
		printf("HBRI-VALIDATED via %s:%s (%s)\n", addr, port, opt_hbri_tls ? "TLS" : "plain");
	}
	close(fd);
}

/* Match a received line against the --expect-line globs. */
static void check_expected(const char* line)
{
	int i;
	for (i = 0; i < opt_expect_line_n; i++)
	{
		/* FNM_NOESCAPE: ADC escapes everything with backslashes ("\s" for a
		   space), and fnmatch would otherwise read those as glob escapes and
		   quietly match the wrong thing. */
		if (!opt_expect_line_seen[i] && fnmatch(opt_expect_line[i], line, FNM_NOESCAPE) == 0)
		{
			opt_expect_line_seen[i] = 1;
			printf("MATCHED: %s\n", opt_expect_line[i]);
		}
	}
}

static void on_alarm(int sig) { (void) sig; timed_out = 1; running = 0; }

static void send_line(struct ADC_client* client, const char* text)
{
	char* esc = adc_msg_escape(text);
	struct adc_message* cmd = adc_msg_construct_source(ADC_CMD_BMSG, ADC_client_get_sid(client), strlen(esc) + 16);
	adc_msg_add_argument(cmd, esc);
	ADC_client_send(client, cmd);
	hub_free(esc);
	printf("SENT: %s\n", text);
}

static int handle(struct ADC_client* client, enum ADC_client_callback_type type, struct ADC_client_callback_data* data)
{
	switch (type)
	{
		case ADC_CLIENT_LOGGED_IN:
		{
			int i;
			logged_in = 1;
			printf("LOGGED_IN\n");
			for (i = 0; i < opt_send_n; i++)
				send_line(client, opt_send[i]);
			for (i = 0; i < opt_raw_n; i++)
				send_raw(client, opt_raw[i]);
			/* Give the hub time to process the command(s) / to kick us, then stop. */
			alarm(opt_linger > 0 ? (unsigned) opt_linger : 1);
			break;
		}
		case ADC_CLIENT_LOGIN_ERROR:
			login_error = 1;
			running = 0;
			if (data && data->status)
				printf("LOGIN_ERROR %03d: %s\n", data->status->code, data->status->message ? data->status->message : "");
			else
				printf("LOGIN_ERROR\n");
			break;
		case ADC_CLIENT_DISCONNECTED:
			printf("DISCONNECTED\n");
			if (logged_in)
				running = 0;   /* kicked/banned after login */
			break;
		case ADC_CLIENT_PROTOCOL_STATUS:
			if (data && data->status)
				printf("STATUS %03d: %s\n", data->status->code, data->status->message ? data->status->message : "");
			break;
		case ADC_CLIENT_MESSAGE:
			if (data && data->chat && data->chat->message)
				printf("MSG: %s\n", data->chat->message);
			break;
		case ADC_CLIENT_USER_JOIN:
			if (data && data->user)
				printf("JOIN: %s\n", data->user->name);
			break;
		case ADC_CLIENT_RAW_LINE:
			if (data && data->line)
			{
				if (opt_dump)
					printf("LINE: %s\n", data->line);
				check_expected(data->line);
				/* One challenge per run: the hub allows one outstanding at a
				   time, and answering twice would say nothing extra. */
				if (opt_hbri && !hbri_answered && !strncmp(data->line, "ITCP ", 5))
					hbri_respond(data->line);
				/* Leave the moment the challenge lands, so the session is over
				   in milliseconds. A test that needs the next user to take this
				   SID within the same second cannot wait out --linger. */
				if (opt_hbri_abandon && !strncmp(data->line, "ITCP ", 5))
					running = 0;
			}
			break;
		default:
			break;
	}
	return 1;
}

int main(int argc, char** argv)
{
	const char* address = NULL;
	const char* nick = NULL;
	const char* password = NULL;
	const char* pid = NULL;
	const char* expect = NULL;
	int show_cid = 0;
	int expect_failed = 0;
	int timeout = 8;
	struct ADC_client* client;
	int i;

	for (i = 1; i < argc; i++)
	{
		if (argv[i][0] != '-' && !address) { address = argv[i]; }
		else if (!strcmp(argv[i], "--nick") && i + 1 < argc) nick = argv[++i];
		else if (!strcmp(argv[i], "--password") && i + 1 < argc) password = argv[++i];
		else if (!strcmp(argv[i], "--pid") && i + 1 < argc) pid = argv[++i];
		else if (!strcmp(argv[i], "--show-cid")) show_cid = 1;
		else if (!strcmp(argv[i], "--send") && i + 1 < argc && opt_send_n < MAX_SEND) opt_send[opt_send_n++] = argv[++i];
		else if (!strcmp(argv[i], "--raw") && i + 1 < argc && opt_raw_n < MAX_RAW) opt_raw[opt_raw_n++] = argv[++i];
		else if (!strcmp(argv[i], "--sup") && i + 1 < argc && opt_sup_n < MAX_SUP) opt_sup[opt_sup_n++] = argv[++i];
		else if (!strcmp(argv[i], "--inf") && i + 1 < argc && opt_inf_n < MAX_INF) opt_inf[opt_inf_n++] = argv[++i];
		else if (!strcmp(argv[i], "--hbri")) opt_hbri = 1;
		else if (!strcmp(argv[i], "--hbri-abandon")) opt_hbri_abandon = 1;
		else if (!strcmp(argv[i], "--expect-line") && i + 1 < argc && opt_expect_line_n < MAX_EXPECT) opt_expect_line[opt_expect_line_n++] = argv[++i];
		else if (!strcmp(argv[i], "--dump")) opt_dump = 1;
		else if (!strcmp(argv[i], "--linger") && i + 1 < argc) opt_linger = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) timeout = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--expect") && i + 1 < argc) expect = argv[++i];
		else { fprintf(stderr, "Unknown/!bad arg: %s\n", argv[i]); return 2; }
	}

	/* --show-cid: print the CID derived from --pid and exit (no connection). */
	if (show_cid)
	{
		if (!pid) { fprintf(stderr, "--show-cid requires --pid\n"); return 2; }
		net_initialize();
		client = ADC_client_create(nick ? nick : "probe", "e2e", NULL);
		ADC_client_set_pid(client, pid);
		printf("%s\n", ADC_client_get_cid(client));
		ADC_client_destroy(client);
		net_destroy();
		return 0;
	}

	if (!address || !nick)
	{
		fprintf(stderr, "Usage: %s <adc://host:port> --nick N [--password P] [--pid PID] "
		                "[--send TEXT]... [--raw LINE]... [--sup ADXXXX]... "
		                "[--expect-line GLOB]... [--dump] "
		                "[--linger S] [--timeout S] [--expect ok|fail]\n"
		                "       %s --pid PID --show-cid\n", argv[0], argv[0]);
		return 2;
	}

	/* Line-buffer stdout so a test harness watching a redirected log file sees
	   events (e.g. LOGGED_IN) as they happen, not only at exit. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	signal(SIGALRM, on_alarm);
	alarm((unsigned) timeout);

	hub_set_log_verbosity(3);
	net_initialize();
	client = ADC_client_create(nick, "e2e", NULL);
	ADC_client_set_callback(client, handle);
	if (password)
		ADC_client_set_password(client, password);
	/* The validation connection has to match the hub's transport. */
	opt_hbri_tls = !strncmp(address, "adcs://", 7);

	if (pid)
		ADC_client_set_pid(client, pid);
	for (i = 0; i < opt_sup_n; i++)
		ADC_client_add_support(client, opt_sup[i]);
	for (i = 0; i < opt_inf_n; i++)
		ADC_client_add_inf(client, opt_inf[i]);
	ADC_client_connect(client, address);

	while (running && net_backend_process()) { }

	ADC_client_destroy(client);
	net_destroy();

	/* Report every pattern, so a failing run says which one never arrived. */
	for (i = 0; i < opt_expect_line_n; i++)
	{
		if (!opt_expect_line_seen[i])
		{
			printf("MISSING: %s\n", opt_expect_line[i]);
			expect_failed = 1;
		}
	}

	printf("RESULT: logged_in=%d login_error=%d timed_out=%d expect_failed=%d\n",
	       logged_in, login_error, timed_out, expect_failed);

	if (expect_failed)
		return 1;

	if (expect && !strcmp(expect, "ok"))
		return (logged_in && !login_error) ? 0 : 1;
	if (expect && !strcmp(expect, "fail"))
		return (login_error) ? 0 : 1;
	return logged_in ? 0 : 1;
}
