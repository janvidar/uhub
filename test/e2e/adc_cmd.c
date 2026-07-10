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
 *           [--send "text"]... [--linger SECONDS] [--timeout SECONDS]
 *           [--expect ok|fail]
 *
 * Exit codes: 0 = expectation met, 1 = expectation not met, 2 = usage/timeout.
 */

#include "adcclient.h"
#include <signal.h>
#include <unistd.h>

#define MAX_SEND 8

static int running = 1;
static int logged_in = 0;
static int login_error = 0;
static int timed_out = 0;

static const char* opt_send[MAX_SEND];
static int opt_send_n = 0;
static int opt_linger = 1;   /* seconds to stay connected after login */

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
		                "[--send TEXT]... [--linger S] [--timeout S] [--expect ok|fail]\n"
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
	if (pid)
		ADC_client_set_pid(client, pid);
	ADC_client_connect(client, address);

	while (running && net_backend_process()) { }

	ADC_client_destroy(client);
	net_destroy();

	printf("RESULT: logged_in=%d login_error=%d timed_out=%d\n", logged_in, login_error, timed_out);

	if (expect && !strcmp(expect, "ok"))
		return (logged_in && !login_error) ? 0 : 1;
	if (expect && !strcmp(expect, "fail"))
		return (login_error) ? 0 : 1;
	return logged_in ? 0 : 1;
}
