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
 * linktest -- a single ADC client with a controllable identity, used to
 * exercise hub federation deterministically (which adcrush cannot: it only
 * PMs itself and names every bot identically).
 *
 * Usage:
 *   linktest <adc[s]://host:port> --nick NAME [options]
 *     --nick NAME        login nickname (default: linktest)
 *     --pm-nick TARGET   when a user named TARGET appears, send it a private
 *                        message (used to drive a cross-hub directed message)
 *     --pm-text TEXT     body of that PM (default: "hello-from-linktest")
 *     --seconds N        run for N seconds then exit (default: 8)
 *
 * It prints one machine-greppable line per interesting event:
 *   LINKTEST <nick>: logged in ...
 *   LINKTEST <nick>: sees user <name> (sid ...)
 *   LINKTEST <nick>: sent PM to <name> ...
 *   LINKTEST <nick>: RECV PM from sid ...: <text>
 *   LINKTEST <nick>: done (received N messages)
 */

#include "adcclient.h"
#include "network/backend.h"
#include "network/timeout.h"

static int running = 1;

static const char* opt_uri      = NULL;
static const char* opt_nick     = "linktest";
static const char* opt_pm_nick  = NULL;
static const char* opt_pm_text  = "hello-from-linktest";
static const char* opt_say      = NULL;
static const char* opt_password = NULL;
static const char* opt_command  = NULL;
static int opt_seconds          = 8;

static int sent_pm = 0;
static int sent_command = 0;
static int recv_count = 0;

static void deadline_cb(struct timeout_evt* t)
{
	(void) t;
	running = 0;
}

static int handle(struct ADC_client* client, enum ADC_client_callback_type type, struct ADC_client_callback_data* data)
{
	switch (type)
	{
		case ADC_CLIENT_LOGGED_IN:
			printf("LINKTEST %s: logged in (sid %s)\n", opt_nick, sid_to_string(ADC_client_get_sid(client)));
			if (opt_command && !sent_command)
			{
				/* Hub commands arrive as a main-chat message starting with '!'. */
				char* esc = adc_msg_escape(opt_command);
				struct adc_message* m = adc_msg_construct_source(ADC_CMD_BMSG,
					ADC_client_get_sid(client), esc ? strlen(esc) : 0);
				if (m && esc)
				{
					adc_msg_add_argument(m, esc);
					ADC_client_send(client, m);
					sent_command = 1;
					printf("LINKTEST %s: ran command: %s\n", opt_nick, opt_command);
				}
				adc_msg_free(m);
				hub_free(esc);
			}
			if (opt_say)
			{
				char* esc = adc_msg_escape(opt_say);
				struct adc_message* m = adc_msg_construct_source(ADC_CMD_BMSG,
					ADC_client_get_sid(client), esc ? strlen(esc) : 0);
				if (m && esc)
				{
					adc_msg_add_argument(m, esc);
					ADC_client_send(client, m);
					printf("LINKTEST %s: said public: %s\n", opt_nick, opt_say);
				}
				adc_msg_free(m);
				hub_free(esc);
			}
			break;

		case ADC_CLIENT_USER_JOIN:
			if (data && data->user)
			{
				printf("LINKTEST %s: sees user %s (sid %s)\n", opt_nick, data->user->name, sid_to_string(data->user->sid));
				if (opt_pm_nick && !sent_pm && strcmp(data->user->name, opt_pm_nick) == 0)
				{
					char* esc = adc_msg_escape(opt_pm_text);
					struct adc_message* m = adc_msg_construct_source_dest(ADC_CMD_DMSG,
						ADC_client_get_sid(client), data->user->sid, esc ? strlen(esc) : 0);
					if (m && esc)
					{
						adc_msg_add_argument(m, esc);
						ADC_client_send(client, m);
						sent_pm = 1;
						printf("LINKTEST %s: sent PM to %s (sid %s)\n", opt_nick, data->user->name, sid_to_string(data->user->sid));
					}
					adc_msg_free(m);
					hub_free(esc);
				}
			}
			break;

		case ADC_CLIENT_MESSAGE:
			if (data && data->chat)
			{
				recv_count++;
				printf("LINKTEST %s: RECV %s from sid %s: %s\n", opt_nick,
					(data->chat->flags & chat_flags_private) ? "PM" : "chat",
					sid_to_string(data->chat->from_sid),
					data->chat->message ? data->chat->message : "");
			}
			break;

		case ADC_CLIENT_HUB_INFO:
			if (data && data->hubinfo && data->hubinfo->description)
				printf("LINKTEST %s: topic: %s\n", opt_nick, data->hubinfo->description);
			break;

		case ADC_CLIENT_LOGIN_ERROR:
			printf("LINKTEST %s: login rejected\n", opt_nick);
			running = 0;
			break;

		case ADC_CLIENT_DISCONNECTED:
			printf("LINKTEST %s: disconnected\n", opt_nick);
			running = 0;
			break;

		default:
			break;
	}
	return 0;
}

static int parse_args(int argc, char** argv)
{
	int i;
	if (argc < 2)
		return 0;
	opt_uri = argv[1];
	if (strncmp(opt_uri, "adc://", 6) != 0 && strncmp(opt_uri, "adcs://", 7) != 0)
		return 0;

	for (i = 2; i < argc; i++)
	{
		if (!strcmp(argv[i], "--nick") && i + 1 < argc)
			opt_nick = argv[++i];
		else if (!strcmp(argv[i], "--pm-nick") && i + 1 < argc)
			opt_pm_nick = argv[++i];
		else if (!strcmp(argv[i], "--pm-text") && i + 1 < argc)
			opt_pm_text = argv[++i];
		else if (!strcmp(argv[i], "--say") && i + 1 < argc)
			opt_say = argv[++i];
		else if (!strcmp(argv[i], "--password") && i + 1 < argc)
			opt_password = argv[++i];
		else if (!strcmp(argv[i], "--command") && i + 1 < argc)
			opt_command = argv[++i];
		else if (!strcmp(argv[i], "--seconds") && i + 1 < argc)
			opt_seconds = atoi(argv[++i]);
		else
			return 0;
	}
	return 1;
}

int main(int argc, char** argv)
{
	struct ADC_client* client;
	struct timeout_evt deadline;

	if (!parse_args(argc, argv))
	{
		fprintf(stderr, "Usage: %s adc[s]://host:port [--nick NAME] [--password PASS] [--command \"!cmd args\"] [--pm-nick TARGET] [--pm-text TEXT] [--say TEXT] [--seconds N]\n", argv[0]);
		return 1;
	}

	net_initialize();
	hub_log_initialize(NULL, 0);
	hub_set_log_verbosity(0); /* keep the library quiet; we print our own lines */

	timeout_evt_initialize(&deadline, deadline_cb, NULL);
	timeout_queue_insert(net_backend_get_timeout_queue(), &deadline, (size_t) opt_seconds);

	client = ADC_client_create(opt_nick, "linktest", NULL);
	ADC_client_set_callback(client, handle);
	if (opt_password)
		ADC_client_set_password(client, opt_password);
	ADC_client_connect(client, opt_uri);

	while (running && net_backend_process())
		;

	ADC_client_disconnect(client);
	ADC_client_destroy(client);
	printf("LINKTEST %s: done (received %d messages)\n", opt_nick, recv_count);

	net_destroy();
	return 0;
}
