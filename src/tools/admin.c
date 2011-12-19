/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2011, Jan Vidar Krey
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "adcclient.h"

static int handle(struct ADC_client* client, enum ADC_client_callback_type type, struct ADC_client_callback_data* data)
{
	switch (type)
	{
		case ADC_CLIENT_CONNECTING:
			puts("*** Connecting...");
			break;

		case ADC_CLIENT_CONNECTED:
			puts("*** Connected.");
			break;

		case ADC_CLIENT_DISCONNECTED:
			puts("*** Disconnected.");
			break;

		case ADC_CLIENT_SSL_HANDSHAKE:
			puts("*** SSL handshake.");
			break;

		case ADC_CLIENT_LOGGING_IN:
			puts("*** Logging in...");
			break;

		case ADC_CLIENT_PASSWORD_REQ:
			puts("*** Requesting password.");
			break;

		case ADC_CLIENT_LOGGED_IN:
			puts("*** Logged in.");
			break;

		case ADC_CLIENT_LOGIN_ERROR:
			puts("*** Login error");
			break;

		case ADC_CLIENT_MESSAGE:
			printf("    <%s> %s\n", sid_to_string(data->chat->from_sid), data->chat->message);
			break;

		case ADC_CLIENT_USER_JOIN:
			printf("    JOIN: %s %s\n", sid_to_string(data->user->sid), data->user->name);
			break;

		case ADC_CLIENT_USER_QUIT:
			printf("    QUIT\n");
			break;

		case ADC_CLIENT_SEARCH_REQ:
			break;

		case ADC_CLIENT_HUB_INFO:
			printf("    Hub: \"%s\" [%s]\n"
				   "         \"%s\"\n", data->hubinfo->name, data->hubinfo->version, data->hubinfo->description);
			break;

		default:
			printf("Not handled event=%d\n", (int) type);
			return 0;
			break;
	}
	return 1;
}

static int running = 1;

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		printf("Usage: %s adc[s]://host:port\n", argv[0]);
		return 1;
	}

	struct ADC_client client;
	net_initialize();

	ADC_client_create(&client, "uhub-admin", "stresstester");
	ADC_client_set_callback(&client, handle);
	ADC_client_connect(&client, argv[1]);

	while (running && net_backend_process()) { }

	ADC_client_destroy(&client);
	net_destroy();
	return 0;
}


