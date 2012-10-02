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

static struct ADC_user g_usermap[SID_MAX];

static void user_add(const struct ADC_user* user)
{
	printf(" >> JOIN: %s (%s)\n", user->name, user->address);
	memcpy(&g_usermap[user->sid], user, sizeof(struct ADC_user));
}

static struct ADC_user* user_get(sid_t sid)
{

	struct ADC_user* user = &g_usermap[sid];
	uhub_assert(user->sid != 0);
	return user;
}


static void user_remove(const struct ADC_client_quit_reason* quit)
{
	struct ADC_user* user = user_get(quit->sid);
	printf(" << QUIT: %s (%s)\n", user->name, quit->message);
	memset(&g_usermap[quit->sid], 0, sizeof(struct ADC_user));
}

static void on_message(struct ADC_chat_message* chat)
{
	struct ADC_user* user;
	const char* pm = (chat->flags & chat_flags_private) ? "PM" : "  ";
	const char* brack1 = (chat->flags & chat_flags_action) ? "*" : "<";
	const char* brack2 = (chat->flags & chat_flags_action) ? "" : ">";
	struct linked_list* lines;
	int ret;
	char* line;

	if (!chat->from_sid)
	{
		printf("HUB ");
	}
	else
	{
		user = user_get(chat->from_sid);
		printf(" %s %s%s%s ", pm, brack1, user->name, brack2);
	}

	lines = list_create();
	ret = split_string(chat->message, "\n", lines, 1);

	line = (char*) list_get_first(lines);

	ret = 0;
	while (line)
	{
		if (ret > 0)
			printf("    ");
		printf("%s\n", line);
		ret++;
		line = (char*) list_get_next(lines);
	}

	list_clear(lines, &hub_free);
	list_destroy(lines);
}

static void status(const char* msg)
{
	printf("*** %s\n", msg);
}

static int handle(struct ADC_client* client, enum ADC_client_callback_type type, struct ADC_client_callback_data* data)
{
	switch (type)
	{
		case ADC_CLIENT_CONNECTING:
			status("Connecting...");
			break;

		case ADC_CLIENT_CONNECTED:
			status("Connected.");
			break;

		case ADC_CLIENT_DISCONNECTED:
			status("Disconnected.");
			break;

		case ADC_CLIENT_SSL_HANDSHAKE:
			status("SSL handshake.");
			break;

		case ADC_CLIENT_LOGGING_IN:
			status("Logging in...");
			break;

		case ADC_CLIENT_PASSWORD_REQ:
			status("Requesting password.");
			break;

		case ADC_CLIENT_LOGGED_IN:
			status("Logged in.");
			break;

		case ADC_CLIENT_LOGIN_ERROR:
			status("Login error");
			break;


		case ADC_CLIENT_MESSAGE:
			on_message(data->chat);
			break;

		case ADC_CLIENT_USER_JOIN:
			
			user_add(data->user);
			break;

		case ADC_CLIENT_USER_QUIT:
			user_remove(data->quit);
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

	struct ADC_client* client;
	net_initialize();

	memset(g_usermap, 0, sizeof(g_usermap));

	client = ADC_client_create("uhub-admin", "stresstester");
	ADC_client_set_callback(client, handle);
	ADC_client_connect(client, argv[1]);

	while (running && net_backend_process()) { }

	ADC_client_destroy(client);
	net_destroy();
	return 0;
}


