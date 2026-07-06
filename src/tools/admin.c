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

#include "adcclient.h"

static void user_add(const struct ADC_user* user)
{
	printf(" >> JOIN: %s (%s)\n", user->name, user->address);
}

static void user_remove(struct ADC_client* client, const struct ADC_client_quit_reason* quit)
{
	/* The user is still in the library's tracked list during the QUIT
	   callback (it is dropped only afterwards), so we can name it here. */
	const struct ADC_user* user = ADC_client_get_user(client, quit->sid);
	printf(" << QUIT: %s (%s)\n", user ? user->name : "?", quit->message);
}

static void on_message(struct ADC_client* client, struct ADC_chat_message* chat)
{
	const struct ADC_user* user;
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
	else if (chat->from_sid == ADC_client_get_sid(client))
	{
		/* our own message, echoed back by the hub; we are not in our own
		   tracked user list, so name ourselves directly */
		printf(" %s %s%s%s ", pm, brack1, ADC_client_get_nick(client), brack2);
	}
	else
	{
		user = ADC_client_get_user(client, chat->from_sid);
		printf(" %s %s%s%s ", pm, brack1, user ? user->name : "?", brack2);
	}

	lines = list_create();
	ret = split_string(chat->message, "\n", lines, 1);

	ret = 0;
	LIST_FOREACH(char*, line, lines,
	{
		if (ret > 0)
			printf("    ");
		printf("%s\n", line);
		ret++;
	});

	list_clear(lines, hub_free_handle);
	list_destroy(lines);
}

static void status(const char* msg)
{
	printf("*** %s\n", msg);
}

/* ------------------------------------------------------------------ *
 *  Interactive input: read stdin from inside the event loop and drive
 *  the client through the typed ADC_client_* intent API. A plain line
 *  is public chat; a line starting with '/' is a local command. (Hub
 *  commands like "!help" are just public chat starting with '!', so
 *  they need no special handling here.)
 * ------------------------------------------------------------------ */

static int running = 1;
static struct net_connection* g_stdin_con = NULL;
static int g_stdin_flags = -1;
static char g_line[1024];
static size_t g_line_len = 0;

struct nick_lookup { const char* name; sid_t sid; };

static void nick_match_cb(const struct ADC_user* user, void* data)
{
	struct nick_lookup* l = (struct nick_lookup*) data;
	if (!l->sid && strcmp(user->name, l->name) == 0)
		l->sid = user->sid;
}

static void who_print_cb(const struct ADC_user* user, void* data)
{
	(void) data;
	printf("    %-20s %-40s %s\n", user->name,
		user->address[0] ? user->address : user->address6,
		sid_to_string(user->sid));
}

static void print_help(void)
{
	printf("*** Commands:\n"
	       "      <text>            send public chat\n"
	       "      /me <text>        send an action (/me waves)\n"
	       "      /msg <nick> <t>   send a private message\n"
	       "      /who              list users in the hub\n"
	       "      /help             this help\n"
	       "      /quit             disconnect and exit\n"
	       "    (a line starting with '!' is sent as a hub command)\n");
}

static void handle_command(struct ADC_client* client, char* line)
{
	char* cmd;
	char* arg;

	/* strip a trailing CR (in case of CRLF input) */
	size_t n = strlen(line);
	if (n && line[n-1] == '\r')
		line[--n] = '\0';

	if (n == 0)
		return;

	if (line[0] != '/')
	{
		if (!ADC_client_say(client, line))
			status("Not connected -- message not sent.");
		return;
	}

	/* split "/cmd" from the remaining argument text */
	cmd = line + 1;
	arg = strchr(cmd, ' ');
	if (arg)
		*arg++ = '\0';
	while (arg && *arg == ' ')
		arg++;

	if (!strcmp(cmd, "quit") || !strcmp(cmd, "q"))
	{
		running = 0;
	}
	else if (!strcmp(cmd, "help") || !strcmp(cmd, "h"))
	{
		print_help();
	}
	else if (!strcmp(cmd, "who") || !strcmp(cmd, "w"))
	{
		printf("*** %zu user(s):\n", ADC_client_user_count(client));
		ADC_client_foreach_user(client, who_print_cb, NULL);
	}
	else if (!strcmp(cmd, "me"))
	{
		if (arg && *arg && !ADC_client_say_me(client, arg))
			status("Not connected -- message not sent.");
	}
	else if (!strcmp(cmd, "msg") || !strcmp(cmd, "pm"))
	{
		char* target = arg;
		char* text = arg ? strchr(arg, ' ') : NULL;
		if (text)
		{
			*text++ = '\0';
			struct nick_lookup l = { target, 0 };
			ADC_client_foreach_user(client, nick_match_cb, &l);
			if (!l.sid)
				printf("*** No such user: %s\n", target);
			else if (!ADC_client_pm(client, l.sid, text))
				status("Not connected -- message not sent.");
		}
		else
			status("Usage: /msg <nick> <text>");
	}
	else
	{
		printf("*** Unknown command: /%s (try /help)\n", cmd);
	}
}

static void stdin_callback(struct net_connection* con, int events, void* ptr)
{
	(void) events;
	struct ADC_client* client = (struct ADC_client*) ptr;
	char buf[1024];
	ssize_t r = read(net_con_get_sd(con), buf, sizeof(buf));
	ssize_t i;

	if (r <= 0)
	{
		/* EOF (Ctrl-D or piped input exhausted): stop watching stdin but
		   keep running so hub events are still observed until SIGINT. A
		   would-block is spurious (level-triggered epoll) and ignored; any
		   other read error is treated like EOF. */
		if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
		{
			if (g_stdin_flags != -1)
			{
				fcntl(STDIN_FILENO, F_SETFL, g_stdin_flags);
				g_stdin_flags = -1;
			}
			net_con_close(con);
			g_stdin_con = NULL;
		}
		return;
	}

	for (i = 0; i < r; i++)
	{
		char c = buf[i];
		if (c == '\n')
		{
			g_line[g_line_len] = '\0';
			handle_command(client, g_line);
			g_line_len = 0;
		}
		else if (g_line_len < sizeof(g_line) - 1)
		{
			g_line[g_line_len++] = c;
		}
		/* overlong lines past the buffer are truncated at the boundary */
	}
}

static void stdin_setup(struct ADC_client* client)
{
	/* net_con_initialize() will flip fd 0 to non-blocking; fd 0's open file
	   description is shared with the parent shell, so remember the original
	   flags and restore them on teardown (otherwise the shell inherits a
	   non-blocking stdin and its next read fails with EAGAIN). */
	g_stdin_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
	g_stdin_con = net_con_create();
	net_con_initialize(g_stdin_con, STDIN_FILENO, stdin_callback, client, NET_EVENT_READ);
	print_help();
}

static void stdin_teardown(void)
{
	if (g_stdin_flags != -1)
	{
		fcntl(STDIN_FILENO, F_SETFL, g_stdin_flags);
		g_stdin_flags = -1;
	}
	if (g_stdin_con)
	{
		net_con_close(g_stdin_con);
		g_stdin_con = NULL;
	}
}

static int handle(struct ADC_client* client, enum ADC_client_event_type type, struct ADC_client_callback_data* data)
{
	switch (type)
	{
		case ADC_CLIENT_NAME_LOOKUP:
			status("Looking up hostname...");
			break;

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

		case ADC_CLIENT_SSL_OK:
			printf("*** SSL connected (%s/%s).\n", data->tls_info->version, data->tls_info->cipher);
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
			if (data && data->status)
				printf("*** Login error %03d: %s\n", data->status->code, data->status->message ? data->status->message : "");
			else
				status("Login error");
			break;

		case ADC_CLIENT_PROTOCOL_STATUS:
			if (data && data->status)
				printf("*** Status %03d: %s\n", data->status->code, data->status->message ? data->status->message : "");
			break;


		case ADC_CLIENT_MESSAGE:
			on_message(client, data->chat);
			break;

		case ADC_CLIENT_USER_JOIN:
		case ADC_CLIENT_USER_UPDATE:
			user_add(data->user);
			break;

		case ADC_CLIENT_USER_QUIT:
			user_remove(client, data->quit);
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

#if !defined(WIN32)
static struct uhub_notify_handle* notify_handle;

void adm_handle_signal(int sig)
{
	switch (sig)
	{
		case SIGINT:
			LOG_INFO("Interrupted. Shutting down...");
			running = 0;
			break;

		case SIGTERM:
			LOG_INFO("Terminated. Shutting down...");
			running = 0;
			break;

		case SIGPIPE:
			break;

		case SIGHUP:
			break;

		default:
			LOG_TRACE("hub_handle_signal(): caught unknown signal: %d", signal);
			running = 0;
			break;
	}
}

static int signals[] =
{
	SIGINT,  /* Interrupt the application */
	SIGTERM, /* Terminate the application */
	SIGPIPE, /* prevent sigpipe from kills the application */
	SIGHUP,  /* reload configuration */
	0
};

void adm_setup_signal_handlers()
{
	sigset_t sig_set;
	struct sigaction act;
	int i;

	sigemptyset(&sig_set);
	act.sa_mask = sig_set;
	act.sa_flags = SA_ONSTACK | SA_RESTART;
	act.sa_handler = adm_handle_signal;

	for (i = 0; signals[i]; i++)
	{
		if (sigaction(signals[i], &act, 0) != 0)
		{
			LOG_ERROR("Error setting signal handler %d", signals[i]);
		}
	}
}

void adm_setup_control_pipe()
{
	notify_handle = net_notify_create(NULL, NULL);
}

void adm_shutdown_control_pipe()
{
	net_notify_destroy(notify_handle);
	notify_handle = NULL;
}

void adm_shutdown_signal_handlers()
{
}
#endif /* !WIN32 */

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		printf("Usage: %s adc[s]://host:port [password]\n", argv[0]);
		return 1;
	}

	hub_set_log_verbosity(5);
	adm_setup_signal_handlers();

	struct ADC_client* client;
	net_initialize();
	adm_setup_control_pipe();

	client = ADC_client_create("uhub-admin", "stresstester", NULL);
	ADC_client_set_callback(client, handle);
	if (argc > 2)
		ADC_client_set_password(client, argv[2]);
	ADC_client_connect(client, argv[1]);

	stdin_setup(client);

	while (running && net_backend_process()) { }

	stdin_teardown();
	adm_shutdown_control_pipe();

	ADC_client_destroy(client);
	net_destroy();
	adm_shutdown_signal_handlers();
	return 0;
}


