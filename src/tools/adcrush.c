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

#define ADC_CLIENTS_DEFAULT 100
#define ADC_MAX_CLIENTS 25000
#define ADC_CID_SIZE 39
#define BIG_BUFSIZE 32768
#define TIGERSIZE 24
#define STATS_INTERVAL 3
/* Initial connects are spread out instead of fired all at once: a simultaneous
   storm of N SYNs overflows the hub's listen backlog (default 50) and the
   connects that lose the accept race fail. Start at most CONNECT_STAGGER_RATE
   connects per second, but never spread them over more than CONNECT_STAGGER_MAX
   seconds -- the timeout wheel is only TIMEOUT_QUEUE_MAX (120s) deep, so the
   offset must stay well under that. Very large runs reuse the final slot and
   lean on the retry logic for any stragglers. */
#define CONNECT_STAGGER_RATE 50
#define CONNECT_STAGGER_MAX 100
#define ADCRUSH "adcrush/0.3"
#define ADC_NICK "[BOT]adcrush"
#define ADC_DESC "crash\\stest\\sdummy"


#define LVL_INFO 1
#define LVL_DEBUG 2
#define LVL_VERBOSE 3

static const char* cfg_uri = 0; /* address */
static int cfg_debug       = 0; /* debug level */
static int cfg_level       = 1; /* activity level (0..3) */
static int cfg_chat        = 0; /* chat mode, allow sending chat messages */
static int cfg_quiet       = 0; /* quiet mode (no output) */
static int cfg_clients     = ADC_CLIENTS_DEFAULT; /* number of clients */
static int cfg_netstats_interval = STATS_INTERVAL;
static int running         = 1;
static int blank           = 0;
static struct net_statistics* stats_intermediate;
static struct net_statistics* stats_total;

static int handle(struct ADC_client* client, enum ADC_client_callback_type type, struct ADC_client_callback_data* data);
static void timer_callback(struct timeout_evt* t);

static void do_blank(int n)
{
	n++;
	while (n > 0)
	{
		fprintf(stdout, " ");
		n--;
	}
}

struct AdcFuzzUser
{
	struct ADC_client* client;
	struct timeout_evt* timer;
	int logged_in;
	int needs_reconnect; /* connect failed, hub dropped us before login, or initial connect still pending; (re)connect on the next timer tick */
	char nick[24];
	const char* description;
};

#define MAX_CHAT_MSGS 35
const char* chat_messages[MAX_CHAT_MSGS] = {
	"hello",
	"I'm an annoying robot, configured to chat in order to measure performance of the hub.",
	"I apologize for the inconvenience.",
	".",
	":)",
	"can anyone help me, pls?",
	"wtf?",
	"bullshit",
	"resistance is futile.",
	"You crossed the line first, sir. You squeezed them, you hammered them to the point of desperation. And in their desperation they turned to a man they didn't fully understand.",
	"beam me up, scotty",
	"morning",
	"You know where Harvey is? You know who he is?",
	"gtg",
	"thanks",
	"*punt*",
	"*nudge*",
	"that's ok",
	"...anyway",
	"hola",
	"hey",
	"hi",
	"nevermind",
	"i think so",
	"dunno",
	"debian ftw",
	"oops",
	"how do I search?",
	"how do I enable active mode?",
	"home, sweet home...",
	"later",
	"Good evening, ladies and gentlemen. We are tonight's entertainment! I only have one question. Where is Harvey Dent?",
	"You know where I can find Harvey? I need to talk to him about something. Just something, a little.",
	"We really should stop fighting, we'll miss the fireworks!",
	"Wanna know how I got these scars?",
};

#define MAX_SEARCH_MSGS 10
const char* search_messages[MAX_SEARCH_MSGS] = {
	"ANmp3 TOauto",
	"ANxxx TOauto",
	"ANdivx TOauto",
	"ANtest ANfoo TOauto",
	"ANwmv TO1289718",
	"ANbabe TO8981884",
	"ANpr0n TOauto",
	"ANmusic TOauto",
	"ANvideo TOauto",
	"ANburnout ANps3 TOauto",
};



static void bot_output(struct ADC_client* client, int level, const char* format, ...)
{
	char logmsg[1024];
	va_list args;
	va_start(args, format);
	vsnprintf(logmsg, 1024, format, args);
	va_end(args);

	if (cfg_debug >= level)
	{
		int num = fprintf(stdout, "* [%p] %s", client, logmsg);
		do_blank(blank - num);
		fprintf(stdout, "\n");
	}
}


static size_t get_wait_rand(size_t max)
{
	static size_t next = 0;
	if (next == 0) next = (size_t) time(0);
	next = (next * 1103515245) + 12345;
	return ((size_t )(next / 65536) % max);
}

static size_t get_next_timeout_evt()
{
	switch (cfg_level)
	{
		case 0: return get_wait_rand(120);
		case 1: return get_wait_rand(60);
		case 2: return get_wait_rand(15);
		case 3: return get_wait_rand(5);
	}
	return 0;
}



static void perf_chat(struct ADC_client* client, int priv)
{
	size_t r = get_wait_rand(MAX_CHAT_MSGS-1);
	char* msg = adc_msg_escape(chat_messages[r]);
	struct adc_message* cmd = NULL;

	if (priv)
		cmd = adc_msg_construct_source_dest(ADC_CMD_DMSG, ADC_client_get_sid(client), ADC_client_get_sid(client), strlen(msg));
	else
		cmd = adc_msg_construct_source(ADC_CMD_BMSG, ADC_client_get_sid(client), strlen(msg));
	hub_free(msg);

	ADC_client_send(client, cmd);
}

static void perf_search(struct ADC_client* client)
{
	size_t r = get_wait_rand(MAX_SEARCH_MSGS-1);
	size_t pst = get_wait_rand(100);
	struct adc_message* cmd = NULL;

	if (pst > 80)
	{
		cmd = adc_msg_construct_source(ADC_CMD_FSCH, ADC_client_get_sid(client), strlen(search_messages[r]) + 6);
		adc_msg_add_argument(cmd, "+TCP4");
	}
	else
	{
		cmd = adc_msg_construct_source(ADC_CMD_BSCH, ADC_client_get_sid(client), strlen(search_messages[r]) + 6);
		adc_msg_add_argument(cmd, "+TCP4");
	}
	ADC_client_send(client, cmd);
}

static void perf_ctm(struct ADC_client* client)
{
	struct adc_message* cmd = adc_msg_construct_source_dest(ADC_CMD_DCTM, ADC_client_get_sid(client), ADC_client_get_sid(client), 32);
	adc_msg_add_argument(cmd, "ADC/1.0");
	adc_msg_add_argument(cmd, "TOKEN123456");
	adc_msg_add_argument(cmd, sid_to_string(ADC_client_get_sid(client)));
	ADC_client_send(client, cmd);
}


static void perf_update(struct ADC_client* client)
{
	char buf[16] = { 0, };
	int n = (int) get_wait_rand(10)+1;
	struct adc_message* cmd = adc_msg_construct_source(ADC_CMD_BINF, ADC_client_get_sid(client), 32);
	snprintf(buf, sizeof(buf), "HN%d", n);
	adc_msg_add_argument(cmd, buf);
	ADC_client_send(client, cmd);
}

static void client_disconnect(struct AdcFuzzUser* c)
{
		/* The client object is NULL for a slot whose initial connect is still
		   pending (see client_schedule), so guard before destroying it. */
		if (c->client)
		{
			ADC_client_destroy(c->client);
			c->client = 0;
		}

		if (c->timer)
		{
			timeout_queue_remove(net_backend_get_timeout_queue(), c->timer);
			hub_free(c->timer);
			c->timer = 0;
		}

		c->logged_in = 0;
}

/* Arm a slot's timer without connecting yet. The first timer tick performs the
   initial connect via the needs_reconnect path in timer_callback, which lets
   runloop() spread the initial connects out over time. nick/description are
   stored on the slot and reused for every (re)connect. */
static void client_schedule(struct AdcFuzzUser* c, size_t timeout)
{
	c->client = 0;
	c->logged_in = 0;
	c->needs_reconnect = 1;
	c->timer = (struct timeout_evt*) hub_malloc(sizeof(struct timeout_evt));
	timeout_evt_initialize(c->timer, timer_callback, c);
	timeout_queue_insert(net_backend_get_timeout_queue(), c->timer, timeout);
}

static void client_connect(struct AdcFuzzUser* c)
{
	size_t timeout = get_next_timeout_evt();
	struct ADC_client* client = ADC_client_create(c->nick, c->description, c);

	c->client = client;
	c->timer = (struct timeout_evt*) hub_malloc(sizeof(struct timeout_evt));
	timeout_evt_initialize(c->timer, timer_callback, c);
	timeout_queue_insert(net_backend_get_timeout_queue(), c->timer, timeout);

	bot_output(client, LVL_VERBOSE, "Initial timeout: %d seconds", timeout);
	c->logged_in = 0;
	c->needs_reconnect = 0;

	ADC_client_set_callback(client, handle);
	ADC_client_connect(client, cfg_uri);
}

static void perf_normal_action(struct ADC_client* client)
{
	struct AdcFuzzUser* user = (struct AdcFuzzUser*) ADC_client_get_ptr(client);
	size_t r = get_wait_rand(5);
	size_t p = get_wait_rand(100);
	(void) p; /* reserved for the commented-out probability checks below */

	switch (r)
	{
		case 0:
			// if (p > (90 - (10 * cfg_level)))
			{
				bot_output(client, LVL_VERBOSE, "timeout -> disconnect");
				client_disconnect(user);
				client_connect(user);
			}
			break;

		case 1:
			if (cfg_chat)
			{
				bot_output(client, LVL_VERBOSE, "timeout -> chat");
				if (user->logged_in)
					perf_chat(client, 0);

			}
			break;

		case 2:
			bot_output(client, LVL_VERBOSE, "timeout -> search");
			if (user->logged_in)
				perf_search(client);
			break;

		case 3:
			bot_output(client, LVL_VERBOSE, "timeout -> update");
			if (user->logged_in)
				perf_update(client);
			break;

		case 4:
			bot_output(client, LVL_VERBOSE, "timeout -> privmsg");
			if (user->logged_in)
				perf_chat(client, 1);
			break;

		case 5:
			bot_output(client, LVL_VERBOSE, "timeout -> ctm/rcm");
			if (user->logged_in)
				perf_ctm(client);
			break;

	}
}

static int handle(struct ADC_client* client, enum ADC_client_callback_type type, struct ADC_client_callback_data* data)
{
	struct AdcFuzzUser* user = (struct AdcFuzzUser*) ADC_client_get_ptr(client);

	switch (type)
	{
		case ADC_CLIENT_CONNECTING:
			bot_output(client, LVL_DEBUG, "*** Connecting...");
			break;

		case ADC_CLIENT_CONNECTED:
			// bot_output(client, LVL_DEBUG, "*** Connected.");
			break;

		case ADC_CLIENT_DISCONNECTED:
			bot_output(client, LVL_DEBUG, "*** Disconnected.");
			/* The connection is gone; stop issuing timer-driven actions against
			   it, otherwise the next perf_* call sends on a NULL connection. */
			user->logged_in = 0;
			/* This fires when a connect attempt failed or the hub dropped us
			   before login. adcrush otherwise only ever reconnects clients that
			   reached the logged-in state (via perf_normal_action), so a client
			   lost during the initial connect storm would stay dead for the rest
			   of the run -- which is why a -n 1000 run settles at ~half. Flag it
			   so the next timer tick reconnects it. (Our own teardown in
			   client_disconnect() goes through ADC_client_destroy(), which does
			   not invoke this callback, so this never races the case-0 path.) */
			user->needs_reconnect = 1;
			break;

		case ADC_CLIENT_LOGGING_IN:
			// bot_output(client, LVL_DEBUG, "*** Logging in...");
			break;

		case ADC_CLIENT_PASSWORD_REQ:
			//bot_output(client, LVL_DEBUG, "*** Requesting password.");
			break;

		case ADC_CLIENT_LOGGED_IN:
			bot_output(client, LVL_DEBUG, "*** Logged in.");
			user->logged_in = 1;
			break;

		case ADC_CLIENT_LOGIN_ERROR:
			if (data && data->status)
				bot_output(client, LVL_DEBUG, "*** Login error %03d: %s", data->status->code, data->status->message ? data->status->message : "");
			else
				bot_output(client, LVL_DEBUG, "*** Login error");
			break;

		case ADC_CLIENT_PROTOCOL_STATUS:
			break;

		case ADC_CLIENT_SSL_HANDSHAKE:
		case ADC_CLIENT_SSL_OK:
			break;

		case ADC_CLIENT_MESSAGE:
// 			bot_output(client, LVL_DEBUG, "    <%s> %s", sid_to_string(data->chat->from_sid), data->chat->message);
			break;

		case ADC_CLIENT_USER_JOIN:
			break;

		case ADC_CLIENT_USER_QUIT:
			break;

		case ADC_CLIENT_SEARCH_REQ:
			break;

		case ADC_CLIENT_HUB_INFO:
			break;

		default:
			bot_output(client, LVL_DEBUG, "Not handled event=%d\n", (int) type);
			return 0;
			break;
	}
	return 1;
}

static void timer_callback(struct timeout_evt* t)
{
	size_t timeout = get_next_timeout_evt();
	struct AdcFuzzUser* client = (struct AdcFuzzUser*) t->ptr;
	if (client->logged_in)
	{
		perf_normal_action(client->client);
		bot_output(client->client, LVL_VERBOSE, "Next timeout: %d seconds", (int) timeout);
	}
	else if (client->needs_reconnect)
	{
		/* Either this slot's initial connect was deferred (staggered startup) or
		   a previous attempt failed / the hub dropped us before login. Tear down
		   whatever is there (client_disconnect tolerates a NULL client) and start
		   a fresh connection, reusing the slot's stored nick/description. The
		   random per-client timer spreads these out, so retries do not re-create
		   the simultaneous-connect storm. */
		bot_output(client->client, LVL_VERBOSE, "timeout -> (re)connect");
		client_disconnect(client);
		client_connect(client);
	}
	timeout_queue_reschedule(net_backend_get_timeout_queue(), client->timer, timeout);
}

static struct AdcFuzzUser client[ADC_MAX_CLIENTS];
void p_status()
{
	static char rxbuf[64] = { "0 B" };
	static char txbuf[64] = { "0 B" };
	int logged_in = 0;
	size_t n;
	static size_t rx = 0, tx = 0;

	for (n = 0; n < (size_t) cfg_clients; n++)
	{
		if (client[n].logged_in)
			logged_in++;
	}

	if (difftime(time(NULL), stats_intermediate->timestamp) >= cfg_netstats_interval)
	{
		net_stats_get(&stats_intermediate, &stats_total);
		rx = stats_intermediate->rx / cfg_netstats_interval;
		tx = stats_intermediate->tx / cfg_netstats_interval;
		net_stats_reset();
		format_size(rx, rxbuf, sizeof(rxbuf));
		format_size(tx, txbuf, sizeof(txbuf));
	}

	n = blank;
	blank = printf("Connected bots: %d/%d, network: rx=%s/s, tx=%s/s", logged_in, cfg_clients, rxbuf, txbuf);
	if (n > (size_t) blank)
		do_blank(n-blank);
	printf("\r");
}

void runloop(size_t clients)
{
	size_t n = 0;
	blank = 0;

	for (n = 0; n < clients; n++)
	{
		struct AdcFuzzUser* c = &client[n];
		size_t offset;

		snprintf(c->nick, sizeof(c->nick), "adcrush_%d", (int) n);
		c->description = "stresstester";

		/* Spread the initial connects out instead of firing every SYN at once.
		   Start CONNECT_STAGGER_RATE per second, capped at CONNECT_STAGGER_MAX
		   seconds so the offset stays inside the timeout wheel. The first tick
		   (>= 1s out) performs the connect. */
		offset = 1 + MIN(n / CONNECT_STAGGER_RATE, (size_t) CONNECT_STAGGER_MAX);
		client_schedule(c, offset);
	}

	while (running && net_backend_process())
	{
		p_status();
	}

	for (n = 0; n < clients; n++)
	{
		struct AdcFuzzUser* c = &client[n];
		client_disconnect(c);
	}
}

static void print_version()
{
	printf(ADCRUSH "\n");
	printf("Copyright (C) 2008-2026, Jan Vidar Krey\n");
	printf("\n");
}

static void print_usage(const char* program)
{
	print_version();

	printf("Usage: %s [adc[s]://<host>:<port>] [options]\n", program);

	printf("\n");
	printf("  OPTIONS\n");
	printf("    -l <0-3>    Level: 0=polite, 1=normal (default), 2=aggressive, 3=excessive.\n");
	printf("    -n <num>    Number of concurrent connections\n");
	printf("    -c          Allow broadcasting chat messages.\n");
	printf("    -d          Enable debug output.\n");
	printf("    -q          Quiet mode (no output).\n");
	printf("    -i <num>    Average network statistics for given interval (default: 3)\n");
	printf("\n");

	exit(0);
}

int parse_address(const char* arg)
{
	if (!arg || strlen(arg) < 9)
		return 0;

	if (strncmp(arg, "adc://", 6) && strncmp(arg, "adcs://", 7))
		return 0;

	cfg_uri = arg;
	return 1;
}

int parse_arguments(int argc, char** argv)
{
	int ok = 1;
	int opt;
	for (opt = 2; opt < argc; opt++)
	{
		if      (!strcmp(argv[opt], "-c"))
			cfg_chat = 1;
		else if (!strncmp(argv[opt], "-d", 2))
			cfg_debug += strlen(argv[opt]) - 1;
		else if (!strcmp(argv[opt], "-q"))
			cfg_quiet = 1;
		else if (!strcmp(argv[opt], "-l") && (++opt) < argc)
		{
			cfg_level = MIN(MAX(uhub_atoi(argv[opt]), 0), 3);
		}
		else if (!strcmp(argv[opt], "-i") && (++opt) < argc)
		{
			cfg_netstats_interval = MAX(uhub_atoi(argv[opt]), 1);
		}
		else if (!strcmp(argv[opt], "-n") && (++opt) < argc)
		{
			cfg_clients = MIN(MAX(uhub_atoi(argv[opt]), 1), ADC_MAX_CLIENTS);
		}
	}
	return ok;
}


void parse_command_line(int argc, char** argv)
{
	if (argc < 2 ||
		!parse_address(argv[1]) ||
		!parse_arguments(argc, argv))
	{
		print_usage(argv[0]);
	}
}

int main(int argc, char** argv)
{

	parse_command_line(argc, argv);

	/* Writing to a peer that has gone away (e.g. the hub disconnecting many bots
	   at once) would otherwise deliver SIGPIPE and kill the process. The hub
	   itself ignores SIGPIPE via its own signal setup; adcrush has its own main()
	   and must do the same. */
#ifdef SIGPIPE
	signal(SIGPIPE, SIG_IGN);
#endif

	net_initialize();
	net_stats_get(&stats_intermediate, &stats_total);

	hub_log_initialize(NULL, 0);
	hub_set_log_verbosity(1000);
	setvbuf(stdout, NULL, _IONBF, 0);
	runloop(cfg_clients);

	net_destroy();
	return 0;
}
