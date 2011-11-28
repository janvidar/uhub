/**
 * An ADC client emulator.
 */

#include "adcclient.h"

#define ADC_CLIENTS_DEFAULT 100
#define ADC_MAX_CLIENTS 25000
#define ADC_CID_SIZE 39
#define BIG_BUFSIZE 32768
#define TIGERSIZE 24
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
static int running         = 1;

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
	fprintf(stdout, "* [%p] %s\n", client, logmsg);
}

#if 0
static size_t get_wait_rand(size_t max)
{
	static size_t next = 0;
	if (next == 0) next = (size_t) time(0);
	next = (next * 1103515245) + 12345;
	return ((size_t )(next / 65536) % max);
}


static void perf_result(struct ADC_client* client, sid_t target, const char* what, const char* token);

static void perf_chat(struct ADC_client* client, int priv)
{
	char buf[1024] = { 0, };
	size_t r = get_wait_rand(MAX_CHAT_MSGS-1);
	char* msg = adc_msg_escape(chat_messages[r]);

	if (priv)
	{
		strcat(buf, "EMSG ");
		strcat(buf, sid_to_string(client->sid));
		strcat(buf, " ");
		strcat(buf, sid_to_string(client->sid));
	}
	else
	{
		strcat(buf, "BMSG ");
		strcat(buf, sid_to_string(client->sid));
	}
	strcat(buf, " ");

	strcat(buf, msg);
	hub_free(msg);
	
	strcat(buf, "\n");
	ADC_client_send(client, buf);
}

static void perf_search(struct ADC_client* client)
{
	char buf[1024] = { 0, };
	size_t r = get_wait_rand(MAX_SEARCH_MSGS-1);
	size_t pst = get_wait_rand(100);
	
	if (pst > 80)
	{
		strcat(buf, "FSCH ");
		strcat(buf, sid_to_string(client->sid));
		strcat(buf, " +TCP4 ");
	}
	else
	{
		strcat(buf, "BSCH ");
		strcat(buf, sid_to_string(client->sid));
		strcat(buf, " ");
	}
	strcat(buf, search_messages[r]);
	strcat(buf, "\n");
	ADC_client_send(client, buf);
}

static void perf_result(struct ADC_client* client, sid_t target, const char* what, const char* token)
{
	char buf[1024] = { 0, };
	strcat(buf, "DRES ");
	strcat(buf, sid_to_string(client->sid));
	strcat(buf, " ");
	strcat(buf, sid_to_string(target));
	strcat(buf, " FN" "test/");
	strcat(buf, what);
	strcat(buf, ".dat");
	strcat(buf, " SL" "0");
	strcat(buf, " SI" "908987128912");
	strcat(buf, " TR" "5T6YJYKO3WECS52BKWVSOP5VUG4IKNSZBZ5YHBA");
	strcat(buf, " TO");
	strcat(buf, token);
	strcat(buf, "\n");
	ADC_client_send(client, buf);
}

static void perf_ctm(struct ADC_client* client)
{
	char buf[1024] = { 0, };
	strcat(buf, "DCTM ");
	strcat(buf, sid_to_string(client->sid));
	strcat(buf, " ");
	strcat(buf, sid_to_string(client->sid));
	strcat(buf, " ");
	strcat(buf, "ADC/1.0");
	strcat(buf, " TOKEN111");
	strcat(buf, sid_to_string(client->sid));
	strcat(buf, "\n");
	ADC_client_send(client, buf);
}


static void perf_update(struct ADC_client* client)
{
	char buf[1024] = { 0, };
	int n = (int) get_wait_rand(10)+1;
	
	strcat(buf, "BINF ");
	strcat(buf, sid_to_string(client->sid));
	strcat(buf, " HN");
	strcat(buf, uhub_itoa(n));

	strcat(buf, "\n");
	ADC_client_send(client, buf);
}

static void perf_normal_action(struct ADC_client* client)
{
	size_t r = get_wait_rand(5);
	size_t p = get_wait_rand(100);

	switch (r)
	{
		case 0:
			if (p > (90 - (10 * cfg_level)))
			{
				bot_output(client, LVL_VERBOSE, "timeout -> disconnect");
				ADC_client_disconnect(client);
			}
			break;

		case 1:
			if (cfg_chat)
			{
				bot_output(client, LVL_VERBOSE, "timeout -> chat");
				perf_chat(client, 0);
				
			}
			break;

		case 2:
			bot_output(client, LVL_VERBOSE, "timeout -> search");
			perf_search(client);
			break;

		case 3:
			bot_output(client, LVL_VERBOSE, "timeout -> update");
			perf_update(client);
			break;

		case 4:
			bot_output(client, LVL_VERBOSE, "timeout -> privmsg");
			perf_chat(client, 1);
			break;

		case 5:
			bot_output(client, LVL_VERBOSE, "timeout -> ctm/rcm");
			perf_ctm(client);
			break;

	}
}
#endif

static int handle(struct ADC_client* client, enum ADC_client_callback_type type, struct ADC_client_callback_data* data)
{
	switch (type)
	{
		case ADC_CLIENT_CONNECTING:
			bot_output(client, LVL_DEBUG, "*** Connecting...");
			break;

		case ADC_CLIENT_CONNECTED:
			bot_output(client, LVL_DEBUG, "*** Connected.");
			break;

		case ADC_CLIENT_DISCONNECTED:
			bot_output(client, LVL_DEBUG, "*** Disconnected.");
			break;

		case ADC_CLIENT_LOGGING_IN:
			bot_output(client, LVL_DEBUG, "*** Logging in...");
			break;

		case ADC_CLIENT_PASSWORD_REQ:
			bot_output(client, LVL_DEBUG, "*** Requesting password.");

		case ADC_CLIENT_LOGGED_IN:
			bot_output(client, LVL_DEBUG, "*** Logged in.");
			break;

		case ADC_CLIENT_LOGIN_ERROR:
			bot_output(client, LVL_DEBUG, "*** Login error");
			break;

		case ADC_CLIENT_MESSAGE:
			bot_output(client, LVL_DEBUG, "    <%s> %s", sid_to_string(data->chat->from_sid), data->chat->message);
			break;

		case ADC_CLIENT_USER_JOIN:
			bot_output(client, LVL_VERBOSE, "    JOIN: %s", data->user->name);
			break;

		case ADC_CLIENT_USER_QUIT:
			bot_output(client, LVL_VERBOSE, "    QUIT");
			break;

		case ADC_CLIENT_SEARCH_REQ:
			break;

		case ADC_CLIENT_HUB_INFO:
			bot_output(client, LVL_DEBUG, "    Hub: \"%s\" [%s]\n"
				   "         \"%s\"\n", data->hubinfo->name, data->hubinfo->version, data->hubinfo->description);
			break;

		default:
			bot_output(client, LVL_DEBUG, "Not handled event=%d\n", (int) type);
			return 0;
			break;
	}
	return 1;
}

void runloop(size_t clients)
{
	size_t n = 0;
	struct ADC_client* client[ADC_MAX_CLIENTS];

	for (n = 0; n < clients; n++)
	{
		struct ADC_client* c = malloc(sizeof(struct ADC_client));
		client[n] = c;

		char nick[20];
		snprintf(nick, 20, "adcrush_%d", (int) n);

		ADC_client_create(c, nick, "stresstester");
		ADC_client_set_callback(c, handle);
		ADC_client_connect(c, cfg_uri);
	}

	while (net_backend_process())
	{
	}

	for (n = 0; n < clients; n++)
	{
		ADC_client_destroy(client[n]);
		free(client[n]);
		client[n] = 0;
	}
}

static void print_version()
{
	printf(ADCRUSH "\n");
	printf("Copyright (C) 2008-2009, Jan Vidar Krey\n");
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
	
	net_initialize();

	hub_log_initialize(NULL, 0);
	hub_set_log_verbosity(1000);

	runloop(cfg_clients);

	net_destroy();
	return 0;
}
