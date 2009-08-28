/**
 * An ADC client emulator.
 */

#include "adcclient.h"

#define ADC_CLIENTS_DEFAULT 100
#define ADC_MAX_CLIENTS 25000
#define ADC_CID_SIZE 39
#define BIG_BUFSIZE 32768
#define TIGERSIZE 24
#define ADCRUSH "adcrush/0.2"
#define ADC_NICK "[BOT]adcrush"
#define ADC_DESC "crash\\stest\\sdummy"

#define LVL_INFO 1
#define LVL_DEBUG 2
#define LVL_VERBOSE 3

static int cfg_mode     = 0; // See enum operationMode
static char* cfg_host   = 0;
static int cfg_port     = 0;
static int cfg_debug    = 0; /* debug level */
static int cfg_level    = 1; /* activity level (0..3) */
static int cfg_chat     = 0; /* chat mode, allow sending chat messages */
static int cfg_quiet    = 0; /* quiet mode (no output) */
static int cfg_clients  = ADC_CLIENTS_DEFAULT; /* number of clients */

static int running = 1;

static struct sockaddr_in saddr;


enum operationMode
{
	mode_performance = 0x01,
	mode_bugs        = 0x02,
	mode_security    = 0x04,
	mode_log         = 0x08,
};

struct commandPattern
{
	unsigned char mode; /* see enum commandMode */
	char cmd[3];
	unsigned char validity; /* see enum commandValidity */
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

	if (cfg_mode == mode_log)
	{
	    fprintf(stdout, "%s\n", logmsg);
	}
	else
	{
	    if (cfg_debug >= level)
		fprintf(stdout, "* [%p] %s\n", client, logmsg);
	}
}

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
		ADC_client_connect(c, "adc://adc.extatic.org:1511");
	}

	event_dispatch();

	for (n = 0; n < clients; n++)
	{
		ADC_client_destroy(client[n]);
		free(client[n]);
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

	printf("Usage: %s <mode> (adc://<host>:<port>) [options]\n", program);
	
	printf("\n");
	printf("  Modes\n");
	printf("    perf        Do performance testing using multiple clients\n");
	printf("    bugs        Bugs mode, use fuzzer to construct pseudo-random commands.\n");
	printf("    security    Perform security tests for the hub.\n");
	printf("    log         Connect one client to the hub and log the output hub.\n");
	
	printf("\n");
	printf("  General options\n");
	printf("    -c          Allow broadcasting chat messages.\n");
	printf("    -d          Enable debug output.\n");
	printf("    -q          Quiet mode (no output).\n");
	
	printf("\n");
	printf("  Performance options:\n");
	printf("    -l <0-3>    Level: 0=polite, 1=normal (default), 2=aggressive, 3=excessive.\n");
	printf("    -n <num>    Number of concurrent connections\n");
	
	printf("\n");
	
	exit(0);
}


int set_defaults()
{
    switch (cfg_mode)
    {
	case mode_performance:
	    break;
	case mode_bugs:
	    break;
	case mode_security:
	    break;
	case mode_log:
	    cfg_quiet = 0;
	    cfg_debug = 2;
	    cfg_clients = 1;
	    break;
    }
    return 1;
}

int parse_mode(const char* arg)
{
	cfg_mode = 0;

	if      (!strcmp(arg, "perf"))
		cfg_mode = mode_performance;
	else if (!strcmp(arg, "bugs"))
		cfg_mode = mode_bugs;
	else if (!strcmp(arg, "security"))
		cfg_mode = mode_security;
	else if (!strcmp(arg, "log"))
		cfg_mode = mode_log;

	return cfg_mode;
}

int parse_address(const char* arg)
{
	char* split;
	struct hostent* dns;
	struct in_addr* addr;

	if (!arg)
		return 0;

	if (strlen(arg) < 9)
		return 0;
	
	if (strncmp(arg, "adc://", 6))
		return 0;
	
	split = strrchr(arg+6, ':');
	if (split == 0 || strlen(split) < 2 || strlen(split) > 6)
		return 0;
	
	cfg_port = strtol(split+1, NULL, 10);
	if (cfg_port <= 0 || cfg_port > 65535)
		return 0;
	
	split[0] = 0;

	dns = gethostbyname(arg+6);
	if (dns)
	{
		addr = (struct in_addr*) dns->h_addr_list[0];
		cfg_host = strdup(inet_ntoa(*addr));
	}
	
	if (!cfg_host)
		return 0;
	
	return 1;
}

int parse_arguments(int argc, char** argv)
{
	int ok = 1;
	int opt;
	for (opt = 3; opt < argc; opt++)
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
		!parse_mode(argv[1]) ||
		!set_defaults() ||
		!parse_address(argv[2]) ||
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

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port   = htons(cfg_port);
	net_string_to_address(AF_INET, cfg_host, &saddr.sin_addr);

	runloop(cfg_clients);

	net_destroy();
	return 0;
}

