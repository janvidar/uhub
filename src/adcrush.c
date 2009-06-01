/**
 * An ADC client emulator.
 */

#include "uhub.h"

#define ADC_CLIENTS_DEFAULT 100
#define ADC_MAX_CLIENTS 25000

#define ADC_BUFSIZE 16384
#define ADC_SIDSIZE 4
#define ADC_CID_SIZE 39

#define BIG_BUFSIZE 131072
#define TIGERSIZE 24

#define ADC_HANDSHAKE "HSUP ADBASE ADTIGR\n"
#define ADCRUSH "adcrush/0.2"
#define ADC_NICK "[BOT]adcrush"
#define ADC_DESC "crash\\stest\\sdummy"

struct ADC_client;

static void ADC_client_on_disconnected(struct ADC_client*);
static void ADC_client_on_connected(struct ADC_client*);
static void ADC_client_on_login(struct ADC_client*);
static void ADC_client_connect(struct ADC_client*);
static void ADC_client_disconnect(struct ADC_client*);
static int  ADC_client_create(struct ADC_client* client, int num);
static void ADC_client_destroy(struct ADC_client* client);

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

enum commandMode
{
	cm_bcast    = 0x01, /* B - broadcast */
	cm_dir      = 0x02, /* D - direct message */
	cm_echo     = 0x04, /* E - echo message */
	cm_fcast    = 0x08, /* F - feature cast message */
	cm_c2h      = 0x10, /* H - client to hub message */
	cm_h2c      = 0x20, /* I - hub to client message */
	cm_c2c      = 0x40, /* C - client to client message */
	cm_udp      = 0x80, /* U - udp message (client to client) */
};

enum commandValidity
{
	cv_protocol = 0x01,
	cv_identify = 0x02,
	cv_verify   = 0x04,
 	cv_normal   = 0x08,
};

enum protocolState
{
	ps_none     = 0x00, /* none or disconnected */
	ps_conn     = 0x01, /* connecting... */
	ps_protocol = 0x02,
	ps_identify = 0x04,
	ps_verify   = 0x08,
	ps_normal   = 0x10,
};

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

const struct commandPattern patterns[] =
{
	{ cm_c2h | cm_c2c | cm_h2c,                     "SUP", cv_protocol | cv_normal }, /* protocol support */
	{ cm_bcast | cm_h2c | cm_c2c,                   "INF", cv_identify | cv_verify | cv_normal }, /* info message */
	{ cm_bcast | cm_h2c | cm_c2c | cm_c2h | cm_udp, "STA", cv_protocol | cv_identify | cv_verify | cv_normal }, /* status message */
	{ cm_bcast | cm_dir | cm_echo | cm_h2c,         "MSG", cv_normal },   /* chat message */
	{ cm_bcast | cm_dir | cm_echo | cm_fcast,       "SCH", cv_normal },   /* search */
	{ cm_dir | cm_udp,                              "RES", cv_normal },   /* search result */
	{ cm_dir | cm_echo,                             "CTM", cv_normal },   /* connect to me */
	{ cm_dir | cm_echo,                             "RCM", cv_normal },   /* reversed, connect to me */
	{ cm_h2c,                                       "QUI", cv_normal },   /* quit message */
	{ cm_h2c,                                       "GPA", cv_identify }, /* password request */
	{ cm_c2h,                                       "PAS", cv_verify }    /* password response */
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

struct ADC_client
{
	int  sd;
	int  num;
	sid_t sid;
	enum protocolState state;
	char info[ADC_BUFSIZE];
	char recvbuf[BIG_BUFSIZE];
	char sendbuf[BIG_BUFSIZE];
	size_t s_offset;
	size_t r_offset;
	struct event ev_read;
	struct event ev_write;
	struct event ev_timer;
	size_t timeout;
};



static void bot_output(struct ADC_client* client, const char* format, ...)
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
	    if (cfg_debug)
		fprintf(stdout, "* [%4d] %s\n", client->num, logmsg);
	}
}

static void adc_cid_pid(struct ADC_client* client)
{
	char seed[64];
	char pid[64];
	char cid[64];
	uint64_t tiger_res1[3];
	uint64_t tiger_res2[3];

	/* create cid+pid pair */
	memset(seed, 0, 64);
	snprintf(seed, 64, ADCRUSH "%p/%d", client, (int) client->num);
	
	tiger((uint64_t*) seed, strlen(seed), tiger_res1);
	base32_encode((unsigned char*) tiger_res1, TIGERSIZE, pid);
	tiger((uint64_t*) tiger_res1, TIGERSIZE, tiger_res2);
	base32_encode((unsigned char*) tiger_res2, TIGERSIZE, cid);
	
	cid[ADC_CID_SIZE] = 0;
	pid[ADC_CID_SIZE] = 0;
	
	strcat(client->info, " PD");
	strcat(client->info, pid);
	strcat(client->info, " ID");
	strcat(client->info, cid);
}

static size_t get_wait_rand(size_t max)
{
	static size_t next = 0;
	if (next == 0) next = (size_t) time(0);
	next = (next * 1103515245) + 12345;
	return ((size_t )(next / 65536) % max);
}

static void client_reschedule_timeout(struct ADC_client* client)
{
	size_t next_timeout = 0;
	struct timeval timeout = { 0, 0 };
	
	switch (client->state)
	{
		case ps_conn:     next_timeout = 30; break;
		case ps_protocol: next_timeout = 30; break;
		case ps_identify: next_timeout = 30; break;
		case ps_verify:   next_timeout = 30; break;
		case ps_normal:   next_timeout = 120; break;
		case ps_none:     next_timeout = 120; break;
	}
	
	if (client->state == ps_normal || client->state == ps_none)
	{
		switch (cfg_level)
		{
			case 0: /* polite */
				next_timeout *= 4;
				break;
					
			case 1: /* normal */
				break;
				
			case 2: /* aggressive */
				next_timeout /= 8;
				break;
				
			case 3: /* excessive */
				next_timeout /= 16;

			case 4: /* excessive */
				next_timeout /= 32;
		}

	}


	if (client->state == ps_conn)
		client->timeout = MAX(next_timeout, 1);
	else
		client->timeout = get_wait_rand(MAX(next_timeout, 1));

	if (!client->timeout) client->timeout++;

	timeout.tv_sec = (time_t) client->timeout;
	evtimer_add(&client->ev_timer, &timeout);
}

static void set_state_timeout(struct ADC_client* client, enum protocolState state)
{
	client->state = state;
	client_reschedule_timeout(client);
}

static void send_client(struct ADC_client* client, char* msg)
{
	int ret = net_send(client->sd, msg, strlen(msg), UHUB_SEND_SIGNAL);
	
	if (cfg_debug > 1)
	{
		char* dump = strdup(msg);
		dump[strlen(msg) - 1] = 0;
		bot_output(client, "- SEND: '%s'", dump);
		free(dump);
	}
	
 	if (ret != strlen(msg))
	{
		if (ret == -1)
		{
			if (net_error() != EWOULDBLOCK)
				ADC_client_on_disconnected(client);
		}
		else
		{
			/* FIXME: Not all data sent! */
			printf("ret (%d) != msg->length (%d)\n", ret, (int) strlen(msg));
		}
	}
}


static void ADC_client_on_connected(struct ADC_client* client)
{
	send_client(client, ADC_HANDSHAKE);
	set_state_timeout(client, ps_protocol);
	bot_output(client, "connected.");
}

static void ADC_client_on_disconnected(struct ADC_client* client)
{
	event_del(&client->ev_read);
	event_del(&client->ev_write);
	
	net_close(client->sd);
	client->sd = -1;
	
	bot_output(client, "disconnected.");
	set_state_timeout(client, ps_none);
}

static void ADC_client_on_login(struct ADC_client* client)
{
	bot_output(client, "logged in.");
	set_state_timeout(client, ps_normal);
}


static void send_client_info(struct ADC_client* client)
{
	client->info[0] = 0;
	strcat(client->info, "BINF ");
	strcat(client->info, sid_to_string(client->sid));
	strcat(client->info, " NI" ADC_NICK);
	if (cfg_clients > 1)
	{
	    strcat(client->info, "_");
	    strcat(client->info, uhub_itoa(client->num));
	}
	strcat(client->info, " VE" ADCRUSH);
	strcat(client->info, " DE" ADC_DESC);
	strcat(client->info, " I40.0.0.0");
	strcat(client->info, " EMuhub@extatic.org");
	strcat(client->info, " SL3");
	strcat(client->info, " HN1");
	strcat(client->info, " HR1");
	strcat(client->info, " HO1");
	
	adc_cid_pid(client);
	
	strcat(client->info, "\n");
	
	send_client(client, client->info);
}

static void perf_result(struct ADC_client* client, sid_t target, const char* what, const char* token);

static int recv_client(struct ADC_client* client)
{
	ssize_t size = 0;
	if (cfg_mode != mode_performance || (cfg_mode == mode_performance && (get_wait_rand(100) < (90 - (15 * cfg_level)))))
	{
		size = net_recv(client->sd, &client->recvbuf[client->r_offset], ADC_BUFSIZE - client->r_offset, 0);
	}
	else
	{
		if (get_wait_rand(1000) == 99)
			return -1; /* Can break tings badly! :-) */
		else
			return 0;
	}
	if (size == 0 || ((size == -1 && net_error() != EWOULDBLOCK)))
		return -1;
	client->recvbuf[client->r_offset + size] = 0;

	char* start = client->recvbuf;
	char* pos;
	char* lastPos;
	while ((pos = strchr(start, '\n')))
	{
		lastPos = pos;
		pos[0] = 0;
		
		if (cfg_debug > 1)
		{
			bot_output(client, "- RECV: '%s'", start);
		}
		
		fourcc_t cmd = 0;
		if (strlen(start) < 4)
		{
			bot_output(client, "Unexpected response from hub: '%s'", start);
			start = &pos[1];
			continue;
		}
		
		cmd = FOURCC(start[0], start[1], start[2], start[3]);
		
		switch (cmd)
		{
			case ADC_CMD_ISUP:
				break;

			case ADC_CMD_ISID:
				if (client->state == ps_protocol)
				{
					client->sid = string_to_sid(&start[5]);
					client->state = ps_identify;
					send_client_info(client);
					
				}
				break;
				
			case ADC_CMD_IINF:
				break;
			
			case ADC_CMD_BSCH:
			case ADC_CMD_FSCH:
			{
				if (get_wait_rand(100) > (90 - (10 * cfg_level)) && cfg_mode == mode_performance)
				{
					sid_t target = string_to_sid(&start[5]);
					const char* what = strstr(&start[5], " AN");
					const char* token = strstr(&start[5], " TO");
					char* split = 0;
					if (!token || !what) break;
					
					token += 3;
					what += 3;

					split = strchr(what, ' ');
					if (!split) break;
					else split[0] = '0';

					split = strchr(token, ' ');
					if (split) split[0] = '0';

					perf_result(client, target, what, token);

				}
				break;
			}
			case ADC_CMD_BINF:
			{
				if (strlen(start) > 9)
				{
					char t = start[9]; start[9] = 0; sid_t sid = string_to_sid(&start[5]); start[9] = t;
					
					if (sid == client->sid)
					{
						if (client->state == ps_verify || client->state == ps_identify)
						{
							ADC_client_on_login(client);
						}
					}
				}
				break;
			}
			
			case ADC_CMD_ISTA:
				if (strncmp(start, "ISTA 000", 8))
				{
					bot_output(client, "status: '%s'\n", (start + 9));
				}
				break;
				
			default:
				break;
		}
		
		start = &pos[1];
	}
	
	client->r_offset = strlen(lastPos);
	memmove(client->recvbuf, lastPos, strlen(lastPos));
	memset(&client->recvbuf[client->r_offset], 0, ADC_BUFSIZE-client->r_offset);
	
	
	return 0;
}

void ADC_client_connect(struct ADC_client* client)
{
	struct timeval timeout = { TIMEOUT_IDLE, 0 };
	net_connect(client->sd, (struct sockaddr*) &saddr, sizeof(struct sockaddr_in));
	set_state_timeout(client, ps_conn);
	event_add(&client->ev_read, &timeout);
	event_add(&client->ev_write, &timeout);
	bot_output(client, "connecting...");
}

void ADC_client_wait_connect(struct ADC_client* client)
{
	set_state_timeout(client, ps_none);
	
}



void ADC_client_disconnect(struct ADC_client* client)
{
	if (client->sd != -1)
	{
		net_close(client->sd);
		client->sd = -1;
		event_del(&client->ev_read);
		event_del(&client->ev_write);
		bot_output(client, "disconnected.");
		
		if (running)
		{
			ADC_client_destroy(client);
			ADC_client_create(client, client->num);
			ADC_client_connect(client);
		}

	}
}

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
	send_client(client, buf);
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
	send_client(client, buf);
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
	send_client(client, buf);
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
	send_client(client, buf);
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
	send_client(client, buf);
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
				if (cfg_debug > 1) bot_output(client, "timeout -> disconnect");
				ADC_client_disconnect(client);
			}
			break;

		case 1:
			if (cfg_chat)
			{
				if (cfg_debug > 1) bot_output(client, "timeout -> chat");
				perf_chat(client, 0);
				
			}
			break;

		case 2:
			if (cfg_debug > 1) bot_output(client, "timeout -> search");
			perf_search(client);
			break;

		case 3:
			if (cfg_debug > 1) bot_output(client, "timeout -> update");
			perf_update(client);
			break;

		case 4:
			if (cfg_debug > 1) bot_output(client, "timeout -> privmsg");
			perf_chat(client, 1);
			break;

		case 5:
			if (cfg_debug > 1) bot_output(client, "timeout -> ctm/rcm");
			perf_ctm(client);
			break;

	}

	client_reschedule_timeout(client);
}

void event_callback(int fd, short ev, void *arg)
{
	struct ADC_client* client = (struct ADC_client*) arg;

	if (ev & EV_READ)
	{
		if (recv_client(client) == -1)
		{
			ADC_client_on_disconnected(client);
		}
	}
	
	if (ev & EV_TIMEOUT)
	{
		if (client->state == ps_none)
		{
			if (client->sd == -1)
			{
				ADC_client_create(client, client->num);
			}

			ADC_client_connect(client);
		}

		if (fd == -1)
		{
			if (client->state == ps_normal && cfg_mode == mode_performance)
			{
				perf_normal_action(client);
			}
		}
	}
	
	if (ev & EV_WRITE)
	{
		if (client->state == ps_conn)
		{
			ADC_client_on_connected(client);
		}
		else
		{
			/* FIXME: Call send again */
		}

	}
}

int ADC_client_create(struct ADC_client* client, int num)
{
	struct timeval timeout = { 0, 0 };
	
	memset(client, 0, sizeof(struct ADC_client));
	client->num = num;
	
	client->sd = net_socket_create(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client->sd == -1) return -1;
	
	event_set(&client->ev_write, client->sd, EV_WRITE, event_callback, client);
	event_set(&client->ev_read,  client->sd, EV_READ | EV_PERSIST, event_callback, client);
	
	net_set_nonblocking(client->sd, 1);
	
	timeout.tv_sec = client->timeout;
	evtimer_set(&client->ev_timer, event_callback, client);

	set_state_timeout(client, ps_none);

	return 0;
}

void ADC_client_destroy(struct ADC_client* client)
{
	ADC_client_disconnect(client);
	evtimer_del(&client->ev_timer);
}


void runloop(size_t clients)
{
	size_t n = 0;
	struct ADC_client* client[ADC_MAX_CLIENTS];

	for (n = 0; n < clients; n++)
	{
		struct ADC_client* c = malloc(sizeof(struct ADC_client));
		client[n] = c;

		ADC_client_create(c, n);
		if (n == 0)
		{
			ADC_client_connect(c);
		}
		else
		{
			ADC_client_wait_connect(c);
		}
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
	event_init();
	
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port   = htons(cfg_port);
	net_string_to_address(AF_INET, cfg_host, &saddr.sin_addr);
	
	runloop(cfg_clients);
	net_destroy();

	return 0;
}

