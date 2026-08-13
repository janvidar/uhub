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
 * uhub-seeder - the seed cache daemon.
 *
 * A separate process from the hub. It logs into a uhub as a registered bot
 * account and serves a content-addressed cache of small files to the other
 * clients on that hub. Because it is an ordinary ADC client rather than part of
 * the hub, it has no notion of its own externally visible address: the hub
 * replaces the I4 it advertises with the address the hub observed (see
 * check_network() in src/core/inf.c), and a NATed seeder is handled by the
 * hub's existing nat_override setting. See seeder/config.h.
 *
 * This file is the process skeleton and the wiring loom: option parsing,
 * logging, config, signals, the reactor loop, and the handful of connections
 * between the modules that do the actual work. It owns every one of them and
 * tears them down in the reverse order it built them.
 */

#include "system.h"
#include "uhub_limits.h"
#include "util/log.h"
#include "util/memory.h"
#include "network/connection.h"
#include "network/ipcalc.h"
#include "network/network.h"
#include "network/backend.h"
#include "network/tls.h"
#include "network/notify.h"
#include "network/timeout.h"
#include "seeder/cache.h"
#include "seeder/cc.h"
#include "seeder/commands.h"
#include "seeder/config.h"
#include "seeder/grant.h"
#include "seeder/hubconn.h"
#include "seeder/ingest.h"
#include "util/getopt.h" /* bundled getopt on platforms without one (NEED_GETOPT; e.g. Windows) */

#include <signal.h> /* sig_atomic_t, and sigaction() on POSIX */

/*
 * How often the sweep timer runs, in seconds.
 *
 * The cache wants expiry, eviction and a metadata flush on a much slower
 * cadence than this, and grants expire after only SEED_GRANT_TTL -- but the
 * timeout wheel is indexed modulo TIMEOUT_QUEUE_MAX, so no single delay may
 * exceed it. Tick often on a short re-armed timer and let seed_cache_sweep()
 * decide what is actually due.
 */
#define SEED_SWEEP_INTERVAL 10

#if SEED_SWEEP_INTERVAL >= TIMEOUT_QUEUE_MAX
#error "SEED_SWEEP_INTERVAL must fit inside the timeout wheel (TIMEOUT_QUEUE_MAX)"
#endif

/** Listen backlog for the client transfer port. */
#define SEED_LISTEN_BACKLOG 50

#ifndef SEEDER_CONFIG
#ifndef WIN32
#define SEEDER_CONFIG "/etc/uhub/uhub-seeder.conf"
#else
#define SEEDER_CONFIG "uhub-seeder.conf"
#endif
#endif

static int arg_verbose      = 5;
static int arg_fork         = 0;
static int arg_check_config = 0;
static const char* arg_config = 0;
static const char* arg_log    = 0;
static const char* arg_pid    = 0;

/* Set from a signal handler, read by the event loop. */
static volatile sig_atomic_t seeder_stopped = 0;

#ifndef WIN32
/* Wakes the reactor from the signal handler. The handlers are installed with
   SA_RESTART so ordinary I/O is not disturbed by EINTR, which means merely
   setting the flag would not break a blocking poll -- the syscall restarts and
   the loop cannot observe the flag until the poll returns on its own. Writing a
   byte to this self-pipe makes the restarted poll return at once. Same trick as
   the hub's src/core/main.c. */
static struct uhub_notify_handle* seeder_signal_wake = 0;

static void seeder_wake_callback(struct uhub_notify_handle* handle, void* ptr)
{
	/* The wake itself is the point; the loop re-checks seeder_stopped once the
	   poll returns. The notify layer has already drained the byte. */
	(void) handle;
	(void) ptr;
}

static void seeder_handle_signal(int sig)
{
	if (sig == SIGPIPE)
		return; /* nothing to react to; do not wake the loop */

	seeder_stopped = 1;
	net_notify_signal_async(seeder_signal_wake);
}

static int seeder_signals[] =
{
	SIGINT,  /* Interrupt the application */
	SIGTERM, /* Terminate the application */
	SIGPIPE, /* a peer going away must not kill the process */
	0
};

static void setup_signal_handlers(void)
{
	struct sigaction act;
	int i;

	/* Created before the handlers are armed, so it is always valid when one
	   fires. net_initialize() has already set the backend up by this point. */
	seeder_signal_wake = net_notify_create(seeder_wake_callback, 0);
	if (!seeder_signal_wake)
		LOG_ERROR("Unable to create signal wake pipe; shutdown may be delayed.");

	memset(&act, 0, sizeof(act));
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	act.sa_handler = seeder_handle_signal;

	for (i = 0; seeder_signals[i]; i++)
		if (sigaction(seeder_signals[i], &act, 0) != 0)
			LOG_ERROR("Error setting signal handler %d", seeder_signals[i]);
}

static void shutdown_signal_handlers(void)
{
	if (seeder_signal_wake)
	{
		net_notify_destroy(seeder_signal_wake);
		seeder_signal_wake = 0;
	}
}

static int pidfile_create(void)
{
	FILE* pidfile;

	if (!arg_pid)
		return 0;

	pidfile = fopen(arg_pid, "w");
	if (!pidfile)
	{
		LOG_FATAL("Unable to write pid file: %s", arg_pid);
		return -1;
	}

	fprintf(pidfile, "%d", (int) getpid());
	fclose(pidfile);
	return 0;
}

static void pidfile_destroy(void)
{
	if (arg_pid)
		unlink(arg_pid);
}
#endif /* !WIN32 */

/*
 * Everything the daemon owns, in the order it is built. Teardown walks it
 * backwards. It is a file static rather than a parameter because the reactor's
 * callbacks carry a void* and nothing else, and because there is exactly one of
 * these per process.
 */
static struct seeder_context
{
	struct seed_config          config;
	struct seed_cache*          cache;
	struct seed_grants*         grants;
	struct seed_hub*            hub;
	struct seed_commands*       commands;
	struct seed_ingest_trigger* ingest;
	struct seed_cc_policy       cc_policy;
	struct ssl_context_handle*  tls_ctx;   /* server context, NULL without a certificate */
	struct net_connection*      listener;
	int                         listen_af; /** Family the listener bound, for SU. */
	struct timeout_evt*         sweep;
} seeder;

/* ------------------------------------------------------------ hub callbacks */

static void seeder_on_logged_in(void* ptr)
{
	struct seeder_context* ctx = (struct seeder_context*) ptr;

	/*
	 * The CID is only settled once the hub connection has been opened, and the
	 * client-to-client policy needs it to identify us in a CINF. The pointer is
	 * into struct seed_hub and is stable for its lifetime, so this is a one time
	 * fixup and not a per-login one -- but it costs nothing to redo.
	 */
	ctx->cc_policy.cid = seed_hub_own_cid(ctx->hub);

	LOG_INFO("Logged in to %s as \"%s\".", ctx->config.seed_hub_url, ctx->config.seed_nick);
}

static void seeder_on_disconnected(void* ptr)
{
	(void) ptr;
	/* seeder/hubconn.c reconnects on its own, with backoff. */
	LOG_INFO("Disconnected from the hub; will retry.");
}

/** One line of a command reply, sent back as a private message. */
static void seeder_command_reply(void* ptr, sid_t to, const char* text)
{
	struct seeder_context* ctx = (struct seeder_context*) ptr;
	seed_hub_send_pm(ctx->hub, to, text);
}

static void seeder_on_chat(void* ptr, const struct seed_user* from, const char* text, int private_msg)
{
	struct seeder_context* ctx = (struct seeder_context*) ptr;

	if (!from || !text)
		return;

	/*
	 * A private message to the bot is how an operator administers the cache.
	 * If it is not a command it falls through and is scanned like any other
	 * message -- posting a magnet in a PM is a perfectly ordinary way to hand
	 * the seeder something.
	 */
	if (private_msg && seed_commands_handle(ctx->commands, from->sid, from->client_type, text))
		return;

	seed_ingest_on_chat(ctx->ingest, from, text);
}

static void seeder_on_search(void* ptr, const struct seed_user* from, const char* tth, const char* token)
{
	struct seeder_context* ctx = (struct seeder_context*) ptr;
	struct seed_entry entry;
	int slots;

	if (!from || !tth)
		return;

	/* Answering a search *is* an access: the file is about to be wanted, so it
	   should not be the next one evicted. */
	if (!seed_cache_lookup(ctx->cache, tth, &entry) || seed_cache_is_blocked(ctx->cache, tth))
	{
		LOG_DEBUG("seed: search from %s for TTH=%s -- not in the cache", from->nick, tth);
		return;
	}

	slots = ctx->config.seed_max_concurrent_upload - (int) seed_cc_active_uploads();
	if (slots < 0)
		slots = 0;

	/* Answering is the whole point of holding the file, so it is said out loud:
	   a hit that produces no download afterwards is a different problem from a
	   search that never matched, and only this line separates them. */
	if (seed_hub_send_result(ctx->hub, from->sid, entry.tth, entry.size,
		*entry.name ? entry.name : entry.tth, slots, token ? token : ""))
	{
		LOG_INFO("seed: answering %s for TTH=%s (%" PRIu64 " bytes, %d slots, token \"%s\")",
			from->nick, entry.tth, entry.size, slots, token ? token : "");
	}
	else
	{
		LOG_WARN("seed: could not answer %s for TTH=%s", from->nick, entry.tth);
	}
}

/**
 * The peer wants us to connect to it: an active downloader's CTM.
 *
 * The address dialled is the one the *hub* reported for that user, never one
 * out of the CTM -- see the note on struct seed_cc_peer.
 */
static void seeder_on_connect_req(void* ptr, const struct seed_user* from, const char* protocol,
	uint16_t port, const char* token)
{
	struct seeder_context* ctx = (struct seeder_context*) ptr;
	struct ip_addr_encap addr;
	struct seed_cc_peer peer;
	const char* speak;

	if (!from || !token || !*token)
		return;

	if (!ip_convert_to_binary(from->address, &addr))
	{
		LOG_DEBUG("seeder: no usable address for %s; not dialling.", from->nick);
		return;
	}

	memset(&peer, 0, sizeof(peer));
	peer.cid = from->cid;
	peer.addr = &addr;

	/*
	 * The hub overwrites a client's I4 with the address it observed, so what the
	 * roster holds is proven -- unless the hub's nat_override covers that user,
	 * which a client cannot see. Treating it as proven is the assumption this
	 * daemon runs on; a hub that NATs its users is one where this should be
	 * revisited.
	 */
	peer.addr_is_client_supplied = 0;

	/*
	 * Dialled with the protocol the peer's own INF justifies, which is not
	 * necessarily the one its CTM named: a client that advertises ADCS or ADC0
	 * expects TLS on every connection with it, and would refuse the plaintext
	 * one its own request literally asked for.
	 */
	speak = seed_cc_protocol_for_peer(&ctx->cc_policy, from->support, protocol);

	LOG_INFO("seed: %s asked us to connect to %s port %u speaking \"%s\"; dialling with %s",
		from->nick, from->address, (unsigned) port, protocol ? protocol : "", speak);

	if (!seed_cc_connect_to_peer(&ctx->cc_policy, &peer, speak, port, token))
		LOG_WARN("seed: could not dial %s for a transfer", from->nick);
}

/**
 * The peer wants us to send it a CTM: a passive downloader's RCM.
 *
 * The token in an RCM belongs to the downloader and must be echoed back
 * unchanged, so the grant is issued *for their token*. It names no TTH: this is
 * an upload, and the peer can only ever CGET something already cached.
 */
static void seeder_on_revconnect_req(void* ptr, const struct seed_user* from, const char* protocol,
	const char* token)
{
	struct seeder_context* ctx = (struct seeder_context*) ptr;
	const char* answer;
	int peer_wants_tls = 0;

	if (!from || !token || !*token)
		return;

	if (!seed_cc_protocol_ok(protocol, &peer_wants_tls))
	{
		LOG_DEBUG("seeder: %s asked for the unsupported protocol \"%s\"", from->nick,
			protocol ? protocol : "");
		return;
	}

	/*
	 * What the peer can do decides this, not what it asked for. A client
	 * advertising ADCS or ADC0 expects every connection with it to be encrypted,
	 * so answering a request for plain ADC in plain would hand it a connection
	 * it will not use. The request only picks the ADCS revision.
	 */
	answer = seed_cc_protocol_for_peer(&ctx->cc_policy, from->support, protocol);

	if (peer_wants_tls && !ctx->tls_ctx)
		LOG_WARN("seeder: %s asked for %s, but no certificate is configured; offering plain ADC.",
			from->nick, protocol);

	if (!seed_grant_issue(ctx->grants, token, from->cid, NULL, time(NULL)))
	{
		LOG_WARN("seed: refusing %s a connection slot for token \"%s\"", from->nick, token);
		return;
	}

	if (seed_hub_send_ctm(ctx->hub, from->sid, answer,
		(uint16_t) ctx->config.seed_client_port, token))
	{
		/* Both halves are logged: which protocol the peer asked for, and which
		   one it is getting. A download that arrives in the clear is otherwise
		   impossible to attribute -- the peer may have asked for plain, or we
		   may have downgraded it. */
		LOG_INFO("seed: %s asked for \"%s\", answering with a connect request to port %u speaking %s",
			from->nick, protocol ? protocol : "",
			(unsigned) ctx->config.seed_client_port, answer);
	}
}

/* --------------------------------------------------- the client transfer port */

/**
 * Build the server TLS context the transfer port answers a ClientHello with.
 *
 * Modelled on load_ssl_certificates() in src/core/hub.c. There is no
 * seed_tls_enable to go with it: the port serves ADCS and plain ADC on the same
 * socket either way, and a certificate is the only thing that decides whether
 * the first of those can be answered at all.
 *
 * A configured certificate that will not load is fatal. The alternative --
 * carrying on without it -- is a seeder that quietly serves grant tokens and
 * file content in the clear while its operator believes otherwise.
 *
 * @return 0 on success, including the no-certificate case.
 */
static int seeder_setup_tls(struct seeder_context* ctx)
{
	const char* cert = ctx->config.seed_tls_certificate;
	const char* key  = ctx->config.seed_tls_private_key;

	if (!*cert && !*key)
	{
		LOG_WARN("No seed_tls_certificate configured: transfers are offered as plain ADC/1.0 "
			"only, and most clients refuse those. Set seed_tls_certificate and "
			"seed_tls_private_key to serve ADCS.");
		return 0;
	}

	/* seed_config_read() rejects one without the other; belt and braces, since
	   the cost of being wrong here is serving in the clear. */
	if (!*cert || !*key)
	{
		LOG_FATAL("seed_tls_certificate and seed_tls_private_key must be set together.");
		return -1;
	}

	ctx->tls_ctx = net_ssl_context_create(ctx->config.seed_tls_version,
		ctx->config.seed_tls_ciphersuite, ctx->config.seed_tls_ciphersuites);
	if (!ctx->tls_ctx)
	{
		LOG_FATAL("Unable to create a TLS context (check seed_tls_version, "
			"seed_tls_ciphersuite and seed_tls_ciphersuites).");
		return -1;
	}

	if (!ssl_load_certificate(ctx->tls_ctx, cert) ||
		!ssl_load_private_key(ctx->tls_ctx, key) ||
		!ssl_check_private_key(ctx->tls_ctx))
	{
		LOG_FATAL("Unable to load the TLS certificate \"%s\" and private key \"%s\".", cert, key);
		return -1;
	}

	LOG_INFO("Serving transfers over ADCS (%s), using certificate: %s, private key: %s",
		net_ssl_get_provider(), cert, key);
	return 0;
}

static void seeder_on_accept(struct net_connection* con, int events, void* arg)
{
	struct seeder_context* ctx = (struct seeder_context*) arg;
	int server_fd = net_con_get_sd(con);

	(void) events;

	for (;;)
	{
		struct ip_addr_encap addr;
		struct net_connection* client;
		int fd = net_accept(server_fd, &addr);

		if (fd == -1)
		{
#ifdef WINSOCK
			if (net_error() != WSAEWOULDBLOCK)
#else
			if (net_error() != EWOULDBLOCK)
#endif
				LOG_ERROR("Accept error: %d %s", net_error(), strerror(net_error()));
			break;
		}

		/*
		 * Keep the descriptor inside the backend's connection table. Drain the
		 * backlog even while refusing, so the kernel accept queue empties and
		 * the listener stops re-firing.
		 */
		if (net_backend_get_num_connections() >= net_backend_get_max_connections() ||
			(size_t) fd >= net_backend_get_max_connections())
		{
			LOG_WARN("Connection limit reached (%zu), rejecting connection.",
				net_backend_get_max_connections());
			net_close(fd);
			continue;
		}

		client = net_con_create();
		if (!client)
		{
			net_close(fd);
			break;
		}

		/* seed_cc_accept() reinitializes this with its own handler; the
		   placeholder here just gets the descriptor into the backend. */
		net_con_initialize(client, fd, seeder_on_accept, ctx, NET_EVENT_READ);

		if (!seed_cc_accept(&ctx->cc_policy, client, &addr))
		{
			LOG_WARN("Unable to accept a client connection from %s.", ip_convert_to_string(&addr));
			net_con_close(client); /* still ours */
		}
	}
}

static struct net_connection* seeder_listen(struct seeder_context* ctx)
{
	struct net_connection* server;
	struct sockaddr_storage addr;
	socklen_t sockaddr_size;
	int sd;

	if (ip_convert_address(ctx->config.seed_client_bind_addr, ctx->config.seed_client_port,
		(struct sockaddr*) &addr, &sockaddr_size) == -1)
	{
		LOG_FATAL("Unable to resolve the bind address \"%s\".", ctx->config.seed_client_bind_addr);
		return NULL;
	}

	sd = net_socket_create(addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (sd == -1)
		return NULL;

	if (net_set_reuseaddress(sd, 1) == -1 || net_set_nonblocking(sd, 1) == -1)
	{
		net_close(sd);
		return NULL;
	}

	if (net_bind(sd, (struct sockaddr*) &addr, sockaddr_size) == -1)
	{
		LOG_FATAL("Unable to bind to %s port %d. errno=%d, str=%s",
			ctx->config.seed_client_bind_addr, ctx->config.seed_client_port,
			net_error(), net_error_string(net_error()));
		net_close(sd);
		return NULL;
	}

	if (net_listen(sd, SEED_LISTEN_BACKLOG) == -1)
	{
		LOG_FATAL("Unable to listen on %s port %d.", ctx->config.seed_client_bind_addr,
			ctx->config.seed_client_port);
		net_close(sd);
		return NULL;
	}

	server = net_con_create();
	if (!server)
	{
		net_close(sd);
		return NULL;
	}

	net_con_initialize(server, sd, seeder_on_accept, ctx, NET_EVENT_READ);

	/* Kept so the INF can claim TCP4 or TCP6 for the family actually bound,
	   rather than whichever one is written more often. */
	ctx->listen_af = addr.ss_family;
	return server;
}

/**
 * The SU the seeder advertises: what it can do, and nothing more.
 *
 * TCP4/TCP6 because the listener above is bound and mandatory -- the daemon
 * exits if it cannot listen -- and ADCS only when there is a certificate to
 * answer a handshake with. Claiming it without one wins the transfer and then
 * hangs the peer on a handshake nothing replies to.
 *
 * Both spellings of that claim go out, the current one first. They mean the
 * same thing, but a client acts only on the one it knows: an installed base
 * looking for ADC0 that finds only ADCS concludes the seeder cannot do
 * encrypted transfers and asks for a plaintext one instead, which is what
 * EiskaltDC++ was observed doing. Leading with ADCS is how that stops being
 * true over time; still sending ADC0 is how transfers work meanwhile.
 */
static void seeder_advertise_support(struct seeder_context* ctx)
{
	char su[SEED_SUPPORT_MAX];
	const char* families = "TCP4";

	if (ctx->listen_af == AF_INET6)
	{
		int v6only = 1;
		socklen_t len = sizeof(v6only);
		int sd = ctx->listener ? net_con_get_sd(ctx->listener) : -1;

		/*
		 * An IPv6 listener is not an IPv6-only listener. "any" binds :: with
		 * IPV6_V6ONLY off on every platform this runs on, and such a socket
		 * accepts IPv4 as well -- so the family the address resolved to says
		 * nothing on its own. Ask the socket instead: claiming only TCP6 on a
		 * dual-stack listener leaves the seeder undialled by every IPv4 client,
		 * which on most hubs is all of them.
		 */
		if (sd >= 0 && getsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &len) == 0 && !v6only)
			families = "TCP4,TCP6";
		else
			families = "TCP6";
	}

	snprintf(su, sizeof(su), "%s%s", families, ctx->tls_ctx ? ",ADCS,ADC0" : "");

	if (!seed_hub_set_support(ctx->hub, su))
		LOG_WARN("seeder: unable to advertise \"%s\".", su);
	else
		LOG_INFO("seeder: advertising SU=%s", su);
}

/* ------------------------------------------------------------- the sweep timer */

static void seeder_sweep_timer(struct timeout_evt* t)
{
	struct seeder_context* ctx = (struct seeder_context*) t->ptr;
	time_t now = time(NULL);

	seed_cache_sweep(ctx->cache, now);
	seed_grant_sweep(ctx->grants, now);

	timeout_queue_reschedule(net_backend_get_timeout_queue(), ctx->sweep, SEED_SWEEP_INTERVAL);
}

static void print_version(void)
{
	fprintf(stdout, "uhub-seeder (" PRODUCT_STRING ")\n");
	fprintf(stdout, COPYRIGHT "\n"
			"This is free software with ABSOLUTELY NO WARRANTY.\n\n");
	exit(0);
}

static void print_usage(const char* program)
{
	fprintf(stderr, "Usage: %s [options]\n\n", program);
	fprintf(stderr,
		"Options:\n"
		"   -v          Verbose mode. Add more -v's for higher verbosity.\n"
		"   -q          Quiet mode - no output\n"
		"   -f          Fork to background\n"
		"   -l <file>   Log messages to given file (default: stderr)\n"
		"   -c <file>   Specify configuration file (default: " SEEDER_CONFIG ")\n"
		"   -C          Check configuration and return\n"
#ifndef WIN32
		"   -p <file>   Store pid in file (process id)\n"
#endif
		"   -h          This message\n"
		"   -V          Show version number.\n"
	);

	exit(0);
}

static void parse_command_line(int argc, char** argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "vqfc:l:p:hVC")) != -1)
	{
		switch (opt)
		{
			case 'V':
				print_version();
				break;

			case 'v':
				arg_verbose++;
				break;

			case 'q':
				arg_verbose = 0;
				break;

			case 'f':
				arg_fork = 1;
				break;

			case 'c':
				arg_config = optarg;
				break;

			case 'C':
				arg_check_config = 1;
				break;

			case 'l':
				arg_log = optarg;
				break;

			case 'p':
				arg_pid = optarg;
				break;

			case 'h':
				print_usage(argv[0]);
				break;

			default:
				print_usage(argv[0]);
				break;
		}
	}

	if (!arg_config)
		arg_config = SEEDER_CONFIG;

	/* Clamp the accumulated verbosity so repeated -v cannot drive the threshold
	   past the highest log level. */
	if (arg_verbose < 0)
		arg_verbose = 0;
	else if (arg_verbose > log_plugin + 1)
		arg_verbose = log_plugin + 1;

	hub_log_initialize(arg_log, 0);
	hub_set_log_verbosity(arg_verbose);
}

static int check_configuration(void)
{
	struct seed_config config;

	if (!seed_config_read(arg_config, &config))
	{
		fprintf(stderr, "ERROR\n");
		return 1;
	}

	seed_config_free(&config);
	fprintf(stdout, "OK\n");
	return 0;
}

/**
 * Build everything, in dependency order. Anything that fails here is fatal:
 * a half-built seeder is not a degraded seeder, it is a process with no purpose.
 *
 * @return 0 on success.
 */
static int seeder_start(struct seeder_context* ctx)
{
	struct seed_cache_config cache_config;
	struct seed_hub_callbacks callbacks;

	/* 1. The cache. Unlike in the hub, where a missing cache just switches a
	   feature off, a seeder without one has nothing to serve and nowhere to put
	   what it fetches, so this is the one place the daemon refuses to start. */
	memset(&cache_config, 0, sizeof(cache_config));
	cache_config.dir                   = ctx->config.seed_cache_dir;
	cache_config.max_bytes             = (uint64_t) ctx->config.seed_cache_size * 1024 * 1024;
	cache_config.max_file_size         = (uint64_t) ctx->config.seed_max_file_size * 1024 * 1024;
	cache_config.max_entries           = (size_t) ctx->config.seed_max_entries;
	cache_config.entry_ttl             = ctx->config.seed_entry_ttl;
	cache_config.max_concurrent_ingest = (size_t) ctx->config.seed_max_concurrent_ingest;
	cache_config.allowed_types         = ctx->config.seed_allowed_types;

	ctx->cache = seed_cache_open(&cache_config);
	if (!ctx->cache)
	{
		LOG_FATAL("Unable to open the seed cache at %s.", ctx->config.seed_cache_dir);
		return -1;
	}

	/* 2. The grant table: the only thing that authorises a client connection. */
	ctx->grants = seed_grants_create();
	if (!ctx->grants)
	{
		LOG_FATAL("Unable to create the connection grant table.");
		return -1;
	}

	/* 3. The hub connection. Created before the listener so that the CID it
	   settles on is available to the client-to-client policy below. */
	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.on_logged_in      = seeder_on_logged_in;
	callbacks.on_disconnected   = seeder_on_disconnected;
	callbacks.on_chat           = seeder_on_chat;
	callbacks.on_search         = seeder_on_search;
	callbacks.on_connect_req    = seeder_on_connect_req;
	callbacks.on_revconnect_req = seeder_on_revconnect_req;

	ctx->hub = seed_hub_create(&ctx->config, &callbacks, ctx);
	if (!ctx->hub)
	{
		LOG_FATAL("Unable to create a connection to %s.", ctx->config.seed_hub_url);
		return -1;
	}

	/* 4. The certificate the transfer port answers a TLS ClientHello with, if
	   there is one. Built before the policy below, which carries the context. */
	if (seeder_setup_tls(ctx) != 0)
		return -1;

	/* 5. What the client connections are allowed to decide with. Every string
	   in here points into ctx, which outlives every connection started with it. */
	memset(&ctx->cc_policy, 0, sizeof(ctx->cc_policy));
	ctx->cc_policy.cache                 = ctx->cache;
	ctx->cc_policy.grants                = ctx->grants;
	ctx->cc_policy.cid                   = seed_hub_own_cid(ctx->hub);
	ctx->cc_policy.max_concurrent_upload = (size_t) ctx->config.seed_max_concurrent_upload;
	ctx->cc_policy.ingest_interval       = ctx->config.seed_ingest_interval;
	ctx->cc_policy.ingest_per_user       = ctx->config.seed_ingest_per_user;
	ctx->cc_policy.ingest_quota_kb       = ctx->config.seed_ingest_quota_kb;

	/*
	 * The same TLS settings serve both directions: what the transfer port
	 * accepts, and what an outbound ADCS dial offers. The peer of a dial is a DC
	 * client with a self-signed certificate, so nothing is verified there -- but
	 * the version floor and the cipher lists still have to come from somewhere,
	 * and net_ssl_context_create() refuses a NULL version outright.
	 */
	ctx->cc_policy.tls_version      = ctx->config.seed_tls_version;
	ctx->cc_policy.tls_ciphersuite  = ctx->config.seed_tls_ciphersuite;
	ctx->cc_policy.tls_ciphersuites = ctx->config.seed_tls_ciphersuites;
	ctx->cc_policy.ssl_ctx          = ctx->tls_ctx;

	ctx->commands = seed_commands_create(ctx->cache, seeder_command_reply, ctx);
	if (!ctx->commands)
	{
		LOG_FATAL("Unable to create the command handler.");
		return -1;
	}

	ctx->ingest = seed_ingest_trigger_create(ctx->cache, &ctx->cc_policy, ctx->hub, &ctx->config);
	if (!ctx->ingest)
	{
		LOG_FATAL("Unable to create the ingest trigger.");
		return -1;
	}

	/* 6. The client transfer port. */
	ctx->listener = seeder_listen(ctx);
	if (!ctx->listener)
		return -1;

	LOG_INFO("Listening for client connections on %s port %d (%s)...",
		ctx->config.seed_client_bind_addr, ctx->config.seed_client_port,
		ctx->tls_ctx ? "ADCS and plain ADC" : "plain ADC only");

	/* Now that both the certificate and the listener are settled, the INF can
	   say what this seeder is. Before seed_hub_start(), which is what sends it. */
	seeder_advertise_support(ctx);

	if (ctx->config.seed_http_enable)
	{
		/* TODO: seeder/http.c serves "GET /seed/<tth>" on its own socket, but is
		   not part of the daemon's build yet. When it is, this is where its
		   listener goes: seed_http_port, and seed_http_accept() per connection. */
		LOG_WARN("seed_http_enable is set, but HTTP serving is not built into this daemon.");
	}

	/* 7. The sweep timer, which is what expires cache entries and grants. */
	ctx->sweep = (struct timeout_evt*) hub_malloc_zero(sizeof(struct timeout_evt));
	if (!ctx->sweep || !net_backend_get_timeout_queue())
	{
		LOG_FATAL("Unable to schedule the maintenance timer.");
		return -1;
	}
	timeout_evt_initialize(ctx->sweep, seeder_sweep_timer, ctx);
	timeout_queue_insert(net_backend_get_timeout_queue(), ctx->sweep, SEED_SWEEP_INTERVAL);

	if (!seed_hub_start(ctx->hub))
	{
		LOG_FATAL("Unable to start the hub connection (check seed_hub_url and seed_nick).");
		return -1;
	}

	return 0;
}

/* Reverse of seeder_start(), and safe on anything it never got round to. */
static void seeder_shutdown(struct seeder_context* ctx)
{
	if (ctx->sweep)
	{
		if (net_backend_get_timeout_queue())
			timeout_queue_remove(net_backend_get_timeout_queue(), ctx->sweep);
		hub_free(ctx->sweep);
		ctx->sweep = NULL;
	}

	if (ctx->listener)
	{
		net_con_close(ctx->listener);
		ctx->listener = NULL;
	}

	/* Cancels any URL fetch still in flight, which would otherwise leak its
	   connection past the cache it is writing into. */
	seed_ingest_trigger_destroy(ctx->ingest);
	ctx->ingest = NULL;

	seed_commands_destroy(ctx->commands);
	ctx->commands = NULL;

	/* Not called from inside a callback: this only ever runs from the loop. */
	seed_hub_destroy(ctx->hub);
	ctx->hub = NULL;

	seed_grants_destroy(ctx->grants);
	ctx->grants = NULL;

	seed_cache_close(ctx->cache);
	ctx->cache = NULL;

	/* Last: an SSL object made from this context holds its own reference, so a
	   connection still being torn down by net_destroy() is unaffected. */
	if (ctx->tls_ctx)
	{
		net_ssl_context_destroy(ctx->tls_ctx);
		ctx->tls_ctx = NULL;
		ctx->cc_policy.ssl_ctx = NULL;
	}
}

static int main_loop(void)
{
	int ret = 0;

	if (!seed_config_read(arg_config, &seeder.config))
		return -1;

	if (net_initialize() == -1)
	{
		seed_config_free(&seeder.config);
		return -1;
	}

#ifndef WIN32
	setup_signal_handlers();
#endif

	if (seeder_start(&seeder) != 0)
	{
		ret = -1;
	}
	else
	{
		LOG_INFO("uhub-seeder started (nick: \"%s\", cache: %s).",
			seeder.config.seed_nick, seeder.config.seed_cache_dir);

		/* Everything -- the reconnect backoff, the transfer timeouts and the
		   sweep -- hangs off the backend's timeout queue, so one call per pass
		   is the whole loop. */
		while (!seeder_stopped)
			net_backend_process();

		LOG_INFO("Shutting down...");
	}

	seeder_shutdown(&seeder);

#ifndef WIN32
	shutdown_signal_handlers();
#endif

	net_destroy();
	seed_config_free(&seeder.config);
	hub_log_shutdown();
	return ret;
}

int main(int argc, char** argv)
{
	int ret;

	parse_command_line(argc, argv);

	if (arg_check_config)
		return check_configuration();

#ifndef WIN32
	if (arg_fork)
	{
		ret = fork();
		if (ret == -1)
		{
			LOG_FATAL("Unable to fork to background!");
			return -1;
		}
		else if (ret == 0)
		{
			/* child process - detach from TTY */
			fclose(stdin);
			fclose(stdout);
			fclose(stderr);
			close(0);
			close(1);
			close(2);
		}
		else
		{
			/* parent process */
			LOG_DEBUG("Forked to background");
			return 0;
		}
	}

	if (pidfile_create() == -1)
		return -1;
#endif

	ret = main_loop();

#ifndef WIN32
	pidfile_destroy();
#endif

	return ret;
}
