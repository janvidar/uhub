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

#include "system.h"
#include "uhub_limits.h"
#include "util/log.h"
#include "util/memory.h"
#include "network/network.h"
#include "core/auth.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/regserver.h"
#include "util/getopt.h" /* bundled getopt on platforms without one (NEED_GETOPT; e.g. Windows) */

#ifndef WIN32
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <openssl/rand.h>
#endif

#ifdef SYSTEMD
#include <systemd/sd-daemon.h>
#endif

static int arg_verbose = 5;
static int arg_fork    = 0;
static int arg_check_config = 0;
static int arg_dump_config  = 0;
static int arg_have_config = 0;
static const char* arg_uid = 0;
static const char* arg_gid = 0;
static const char* arg_config  = 0;
static const char* arg_log = 0;
static const char* arg_pid = 0;
static int arg_log_syslog = 0;


#if !defined(WIN32)
extern struct hub_info* g_hub;
void hub_handle_signal(int sig)
{
	struct hub_info* hub = g_hub;

	switch (sig)
	{
		case SIGINT:
			LOG_INFO("Interrupted. Shutting down...");
			hub->status = hub_status_shutdown;
			break;

		case SIGTERM:
			LOG_INFO("Terminated. Shutting down...");
			hub->status = hub_status_shutdown;
			break;

		case SIGPIPE:
			break;

		case SIGHUP:
			hub->status = hub_status_restart;
			break;

		default:
			LOG_TRACE("hub_handle_signal(): caught unknown signal: %d", signal);
			hub->status = hub_status_shutdown;
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

void setup_signal_handlers(struct hub_info* hub)
{
	(void) hub;
	sigset_t sig_set;
	struct sigaction act;
	int i;

	sigemptyset(&sig_set);
	act.sa_mask = sig_set;
	act.sa_flags = SA_ONSTACK | SA_RESTART;
	act.sa_handler = hub_handle_signal;

	for (i = 0; signals[i]; i++)
	{
		if (sigaction(signals[i], &act, 0) != 0)
		{
			LOG_ERROR("Error setting signal handler %d", signals[i]);
		}
	}
}

void shutdown_signal_handlers(struct hub_info* hub)
{
	(void) hub;
}
#endif /* !WIN32 */


#ifndef WIN32
/* --------------------------------------------------------------------------
 * Multi-process "logical hub" launcher.
 *
 * When `workers` > 1 the top-level process becomes a master that forks N worker
 * processes. Each worker is a normal single-threaded hub, but with config
 * overridden so the workers share the client port (SO_REUSEPORT) and link to
 * one another over Unix sockets in a private runtime directory, presenting one
 * roster and SID space. The master serves no clients; it only supervises and
 * restarts workers, and tears them down on exit.
 * -------------------------------------------------------------------------- */

static int   g_worker_index = -1; /* >= 0 inside a worker, else master/single */
static int   g_worker_count = 0;
static char  g_worker_secret[33] = {0};
static char  g_worker_dir[80] = {0};
static pid_t* g_worker_pids = 0;
static volatile sig_atomic_t g_master_stop = 0;

static int resolve_worker_count(int configured)
{
	if (configured == 0)
	{
		long n = sysconf(_SC_NPROCESSORS_ONLN);
		return (n > 0) ? (int) n : 1;
	}
	return configured;
}

static void set_config_str(char** field, const char* value)
{
	hub_free(*field);
	*field = hub_strdup(value);
}

/* In a worker: override config so this process is node g_worker_index of a
   g_worker_count cluster, sharing the port and meshed over Unix sockets. */
static void apply_worker_overrides(struct hub_config* cfg)
{
	char path[128];
	char peers[8192];
	int j;

	if (g_worker_index < 0)
		return;

	cfg->server_reuseport = 1;
	cfg->node_count = g_worker_count;
	cfg->node_id = g_worker_index;
	set_config_str(&cfg->link_secret, g_worker_secret);

	snprintf(path, sizeof(path), "%s/w%d.sock", g_worker_dir, g_worker_index);
	set_config_str(&cfg->link_socket, path);

	/* Connect only to lower-indexed workers, so each pair is linked once. */
	peers[0] = 0;
	for (j = 0; j < g_worker_index; j++)
	{
		char one[128];
		snprintf(one, sizeof(one), "%s%s/w%d.sock", (j ? "," : ""), g_worker_dir, j);
		strncat(peers, one, sizeof(peers) - strlen(peers) - 1);
	}
	set_config_str(&cfg->link_peer, peers);
}

static void master_signal(int sig)
{
	(void) sig;
	g_master_stop = 1;
}

static pid_t spawn_worker(int index, int count);

int main_loop(); /* forward */

static int run_master(int n)
{
	struct hub_config cfg;
	char dir[80];
	unsigned char rnd[16];
	struct sigaction act;
	int i;

	if (read_config(arg_config, &cfg, !arg_have_config) == -1)
		return -1;
	snprintf(dir, sizeof(dir), "%s/uhub-%d", cfg.worker_socket_dir, (int) getpid());
	free_config(&cfg);

	/* Private runtime directory for the inter-worker sockets. */
	if (mkdir(dir, 0700) == -1 && errno != EEXIST)
	{
		LOG_FATAL("Unable to create worker socket directory %s: %s", dir, strerror(errno));
		return -1;
	}
	snprintf(g_worker_dir, sizeof(g_worker_dir), "%s", dir);

	/* Ephemeral shared link secret (memory only), hex-encoded. */
	if (RAND_bytes(rnd, sizeof(rnd)) != 1)
	{
		LOG_FATAL("Unable to generate worker link secret");
		return -1;
	}
	for (i = 0; i < (int) sizeof(rnd); i++)
		snprintf(g_worker_secret + i * 2, 3, "%02x", rnd[i]);

	g_worker_pids = (pid_t*) hub_malloc_zero((size_t) n * sizeof(pid_t));
	if (!g_worker_pids)
		return -1;

	memset(&act, 0, sizeof(act));
	act.sa_handler = master_signal;
	sigaction(SIGTERM, &act, 0);
	sigaction(SIGINT, &act, 0);

	LOG_INFO("Starting logical hub with %d worker processes (sockets in %s)", n, dir);
	for (i = 0; i < n; i++)
		g_worker_pids[i] = spawn_worker(i, n);

	while (!g_master_stop)
	{
		int status;
		pid_t dead = waitpid(-1, &status, 0);
		if (dead < 0)
		{
			if (errno == EINTR)
				continue;
			break;
		}
		if (g_master_stop)
			break;
		for (i = 0; i < n; i++)
		{
			if (g_worker_pids[i] == dead)
			{
				LOG_WARN("worker %d (pid %d) exited; restarting", i, (int) dead);
				g_worker_pids[i] = spawn_worker(i, n);
				break;
			}
		}
	}

	LOG_INFO("Shutting down %d workers...", n);
	for (i = 0; i < n; i++)
		if (g_worker_pids[i] > 0)
			kill(g_worker_pids[i], SIGTERM);
	for (i = 0; i < n; i++)
		if (g_worker_pids[i] > 0)
			waitpid(g_worker_pids[i], 0, 0);

	hub_free(g_worker_pids);
	g_worker_pids = 0;
	rmdir(dir);
	return 0;
}

static pid_t spawn_worker(int index, int count)
{
	pid_t pid = fork();
	if (pid == 0)
	{
		/* Worker: reset the master's signal disposition (main_loop installs the
		   hub's own handlers) and re-enter as a hub with overridden config. */
		signal(SIGTERM, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		g_worker_index = index;
		g_worker_count = count;
		exit(main_loop());
	}
	if (pid < 0)
		LOG_ERROR("fork failed for worker %d: %s", index, strerror(errno));
	return pid;
}
#endif /* !WIN32 */

int main_loop()
{
	struct hub_config configuration;
	struct acl_handle acl;
	struct hub_info* hub = 0;
	int announce_pending = 0;

#ifndef WIN32
	/* Top-level process: if configured for multiple workers, become the master
	   supervisor instead of serving directly. Workers (g_worker_index >= 0)
	   skip this and run as normal hubs below. */
	if (g_worker_index < 0)
	{
		struct hub_config cfg;
		int n;
		if (read_config(arg_config, &cfg, !arg_have_config) == -1)
			return -1;
		n = resolve_worker_count(cfg.workers);
		free_config(&cfg);
		if (n > 1)
			return run_master(n);
	}
#endif

	if (net_initialize() == -1)
		return -1;

	do
	{
		if (hub)
		{
			LOG_INFO("Reloading configuration files...");
			LOG_DEBUG("Hub status: %d", (int) hub->status);

			/* Reinitialize logs */
			hub_log_shutdown();
			hub_log_initialize(arg_log, arg_log_syslog);
			hub_set_log_verbosity(arg_verbose);
		}

		if (read_config(arg_config, &configuration, !arg_have_config) == -1)
			return -1;

#ifndef WIN32
		apply_worker_overrides(&configuration);
#endif

		if (acl_initialize(&configuration, &acl) == -1)
			return -1;

		/*
		 * Don't restart networking when re-reading configuration.
		 * This might not be possible either, since we might have
		 * dropped our privileges to do so.
		 */
		if (!hub)
		{
			hub = hub_start_service(&configuration);
			if (!hub)
			{
				acl_shutdown(&acl);
				free_config(&configuration);
				net_destroy();
				hub_log_shutdown();
				return -1;
			}
#if !defined(WIN32)
			setup_signal_handlers(hub);
#ifdef SYSTEMD
                        /* Notify the service manager that this daemon has
                         * been successfully initialized and shall enter the
                         * main loop.
                         */
                        sd_notifyf(0, "READY=1\n"
                                      "MAINPID=%lu", (unsigned long) getpid());
#endif /* SYSTEMD */

#endif /* ! WIN32 */
			announce_pending = 1;
		}

		hub_set_variables(hub, &acl);

		/* Announce to the registration server once, at first start only (not on
		 * SIGHUP config reloads). command_info is built by hub_set_variables. */
		if (announce_pending)
		{
			regserver_announce(hub);
			announce_pending = 0;
		}

		hub_event_loop(hub);

		hub_free_variables(hub);
		acl_shutdown(&acl);
		free_config(&configuration);

	} while (hub->status == hub_status_restart);

#if !defined(WIN32)
	shutdown_signal_handlers(hub);
#endif

	if (hub)
	{
		hub_shutdown_service(hub);
	}

	net_destroy();
	hub_log_shutdown();
	return 0;
}


int check_configuration(int dump)
{
	struct hub_config configuration;
	int ret = read_config(arg_config, &configuration, 0);

	if (dump)
	{
		if (ret != -1)
		{
			dump_config(&configuration, dump > 1);
		}
		return 0;
	}

	if (ret == -1)
	{
		fprintf(stderr, "ERROR\n");
        	return 1;
	}

	fprintf(stdout, "OK\n");
	return 0;
}


void print_version()
{
	fprintf(stdout, PRODUCT_STRING "\n");
	fprintf(stdout, COPYRIGHT "\n"
			"This is free software with ABSOLUTELY NO WARRANTY.\n\n");
	exit(0);
}


void print_usage(char* program)
{
	fprintf(stderr, "Usage: %s [options]\n\n", program);
	fprintf(stderr,
		"Options:\n"
		"   -v          Verbose mode. Add more -v's for higher verbosity.\n"
		"   -q          Quiet mode - no output\n"
		"   -f          Fork to background\n"
		"   -l <file>   Log messages to given file (default: stderr)\n"
		"   -c <file>   Specify configuration file (default: " SERVER_CONFIG ")\n"
		"   -C          Check configuration and return\n"
		"   -s          Show configuration parameters\n"
		"   -S          Show configuration parameters, but ignore defaults\n"
		"   -h          This message\n"
#ifndef WIN32
#ifdef SYSTEMD
		"   -L          Log messages to journal\n"
#else
		"   -L          Log messages to syslog\n"
#endif
		"   -u <user>   Run as given user\n"
		"   -g <group>  Run with given group permissions\n"
		"   -p <file>   Store pid in file (process id)\n"
#endif
		"   -V          Show version number.\n"
	);

	exit(0);
}


void parse_command_line(int argc, char** argv)
{
	int opt;
	while ((opt = getopt(argc, argv, "vqfc:l:hu:g:VCsSLp:")) != -1)
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
				arg_have_config = 1;
				break;

			case 'C':
				arg_check_config = 1;
				arg_have_config = 1;
				break;

			case 's':
				arg_dump_config = 1;
				arg_check_config = 1;
				break;

			case 'S':
				arg_dump_config = 2;
				arg_check_config = 1;
				break;

			case 'l':
				arg_log = optarg;
				break;

			case 'L':
				arg_log_syslog = 1;
				break;

			case 'h':
				print_usage(argv[0]);
				break;

			case 'u':
				arg_uid = optarg;
				break;

			case 'g':
				arg_gid = optarg;
				break;

			case 'p':
				arg_pid = optarg;
				break;

			default:
				print_usage(argv[0]);
				break;
		}
	}

	if (arg_config == NULL)
	{
		arg_config = SERVER_CONFIG;
	}

	/* Clamp the accumulated verbosity to the valid log-level range so repeated
	   -v cannot drive the threshold past the highest level (log_plugin). */
	if (arg_verbose < 0)
		arg_verbose = 0;
	else if (arg_verbose > log_plugin + 1)
		arg_verbose = log_plugin + 1;

	hub_log_initialize(arg_log, arg_log_syslog);
	hub_set_log_verbosity(arg_verbose);
}


#ifndef WIN32
int drop_privileges()
{
	struct group* perm_group = 0;
	struct passwd* perm_user = 0;
	gid_t perm_gid = 0;
	uid_t perm_uid = 0;
	int gid_ok = 0;
	int ret = 0;

	if (arg_uid || arg_gid)
	{
		if (setgroups(0, NULL) == -1)
		{
			LOG_FATAL("Unable to clear supplementary groups.");
			return -1;
		}
	}

	if (arg_gid)
	{
		ret = 0;
		while ((perm_group = getgrent()) != NULL)
		{
			if (strcmp(perm_group->gr_name, arg_gid) == 0)
			{
				perm_gid = perm_group->gr_gid;
				ret = 1;
				break;
			}
		}

		endgrent();

		if (!ret)
		{
			LOG_FATAL("Unable to determine group id, check group name.");
			return -1;
		}

		LOG_TRACE("Setting group id %d (%s)", (int) perm_gid, arg_gid);
		ret = setgid(perm_gid);
		if (ret == -1)
		{
			LOG_FATAL("Unable to change group id, permission denied.");
			return -1;
		}
		gid_ok = 1;
	}

	if (arg_uid)
	{
		ret = 0;
		while ((perm_user = getpwent()) != NULL)
		{
			if (strcmp(perm_user->pw_name, arg_uid) == 0)
			{
				perm_uid = perm_user->pw_uid;
				if (!gid_ok)
					perm_gid = perm_user->pw_gid;
				ret = 1;
				break;
			}
		}

		endpwent();

		if (!ret)
		{
			LOG_FATAL("Unable to determine user id, check user name.");
			return -1;
		}

		if (!gid_ok) {
			LOG_TRACE("Setting group id %d (%s)", (int) perm_gid, arg_gid);
			ret = setgid(perm_gid);
			if (ret == -1)
			{
				LOG_FATAL("Unable to change group id, permission denied.");
				return -1;
			}
		}

		LOG_TRACE("Setting user id %d (%s)", (int) perm_uid, arg_uid);
		ret = setuid(perm_uid);
		if (ret == -1)
		{
			LOG_FATAL("Unable to change user id, permission denied.");
			return -1;
		}
	}

	/*
	 * Verify the drop actually took effect. setgid/setuid can appear to
	 * succeed yet leave a privileged id reachable (e.g. only the effective id
	 * changed, or a saved-set uid lingers), so confirm both the real and
	 * effective ids are the target and that root can no longer be regained. A
	 * silent half-drop is worse than not dropping at all -- abort rather than
	 * run on with more privilege than intended.
	 */
	if (arg_gid || (arg_uid && !gid_ok))
	{
		if (getgid() != perm_gid || getegid() != perm_gid)
		{
			LOG_FATAL("Group privilege drop did not take effect (gid is %d, wanted %d).",
				(int) getgid(), (int) perm_gid);
			return -1;
		}
	}

	if (arg_uid)
	{
		if (getuid() != perm_uid || geteuid() != perm_uid)
		{
			LOG_FATAL("User privilege drop did not take effect (uid is %d, wanted %d).",
				(int) getuid(), (int) perm_uid);
			return -1;
		}

		/* If we dropped away from root, root must no longer be reachable. */
		if (perm_uid != 0 && setuid(0) != -1)
		{
			LOG_FATAL("Able to regain root after dropping privileges; refusing to continue.");
			return -1;
		}
	}

	return 0;
}

int pidfile_create()
{
	if (arg_pid)
	{
		FILE* pidfile = fopen(arg_pid, "w");
	        if (!pidfile)
		{
			LOG_FATAL("Unable to write pid file: %s\n", arg_pid);
			return -1;
		}

		fprintf(pidfile, "%d", (int) getpid());
		fclose(pidfile);
	}
	return 0;
}

int pidfile_destroy()
{
	if (arg_pid)
	{
		return unlink(arg_pid);
	}
	return 0;
}

#endif /* WIN32 */


int main(int argc, char** argv)
{
	int ret = 0;

	parse_command_line(argc, argv);

	if (arg_check_config)
	{
		return check_configuration(arg_dump_config);
	}

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
			LOG_DEBUG("Forked to background\n");
			return 0;
		}
	}

	if (pidfile_create() == -1)
		return -1;

	if (drop_privileges() == -1)
		return -1;
#endif /* WIN32 */

	ret = main_loop();

#ifndef WIN32
	pidfile_destroy();
#endif

	return ret;
}

