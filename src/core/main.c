/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2014, Jan Vidar Krey
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

#include "uhub.h"

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
}
#endif /* !WIN32 */


int main_loop()
{
	struct hub_config configuration;
	struct acl_handle acl;
	struct hub_info* hub = 0;

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
                         * been successfully initalized and shall enter the
                         * main loop.
                         */
                        sd_notifyf(0, "READY=1\n"
                                      "MAINPID=%lu", (unsigned long) getpid());
#endif /* SYSTEMD */

#endif /* ! WIN32 */
		}

		hub_set_variables(hub, &acl);

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
				arg_verbose -= 99;
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
			/* child process - detatch from TTY */
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

