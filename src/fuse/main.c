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

#include "fuse/config.h"
#include "fuse/fs.h"
#include "fuse/transfer.h"
#include "fuse/session.h"
#include "network/network.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/threads.h"
#include "version.h"

/*
 * uhub-fuse: an ADC hub, mounted.
 *
 * Two threads. This one ends up inside fuse_main(), which owns the process's
 * signal handling and does not return until the filesystem is unmounted. The
 * other runs uhub's event loop and owns every piece of hub state there is; see
 * fuse/bridge.h for how the two meet.
 *
 * The event loop is started before fuse_main() rather than from an init()
 * callback, so that a hub which refuses the login has somewhere to report it
 * other than a mounted, empty directory.
 */

struct fs_options
{
	char* config;
	char* address;
	char* nick;
	char* password;
};

static struct fs_options options;

#define FS_OPT(t, p) { t, offsetof(struct fs_options, p), 1 }

static const struct fuse_opt option_spec[] = {
	FS_OPT("--config=%s",   config),
	FS_OPT("--hub=%s",      address),
	FS_OPT("--nick=%s",     nick),
	FS_OPT("--password=%s", password),
	FUSE_OPT_END
};

static void usage(const char* program)
{
	printf("Usage: %s --hub=adc[s]://host:port [options] <mountpoint>\n\n", program);
	printf("uhub-fuse options:\n");
	printf("    --config=FILE          read the settings below from FILE instead.\n");
	printf("                           Keep the password there, not on the command\n");
	printf("                           line, and chmod 600 it\n");
	printf("    --hub=URL              the hub to mount. Use adcs:// for TLS, and\n");
	printf("                           adcs://host:port/?kp=SHA256/<base32> to pin\n");
	printf("                           the hub's certificate\n");
	printf("    --nick=NAME            the nick to log in with (default: uhub-fuse)\n");
	printf("    --password=SECRET      the password, for a registered account. Every\n");
	printf("                           user on this machine can read it out of ps;\n");
	printf("                           prefer --config\n");
	printf("\n");
	printf("The mount holds hub/ (what the hub says about itself), me/, users/ (one\n");
	printf("directory per user, named by CID) and by-nick/ (symlinks into users/).\n");
	printf("\n");
}

/** The ADC thread: uhub's event loop, and everything it owns. */
static void* session_thread(void* ptr)
{
	struct fs_session* session = (struct fs_session*) ptr;

	fs_session_run(session);
	return NULL;
}

int main(int argc, char** argv)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_cmdline_opts opts;
	struct fs_session* session = NULL;
	struct fs_config config;
	struct fuse* fuse = NULL;
	uhub_thread_t* thread = NULL;
	int mounted = 0;
	int handlers = 0;
	int result = 1;
	int loop_result;

	memset(&options, 0, sizeof(options));
	memset(&opts, 0, sizeof(opts));
	memset(&config, 0, sizeof(config));

	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;

	/*
	 * The FUSE_USE_VERSION 31 spelling of fuse_loop_mt() takes no thread
	 * configuration, so its idle thread count stays at the UINT_MAX default
	 * that libfuse >= 3.12 warns about on every start. The mount option is the
	 * only way to set it at this API version. Inserted at the front so an -o
	 * the caller passes is parsed later and still wins.
	 *
	 * Staying on 31 is deliberate: the configuration API arrived in libfuse
	 * 3.12, and several distributions that are current still ship 3.10.
	 */
	fuse_opt_insert_arg(&args, 1, "-o");
	fuse_opt_insert_arg(&args, 2, "max_idle_threads=10");

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;

	if (opts.show_help)
	{
		usage(argv[0]);
		fuse_cmdline_help();
		fuse_lib_help(&args);
		result = 0;
		goto cleanup;
	}

	if (opts.show_version)
	{
		printf("uhub-fuse %s\n", VERSION);
		fuse_lowlevel_version();
		result = 0;
		goto cleanup;
	}

	if (!opts.mountpoint)
	{
		fprintf(stderr, "%s: no mountpoint given. See --help.\n", argv[0]);
		goto cleanup;
	}

	/*
	 * The file first, then the command line over it: an operator who keeps a
	 * password in a 0600 file must still be able to point the same file at a
	 * different hub for one run.
	 */
	fs_config_defaults(&config);

	if (options.config && !fs_config_read(options.config, &config))
		goto cleanup;

	if (options.address && !fs_config_set(&config, "hub", options.address))
		goto cleanup;

	if (options.nick && !fs_config_set(&config, "nick", options.nick))
		goto cleanup;

	if (options.password)
	{
		if (!fs_config_set(&config, "password", options.password))
			goto cleanup;

		/* Said once, plainly. The value is in argv either way by the time we
		   are running, so this is a warning and not a refusal. */
		fprintf(stderr, "%s: --password is visible to every user on this machine "
		                "in ps; use --config with a file chmod 600.\n", argv[0]);
	}

	if (!config.address || !*config.address)
	{
		fprintf(stderr, "%s: no hub given. Use --hub=adc://host:port or a config "
		                "file, or --help.\n", argv[0]);
		goto cleanup;
	}

	fuse = fuse_new(&args, fs_get_operations(), sizeof(struct fuse_operations), NULL);
	if (!fuse)
		goto cleanup;

	if (fuse_mount(fuse, opts.mountpoint) != 0)
		goto cleanup;
	mounted = 1;

	/*
	 * Everything above this line runs in the process that was started;
	 * everything below may run in a forked child. fuse_daemonize() is the
	 * fork, and a thread does not survive one -- the child would come up with
	 * a mounted filesystem, no event loop behind it, and every operation
	 * blocking for ever. So the hub session is built and started here, after
	 * the fork, and not before it.
	 */
	if (fuse_daemonize(opts.foreground) != 0)
		goto cleanup;

	/*
	 * In the foreground, say what is happening: a mount that is fetching a
	 * file from somebody has nowhere else to report progress, and INFO is
	 * where those messages are. Daemonized, keep to what an operator would
	 * want in a log.
	 */
	hub_set_log_verbosity(opts.foreground ? 5 : 4);
	net_initialize();

	session = fs_session_create(&config);
	if (!session)
	{
		fprintf(stderr, "%s: unable to create the hub session.\n", argv[0]);
		goto cleanup;
	}

	/*
	 * A mount without a transfer port still works; it just cannot fetch
	 * anything, so by-tth is empty. Worth a warning rather than a refusal --
	 * the port may be taken by a second mount, and reading the user list is
	 * the greater part of what this is for.
	 */
	fs_session_set_transfer(session, fs_transfer_create(session, &config));

	fs_set_session(session);

	fs_session_start(session);

	thread = uhub_thread_create(session_thread, session);
	if (!thread)
	{
		fprintf(stderr, "%s: unable to start the hub thread.\n", argv[0]);
		goto cleanup;
	}

	if (fuse_set_signal_handlers(fuse_get_session(fuse)) != 0)
		goto cleanup;
	handlers = 1;

	if (opts.singlethread)
	{
		loop_result = fuse_loop(fuse);
	}
	else
	{
		loop_result = fuse_loop_mt(fuse, opts.clone_fd);
	}

	/*
	 * The loop reports three things in one int: 0 for the unmount, a negative
	 * errno for a failure, and -- easy to mistake for one -- a *positive*
	 * signal number when it was terminated by a signal. Both of the first and
	 * last are a shutdown that did what it was asked, and an init system that
	 * saw SIGTERM answered with a non-zero status would record every clean
	 * stop as a crash.
	 */
	result = (loop_result < 0) ? 1 : 0;

cleanup:
	if (session)
		fs_session_stop(session);

	if (thread)
		uhub_thread_join(thread);

	if (handlers)
		fuse_remove_signal_handlers(fuse_get_session(fuse));

	if (mounted)
		fuse_unmount(fuse);

	if (fuse)
		fuse_destroy(fuse);

	if (session)
	{
		fs_session_destroy(session);
		net_destroy();
	}

	fs_config_free(&config);

	free(opts.mountpoint);
	fuse_opt_free_args(&args);

	hub_free(options.config);
	hub_free(options.address);
	hub_free(options.nick);

	/* fuse_opt_parse() strdup'd it out of argv; the copy goes now, even though
	   the original is still there for anyone reading ps. */
	if (options.password)
	{
		memset(options.password, 0, strlen(options.password));
		hub_free(options.password);
	}

	return result;
}
