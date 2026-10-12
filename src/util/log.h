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

#ifndef HAVE_UHUB_LOG_H
#define HAVE_UHUB_LOG_H

enum log_verbosity {
	log_fatal    = 0,
	log_error    = 1,
	log_warning  = 2,
	log_user     = 3,
	log_info     = 4,
	log_debug    = 5,
	log_trace    = 6,
	log_dump     = 7,
	log_memory   = 8,
	log_protocol = 9,
	log_plugin   = 10,
};

#define LOG_FATAL(format, ...)  hub_log(log_fatal,    format __VA_OPT__(,) __VA_ARGS__)
#define LOG_ERROR(format, ...)  hub_log(log_error,    format __VA_OPT__(,) __VA_ARGS__)
#define LOG_WARN(format, ...)   hub_log(log_warning,  format __VA_OPT__(,) __VA_ARGS__)
#define LOG_USER(format, ...)   hub_log(log_user,     format __VA_OPT__(,) __VA_ARGS__)
#define LOG_INFO(format, ...)   hub_log(log_info,     format __VA_OPT__(,) __VA_ARGS__)

#ifdef DEBUG
# define LOG_DEBUG(format, ...)  hub_log(log_debug,    format __VA_OPT__(,) __VA_ARGS__)
# define LOG_TRACE(format, ...)  hub_log(log_trace,    format __VA_OPT__(,) __VA_ARGS__)
# define LOG_PLUGIN(format, ...) hub_log(log_plugin,   format __VA_OPT__(,) __VA_ARGS__)
#else
# define LOG_DEBUG(format, ...)  do { } while(0)
# define LOG_TRACE(format, ...)  do { } while(0)
# define LOG_PLUGIN(format, ...) do { } while(0)
#endif

/*
 * A wire-level protocol trace that survives a release build.
 *
 * LOG_DEBUG and LOG_TRACE compile to nothing unless DEBUG is defined, and
 * LOG_PROTO needs LOWLEVEL_DEBUG on top of that, so on a packaged binary there
 * is no way to see what was actually said on a connection -- which is precisely
 * what diagnosing a transfer against somebody else's client needs, and
 * rebuilding the daemon is rarely an option at the point the question is asked.
 *
 * LOG_WIRE is compiled in unconditionally and gated at runtime instead: it
 * prints only once the verbosity has been raised to log_protocol (uhub-seeder
 * -vvvvvv, uhub-fuse --trace). Keep it to per-line and per-event protocol
 * detail; anything an operator would want in an ordinary log belongs in
 * LOG_INFO.
 */
#define LOG_WIRE(format, ...)   hub_log(log_protocol, format __VA_OPT__(,) __VA_ARGS__)

#ifdef LOWLEVEL_DEBUG
# define LOG_DUMP(format, ...)   hub_log(log_dump,     format __VA_OPT__(,) __VA_ARGS__)
# define LOG_MEMORY(format, ...) hub_log(log_memory,   format __VA_OPT__(,) __VA_ARGS__)
# define LOG_PROTO(format, ...)  hub_log(log_protocol, format __VA_OPT__(,) __VA_ARGS__)
#else
# define LOG_DUMP(format, ...)   do { } while(0)
# define LOG_MEMORY(format, ...) do { } while(0)
# define LOG_PROTO(format, ...)  do { } while(0)
#endif


/**
 * Specify a minimum log verbosity for what messages should
 * be printed in the log.
 */
extern void hub_set_log_verbosity(int log_verbosity);

/**
 * The current verbosity. A message is printed when its level is below it, so
 * the most detailed level shown is one less, and 0 means nothing is printed.
 */
extern int hub_get_log_verbosity(void);

/**
 * The name of a log level ("info"), or NULL for a value that is not one.
 */
extern const char* hub_log_level_to_string(int level);

/**
 * The log level with this name, ignoring case, or -1 for an unknown name.
 */
extern int hub_log_level_from_string(const char* name);

/**
 * @return 1 when a message logged at @p log_verbosity would be printed.
 *
 * For callers that would otherwise pay to format a message nobody will see --
 * a hex dump of a chunk of body, most of all.
 */
extern int hub_log_enabled(int log_verbosity);

/**
 * Print a message in the log.
 */
extern void hub_log(int log_verbosity, const char *format, ...);

/**
 * Initialize the log subsystem, if no output file is given (file is null)
 * stderr is assumed by default.
 * If the file cannot be opened for writing, stdout is also used.
 */
extern void hub_log_initialize(const char* file, int syslog);

/**
 * Shut down and close the logfile.
 */
extern void hub_log_shutdown();

#endif /* HAVE_UHUB_LOG_H */
