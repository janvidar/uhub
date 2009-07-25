/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2009, Jan Vidar Krey
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
};

/**
 * Specify a minimum log verbosity for what messages should
 * be printed in the log.
 */
extern void hub_set_log_verbosity(int log_verbosity);

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
