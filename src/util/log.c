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
#include <locale.h>

#ifndef WIN32

#ifdef SYSTEMD
#define SD_JOURNAL_SUPPRESS_LOCATION
#include <systemd/sd-journal.h>

#else
#include <syslog.h>
#endif

static int use_syslog = 0;
#endif

static int verbosity = 4;
static FILE* logfile = NULL;

#ifdef MEMORY_DEBUG
static FILE* memfile = NULL;
#define MEMORY_DEBUG_FILE "memlog.txt"
#endif

#ifdef NETWORK_DUMP_DEBUG
#define NETWORK_DUMP_FILE "netdump.log"
static FILE* netdump = NULL;
#endif


static const char* prefixes[] =
{
	"FATAL",
	"ERROR",
	"WARN",
	"USER",
	"INFO",
	"DEBUG",
	"TRACE",
	"DUMP",
	"MEM",
	"PROTO",
	"PLUGIN",
	0
};


void hub_log_initialize(const char* file, int syslog)
{

	setlocale(LC_ALL, "C");

#ifdef MEMORY_DEBUG
	memfile = fopen(MEMORY_DEBUG_FILE, "w");
	if (!memfile)
	{
		fprintf(stderr, "Unable to create " MEMORY_DEBUG_FILE " for logging memory allocations\n");
		return;
	}
#endif

#ifdef NETWORK_DUMP_DEBUG
	netdump = fopen(NETWORK_DUMP_FILE, "w");
	if (!netdump)
	{
		fprintf(stderr, "Unable to create " NETWORK_DUMP_FILE " for logging network traffic\n");
		return;
	}
#endif

#ifndef WIN32
	if (syslog)
	{
		use_syslog = 1;
                #ifndef SYSTEMD
		openlog("uhub", LOG_PID, LOG_USER);
                #endif
	}
#endif


	if (!file)
	{
		logfile = stderr;
		return;
	}

	logfile = fopen(file, "a");
	if (!logfile)
	{
		logfile = stderr;
		return;
	}

}


void hub_log_shutdown()
{
	if (logfile && logfile != stderr)
	{
		fclose(logfile);
		logfile = NULL;
	}

#ifdef MEMORY_DEBUG
	if (memfile)
	{
		fclose(memfile);
		memfile = NULL;
	}
#endif

#ifdef NETWORK_DUMP_DEBUG
	if (netdump)
	{
		fclose(netdump);
		netdump = NULL;
	}
#endif

#ifndef WIN32
	if (use_syslog)
	{
		use_syslog = 0;
                #ifndef SYSTEMD
		closelog();
                #endif
	}
#endif
}


void hub_set_log_verbosity(int verb)
{
	verbosity = verb;
}

void hub_log(int log_verbosity, const char *format, ...)
{
	static char logmsg[1024];
	static char timestamp[32];
	struct tm *tmp;
	time_t t;
	va_list args;

#ifdef MEMORY_DEBUG
	if (memfile && log_verbosity == log_memory)
	{
		va_start(args, format);
		vsnprintf(logmsg, 1024, format, args);
		va_end(args);
		fprintf(memfile, "%s\n", logmsg);
		fflush(memfile);
		return;
	}
#endif

#ifdef NETWORK_DUMP_DEBUG
	if (netdump && log_verbosity == log_protocol)
	{
		va_start(args, format);
		vsnprintf(logmsg, 1024, format, args);
		va_end(args);
		fprintf(netdump, "%s\n", logmsg);
		fflush(netdump);
		return;
	}
#endif

	if (log_verbosity < verbosity)
	{
		t = time(NULL);
		tmp = localtime(&t);
		strftime(timestamp, 32, "%Y-%m-%d %H:%M:%S", tmp);
		va_start(args, format);
		vsnprintf(logmsg, 1024, format, args);
		va_end(args);

		if (logfile)
		{
			fprintf(logfile, "%s %6s: %s\n", timestamp, prefixes[log_verbosity], logmsg);
			fflush(logfile);
		}
		else
		{
			fprintf(stderr, "%s %6s: %s\n", timestamp, prefixes[log_verbosity], logmsg);
		}
	}

#ifndef WIN32
	if (use_syslog)
	{
		int level = 0;

		if (verbosity < log_info)
			return;

		va_start(args, format);
		vsnprintf(logmsg, 1024, format, args);
		va_end(args);

		switch (log_verbosity)
		{
			case log_fatal:    level = LOG_CRIT; break;
			case log_error:    level = LOG_ERR; break;
			case log_warning:  level = LOG_WARNING; break;
                        #ifdef SYSTEMD
                        case log_user:     level = LOG_INFO; break;

                        #else
                        case log_user:     level = LOG_INFO | LOG_AUTH; break;
                        #endif
			case log_info:     level = LOG_INFO; break;
			case log_debug:    level = LOG_DEBUG; break;

			default:
				level = 0;
				break;
		}

		if (level == 0)
			return;

                #ifdef SYSTEMD
		sd_journal_print(level, "%s", logmsg);

                #else
		level |= (LOG_USER | LOG_DAEMON);
		syslog(level, "%s", logmsg);
                #endif
	}
#endif

}
