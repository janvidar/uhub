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

#include "util/getopt.h"

#ifdef NEED_GETOPT

char *optarg = NULL;
int optind = 1;

/*
 * This is a very simple subset of the real getopt().
 */
int getopt(int argc, char* const argv[], const char *optstring)
{
	int ret;
	char* pos;
	char* arg;
	optarg = NULL;

	/* Bounds-check before indexing argv: argv[argc] is NULL and anything past
	   it is out of bounds. Read the argument only once it is known to exist. */
	if (optind >= argc)
		return -1;
	arg = argv[optind++];

	if (!arg || *arg != '-')
		return -1;

	arg++;
	if (*arg == '-')
		arg++;

	ret = *arg;

	pos = strchr(optstring, ret);
	if (!pos)
		return ret;

	/* Consume the option-argument only if one actually follows. */
	if (*(pos+1) == ':' && optind < argc)
		optarg = argv[optind++];

	return ret;
}

#endif

