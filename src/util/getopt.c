/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2013, Jan Vidar Krey
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
	char* arg = argv[optind++];
	optarg = NULL;

	if (optind > argc)
		return -1;

	if (*arg != '-')
		return -1;

	arg++;
	if (*arg == '-')
		arg++;

	ret = *arg;

	pos = strchr(optstring, ret);
	if (!pos)
		return ret;

	if (*(pos+1) == ':')
		optarg = argv[optind++];

	return ret;
}

#endif

