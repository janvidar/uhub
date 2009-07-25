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

#include "uhub.h"

const char* BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

char* sid_to_string(sid_t sid_)
{
	static char t_sid[5];
	sid_t sid = (sid_ & 0xFFFFF); /*  20 bits only */
	sid_t A, B, C, D = 0;
	D     = (sid % 32);
	sid   = (sid - D) / 32;
	C     = (sid % 32);
	sid   = (sid - C) / 32;
	B     = (sid % 32);
	sid   = (sid - B) / 32;
	A     = (sid % 32);
	t_sid[0] = BASE32_ALPHABET[A];
	t_sid[1] = BASE32_ALPHABET[B];
	t_sid[2] = BASE32_ALPHABET[C];
	t_sid[3] = BASE32_ALPHABET[D];
	t_sid[4] = 0;
	return t_sid;
}


sid_t string_to_sid(const char* sid)
{
	sid_t nsid = 0;
	sid_t n, x;
	sid_t factors[] = { 32768, 1024, 32, 1};
	
	if (!sid || strlen(sid) != 4) return 0;

	for (n = 0; n < 4; n++) {
		for (x = 0; x < strlen(BASE32_ALPHABET); x++)
			if (sid[n] == BASE32_ALPHABET[x]) break;
		if (x == 32) return 0;
		nsid += x * factors[n];
	}
	return nsid;
}

