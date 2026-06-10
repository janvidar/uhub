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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

/*
 * libFuzzer harness for the IP address / range parser (ipcalc).
 *
 * The IPv6 and IPv4 address strings themselves are validated via inet_pton
 * (net_string_to_address), but the uhub-specific glue around it is hand-rolled
 * and security-relevant: ip_convert_address_to_range() parses the ACL
 * "deny_ip" / range syntax ("addr/cidr", "lo-hi", or a bare address) for both
 * families, routing through the CIDR mask creation/application and the address
 * comparison math -- the same math that previously had signed-overflow and
 * left-shift-of-negative undefined behaviour.
 *
 * This feeds arbitrary text into both the range parser and the single-address
 * converter, then exercises the downstream address operations (compare,
 * range-membership, to-string) on whatever parsed successfully.
 *
 * Build with:  cmake -B build-fuzz -DFUZZING=ON -DSSL_SUPPORT=OFF .  (clang)
 * Run with:    ./build-fuzz/fuzz_ipcalc autotest/fuzz/corpus/ipcalc
 */

#include "uhub.h"

#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
	(void) argc;
	(void) argv;
	hub_set_log_verbosity(0);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	struct ip_range range;
	struct ip_addr_encap addr;

	char* s = hub_malloc(size + 1);
	if (!s)
		return 0;
	memcpy(s, data, size);
	s[size] = '\0';

	/* 1. The full ACL range syntax: "addr/cidr", "lo-hi", or a bare address,
	 *    for both IPv4 and IPv6. This reaches check_ip_mask() (CIDR mask
	 *    creation + AND/OR application) and check_ip_range(). */
	if (ip_convert_address_to_range(s, &range))
	{
		ip_compare(&range.lo, &range.hi);
		ip_convert_to_string(&range.lo);
		ip_convert_to_string(&range.hi);
	}

	/* 2. Single-address conversion, then the downstream address math on the
	 *    parsed binary form. */
	if (ip_convert_to_binary(s, &addr) != -1)
	{
		ip_convert_to_string(&addr);
		ip_is_valid_ipv6(s);
		ip_is_valid_ipv4(s);

		if (ip_convert_address_to_range(s, &range))
			ip_in_range(&addr, &range);
	}

	hub_free(s);
	return 0;
}
