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
#include "network/network.h"
#include "testutil_net.h"

/* One count for the whole test binary: this file is compiled once. */
static int test_net_refs = 0;

int test_net_acquire(void)
{
	if (test_net_refs == 0 && net_initialize() != 0)
		return 0;
	test_net_refs++;
	return 1;
}

void test_net_release(void)
{
	if (test_net_refs > 0 && --test_net_refs == 0)
		net_destroy();
}
