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

#ifndef HAVE_UHUB_TESTUTIL_NET_H
#define HAVE_UHUB_TESTUTIL_NET_H

/**
 * The network layer (net_initialize / net_destroy) is process-wide, but several
 * test files need it, and under --sort=random their tests interleave: one
 * file's teardown must not shut it down under another's. So a file takes a
 * reference in its EXO_SETUP and drops it in its EXO_TEARDOWN; the first
 * acquire initializes the network and the last release destroys it.
 *
 * Returns 1 on success, as an EXO_SETUP does.
 */
extern int test_net_acquire(void);
extern void test_net_release(void);

#endif /* HAVE_UHUB_TESTUTIL_NET_H */
