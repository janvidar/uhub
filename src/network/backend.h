/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2010, Jan Vidar Krey
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

#ifndef HAVE_UHUB_NETWORK_BACKEND_H
#define HAVE_UHUB_NETWORK_BACKEND_H

/**
 * Initialize the network backend.
 * Returns 1 on success, or 0 on failure.
 */
extern int net_backend_initialize();

/**
 * Shutdown the network connection backend.
 */
extern void net_backend_shutdown();

/**
 * Process the network backend.
 */
extern int net_backend_process();

#endif /* HAVE_UHUB_NETWORK_BACKEND_H */
