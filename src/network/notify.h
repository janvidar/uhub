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

#ifndef HAVE_UHUB_NETWORK_NOTIFY_API_H
#define HAVE_UHUB_NETWORK_NOTIFY_API_H

struct uhub_notify_handle;

typedef void (*net_notify_callback)(struct uhub_notify_handle* handle, void* ptr);

/*
 * This contains a mechanism to wake up the main thread
 * in a thread safe manner while it would be blocking
 * in select() or something equivalent typically invoked from
 * net_backend_process().
 *
 * The main usage is for the DNS resolver to notify the
 * main thread that there are DNS results to be
 * processed.
 */

/**
 * Create a notification handle.
 */
struct uhub_notify_handle* net_notify_create(net_notify_callback cb, void* ptr);

/**
 * Destroy a notification handle.
 */
void net_notify_destroy(struct uhub_notify_handle*);

/**
 * Signal the notification handle, this will surely
 * interrupt the net_backend_process(), and force it to
 * process messages.
 */
void net_notify_signal(struct uhub_notify_handle*, char data);


#endif /* HAVE_UHUB_NETWORK_NOTIFY_API_H */
