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

#include "uhub.h"

struct uhub_notify_handle
{
	net_notify_callback callback;
	void* ptr;
#ifndef WIN32
	int pipe_fd[2];
	struct net_connection* con;
#endif
};

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
#ifndef WIN32
static void notify_callback(struct net_connection* con, int event, void* ptr)
{
	LOG_TRACE("notify_callback()");
	struct uhub_notify_handle* handle = (struct uhub_notify_handle*) ptr;
	char buf;
	int ret = read(handle->pipe_fd[0], &buf, 1);
	if (ret == 1)
	{
		if (handle->callback)
			handle->callback(handle, handle->ptr);
	}
}
#endif

struct uhub_notify_handle* net_notify_create(net_notify_callback cb, void* ptr)
{
	LOG_TRACE("net_notify_create()");
	struct uhub_notify_handle* handle = (struct uhub_notify_handle*) hub_malloc(sizeof(struct uhub_notify_handle));
	handle->callback = cb;
	handle->ptr = ptr;
#ifndef WIN32
	int ret = pipe(handle->pipe_fd);
	if (ret == -1)
	{
		LOG_ERROR("Unable to setup notification pipes.");
		hub_free(handle);
		return 0;
	}

	handle->con = net_con_create();
	net_con_initialize(handle->con, handle->pipe_fd[0], notify_callback, handle, NET_EVENT_READ);
#endif
	return handle;
}


void net_notify_destroy(struct uhub_notify_handle* handle)
{
	LOG_TRACE("net_notify_destroy()");
#ifndef WIN32
	net_con_destroy(handle->con);
	close(handle->pipe_fd[0]);
	close(handle->pipe_fd[1]);
	handle->pipe_fd[0] = -1;
	handle->pipe_fd[0] = -1;
#endif
	hub_free(handle);
}

void net_notify_signal(struct uhub_notify_handle* handle, char data)
{
	LOG_TRACE("net_notify_signal()");
#ifndef WIN32
	write(handle->pipe_fd[1], &data, 1);
#endif
}