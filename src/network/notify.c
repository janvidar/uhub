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
#include "util/log.h"
#include "util/memory.h"
#include "network/connection.h"
#include "network/network.h"
#include "network/ipcalc.h"
#include "network/notify.h"

struct uhub_notify_handle
{
	net_notify_callback callback;
	void* ptr;
	int pipe_fd[2];              /* [0] = read end (polled), [1] = write end (signalled) */
	struct net_connection* con; /* wraps the read end so the event loop watches it */
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
 *
 * The wake channel is an anonymous pipe on POSIX. On Windows select() only
 * accepts SOCKETs (a pipe handle cannot be waited on), so we use a loopback TCP
 * socket pair instead: the read end is a real socket the select backend can
 * poll, and signalling is a 1-byte send() on the write end.
 */

#ifdef WINSOCK
/*
 * A socketpair()-style connected loopback TCP pair, since Windows lacks both
 * socketpair() and pollable pipes. fd[0] is the accepted (read) end, fd[1] the
 * connected (write) end. Returns 0 on success, -1 on failure.
 */
static int notify_pipe_create(int fd[2])
{
	struct sockaddr_in addr, me, peer;
	socklen_t len;
	int listener, client, server;
	struct ip_addr_encap dummy;

	fd[0] = fd[1] = -1;

	listener = net_socket_create(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listener == -1)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0; /* ephemeral */

	len = sizeof(addr);
	if (net_bind(listener, (struct sockaddr*) &addr, sizeof(addr)) == -1
		|| getsockname(listener, (struct sockaddr*) &addr, &len) == -1
		|| net_listen(listener, 1) == -1)
	{
		net_close(listener);
		return -1;
	}

	client = net_socket_create(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client == -1)
	{
		net_close(listener);
		return -1;
	}

	/* Blocking connect to a listening loopback port completes at once. */
	if (net_connect(client, (struct sockaddr*) &addr, sizeof(addr)) == -1)
	{
		net_close(listener);
		net_close(client);
		return -1;
	}

	server = net_accept(listener, &dummy);
	net_close(listener);
	if (server == -1)
	{
		net_close(client);
		return -1;
	}

	/* Guard against another local process racing in on the ephemeral port:
	   the accepted peer must be exactly our client's local endpoint. */
	len = sizeof(me);
	socklen_t plen = sizeof(peer);
	if (getsockname(client, (struct sockaddr*) &me, &len) == -1
		|| getpeername(server, (struct sockaddr*) &peer, &plen) == -1
		|| me.sin_family != peer.sin_family
		|| me.sin_addr.s_addr != peer.sin_addr.s_addr
		|| me.sin_port != peer.sin_port)
	{
		net_close(client);
		net_close(server);
		return -1;
	}

	fd[0] = server;
	fd[1] = client;
	return 0;
}

static int notify_pipe_read(int fd, char* buf)  { return net_recv(fd, buf, 1, 0) == 1; }
static int notify_pipe_write(int fd, char data) { return net_send(fd, &data, 1, 0) == 1; }
static void notify_pipe_close(int fd)           { net_close(fd); }

#else /* POSIX: anonymous pipe + raw read/write */

static int notify_pipe_create(int fd[2])        { return pipe(fd); }
static int notify_pipe_read(int fd, char* buf)  { return read(fd, buf, 1) == 1; }
static int notify_pipe_write(int fd, char data) { return write(fd, &data, 1) == 1; }
static void notify_pipe_close(int fd)           { close(fd); }

#endif

static void notify_callback(struct net_connection* con, int event, void* ptr)
{
	(void) con; (void) event;
	LOG_TRACE("notify_callback()");
	struct uhub_notify_handle* handle = (struct uhub_notify_handle*) ptr;
	char buf;
	if (notify_pipe_read(handle->pipe_fd[0], &buf))
	{
		if (handle->callback)
			handle->callback(handle, handle->ptr);
	}
}

struct uhub_notify_handle* net_notify_create(net_notify_callback cb, void* ptr)
{
	LOG_TRACE("net_notify_create()");
	struct uhub_notify_handle* handle = (struct uhub_notify_handle*) hub_malloc(sizeof(struct uhub_notify_handle));
	handle->callback = cb;
	handle->ptr = ptr;

	if (notify_pipe_create(handle->pipe_fd) == -1)
	{
		LOG_ERROR("Unable to setup notification pipes.");
		hub_free(handle);
		return 0;
	}

	handle->con = net_con_create();
	net_con_initialize(handle->con, handle->pipe_fd[0], notify_callback, handle, NET_EVENT_READ);
	return handle;
}


void net_notify_destroy(struct uhub_notify_handle* handle)
{
	LOG_TRACE("net_notify_destroy()");
	net_con_destroy(handle->con);
	notify_pipe_close(handle->pipe_fd[0]);
	notify_pipe_close(handle->pipe_fd[1]);
	handle->pipe_fd[0] = -1;
	handle->pipe_fd[1] = -1;
	hub_free(handle);
}

void net_notify_signal(struct uhub_notify_handle* handle, char data)
{
	LOG_TRACE("net_notify_signal()");
	(void) notify_pipe_write(handle->pipe_fd[1], data);
}