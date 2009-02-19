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

#ifdef HAVE_KQUEUE

static struct kevent* events = 0;
static struct kevent* change = 0;
static int kfd = -1;


static void set_poll_events(struct kevent* handle, short trigger)
{
	if (!handle) {
		hub_log(log_error, "OOOPS!!");
		return;
	}

	memset(handle, 0, sizeof(struct kevent));
	
	if (trigger & evt_accept || trigger & evt_read || trigger & evt_close)
		handle->filter |= EVFILT_READ;
	
	if (trigger & evt_write /* || trigger & evt_accept*/)
		handle->filter |= EVFILT_WRITE;
}

static short get_poll_events(struct kevent* handle)
{
	short trig = handle->flags;
	short evt  = 0;
	
	if (trig & EVFILT_READ)
		evt |= evt_read;
		
	if (trig & EVFILT_WRITE)
		evt |= evt_write;
	
	if (trig & EV_EOF)
	{
		evt |= evt_close;
		
		if (handle->fflags)
			evt |= evt_error;
	}
	
	if (handle->filter == -1)
	{
		
		evt |= evt_error;
	}
	
	if (handle->data)
	{
		evt |= evt_accept;
	}
	
	if (evt)
	{
		hub_log(log_error, "Evt: fd=%d, filter=%d, flags=%d, fflags=%d, data=%d evt=%#x", handle->ident, handle->filter, handle->flags, handle->fflags, (int) handle->data, evt);
		
		
	}
	
	
	return evt;
}

int net_initialize(int capacity)
{
	int i;
	max_connections = capacity;
	num_connections = 0;
	kfd = kqueue();
	if (kfd == -1)
	{
		hub_log(log_error, "net_initialize(): kqueue failed");
		return -1;
	}
	
	events = (void*) hub_malloc_zero(sizeof(struct kevent) * max_connections);
	if (!events)
	{
		hub_log(log_error, "net_initialize(): hub_malloc failed");
		return -1;
	}
	
	change = (void*) hub_malloc_zero(sizeof(struct kevent) * max_connections);
	if (!events)
	{
		hub_log(log_error, "net_initialize(): hub_malloc failed");
		hub_free(events);
		return -1;
	}
	
	
	listeners = (void*) hub_malloc_zero(sizeof(struct net_event_listener) * max_connections);
	if (!listeners)
	{
		hub_log(log_error, "net_initialize(): hub_malloc failed");
		hub_free(change);
		hub_free(events);
		return -1;
	}
	
	for (i = 0; i < max_connections; i++)
	{
		listeners[i].fd = -1;
	}
	
	net_stats_initialize();
	
	return 0;
}


int net_shutdown()
{
	if (kfd != -1) {
		return close(kfd);
	}
	
	hub_free(events);
	hub_free(change);
	hub_free(listeners);
	return 0;
}


int net_wait(int timeout_ms)
{
	int fired, n, max, ret;
	struct net_event_listener* listener;
	struct timespec timeout = { (timeout_ms / 1000), (timeout_ms % 1000) * 1000 };
	
	fired = kevent(kfd, events, num_connections, change, num_connections, &timeout);
	if (fired == -1) {
		if (errno != EINTR)
		{
			hub_log(log_error, "net_wait(): kevent failed");
		}
		return -1;
	}
	
	for (n = 0; n < fired; n++)
	{
		listener = (struct net_event_listener*) events[n].udata;
		if (listener)
		{
			listener->revents = get_poll_events(&events[n]);
			hub_log(log_dump, "net_wait(): kqueue event detected (fd=%d, evt=%d, ptr=%p)", listener->fd, listener->revents, listener);
		}
	}
	
	max = num_connections;
	for (n = 0; n < max; n++)
	{
		listener = &listeners[n];
		if (listener && listener->fd != -1 && listener->revents != 0)
		{
			hub_log(log_dump, "net_wait(): kqueue trigger call  (fd=%d, evt=%d, ptr=%p)", listener->fd, listener->revents, listener);
			ret = listener->handler(listener);
			listener->revents = 0;
		}
	}
	
	return 0;
}


int net_add(int fd, short events_, void* data, net_event_handler_t handler)
{
	struct kevent* event;
	struct net_event_listener* listener = monitor_get_listener(fd);
	
	hub_log(log_trace, "net_add(): adding socket (fd=%d)", fd);
	
	if (listener)
	{
		/* Already added! */
		return -1;
	}
	
	listener = monitor_get_free_listener();
	if (!listener)
	{
		hub_log(log_error, "net_add(): unable to poll more sockets");
		return -1;
	}
	
	net_event_listener_set(listener, fd, events_, data, handler);
	
	event = &events[pos];
	set_poll_events(event, events_);
	event->ident = fd;
	
	event->flags |= EV_ADD;
	event->flags |= EV_ONESHOT;
	
#ifdef __APPLE__
	 event->flags |= EV_ENABLE;
#endif
	event->udata = listener;

	num_connections++;
	return 0;
}

int net_modify(int fd, short events_)
{
	struct kevent* event;
	struct net_event_listener* listener = monitor_get_listener(fd);
	
	hub_log(log_trace, "net_modify(): modifying socket (fd=%d)", fd);
	
	if (!listener)
	{
		/* The socket is not being monitored */
		hub_log(log_error, "net_modify(): unable to find socket (fd=%d)", fd);
		return -1;
	}
	
	event = &events[pos];
	// set_poll_events(event, events_);
	
	event->ident = fd;
	event->flags |= EV_ADD;
	event->flags |= EV_ONESHOT;
#ifdef __APPLE__
	event->flags |= EV_ENABLE;
#endif
	return 0;
}


int net_remove(int fd)
{
	struct kevent* event;
	struct net_event_listener* listener = monitor_get_listener(fd);
	
	hub_log(log_trace, "net_remove(): removing socket (fd=%d)", fd);
	
	if (!listener)
	{
		/* The socket is not being monitored */
		hub_log(log_error, "net_remove(): unable to remove socket (fd=%d)", fd);
		return -1;
	}

	net_event_listener_clear(listener);
	
	event = &events[pos];
	event->ident = fd;
	event->filter = 0;
	event->flags = EV_DELETE;

#ifdef __APPLE__
	event->flasg |= EV_DISABLE;
#endif

	event->fflags = 0;
	event->data = 0;
	event->udata = 0;

	num_connections--;
	return 0;
}


#endif /* HAVE_KQUEUE */



