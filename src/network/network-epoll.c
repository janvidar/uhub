/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007, Jan Vidar Krey
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

#ifdef HAVE_EPOLL

// #define DEBUG_EPOLL
static struct epoll_event* events = 0;
static int epfd = -1;

#ifdef DEBUG_EPOLL
static void dump_listeners()
{
	int i;
	struct net_event_listener* listener;
	
	
	hub_log(log_dump, "listeners: number=%d", num_connections);
	
	for (i = 0; i < num_connections; i++)
	{
		listener = &listeners[i];
		
		if (listener)
		{
			if (listener->fd != -1)
			{
				hub_log(log_dump, "epoll_dump_listeners: pos=%d/%d fd=%d, ptr=%p", i, num_connections, listeners->fd, listeners);
			}
			else
			{
				hub_log(log_dump, "epoll_dump_listeners: pos=%d/%d (unused)", i, num_connections);
			}
			
			listener = 0;
		}
	}
	
	getc(stdin);
	
}

#endif


static void set_poll_events(struct epoll_event* handle, short trigger)
{
	memset(handle, 0, sizeof(struct epoll_event));
	
	if (trigger & evt_accept || trigger & evt_read || trigger & evt_close)
		handle->events |= EPOLLIN;
	
	if (trigger & evt_write)
		handle->events |= EPOLLOUT;

	if (trigger & evt_urgent)
		handle->events |= EPOLLPRI;

#ifdef EPOLLRDHUP
	if (triggers & evt_close)
		handle->events |= EPOLLRDHUP;
#endif
}

static short get_poll_events(struct epoll_event* handle)
{
	short trig = handle->events;
	short evt  = 0;
	
	if (trig & EPOLLIN)
		evt |= evt_read;
		
	if (trig & EPOLLPRI)
		evt |= evt_urgent;
	
	if (trig & EPOLLOUT)
		evt |= evt_write;
	
	if (trig & EPOLLHUP)
		evt |= evt_close;

	if (trig & EPOLLERR)
		evt |= evt_error;

#ifdef EPOLLRDHUP
	if (trig & EPOLLRDHUP)
		evt |= evt_close;
#endif

	return evt;
}


int net_initialize(int capacity)
{
	int i;
	max_connections = capacity;
	num_connections = 0;
	epfd = epoll_create(max_connections);
	if (epfd == -1)
	{
		hub_log(log_error, "net_initialize(): epoll_create failed");
		return -1;
	}
	
	events = hub_malloc_zero(sizeof(struct epoll_event) * max_connections);
	if (!events)
	{
		hub_log(log_error, "net_initialize(): hub_malloc failed");
		return -1;
	}
	
	monitor_allocate((size_t) capacity);
	

	
#ifdef DEBUG_EPOLL
	dump_listeners();
#endif
	
	net_stats_initialize();
	
	return 0;
}


int net_shutdown()
{
	hub_log(log_trace, "Shutting down network monitor");
	if (epfd != -1)
	{
		close(epfd);
	}
	
	hub_free(events);
	hub_free(listeners);
	return 0;
}

#ifdef DEBUG_EPOLL
uint64_t get_time_difference_in_msec(struct timeval before, struct timeval after)
{
	uint64_t seconds = (after.tv_sec - before.tv_sec);
	uint64_t out = seconds*1000;
	if (seconds > 0)
		out += ((after.tv_usec / 1000) + (1000 - (before.tv_usec / 1000)));
	else
		out += ((after.tv_usec - before.tv_usec) / 1000);
	return out;
}
#endif

int net_wait(int timeout_ms)
{
	int fired, n, max, ret;
	struct net_event_listener* listener;
	
#ifdef DEBUG_EPOLL
	struct timeval tm_before;
	struct timeval tm_after;
	gettimeofday(&tm_before, NULL);
	dump_listeners();
#endif
	
	fired = epoll_wait(epfd, events, num_connections, timeout_ms);
	if (fired == -1) {
		if (errno != EINTR)
		{
			hub_log(log_error, "net_wait(): epoll_wait failed");
		}
		return -1;
	}
	
	for (n = 0; n < fired; n++)
	{
		listener = (struct net_event_listener*) events[n].data.ptr;
		listener->revents = get_poll_events(&events[n]);
		hub_log(log_dump, "net_wait(): epoll event detected (fd=%d, evt=%d, ptr=%p)", listener->fd, listener->revents, listener);
	}
	
	max = num_connections;
	
	for (n = 0; n < max; n++)
	{
		listener = &listeners[n];
		if (listener && listener->fd != -1 && listener->revents)
		{
			hub_log(log_dump, "net_wait(): epoll trigger call  (fd=%d, evt=%d, ptr=%p)", listener->fd, listener->revents, listener);
			ret = listener->handler(listener);
			listener->revents = 0;
		}
#ifdef DEBUG_EPOLL
		else
		{
			if (listener)
				hub_log(log_dump, "net_wait(): epoll trigger ignore (fd=%d, evt=%d, ptr=%p)", listener->fd, listener->revents, listener);
		}
#endif
	}

#ifdef DEBUG_EPOLL
	gettimeofday(&tm_after, NULL);
	size_t diff = (size_t) get_time_difference_in_msec(tm_before, tm_after);
	dump_listeners();
	hub_log(log_debug, "net_wait(): time=%dms, triggered=%d", diff, fired);
#endif
	
	return 0;
}


int net_add(int fd, short events, void* data, net_event_handler_t handler)
{
	struct epoll_event ev;
	struct net_event_listener* listener = monitor_get_free_listener();
	
	hub_log(log_trace, "net_add(): adding socket (fd=%d, pos=%d)", fd, pos);
	
	if (!listener)
	{
		hub_log(log_error, "net_add(): unable to poll more sockets");
		return -1;
	}
	
	net_event_listener_set(listener, fd, events, data, handler);
	
	set_poll_events(&ev, events);
	ev.data.ptr = listener;
	
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0)
	{
		hub_log(log_error, "net_add(): epoll_ctl error while adding socket (fd=%d)", fd);
		net_event_listener_clear(listener);
		return -1;
	}
	
	num_connections++;
	
#ifdef DEBUG_EPOLL
	dump_listeners();
#endif
	return 0;
}

int net_modify(int fd, short events)
{
	struct epoll_event ev;
	struct net_event_listener* listener = monitor_get_listener(fd);
	hub_log(log_trace, "net_modify(): modifying socket events (fd=%d)", fd);
	
	if (!listener)
	{
		hub_log(log_error, "net_modify(): unable to find socket.");
		return -1;
	}
	
	listener->events = events;
	set_poll_events(&ev, events);
	ev.data.ptr = listener;
	
	if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev) < 0)
	{
		hub_log(log_error, "net_add(): epoll_ctl error while modifying socket (fd=%d)", fd);
		return -1;
	}
	
#ifdef DEBUG_EPOLL
	dump_listeners();
#endif

	return 0;
}


int net_remove(int fd)
{
	struct epoll_event ev;
	struct net_event_listener* listener = monitor_get_listener(fd);
	
	hub_log(log_trace, "net_remove(): removing socket (fd=%d, pos=%d)", fd, pos);
	
	if (!listener)
	{
		/* The socket is not being monitored */
		hub_log(log_error, "net_remove(): unable to remove socket (fd=%d)", fd);
		return -1;
	}
	
	net_event_listener_clear(listener);

	if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev) < 0)
	{
		hub_log(log_error, "net_remove(): epoll_ctl error while removing socket (fd=%d)", fd);
		return -1;
	}
	num_connections--;
	
#ifdef DEBUG_EPOLL
	dump_listeners();
#endif
	
	return 0;
}


#endif /* HAVE_EPOLL */



