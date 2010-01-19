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

#ifdef USE_LIBEVENT

struct net_connection
{
	NET_CON_STRUCT_COMMON
	struct event         event;     /** libevent struct for read/write events */
	struct event         timeout;   /** Used for internal timeout handling */
};

struct net_timer
{
	unsigned int         initialized;
	struct event         timeout;
	net_timeout_cb       callback;
	void*                ptr;
};

int net_con_get_sd(struct net_connection* con)
{
	return con->sd;
}

void* net_con_get_ptr(struct net_connection* con)
{
	return con->ptr;
}

struct net_connection* net_con_create()
{
	struct net_connection* con = (struct net_connection*) hub_malloc(sizeof(struct net_connection));
	return con;
}

static inline int net_con_flag_get(struct net_connection* con, unsigned int flag)
{
    return con->flags & flag;
}

static inline void net_con_flag_set(struct net_connection* con, unsigned int flag)
{
    con->flags |= flag;
}

static inline void net_con_flag_unset(struct net_connection* con, unsigned int flag)
{
    con->flags &= ~flag;
}

void net_con_destroy(struct net_connection* con)
{
	hub_free(con);
}

static inline int net_con_convert_to_libevent_mask(int ev)
{
	int events = 0;
	if (ev & NET_EVENT_READ)  events |= EV_READ;
	if (ev & NET_EVENT_WRITE) events |= EV_WRITE;
	return events;
}

static inline int net_con_convert_from_libevent_mask(int ev)
{
	int events = 0;
	if (ev & EV_TIMEOUT)    events |= NET_EVENT_TIMEOUT;
	if (ev & EV_READ)       events |= NET_EVENT_READ;
	if (ev & EV_WRITE)      events |= NET_EVENT_WRITE;
	return events;
}

static void net_con_event(int fd, short ev, void *arg);


int net_con_close(struct net_connection* con)
{
	uhub_assert(con);

	con->ptr = 0;

	if (net_con_flag_get(con, NET_CLEANUP))
		return 0;

	if (net_con_flag_get(con, NET_PROCESSING_BUSY))
	{
		net_con_flag_set(con, NET_CLEANUP);
		return 0;
	}

	net_con_after_close(con);
	return 1;
}

static void net_con_set(struct net_connection* con)
{
	uhub_assert(con);

	int ev = 0;
	if (net_con_flag_get(con, NET_WANT_READ | NET_WANT_SSL_READ))   ev |= EV_READ;
	if (net_con_flag_get(con, NET_WANT_WRITE | NET_WANT_SSL_WRITE)) ev |= EV_WRITE;

	if (net_con_flag_get(con, NET_EVENT_SET) != 0)
	{
		event_del(&con->event);
	}
	net_con_flag_set(con, NET_EVENT_SET);

	LOG_MEMORY("SET: set+add: CON={ %p, %p, %d, %d}", con, &con->event, con->sd, ev);
	event_set(&con->event, con->sd, ev, net_con_event, con);
	event_add(&con->event, 0);

	net_con_flag_set(con, NET_INITIALIZED);
}

static void net_con_after_close(struct net_connection* con)
{
	if (net_con_flag_get(con, NET_INITIALIZED))
	{
		LOG_MEMORY("DEL:   close: CON={ %p, %p, %d, %d}", con, &con->event, con->sd, -1);
		net_con_flag_unset(con, NET_EVENT_SET);

		event_del(&con->event);
		net_con_flag_unset(con, NET_INITIALIZED);
	}

	net_con_clear_timeout(con);
	net_close(con->sd);
	con->sd = -1;

	hub_free(con);
}

void net_con_initialize(struct net_connection* con, int sd, net_connection_cb callback, const void* ptr, int ev)
{
	uhub_assert(con);

	int events = net_con_convert_to_libevent_mask(ev);
	if (ev & NET_EVENT_READ)  net_con_flag_set(con, NET_WANT_READ);
	if (ev & NET_EVENT_WRITE) net_con_flag_set(con, NET_WANT_WRITE);

	con->sd = sd;
	con->flags = 0;
	con->ptr = (void*) ptr;
	con->callback = callback;
	con->last_send = time(0);
	con->last_recv = con->last_send;

	if (ev)
	{
		uhub_assert(net_con_flag_get(con, NET_EVENT_SET) == 0);
		net_con_flag_set(con, NET_EVENT_SET);

		LOG_MEMORY("SET:    init: CON={ %p, %p, %d, %d}", con, &con->event, con->sd, ev);
		event_set(&con->event, con->sd, events, net_con_event, con);
		event_add(&con->event, 0);
		net_con_flag_set(con, NET_INITIALIZED);
	}

	net_set_nonblocking(sd, 1);
	net_set_nosigpipe(sd, 1);

#ifdef SSL_SUPPORT
	con->ssl = NULL;
	con->write_len = 0;
#endif
}

void net_con_reinitialize(struct net_connection* con, net_connection_cb callback, const void* ptr, int events)
{
	uhub_assert(con);
	con->callback = callback;
	con->ptr = (void*) ptr;
	net_con_update(con, events);
}

void net_con_update(struct net_connection* con, int ev)
{
	uhub_assert(con);

	if (ev & NET_EVENT_READ)
		net_con_flag_set(con, NET_EVENT_READ);
	else
		net_con_flag_unset(con, NET_EVENT_READ);

	if (ev & NET_EVENT_WRITE)
		net_con_flag_set(con, NET_EVENT_WRITE);
	else
		net_con_flag_unset(con, NET_EVENT_WRITE);

	if (!net_con_flag_get(con, NET_PROCESSING_BUSY))
	{
		net_con_set(con);
	}
}

#define CALLBACK(CON, EVENTS) \
	if (CON->callback) \
		CON->callback(con, EVENTS, CON->ptr);

static void net_con_event(int fd, short ev, void *arg)
{
	struct net_connection* con = (struct net_connection*) arg;
	int events = net_con_convert_from_libevent_mask(ev);

	if (!net_con_flag_get(con, NET_INITIALIZED))
	{
		return;
	}

	if (net_con_flag_get(con, NET_CLEANUP))
	{
		net_con_after_close(con);
		return;
	}

	net_con_flag_set(con, NET_PROCESSING_BUSY);

// 	uhub_assert(net_con_flag_get(con, NET_EVENT_SET) != 0);
	net_con_flag_unset(con, NET_EVENT_SET);

	LOG_MEMORY("EVT: process: CON={ %p, %p, %d, %d}", con, &con->event, con->sd, (int) ev);

#ifdef SSL_SUPPORT
	if (!con->ssl)
	{
#endif
		CALLBACK(con, events);
#ifdef SSL_SUPPORT
	}
	else
	{
#ifdef NETWORK_DUMP_DEBUG
		LOG_PROTO("net_con_event: events=%d, con=%p", ev, con);
#endif
		if (ev & (EV_READ | EV_WRITE))
		{
			if (net_con_flag_get(con, NET_WANT_SSL_ACCEPT))
			{
				if (net_con_ssl_accept(con) < 0)
					CALLBACK(con, NET_EVENT_SOCKERROR);
			}
			else if (net_con_flag_get(con, NET_WANT_SSL_CONNECT))
			{
				if (net_con_ssl_connect(con) < 0)
					CALLBACK(con, NET_EVENT_SOCKERROR);
			}
			else if (ev == EV_READ && net_con_flag_get(con, NET_WANT_SSL_READ))
			{
				CALLBACK(con, NET_EVENT_WRITE);
			}
			else if (ev == EV_WRITE && net_con_flag_get(con, NET_WANT_SSL_WRITE))
			{
				CALLBACK(con, events & NET_EVENT_READ);
			}
			else
			{
				CALLBACK(con, events);
			}
		}
		else
		{
			CALLBACK(con, events);
		}
	}
#endif
	net_con_flag_unset(con, NET_PROCESSING_BUSY);

	if (net_con_flag_get(con, NET_CLEANUP))
	{
		net_con_after_close(con);
	}
	else
	{
		net_con_set(con);
	}
}


static void net_timer_event(int fd, short ev, void *arg)
{
	struct net_timer* timer = (struct net_timer*) arg;
	timer->callback(timer, timer->ptr);
}

void net_timer_initialize(struct net_timer* timer, net_timeout_cb callback, void* ptr)
{
	timer->initialized = 0;
	timer->callback = callback;
	timer->ptr = ptr;
}

void net_timer_reset(struct net_timer* timer, int seconds)
{
	struct timeval timeout = { seconds, 0 };
	if (timer->initialized)
	{
		evtimer_del(&timer->timeout);
		timer->initialized = 0;
	}
	evtimer_set(&timer->timeout, net_timer_event, timer);
	evtimer_add(&timer->timeout, &timeout);
}

void net_timer_shutdown(struct net_timer* timer)
{
	if (timer->initialized)
	{
		evtimer_del(&timer->timeout);
		timer->initialized = 0;
	}
	timer->callback = 0;
	timer->ptr = 0;
}


void net_con_set_timeout(struct net_connection* con, int seconds)
{
	uhub_assert(con);

	struct timeval timeout = { seconds, 0 };
	net_con_clear_timeout(con);

	evtimer_set(&con->timeout, net_con_event, con);
	evtimer_add(&con->timeout, &timeout);
	net_con_flag_set(con, NET_TIMER_ENABLED);
}

void net_con_clear_timeout(struct net_connection* con)
{
	uhub_assert(con);

	if (net_con_flag_get(con, NET_TIMER_ENABLED))
	{
		evtimer_del(&con->timeout);
		net_con_flag_unset(con, NET_TIMER_ENABLED);
	}
}

static struct event_base g_evbase = 0;

/**
 * Initialize the network backend.
 * Returns 1 on success, or 0 on failure.
 */
int net_backend_initialize()
{
	g_evbase = event_init();
	if (!g_evbase)
	{
		LOG_ERROR("Unable to initialize libevent.");
		return 0;
	}
	LOG_DEBUG("Using libevent %s, backend: %s", event_get_version(), event_get_method());
	return 1;
}

/**
 * Shutdown the network connection backend.
 */
void net_backend_shutdown()
{
	event_base_free(g_evbase);
}

/**
 * Process the network backend.
 */
int net_backend_process()
{
	int ret = event_base_loop(g_evbase, EVLOOP_ONCE);
	if (ret != 0)
	{
		LOG_DEBUG("event_base_loop returned: %d", (int) ret);
	}
	if (ret < 0)
		return 0;
	return 1;
}


#endif /* USE_LIBEVENT */
