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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "uhub.h"
#include "network/common.h"
#include "network/backend.h"

static int is_blocked_or_interrupted()
{
	int err = net_error();
	return
#ifdef WINSOCK
				err == WSAEWOULDBLOCK
#else
				err == EWOULDBLOCK
#endif
				|| err == EINTR;
}

ssize_t net_con_send(struct net_connection* con, const void* buf, size_t len)
{
	int ret;
#ifdef SSL_SUPPORT
	if (!con->ssl)
	{
#endif
		ret = net_send(con->sd, buf, len, UHUB_SEND_SIGNAL);
		if (ret == -1)
		{
			if (is_blocked_or_interrupted())
				return 0;
			return -1;
		}
#ifdef SSL_SUPPORT
	}
	else
	{
		ret = net_ssl_send(con, buf, len);
	}
#endif /* SSL_SUPPORT */
	return ret;
}

ssize_t net_con_recv(struct net_connection* con, void* buf, size_t len)
{
	int ret;
#ifdef SSL_SUPPORT
	if (!con->ssl)
	{
#endif
		ret = net_recv(con->sd, buf, len, 0);
		if (ret == -1)
		{
			if (is_blocked_or_interrupted())
				return 0;
			return -net_error();
		}
		else if (ret == 0)
		{
			return -1;
		}
#ifdef SSL_SUPPORT
	}
	else
	{
		ret = net_ssl_recv(con, buf, len);
	}
#endif /* SSL_SUPPORT */
	return ret;
}

ssize_t net_con_peek(struct net_connection* con, void* buf, size_t len)
{
	int ret = net_recv(con->sd, buf, len, MSG_PEEK);
	if (ret == -1)
	{
		if (is_blocked_or_interrupted())
			return 0;
		return -net_error();
	}
	else if (ret == 0)
		return -1;
	return ret;
}

#ifdef SSL_SUPPORT

int net_con_is_ssl(struct net_connection* con)
{
	return !!con->ssl;
}
#endif /* SSL_SUPPORT */

int net_con_get_sd(struct net_connection* con)
{
	return con->sd;
}

void* net_con_get_ptr(struct net_connection* con)
{
	return con->ptr;
}

void net_con_update(struct net_connection* con, int events)
{
#ifdef SSL_SUPPORT
	if (con->ssl)
		net_ssl_update(con, events);
	else
#endif
		net_backend_update(con, events);
}

void net_con_reinitialize(struct net_connection* con, net_connection_cb callback, const void* ptr, int events)
{
	con->callback = callback;
	con->ptr = (void*) ptr;
	net_con_update(con, events);
}

void net_con_destroy(struct net_connection* con)
{
#ifdef SSL_SUPPORT
	if (con && con->ssl)
		net_ssl_destroy(con);
#endif
	hub_free(con);
}

void net_con_callback(struct net_connection* con, int events)
{
	if (con->flags & NET_CLEANUP)
		return;

	if (events == NET_EVENT_TIMEOUT)
	{
		LOG_TRACE("net_con_callback(%p, TIMEOUT)", con);
		con->callback(con, events, con->ptr);
		return;
	}

#ifdef SSL_SUPPORT
	if (con->ssl)
		net_ssl_callback(con, events);
	else
#endif
		con->callback(con, events, con->ptr);
}

struct net_connect_job
{
	struct net_connection* con;
	struct net_connect_handle* handle;
	struct sockaddr_storage addr;
	struct net_connect_job* next;
};

struct net_connect_handle
{
	const char* address;
	uint16_t port;
	void* ptr;
	net_connect_cb callback;
	struct net_dns_job* dns;
	const struct net_dns_result* result;
	struct net_connect_job* job4;
	struct net_connect_job* job6;
};

static void net_connect_callback(struct net_connect_handle* handle, enum net_connect_status status, struct net_connection* con);
static void net_connect_job_internal_cb(struct net_connection* con, int event, void* ptr);

/**
 * Check if a connection job is completed.
 * @return -1 on completed with an error, 0 on not yet completed, or 1 if completed successfully (connected).
 */
static int net_connect_job_check(struct net_connect_job* job)
{
	struct net_connection* con = job->con;
	int af = job->addr.ss_family;
	enum net_connect_status status;

	int ret = net_connect(net_con_get_sd(con), (struct sockaddr*) &job->addr, af == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	if (ret == 0 || (ret == -1 && net_error() == EISCONN))
	{
		LOG_TRACE("net_connect_job_check(): Socket connected!");
		job->con = NULL;
		net_connect_callback(job->handle, net_connect_status_ok, con);
		return 1;
	}
	else if (ret == -1 && (net_error() == EALREADY || net_error() == EINPROGRESS || net_error() == EWOULDBLOCK || net_error() == EINTR))
	{
		return 0;
	}
	LOG_TRACE("net_connect_job_check(): Socket error!");

	switch (net_error())
	{
		case ECONNREFUSED:
			status = net_connect_status_refused;
			break;
		case ENETUNREACH:
			status = net_connect_status_unreachable;
			break;

		default:
			status = net_connect_status_socket_error;
	}

	net_connect_callback(job->handle, status, NULL);
	return -1;
}

static void net_connect_job_free(struct net_connect_job* job)
{
	if (job->con)
		net_con_close(job->con);
	job->handle = NULL;
	job->next = NULL;
	hub_free(job);
}

static void net_connect_job_stop(struct net_connect_job* job)
{
	if (job->addr.ss_family == AF_INET6)
	{
		job->handle->job6 = job->next;
	}
	else
	{
		job->handle->job4 = job->next;
	}

	net_connect_job_free(job);
}

static int net_connect_depleted(struct net_connect_handle* handle)
{
	return (!handle->job6 && !handle->job4);
}

static int net_connect_job_process(struct net_connect_job* job)
{
	int sd;
	if (!job->con)
	{
		sd = net_socket_create(job->addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
		if (sd == -1)
		{
			LOG_DEBUG("net_connect_job_process: Unable to create socket!");
			net_connect_callback(job->handle, net_connect_status_socket_error, NULL);
			return -1; // FIXME
		}

		job->con = 	net_con_create();
		net_con_initialize(job->con, sd, net_connect_job_internal_cb, job, NET_EVENT_WRITE);
		net_con_set_timeout(job->con, TIMEOUT_CONNECTED); // FIXME: Use a proper timeout value!
	}

	return net_connect_job_check(job);
}


/*
 * Internal callback used to establish an outbound connection.
 */
static void net_connect_job_internal_cb(struct net_connection* con, int event, void* ptr)
{
	int ret;
	struct net_connect_job* job = net_con_get_ptr(con);
	struct net_connect_job* next_job = job->next;
	struct net_connect_handle* handle = job->handle;

	if (event == NET_EVENT_TIMEOUT)
	{
		// FIXME: Try next address, or if no more addresses left declare failure to connect.
		if (job->addr.ss_family == AF_INET6)
		{
			net_connect_job_stop(job);

			if (!next_job)
			{
				LOG_TRACE("No more IPv6 addresses to try!");
			}

		}
		else
		{
			net_connect_job_stop(job);

			if (!next_job)
			{
				LOG_TRACE("No more IPv4 addresses to try!");
			}
		}

		if (net_connect_depleted(handle))
		{
			LOG_TRACE("No more addresses left. Unable to connect!");
			net_connect_callback(handle, net_connect_status_timeout, NULL);
		}
		return;
	}

	if (event == NET_EVENT_WRITE)
	{
		net_connect_job_process(job);
	}
}


static void net_connect_cancel(struct net_connect_handle* handle)
{
	struct net_connect_job* job;

	job = handle->job6;
	while (job)
	{
		job = job->next;
		net_connect_job_free(handle->job6);
		handle->job6 = job;
	}

	job = handle->job4;
	while (job)
	{
		job = job->next;
		net_connect_job_free(handle->job4);
		handle->job4 = job;
	}
}


static int net_connect_process_queue(struct net_connect_handle* handle, struct net_connect_job* job)
{
	int ret;
	while (job)
	{
		ret = net_connect_job_process(job);
		if (ret < 0)
		{
			net_connect_job_stop(job);
			continue;
		}
		else if (ret == 0)
		{
			// Need to process again
			return 0;
		}
		else
		{
			// FIXME: Success!
			return 1;
		}
	}
	return -1;
}

static int net_connect_process(struct net_connect_handle* handle)
{
	int ret4, ret6;

	ret6 = net_connect_process_queue(handle, handle->job6);
	if (ret6 == 1)
		return 1; // Connected - cool!

	net_connect_process_queue(handle, handle->job4);
	return 0;
}


static int net_connect_job_schedule(struct net_connect_handle* handle, struct ip_addr_encap* addr)
{
	struct net_connect_job* job;
	struct sockaddr_in* addr4;
	struct sockaddr_in6* addr6;

	if (addr->af == AF_INET6 && !net_is_ipv6_supported())
	{
		LOG_TRACE("net_connect_job_schedule(): Skipping IPv6 support since IPv6 is not supported.");
		return 0;
	}
	else
	{
		job = hub_malloc_zero(sizeof(struct net_connect_job));
		job->handle = handle;
		if (addr->af == AF_INET6)
		{
			addr6 = (struct sockaddr_in6*) &job->addr;
			LOG_TRACE("net_connect_job_schedule(): Scheduling IPv6 connect job.");
			addr6->sin6_family = AF_INET6;
			addr6->sin6_port = htons(handle->port);
			memcpy(&addr6->sin6_addr, &addr->internal_ip_data.in6, sizeof(struct in6_addr));

			// prepend
			job->next = handle->job6;
			handle->job6 = job;
		}
		else
		{
			addr4 = (struct sockaddr_in*) &job->addr;
			LOG_TRACE("net_connect_job_schedule(): Scheduling IPv4 connect job.");
			addr4->sin_family = AF_INET;
			addr4->sin_port = htons(handle->port);
			memcpy(&addr4->sin_addr, &addr->internal_ip_data.in, sizeof(struct in_addr));

			// prepend
			job->next = handle->job4;
			handle->job4 = job;
		}
	}
	return 1;
}


/*
 * Callback when the DNS results are ready.
 * Create a list of IPv6 and IPv4 addresses, then
 * start connecting to them one by one until one succeeds.
 */
static int net_con_connect_dns_callback(struct net_dns_job* job, const struct net_dns_result* result)
{
	struct ip_addr_encap* addr;
	struct net_connect_handle* handle = (struct net_connect_handle*) net_dns_job_get_ptr(job);
	handle->dns = NULL;
	size_t usable = 0;
	int ret;

	LOG_TRACE("net_con_connect(): async - Got DNS results");
	if (!result)
	{
		LOG_DEBUG("net_con_connect() - Unable to lookup host!");
		net_connect_callback(handle, net_connect_status_dns_error, NULL);
		return 1;
	}

	if (!net_dns_result_size(result))
	{
		LOG_DEBUG("net_con_connect() - Host not found!");
		net_connect_callback(handle, net_connect_status_host_not_found, NULL);
		return 1;
	}

	handle->result = result;

	// Extract results into a separate list of IPv4 and IPv6 addresses.
	addr = net_dns_result_first(result);
	while (addr)
	{
		if (net_connect_job_schedule(handle, addr))
			usable++;
		addr = net_dns_result_next(result);
	}

	net_connect_process(handle);

	return 0;
}

// typedef void (*net_connect_cb)(struct net_connect_handle*, enum net_connect_handle_code, struct net_connection* con);

struct net_connect_handle* net_con_connect(const char* address, uint16_t port, net_connect_cb callback, void* ptr)
{
	struct net_connect_handle* handle = hub_malloc_zero(sizeof(struct net_connect_handle));

	handle->address = hub_strdup(address);
	handle->port = port;
	handle->ptr = ptr;
	handle->callback = callback;

	// FIXME: Check if DNS resolving is necessary ?
	handle->dns = net_dns_gethostbyname(address, AF_UNSPEC, net_con_connect_dns_callback, handle);
	if (!handle->dns)
	{
		LOG_TRACE("net_con_connect(): Unable to create DNS lookup job.");
		hub_free((char*) handle->address);
		hub_free(handle);
		return NULL;
	}

	return handle;
}

void net_connect_destroy(struct net_connect_handle* handle)
{
	hub_free((char*) handle->address);

	// cancel DNS job if pending
	if (handle->dns)
		net_dns_job_cancel(handle->dns);

	// Stop any connect jobs.
	net_connect_cancel(handle);

	// free any DNS results
	net_dns_result_free(handle->result);

	hub_free(handle);
}

static void net_connect_callback(struct net_connect_handle* handle, enum net_connect_status status, struct net_connection* con)
{
	uhub_assert(handle->callback != NULL);

	// Call the callback
	handle->callback(handle, status, con, handle->ptr);
	handle->callback = NULL;

	// Cleanup
	net_connect_destroy(handle);
}
