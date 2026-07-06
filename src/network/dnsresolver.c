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

#include "util/list.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/threads.h"
#include "network/dnsresolver.h"
#include "network/notify.h"

// Emitting a preprocessor directive inside a function-like macro's argument
// list (the LIST_FOREACH delivery loop below) is undefined behaviour, so the
// optional lookup timing is wrapped in its own macro that fully resolves before
// LIST_FOREACH expands.
#ifdef DEBUG_LOOKUP_TIME
#define DNS_LOG_LOOKUP_TIME(job) do { \
		struct timeval time_result; \
		timersub(&(job)->time_finish, &(job)->time_start, &time_result); \
		LOG_TRACE("DNS lookup took %d ms", (int) ((time_result.tv_sec * 1000) + (time_result.tv_usec / 1000))); \
	} while (0)
#else
#define DNS_LOG_LOOKUP_TIME(job) do { } while (0)
#endif

/*
 * The resolver runs a pool of worker threads that drain a shared queue of
 * lookup jobs. getaddrinfo() is blocking, so it must run off the main
 * (event-loop) thread; the pool bounds how many lookups run concurrently
 * instead of spawning one thread per lookup.
 *
 * The pool size is configurable (hub option dns_thread_pool_size) via
 * net_dns_set_pool_size(). Because the subsystem is initialized before the
 * configuration is read, the workers are spawned lazily on the first lookup,
 * by which point the configured size is known.
 */
#define DNS_DEFAULT_WORKERS 4
#define DNS_MAX_WORKERS 64

enum dns_job_state
{
	JOB_QUEUED  = 0, // waiting in the queue (default for a zeroed job)
	JOB_RUNNING = 1, // a worker is currently resolving it
	JOB_DONE    = 2, // resolved; result sits in the results queue
};

struct net_dns_job
{
	net_dns_job_cb callback;
	void* ptr;

	char* host;
	int af;

	enum dns_job_state state;
	int cancelled; // set by net_dns_job_cancel() while a worker holds the job

#ifdef DEBUG_LOOKUP_TIME
	struct timeval time_start;
	struct timeval time_finish;
#endif
};

struct net_dns_result
{
	struct linked_list* addr_list;
	struct net_dns_job* job;
	int error; // set if the lookup failed outright (delivered as a NULL result)
};

static struct net_dns_result* find_and_remove_result(struct net_dns_job* job);

static void free_job(struct net_dns_job* job)
{
	if (job)
	{
		hub_free(job->host);
		hub_free(job);
	}
}

// void(*)(void*) adapters for list_clear(); hub_free is a macro and free_job /
// net_dns_result_free are not directly assignable as function pointers.
static void free_job_handle(void* ptr)
{
	free_job((struct net_dns_job*) ptr);
}

static void free_result_handle(void* ptr)
{
	net_dns_result_free((struct net_dns_result*) ptr);
}

static void notify_callback(struct uhub_notify_handle* handle, void* ptr)
{
	(void) handle; (void) ptr;
	net_dns_process();
}


// NOTE: Any code manipulating the queue/results lists or the shutdown flag
// must hold the mutex! work_cond signals workers that the queue changed (or
// that shutdown was requested); done_cond signals a completed lookup to a
// synchronous waiter.
struct net_dns_subsystem
{
	struct linked_list* queue;   // jobs waiting to be picked up by a worker
	struct linked_list* results; // results awaiting delivery to their callback
	uhub_mutex_t mutex;
	uhub_cond_t work_cond;
	uhub_cond_t done_cond;
	int shutdown;

	uhub_thread_t* workers[DNS_MAX_WORKERS];
	size_t num_workers;     // workers actually spawned
	size_t desired_workers; // configured target, applied when the pool starts
	int workers_started;    // pool is spawned lazily on the first lookup

	struct uhub_notify_handle* notify_handle; // used to signal back to the event loop that there is something to process.
};

static struct net_dns_subsystem* g_dns = NULL;

static void* dns_worker_thread(void* ptr);

void net_dns_initialize()
{
	LOG_TRACE("net_dns_initialize()");
	g_dns = (struct net_dns_subsystem*) hub_malloc_zero(sizeof(struct net_dns_subsystem));
	g_dns->queue = list_create();
	g_dns->results = list_create();
	uhub_mutex_init(&g_dns->mutex);
	uhub_cond_init(&g_dns->work_cond);
	uhub_cond_init(&g_dns->done_cond);
	g_dns->desired_workers = DNS_DEFAULT_WORKERS;
	g_dns->notify_handle = net_notify_create(notify_callback, g_dns);
	// Workers are spawned lazily on the first lookup (see dns_start_workers),
	// by which point net_dns_set_pool_size() has applied the configured size.
}

void net_dns_set_pool_size(size_t num_workers)
{
	if (!g_dns)
		return;

	if (num_workers < 1)
		num_workers = 1;
	else if (num_workers > DNS_MAX_WORKERS)
		num_workers = DNS_MAX_WORKERS;

	uhub_mutex_lock(&g_dns->mutex);
	if (g_dns->workers_started)
		LOG_DEBUG("net_dns_set_pool_size(): pool already running with %d workers; ignoring change to %d", (int) g_dns->num_workers, (int) num_workers);
	else
		g_dns->desired_workers = num_workers;
	uhub_mutex_unlock(&g_dns->mutex);
}

// Spawn the worker pool on first use. NOTE: mutex must be held.
static void dns_start_workers(void)
{
	size_t i;
	if (g_dns->workers_started)
		return;
	g_dns->workers_started = 1;

	for (i = 0; i < g_dns->desired_workers; i++)
	{
		uhub_thread_t* worker = uhub_thread_create(dns_worker_thread, g_dns);
		if (worker)
			g_dns->workers[g_dns->num_workers++] = worker; // store compactly so destroy can join [0, num_workers)
		else
			LOG_WARN("dns_start_workers(): unable to create DNS worker thread %d", (int) i);
	}
	LOG_TRACE("dns_start_workers(): started %d of %d DNS worker threads", (int) g_dns->num_workers, (int) g_dns->desired_workers);
}

void net_dns_destroy()
{
	int i;

	// Tell the workers to exit, then wait for them. After this no worker is
	// running, so the queue and results lists can be torn down without locking.
	uhub_mutex_lock(&g_dns->mutex);
	LOG_TRACE("net_dns_destroy(): queue=%d, results=%d", (int) list_size(g_dns->queue), (int) list_size(g_dns->results));
	g_dns->shutdown = 1;
	uhub_cond_broadcast(&g_dns->work_cond);
	uhub_mutex_unlock(&g_dns->mutex);

	for (i = 0; i < (int) g_dns->num_workers; i++)
	{
		if (g_dns->workers[i])
			uhub_thread_join(g_dns->workers[i]);
	}

	// Jobs still queued never ran; results were resolved but never delivered.
	list_clear(g_dns->queue, &free_job_handle);
	list_clear(g_dns->results, &free_result_handle);

	list_destroy(g_dns->queue);
	list_destroy(g_dns->results);
	uhub_cond_destroy(&g_dns->work_cond);
	uhub_cond_destroy(&g_dns->done_cond);
	uhub_mutex_destroy(&g_dns->mutex);
	net_notify_destroy(g_dns->notify_handle);
	hub_free(g_dns);
	g_dns = NULL;
}

void net_dns_process()
{
	struct net_dns_result* result;
	struct linked_list* ready = list_create();

	uhub_mutex_lock(&g_dns->mutex);
	LOG_TRACE("net_dns_process(): queue=%d, results=%d", (int) list_size(g_dns->queue), (int) list_size(g_dns->results));

	// Collect the results that have a callback. Results without one belong to a
	// synchronous waiter (net_dns_job_sync_wait) and must be left in place.
	LIST_FOREACH(struct net_dns_result*, result, g_dns->results,
	{
		if (result->job && result->job->callback)
			list_append(ready, result);
	});

	LIST_FOREACH(struct net_dns_result*, result, ready,
	{
		list_remove(g_dns->results, result);
	});
	uhub_mutex_unlock(&g_dns->mutex);

	// Deliver callbacks without holding the lock, so a callback is free to
	// start a new lookup (or cancel one) without deadlocking.
	LIST_FOREACH(struct net_dns_result*, result, ready,
	{
		struct net_dns_job* job = result->job;
		const struct net_dns_result* delivered = result->error ? NULL : result;
		DNS_LOG_LOOKUP_TIME(job);
		if (job->callback(job, delivered))
		{
			net_dns_result_free(result);
		}
		else
		{
			/* Caller wants to keep the result data, and
			 * thus needs to call net_dns_result_free() to release it later.
			 * We only clean up the job data here and keep the results intact.
			 */
			result->job = NULL;
			free_job(job);
		}
	});

	list_clear(ready, NULL); // free the nodes only; results were freed above
	list_destroy(ready);
}

// Perform the (blocking) name resolution for a job. Runs on a worker thread
// with no lock held and touches no shared state. Always returns a result
// object; result->error is set if the lookup failed outright.
static struct net_dns_result* do_resolve(struct net_dns_job* job)
{
	struct addrinfo hints, *result, *it;
	struct net_dns_result* dns_results;
	int ret;
	int count = 0;
	(void) count; /* only referenced by LOG_DUMP, compiled out in release */

	dns_results = (struct net_dns_result*) hub_malloc_zero(sizeof(struct net_dns_result));
	dns_results->addr_list = list_create();
	dns_results->job = job;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = job->af;
	hints.ai_protocol = IPPROTO_TCP;

	ret = getaddrinfo(job->host, NULL, &hints, &result);
	if (ret != 0 && ret != EAI_NONAME)
	{
		LOG_TRACE("getaddrinfo() failed: %s", gai_strerror(ret));
		dns_results->error = 1;
#ifdef DEBUG_LOOKUP_TIME
		gettimeofday(&job->time_finish, NULL);
#endif
		return dns_results;
	}

	if (ret != EAI_NONAME)
	{
		for (it = result; it; it = it->ai_next)
		{
			struct ip_addr_encap* ipaddr = hub_malloc_zero(sizeof(struct ip_addr_encap));
			ipaddr->af = it->ai_family;

			if (it->ai_family == AF_INET)
			{
				struct sockaddr_in* addr4 = (struct sockaddr_in*) it->ai_addr;
				memcpy(&ipaddr->internal_ip_data.in, &addr4->sin_addr, sizeof(struct in_addr));
			}
			else if (it->ai_family == AF_INET6)
			{
				struct sockaddr_in6* addr6 = (struct sockaddr_in6*) it->ai_addr;
				memcpy(&ipaddr->internal_ip_data.in6, &addr6->sin6_addr, sizeof(struct in6_addr));
			}
			else
			{
				LOG_TRACE("getaddrinfo() returned result with unknown address family: %d", it->ai_family);
				hub_free(ipaddr);
				continue;
			}

			LOG_DUMP("getaddrinfo() - Address (%d) %s for \"%s\"", count++, ip_convert_to_string(ipaddr), job->host);
			list_append(dns_results->addr_list, ipaddr);
		}
		freeaddrinfo(result);
	}

#ifdef DEBUG_LOOKUP_TIME
	gettimeofday(&job->time_finish, NULL);
#endif

	return dns_results;
}

static void* dns_worker_thread(void* ptr)
{
	struct net_dns_subsystem* dns = (struct net_dns_subsystem*) ptr;

	for (;;)
	{
		struct net_dns_job* job;
		struct net_dns_result* res;

		uhub_mutex_lock(&dns->mutex);
		while (!dns->shutdown && list_size(dns->queue) == 0)
			uhub_cond_wait(&dns->work_cond, &dns->mutex);

		if (dns->shutdown)
		{
			uhub_mutex_unlock(&dns->mutex);
			break;
		}

		job = (struct net_dns_job*) list_get_first(dns->queue);
		list_remove(dns->queue, job);
		job->state = JOB_RUNNING;
		uhub_mutex_unlock(&dns->mutex);

		res = do_resolve(job);

		uhub_mutex_lock(&dns->mutex);
		if (job->cancelled)
		{
			// The caller abandoned this job via net_dns_job_cancel() while we
			// were resolving it; drop the result (and the job) silently.
			net_dns_result_free(res);
		}
		else
		{
			job->state = JOB_DONE;
			list_append(dns->results, res);
			uhub_cond_broadcast(&dns->done_cond);
			net_notify_signal(dns->notify_handle, 1);
		}
		uhub_mutex_unlock(&dns->mutex);
	}

	return NULL;
}


extern struct net_dns_job* net_dns_gethostbyname(const char* host, int af, net_dns_job_cb callback, void* ptr)
{
	struct net_dns_job* job = (struct net_dns_job*) hub_malloc_zero(sizeof(struct net_dns_job));
	if (!job)
		return NULL;

	job->host = hub_strdup(host);
	if (!job->host)
	{
		hub_free(job);
		return NULL;
	}

	job->af = af;
	job->callback = callback;
	job->ptr = ptr;
	job->state = JOB_QUEUED;

#ifdef DEBUG_LOOKUP_TIME
	gettimeofday(&job->time_start, NULL);
#endif

	// Hand the job to the worker pool and wake one worker, spawning the pool
	// on the first lookup.
	uhub_mutex_lock(&g_dns->mutex);
	dns_start_workers();
	list_append(g_dns->queue, job);
	uhub_cond_signal(&g_dns->work_cond);
	uhub_mutex_unlock(&g_dns->mutex);
	return job;
}



// NOTE: mutex must be locked first!
static struct net_dns_result* find_and_remove_result(struct net_dns_job* job)
{
	struct net_dns_result* it;
	LIST_FOREACH(struct net_dns_result*, it, g_dns->results,
	{
		if (it->job == job)
		{
			list_remove(g_dns->results, it);
			return it;
		}
	});
	return NULL;
}


extern int net_dns_job_cancel(struct net_dns_job* job)
{
	int retval = 0;
	struct net_dns_result* res;

	LOG_TRACE("net_dns_job_cancel(): job=%p, name=%s", job, job->host);

	/*
	 * A job is in exactly one of three states (all transitions happen under
	 * the mutex):
	 *  - JOB_QUEUED:  not yet picked up. Remove it from the queue and free it.
	 *  - JOB_RUNNING: a worker holds it. We cannot interrupt getaddrinfo(), so
	 *    flag it cancelled; the worker discards the result and frees the job
	 *    when it finishes.
	 *  - JOB_DONE:    resolved, result waiting for delivery. Drop the result
	 *    (which frees the job too).
	 */
	uhub_mutex_lock(&g_dns->mutex);
	if (job->state == JOB_QUEUED)
	{
		list_remove(g_dns->queue, job);
		free_job(job);
		retval = 1;
	}
	else if (job->state == JOB_RUNNING)
	{
		job->cancelled = 1;
		retval = 1;
	}
	else if ((res = find_and_remove_result(job)))
	{
		// job already finished - drop the undelivered result.
		net_dns_result_free(res);
	}
	uhub_mutex_unlock(&g_dns->mutex);
	return retval;
}

extern struct net_dns_result* net_dns_job_sync_wait(struct net_dns_job* job)
{
	struct net_dns_result* res;

	// Block until a worker has resolved this specific job and parked its
	// result. Removing the result here prevents net_dns_process() from
	// delivering it to a callback.
	uhub_mutex_lock(&g_dns->mutex);
	while ((res = find_and_remove_result(job)) == NULL)
		uhub_cond_wait(&g_dns->done_cond, &g_dns->mutex);
	res->job = NULL;
	free_job(job);
	uhub_mutex_unlock(&g_dns->mutex);
	return res;
}

void* net_dns_job_get_ptr(const struct net_dns_job* job)
{
	return job->ptr;
}

extern size_t net_dns_result_size(const struct net_dns_result* res)
{
	return list_size(res->addr_list);
}

extern struct ip_addr_encap* net_dns_result_first(const struct net_dns_result* res)
{
	struct ip_addr_encap* ipaddr = list_get_first(res->addr_list);
	LOG_TRACE("net_dns_result_first() - Address: %s", ipaddr ? ip_convert_to_string(ipaddr) : "(no address)");
	return ipaddr;
}

extern struct ip_addr_encap* net_dns_result_next(const struct net_dns_result* res)
{
	struct ip_addr_encap* ipaddr = list_get_next(res->addr_list);
	LOG_TRACE("net_dns_result_next() - Address: %s", ipaddr ? ip_convert_to_string(ipaddr) : "(no more addresses)");
	return ipaddr;
}

extern void net_dns_result_free(const struct net_dns_result* res)
{
	if (!res)
		return;

	list_clear(res->addr_list, hub_free_handle);
	list_destroy(res->addr_list);
	free_job(res->job);
	hub_free((struct net_dns_result*) res);
}
