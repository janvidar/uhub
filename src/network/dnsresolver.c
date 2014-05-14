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

static struct net_dns_job* find_and_remove_job(struct net_dns_job* job);
static struct net_dns_result* find_and_remove_result(struct net_dns_job* job);

struct net_dns_job
{
	net_dns_job_cb callback;
	void* ptr;

	char* host;
	int af;

#ifdef DEBUG_LOOKUP_TIME
	struct timeval time_start;
	struct timeval time_finish;
#endif

	uhub_thread_t* thread_handle;
};

struct net_dns_result
{
	struct linked_list* addr_list;
	struct net_dns_job* job;
};

static void free_job(struct net_dns_job* job)
{
	if (job)
	{
		hub_free(job->host);
		hub_free(job);
	}
}

static void shutdown_free_jobs(void* ptr)
{
	struct net_dns_job* job = (struct net_dns_job*) ptr;
	uhub_thread_cancel(job->thread_handle);
	uhub_thread_join(job->thread_handle);
	free_job(job);
}

static void shutdown_free_results(void* ptr)
{
	struct net_dns_result* result = (struct net_dns_result*) ptr;
	uhub_thread_join(result->job->thread_handle);
	net_dns_result_free(result);
}


// NOTE: Any job manipulating the members of this
// struct must lock the mutex!
struct net_dns_subsystem
{
	struct linked_list* jobs;    // currently running jobs
	struct linked_list* results; // queue of results that are awaiting being delivered to callback.
	uhub_mutex_t mutex;
};

static struct net_dns_subsystem* g_dns = NULL;

void net_dns_initialize()
{
	LOG_TRACE("net_dns_initialize()");
	g_dns = (struct net_dns_subsystem*) hub_malloc_zero(sizeof(struct net_dns_subsystem));
	g_dns->jobs = list_create();
	g_dns->results = list_create();
	uhub_mutex_init(&g_dns->mutex);
}

void net_dns_destroy()
{
	struct net_dns_job* job;
	struct net_dns_result* result;

	uhub_mutex_lock(&g_dns->mutex);
	LOG_TRACE("net_dns_destroy(): jobs=%d", (int) list_size(g_dns->jobs));
	list_clear(g_dns->jobs, &shutdown_free_jobs);

	LOG_TRACE("net_dns_destroy(): results=%d", (int) list_size(g_dns->results));
	list_clear(g_dns->results, &shutdown_free_results);
	uhub_mutex_unlock(&g_dns->mutex);

	list_destroy(g_dns->jobs);
	list_destroy(g_dns->results);
	uhub_mutex_destroy(&g_dns->mutex);
	hub_free(g_dns);
	g_dns = NULL;
}

static void dummy_free(void* ptr)
{
}


void net_dns_process()
{
	struct net_dns_result* result;
	uhub_mutex_lock(&g_dns->mutex);
	LOG_DUMP("net_dns_process(): jobs=%d, results=%d", (int) list_size(g_dns->jobs), (int) list_size(g_dns->results));

	LIST_FOREACH(struct net_dns_result*, result, g_dns->results,
	{
		struct net_dns_job* job = result->job;
#ifdef DEBUG_LOOKUP_TIME
		struct timeval time_result;
		timersub(&result->job->time_finish, &result->job->time_start, &time_result);
		LOG_TRACE("DNS lookup took %d ms", (time_result.tv_sec * 1000) + (time_result.tv_usec / 1000));
#endif

		// wait for the work thread to finish
		uhub_thread_join(job->thread_handle);

		// callback - should we delete the data immediately?
		if (job->callback(job, result))
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

	list_clear(g_dns->results, &dummy_free);
	uhub_mutex_unlock(&g_dns->mutex);
}

static void* job_thread_resolve_name(void* ptr)
{
	struct net_dns_job* job = (struct net_dns_job*) ptr;
	struct addrinfo hints, *result, *it;
	struct net_dns_result* dns_results;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = job->af;
	hints.ai_protocol = IPPROTO_TCP;

	ret = getaddrinfo(job->host, NULL, &hints, &result);
	if (ret != 0 && ret != EAI_NONAME)
	{
		LOG_TRACE("getaddrinfo() failed: %s", gai_strerror(ret));
		return NULL;
	}

	dns_results = (struct net_dns_result*) hub_malloc(sizeof(struct net_dns_result));
	dns_results->addr_list = list_create();
	dns_results->job = job;

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

			LOG_DUMP("getaddrinfo() - Address (%d) %s for \"%s\"", ret++, ip_convert_to_string(ipaddr), job->host);
			list_append(dns_results->addr_list, ipaddr);
		}
		freeaddrinfo(result);
	}
	else
	{
		/* hm */
	}

#ifdef DEBUG_LOOKUP_TIME
	gettimeofday(&job->time_finish, NULL);
#endif

	uhub_mutex_lock(&g_dns->mutex);
	list_remove(g_dns->jobs, job);
	list_append(g_dns->results, dns_results);
	uhub_mutex_unlock(&g_dns->mutex);

	return dns_results;
}


extern struct net_dns_job* net_dns_gethostbyname(const char* host, int af, net_dns_job_cb callback, void* ptr)
{
	struct net_dns_job* job = (struct net_dns_job*) hub_malloc_zero(sizeof(struct net_dns_job));
	job->host = strdup(host);
	job->af = af;
	job->callback = callback;
	job->ptr = ptr;

#ifdef DEBUG_LOOKUP_TIME
	gettimeofday(&job->time_start, NULL);
#endif

	// FIXME - scheduling - what about a max number of threads?
	uhub_mutex_lock(&g_dns->mutex);
	job->thread_handle = uhub_thread_create(job_thread_resolve_name, job);
	if (!job->thread_handle)
	{
		LOG_WARN("Unable to create thread");
		free_job(job);
		job = NULL;
	}
	else
	{
		list_append(g_dns->jobs, job);
	}
	uhub_mutex_unlock(&g_dns->mutex);
	return job;
}



extern struct net_dns_job* net_dns_gethostbyaddr(struct ip_addr_encap* ipaddr, net_dns_job_cb callback, void* ptr)
{
	struct net_dns_job* job = (struct net_dns_job*) hub_malloc_zero(sizeof(struct net_dns_job));
// 	job->host = strdup(addr);
	job->af = ipaddr->af;
	job->callback = callback;
	job->ptr = ptr;


// 	if (pthread_create(&job->thread_handle, NULL, start_job, job))
// 	{
// 		free_job(job);
// 		return NULL;
// 	}
	return job;
}

// NOTE: mutex must be locked first!
static struct net_dns_job* find_and_remove_job(struct net_dns_job* job)
{
	struct net_dns_job* it;
	LIST_FOREACH(struct net_dns_job*, it, g_dns->jobs,
	{
		if (it == job)
		{
			list_remove(g_dns->jobs, it);
			return job;
		}
	});
	return NULL;
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
	 * This function looks up the job in the jobs queue (which contains only active jobs)
	 * If that is found then the thread is cancelled, and the object is deleted.
	 * If the job was not found, that is either because it was an invalid job, or because
	 * it was already finished. At which point it was not deleted.
	 * If the job is already finished, but the result has not been delivered, then this
	 * deletes the result and the job.
	 */
	uhub_mutex_lock(&g_dns->mutex);
	if (find_and_remove_job(job))
	{
		// job still active - cancel it, then close it.
		uhub_thread_cancel(job->thread_handle);
		uhub_thread_join(job->thread_handle);
		free_job(job);
		retval = 1;
	}
	else if ((res = find_and_remove_result(job)))
	{
		// job already finished - close it.
		uhub_thread_join(job->thread_handle);
		net_dns_result_free(res);
	}
	uhub_mutex_unlock(&g_dns->mutex);
	return retval;
}

extern struct net_dns_result* net_dns_job_sync_wait(struct net_dns_job* job)
{
	struct net_dns_result* res = NULL;

	// Wait for job to finish (if not already)
	// This should make sure the job is removed from jobs and a result is
	// present in results.
	uhub_thread_join(job->thread_handle);

	// Remove the result in order to prevent the callback from being called.
	uhub_mutex_lock(&g_dns->mutex);
	res = find_and_remove_result(job);
	uhub_assert(res != NULL);
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

	list_clear(res->addr_list, &hub_free);
	list_destroy(res->addr_list);
	free_job(res->job);
	hub_free((struct net_dns_result*) res);
}
