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

#ifndef HAVE_UHUB_NETWORK_DNS_RESOLVER_H
#define HAVE_UHUB_NETWORK_DNS_RESOLVER_H

struct net_dns_job;
struct net_dns_result;

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
/// Initialize the DNS subsystem
void net_dns_initialize();

/// Shutdown and destroy the DNS subsystem. This will cancel any pending DNS jobs.
void net_dns_destroy();

/// Process finished DNS lookups.
void net_dns_process();


// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

/**
 * Callback to be called when the DNS job has finished.
 * If the name or address could not be resolved to an IP address (host not found, or found but has no address)
 * then 'result' contains an empty list (@see net_dns_result_size()).
 * If resolving caused an error then result is NULL.
 *
 * After this callback is called the job is considered done, and is freed.
 *
 * @param If 1 is returned then result is deleted immediately after the callback,
 * otherwise the callback becomes owner of the result data which must be freed with net_dns_result_free().
 */
typedef int (*net_dns_job_cb)(struct net_dns_job*, const struct net_dns_result* result);

/**
 * Resolve a hostname.
 *
 * @param host the hostname to be resolved.
 * @param af the indicated address family. Should be AF_INET, AF_INET6 (or AF_UNSPEC - which means both AF_INET and AF_INET6.
 * @param callback the callback to be called when the hostname has been resolved.
 * @param ptr A user-defined pointer value.
 *
 * @return A resolve job handle if the job has successfully started or NULL if unable to start resolving.
 */
extern struct net_dns_job* net_dns_gethostbyname(const char* host, int af, net_dns_job_cb callback, void* ptr);

/**
 * Perform a reverse DNS lookup for a given IP address.
 *
 * @see net_dns_gethostbyname()
 * @return A resolve job handle if the job has successfully started or NULL if unable to start resolving.
 */
extern struct net_dns_job* net_dns_gethostbyaddr(struct ip_addr_encap* ipaddr, net_dns_job_cb callback, void* ptr);

/**
 * Cancel a DNS lookup job.
 *
 * It is only allowed to call this once after a job has been started (@see net_dns_gethostbyname(), @see net_dns_gethostbyaddr())
 * but before it has finished and delivered a to the callback address (@see net_dns_job_cb).
 *
 * @returns 1 if cancelled, or 0 if not cancelled (because the job was not found!)
 */
extern int net_dns_job_cancel(struct net_dns_job* job);

/**
 * Wait in a synchronous manner for a running DNS job to finished and
 * return the result here.
 * The job must be started with net_dns_gethostbyaddr/net_dns_gethostbyname
 * and not finished or cancelled.
 *
 * If this function is invoked then the callback function will not be called and
 * can therefore be NULL.
 *
 * <code>
 *    struct net_dns_job* job = net_dns_gethostbyname("www.example.com", AF_INET, NULL, NULL);
 *    struct net_dns_result* net_dns_job_sync_wait(job);
 * </code>
 */
extern struct net_dns_result* net_dns_job_sync_wait(struct net_dns_job* job);

/**
 * Returns the user specified pointer assigned to the resolving job
*/
extern void* net_dns_job_get_ptr(const struct net_dns_job* job);

/// Returns the number of results provided. This is 0 if the host could not be found (or has no matching IP address).
extern size_t net_dns_result_size(const struct net_dns_result*);

/// Returns the first result (if net_dns_result_size > 0), or NULL if not first result exists.
extern struct ip_addr_encap* net_dns_result_first(const struct net_dns_result*);

/// Returns the next result or NULL if no next result exists.
extern struct ip_addr_encap* net_dns_result_next(const struct net_dns_result*);

/// When finished with the results
extern void net_dns_result_free(const struct net_dns_result*);

#endif /* HAVE_UHUB_NETWORK_DNS_RESOLVER_H */
