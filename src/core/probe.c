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

#include "uhub_limits.h"
#include "util/log.h"
#include "util/memory.h"
#include "network/connection.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/probe.h"
#include "probe.h"

#define PROBE_RECV_SIZE 12
static char probe_recvbuf[PROBE_RECV_SIZE];

static void probe_net_event(struct net_connection* con, int events, void *arg)
{
	struct hub_probe* probe = (struct hub_probe*) net_con_get_ptr(con);
	if (events == NET_EVENT_TIMEOUT)
	{
		probe_destroy(probe);
		return;
	}

	if (events & NET_EVENT_READ)
	{
		int bytes = net_con_peek(con, probe_recvbuf, PROBE_RECV_SIZE);
		if (bytes < 0)
		{
			probe_destroy(probe);
			return;
		}

		if (bytes >= 4)
		{
			/* "HSUP" starts a normal login; "HTCP" starts an HBRI secondary-
			   protocol validation connection (see hbri.c). Both are ADC and
			   handled by the per-user command dispatcher once a user exists. */
			if (memcmp(probe_recvbuf, "HSUP", 4) == 0 || memcmp(probe_recvbuf, "HTCP", 4) == 0)
			{
				LOG_TRACE("Probed ADC");
				if (probe->hub->config->tls_enable && probe->hub->config->tls_require)
				{
					LOG_TRACE("Not TLS connection - closing connection.");
					if (*probe->hub->config->tls_require_redirect_addr)
					{
						char buf[512];
						ssize_t len = snprintf(buf, sizeof(buf), "ISUP " ADC_PROTO_SUPPORT "\nISID AAAB\nIINF NIRedirecting...\nIQUI AAAB RD%s\n", probe->hub->config->tls_require_redirect_addr);
						if (len > 0 && (size_t) len < sizeof(buf))
							net_con_send(con, buf, (size_t) len);
						LOG_TRACE("Not TLS connection - Redirecting to %s.", probe->hub->config->tls_require_redirect_addr);
					}
					else
					{
						LOG_TRACE("Not TLS connection - closing connection.");
					}
				}
				else
				if (user_create(probe->hub, probe->connection, &probe->addr))
				{
					probe->connection = 0;
				}
				probe_destroy(probe);
				return;
			}
			else if ((memcmp(probe_recvbuf, "GET ", 4) == 0) ||
				 (memcmp(probe_recvbuf, "POST", 4) == 0) ||
				 (memcmp(probe_recvbuf, "HEAD", 4) == 0))
			{
				/* Looks like HTTP - Not supported, but we log it. */
				LOG_TRACE("Probed HTTP connection. Not supported closing connection (%s)", ip_convert_to_string(&probe->addr));
				const char* buf = "501 Not implemented\r\n\r\n";
				net_con_send(con, buf, strlen(buf));
			}
			else if (bytes >= 11 &&
				probe_recvbuf[0] == 22 &&
				probe_recvbuf[1] == 3 && /* protocol major version */
				probe_recvbuf[5] == 1 && /* message type */
				probe_recvbuf[9] == probe_recvbuf[1])
			{
				if (probe->hub->config->tls_enable)
				{
					LOG_TRACE("Probed TLS %d.%d connection", (int) probe_recvbuf[9], (int) probe_recvbuf[10]);
					if (net_con_ssl_handshake(con, net_con_ssl_mode_server, probe->hub->ctx) < 0)
					{
						LOG_TRACE("TLS handshake negotiation failed.");
					}
					else if (user_create(probe->hub, probe->connection, &probe->addr))
					{
						probe->connection = 0;
					}
				}
				else
				{
					LOG_TRACE("Probed TLS %d.%d connection. TLS disabled in hub.", (int) probe_recvbuf[9], (int) probe_recvbuf[10]);
				}
			}
			else
			{
				LOG_TRACE("Probed unsupported protocol: %x%x%x%x.", (int) probe_recvbuf[0], (int) probe_recvbuf[1], (int) probe_recvbuf[2], (int) probe_recvbuf[3]);
			}
			probe_destroy(probe);
			return;
		}
	}
}

struct hub_probe* probe_create(struct hub_info* hub, int sd, struct ip_addr_encap* addr)
{
	struct hub_probe* probe = (struct hub_probe*) hub_malloc_zero(sizeof(struct hub_probe));

	if (probe == NULL)
		return NULL; /* OOM */

	LOG_TRACE("probe_create(): %p", probe);

	probe->hub = hub;
	probe->connection = net_con_create();
	net_con_initialize(probe->connection, sd, probe_net_event, probe, NET_EVENT_READ);
	net_con_set_timeout(probe->connection, TIMEOUT_CONNECTED);

	memcpy(&probe->addr, addr, sizeof(struct ip_addr_encap));
	return probe;
}

void probe_destroy(struct hub_probe* probe)
{
	LOG_TRACE("probe_destroy(): %p (connection=%p)", probe, probe->connection);
	if (probe->connection)
	{
		net_con_close(probe->connection);
		probe->connection = 0;
	}
	hub_free(probe);
}
