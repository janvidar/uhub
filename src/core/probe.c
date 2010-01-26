/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2010, Jan Vidar Krey
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
			if (memcmp(probe_recvbuf, "HSUP", 4) == 0)
			{
				LOG_TRACE("Probed ADC");
				if (user_create(probe->hub, probe->connection, &probe->addr))
				{
					probe->connection = 0;
				}
				probe_destroy(probe);
				return;
			}

#ifdef SSL_SUPPORT
			if (bytes >= 11 &&
				probe_recvbuf[0] == 22 && 
				probe_recvbuf[1] == 3 && /* protocol major version */
				probe_recvbuf[5] == 1 && /* message type */
				probe_recvbuf[9] == probe_recvbuf[1] &&
				probe_recvbuf[10] == probe_recvbuf[2])
			{
				if (probe->hub->config->tls_enable)
				{
					LOG_TRACE("Probed TLS %d.%d connection", (int) probe_recvbuf[1], (int) probe_recvbuf[2]);
					if (user_create(probe->hub, probe->connection, &probe->addr))
					{
						probe->connection = 0;
					}
					net_con_ssl_handshake(con, net_con_ssl_mode_server, probe->hub->ssl_ctx);
				}
				else
				{
					LOG_TRACE("Probed TLS %d.%d connection. TLS disabled in hub.", (int) probe_recvbuf[1], (int) probe_recvbuf[2]);
				}
				probe_destroy(probe);
				return;
			}
			else
			{
				LOG_TRACE("Probed TLS %d.%d connection", (int) probe_recvbuf[1], (int) probe_recvbuf[2]);

				net_con_ssl_handshake(con, net_con_ssl_mode_server, probe->hub->ssl_ctx);
				return;
			}
#endif
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

	probe->hub = hub;
	probe->connection = net_con_create();
	net_con_initialize(probe->connection, sd, probe_net_event, probe, NET_EVENT_READ);
	net_con_set_timeout(probe->connection, TIMEOUT_CONNECTED);

	memcpy(&probe->addr, addr, sizeof(struct ip_addr_encap));
	return probe;
}

void probe_destroy(struct hub_probe* probe)
{
	if (probe->connection)
	{
		net_con_close(probe->connection);
		probe->connection = 0;
	}
	hub_free(probe);
}
