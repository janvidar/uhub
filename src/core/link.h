/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2013, Jan Vidar Krey
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

#ifndef HAVE_UHUB_LINK_H
#define HAVE_UHUB_LINK_H

#ifdef LINK_SUPPORT

struct hub_link
{
	char name[MAX_NICK_LEN+1];         /** The name of the linked hub */
	char user_agent[MAX_UA_LEN+1];     /** The user agent of the linked hub */
	char address[256];                 /** The official address of the linked hub */
	enum link_mode { link_mode_client, link_mode_server } mode;
	enum user_state state;
	struct ioq_send* send_queue;
	struct ioq_recv* recv_queue;
	struct net_connection* connection; /** Connection data */
	struct net_connect_handle* connect_job; /** Only used when establishing a connection in client mode */
	struct hub_info* hub;
	int flags;
};

/**
 * Create a link from an accepted connection (act as a link server).
 */
extern struct hub_link* link_create(struct hub_info* hub, struct net_connection* con, struct ip_addr_encap* addr);

/**
 * Connect this hub to an upstream server (act as a link client).
 */
extern struct hub_link* link_connect(struct hub_info* hub, const char* address, uint16_t port);
extern struct hub_link* link_connect_uri(struct hub_info* hub, const char* address);

/**
 * Disconnect a link connection.
 */
extern void link_disconnect(struct hub_link*);

/**
 * Read from link connection and process messages.
 * @return 0 on success, and a negative value otherwise
 */
extern int link_handle_read(struct hub_link* link);

/**
 * Write queued messages to the link.
 * @return 0 on success, and a negative value otherwise.
 */
extern int link_handle_write(struct hub_link* link);

#endif // LINK_SUPPORT

#endif /* HAVE_UHUB_LINK_H */
