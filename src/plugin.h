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

typedef void (*plugin_event_startup)(struct hub*);
typedef void (*plugin_event_shutdown)(struct hub*);
typedef void (*plugin_event_user_login)(struct hub*, struct user*);
typedef void (*plugin_event_user_logout)(struct hub*, struct user*);
typedef int  (*plugin_event_connect)(struct hub*, struct ip_addr_encap);
typedef void (*plugin_event_disconnect)(struct hub*, struct user*);
typedef int  (*plugin_event_message)(struct hub*, struct user*, struct adc_message*);
typedef void (*plugin_event_support)(struct hub*, struct user*, int);

struct uhub_plugin
{
	/** Starting the hub */
	plugin_event_startup     evt_startup;

	/** Shutting down the hub */
	plugin_event_shutdown    evt_shutdown;

	/** Someone connected to the hub (we only have IP at this point). */
	plugin_event_connect     evt_connect;

	/** Someone disconnected from the hub (but was not successfully logged in). */
	plugin_event_disconnect  evt_disconnect;

	/** A client sent a message about which protocol extensions it supports */
	plugin_event_support     evt_support;

	/** A client was successfully logged in to the hub */
	plugin_event_user_login  evt_login;

	/** A client (previously logged in) has disconnected. */
	plugin_event_user_logout evt_logout;
};

