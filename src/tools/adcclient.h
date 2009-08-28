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

#ifndef HAVE_UHUB_ADC_CLIENT_H
#define HAVE_UHUB_ADC_CLIENT_H

#define ADC_BUFSIZE 16384
#define ADC_SIDSIZE 4

enum ADC_client_state
{
	ps_none     = 0x00, /* Not connected */
	ps_conn     = 0x01, /* Connecting... */
	ps_protocol = 0x02, /* Have sent HSUP */
	ps_identify = 0x04, /* Have sent BINF */
	ps_verify   = 0x08, /* Have sent HPAS */
	ps_normal   = 0x10, /* Are fully logged in */
};

struct ADC_client;

typedef void (*adc_client_connection_status_cb)(struct ADC_client*, int code, const char* data);
typedef void (*adc_client_message_cb)(struct ADC_client*, const char* msg, int flags);
typedef void (*adc_client_status_cb)(struct ADC_client*, const char* status, int code);

struct ADC_client_callbacks
{
	adc_client_connection_status_cb connection;
	adc_client_message_cb message;
	adc_client_status_cb status;
};

struct ADC_client
{
	sid_t sid;
	enum ADC_client_state state;
	char info[ADC_BUFSIZE];
	char recvbuf[ADC_BUFSIZE];
	char sendbuf[ADC_BUFSIZE];
	size_t s_offset;
	size_t r_offset;
	size_t timeout;
	struct net_connection* con;
	struct net_timer* timer;
	struct ADC_client_callbacks callbacks;
	struct sockaddr_in addr;
	char* hub_address;
	char* nick;
	char* desc;
};



/**
 * Create/Allocate/Initialize an ADC_client struct
 * NOTE: If this is successful, one must call ADC_client_destroy to cleanup afterwards.
 */
extern int ADC_client_create(struct ADC_client* client, const char* nickname, const char* description);

/**
 * Destroy an ADC_client struct.
 */
extern void ADC_client_destroy(struct ADC_client* client);

extern int ADC_client_connect(struct ADC_client* client, const char* address);

extern void ADC_client_disconnect(struct ADC_client* client);

/**
 * Send a message (ADC command)
 */
extern void ADC_client_send(struct ADC_client* client, char* msg);

#endif /* HAVE_UHUB_ADC_CLIENT_H */


