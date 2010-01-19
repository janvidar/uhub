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

#ifndef HAVE_UHUB_ADC_CLIENT_H
#define HAVE_UHUB_ADC_CLIENT_H

#include "uhub.h"

#define ADC_BUFSIZE 16384

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

enum ADC_client_callback_type
{
	ADC_CLIENT_CONNECTING       = 1001,
	ADC_CLIENT_CONNECTED        = 1002,
	ADC_CLIENT_DISCONNECTED     = 1003,

	ADC_CLIENT_LOGGING_IN       = 2001,
	ADC_CLIENT_PASSWORD_REQ     = 2002,
	ADC_CLIENT_LOGGED_IN        = 2003,
	ADC_CLIENT_LOGIN_ERROR      = 2004,

	ADC_CLIENT_PROTOCOL_STATUS  = 3001,
	ADC_CLIENT_MESSAGE          = 3002,
	ADC_CLIENT_CONNECT_REQ      = 3003,
	ADC_CLIENT_REVCONNECT_REQ   = 3004,
	ADC_CLIENT_SEARCH_REQ       = 3005,
	ADC_CLIENT_SEARCH_REP       = 3006,

	ADC_CLIENT_USER_JOIN        = 4001,
	ADC_CLIENT_USER_QUIT        = 4002,
	ADC_CLIENT_USER_UPDATE      = 4003,

	ADC_CLIENT_HUB_INFO         = 5001,
};

struct ADC_hub_info
{
	char* name;
	char* description;
	char* version;
};

struct ADC_chat_message
{
	sid_t from_sid;
	sid_t to_sid;
	char* message;
	int flags;
};

struct ADC_user
{
	sid_t sid;
	char* cid;
	char* name;
	char* description;
	char* address;
	char* version;
};


struct ADC_client_callback_data
{
	union {
		struct ADC_hub_info* hubinfo;
		struct ADC_chat_message* chat;
		struct ADC_user* user;
	};
};

typedef int (*adc_client_cb)(struct ADC_client*, enum ADC_client_callback_type, struct ADC_client_callback_data* data);

struct ADC_client
{
	sid_t sid;
	enum ADC_client_state state;
	struct adc_message* info;
	char recvbuf[ADC_BUFSIZE];
	char sendbuf[ADC_BUFSIZE];
	adc_client_cb callback;
	size_t s_offset;
	size_t r_offset;
	size_t timeout;
	struct net_connection* con;
	struct net_timer* timer;
	struct sockaddr_in addr;
	char* hub_address;
	char* nick;
	char* desc;
};

int ADC_client_create(struct ADC_client* client, const char* nickname, const char* description);
void ADC_client_set_callback(struct ADC_client* client, adc_client_cb);
void ADC_client_destroy(struct ADC_client* client);
int ADC_client_connect(struct ADC_client* client, const char* address);
void ADC_client_disconnect(struct ADC_client* client);
void ADC_client_send(struct ADC_client* client, char* msg);

#endif /* HAVE_UHUB_ADC_CLIENT_H */


