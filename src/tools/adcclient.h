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

#ifndef HAVE_UHUB_ADC_CLIENT_H
#define HAVE_UHUB_ADC_CLIENT_H

#include "uhub.h"

#define ADC_BUFSIZE 16384

struct ADC_client;

enum ADC_client_callback_type
{
	ADC_CLIENT_NAME_LOOKUP      = 1000,
	ADC_CLIENT_CONNECTING       = 1001,
	ADC_CLIENT_CONNECTED        = 1002,
	ADC_CLIENT_DISCONNECTED     = 1003,
	ADC_CLIENT_SSL_HANDSHAKE    = 1101,
	ADC_CLIENT_SSL_OK           = 1102,

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

enum ADC_chat_message_flags
{
	chat_flags_none = 0,
	chat_flags_action = 1,
	chat_flags_private = 2
};

struct ADC_chat_message
{
	sid_t from_sid;
	sid_t to_sid;
	char* message;
	int flags;
};

#define MAX_DESC_LEN 128
struct ADC_user
{
	sid_t sid;
	char cid[MAX_CID_LEN+1];
	char name[MAX_NICK_LEN+1];
	char description[MAX_DESC_LEN+1];
	char address[INET6_ADDRSTRLEN+1];
	char version[MAX_UA_LEN+1];
};

struct ADC_client_quit_reason
{
	sid_t sid;
	sid_t initator; // 0 = default/hub.
	char message[128]; // optional
	int flags;
};


struct ADC_client_callback_data
{
	union {
		struct ADC_hub_info* hubinfo;
		struct ADC_chat_message* chat;
		struct ADC_user* user;
		struct ADC_client_quit_reason* quit;
	};
};

sid_t ADC_client_get_sid(const struct ADC_client* client);
const char* ADC_client_get_nick(const struct ADC_client* client);
const char* ADC_client_get_description(const struct ADC_client* client);
void* ADC_client_get_ptr(const struct ADC_client* client);

typedef int (*adc_client_cb)(struct ADC_client*, enum ADC_client_callback_type, struct ADC_client_callback_data* data);

struct ADC_client* ADC_client_create(const char* nickname, const char* description, void* ptr);
void ADC_client_set_callback(struct ADC_client* client, adc_client_cb);
void ADC_client_destroy(struct ADC_client* client);
int ADC_client_connect(struct ADC_client* client, const char* address);
void ADC_client_disconnect(struct ADC_client* client);
void ADC_client_send(struct ADC_client* client, struct adc_message* msg);

#endif /* HAVE_UHUB_ADC_CLIENT_H */


