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

#include "uhub.h"

#define CHAT_MSG_HANDLED  1
#define CHAT_MSG_IGNORED  0
#define CHAT_MSG_INVALID -1

typedef int (*plugin_event_chat_message)(struct hub_info*, struct hub_user*, struct adc_message*);

struct command_info
{
	const char* prefix;
	enum user_credentials cred;
	plugin_event_chat_message function;
};

int command_dipatcher(struct hub_info* hub, struct hub_user* user, const char* message);
