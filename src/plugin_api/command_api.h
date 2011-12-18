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

#ifndef HAVE_UHUB_PLUGIN_API_H
#define HAVE_UHUB_PLUGIN_API_H

/**
 * This file describes the interface a plugin implementation may use from
 * uhub.
 */

#include "system.h"
#include "plugin_api/types.h"

struct plugin_command
{
	const char* message;
	const char* prefix;
	struct linked_list* args;
};

typedef int (*plugin_command_handler)(struct plugin_handle*, struct plugin_user* to, struct plugin_command*);

struct plugin_command_handle
{
	void* internal_handle;			/**<<< "Internal used by the hub only" */
	struct plugin_handle* handle;	/**<<< "The plugin handle this is associated with" */
	const char* prefix;				/**<<< "Command prefix, for instance 'help' would be the prefix for the !help command." */
	size_t length;					/**<<< "Length of the prefix" */
	const char* args;				/**<<< "Argument codes" */
	enum auth_credentials cred;		/**<<< "Minimum access level for the command" */
	plugin_command_handler handler;	/**<<< "Function pointer for the command" */
	const char* description;		/**<<< "Description for the command" */
	const char* origin;				/**<<< "Name of plugin where the command originated." */
};

#define PLUGIN_COMMAND_INITIALIZE(PTR, HANDLE, PREFIX, ARGS, CRED, CALLBACK, DESC) \
	do { \
		PTR->internal_handle = 0; \
		PTR->handle = HANDLE; \
		PTR->prefix = PREFIX; \
		PTR->length = strlen(PREFIX); \
		PTR->args = ARGS; \
		PTR->cred = CRED; \
		PTR->handler = CALLBACK; \
		PTR->description = DESC; \
	} while (0)

extern int plugin_command_add(struct plugin_handle*, struct plugin_command_handle*);
extern int plugin_command_del(struct plugin_handle*, struct plugin_command_handle*);

/**
 * Send a message to a user.
 * From the user's perspective the message will originate from the hub.
 */
extern int plugin_command_send_message(struct plugin_handle*, struct plugin_user* to, const char* message);

/**
 * Send a reply to a command.
 */
extern int plugin_command_send_reply(struct plugin_handle*, struct plugin_user* user, struct plugin_command* command, const char* message);

#endif /* HAVE_UHUB_PLUGIN_API_H */
