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

#ifndef HAVE_UHUB_PLUGIN_TYPES_H
#define HAVE_UHUB_PLUGIN_TYPES_H

#define PLUGIN_API_VERSION 2

#ifndef MAX_NICK_LEN
#define MAX_NICK_LEN 64
#endif

#ifndef MAX_PASS_LEN
#define MAX_PASS_LEN 64
#endif

#ifndef MAX_CID_LEN
#define MAX_CID_LEN 39
#endif

#ifndef MAX_UA_LEN
#define MAX_UA_LEN   32
#endif

#ifndef SID_T_DEFINED
typedef uint32_t sid_t;
#define SID_T_DEFINED
#endif

struct plugin_handle;

struct plugin_user
{
	sid_t sid;
	char nick[MAX_NICK_LEN+1];
	char cid[MAX_CID_LEN+1];
	char user_agent[MAX_UA_LEN+1];
	struct ip_addr_encap addr;
	enum auth_credentials credentials;
};

struct plugin_hub_info
{
	const char* description;
};

enum plugin_status
{
	st_default = 0,    /* Use default */
	st_allow = 1,      /* Allow action */
	st_deny = -1,      /* Deny action */
};

typedef enum plugin_status plugin_st;

struct auth_info
{
	char nickname[MAX_NICK_LEN+1];
	char password[MAX_PASS_LEN+1];
	enum auth_credentials credentials;
};

enum ban_flags
{
	ban_nickname = 0x01, /* Nickname is banned */
	ban_cid      = 0x02, /* CID is banned */
	ban_ip       = 0x04, /* IP address (range) is banned */
};

struct ban_info
{
	unsigned int flags;                 /* See enum ban_flags. */
	char nickname[MAX_NICK_LEN+1];      /* Nickname - only defined if (ban_nickname & flags). */
	char cid[MAX_CID_LEN+1];            /* CID - only defined if (ban_cid & flags). */
	struct ip_addr_encap ip_addr_lo;    /* Low IP address of an IP range */
	struct ip_addr_encap ip_addr_hi;    /* High IP address of an IP range */
	time_t expiry;                      /* Time when the ban record expires */
};

enum plugin_command_arg_type
{
	plugin_cmd_arg_type_integer,
	plugin_cmd_arg_type_string,
	plugin_cmd_arg_type_user,
	plugin_cmd_arg_type_address,
	plugin_cmd_arg_type_range,
	plugin_cmd_arg_type_credentials,
};

/* Specifies which categories a command appears in. To make a command appear in
 * multiple categories, simply OR the appropriate values together. */
enum plugin_ucmd_categories
{
	/* Appears in the main hub chat window. */
	ucmd_category_hub = 1,

	/* Appears in the hub user list. */
	ucmd_category_user = 2,

	/* Appears in the search results. */
	ucmd_category_search = 4,

	/* Appears in the file list. */
	ucmd_category_file = 8,

	/* Special case: appear everywhere. */
	ucmd_category_all = 15,
};

/* Holds information about a user command. Note that a unique name is required
 * for every command, even if it is only a separator.
 *
 * You should not create one of these yourself but instead use the
 * plugin_handle->hub.ucmd_create() function.
 *
 * Similarly, you should only manually modify the first four entries below, and
 * use the plugin_handle->hub.ucmd_xxxx() functions to make any other changes.
 * */
struct plugin_ucmd
{
	/* Which categories the command appears in. */
	enum plugin_ucmd_categories categories;

	/* If true, removes an existing command rather than adding a new one. */
	int remove;

	/* If true, adds a separator to the user command menu rather than an actual command. */
	int separator;

	/* Sometimes a command can be sent on multiple users (e.g., in search
	 * results). If this field is true, the command is limited to run once per
	 * CID. */
	int constrained;

	/* Plugins must not modify the following fields. */
	char *name;
	size_t namelen;
	char *tt;
	size_t length;
	size_t capacity;
};

#endif /* HAVE_UHUB_PLUGIN_TYPES_H */
