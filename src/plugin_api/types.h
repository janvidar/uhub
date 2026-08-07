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

#ifndef HAVE_UHUB_PLUGIN_TYPES_H
#define HAVE_UHUB_PLUGIN_TYPES_H

#include <time.h>

#include "adc/adctypes.h"
#include "util/credentials.h"
#include "network/ipcalc.h"

#define PLUGIN_API_VERSION 8

/* Oldest plugin ABI the current hub still accepts. Version 8 made struct
   plugin_user opaque, which retired the guarantee that its layout mirrors the
   head of the hub's internal user struct. A v5-v7 plugin dereferences that
   layout directly, so once the hub reorders its internals such a plugin would
   read garbage rather than fail -- hence the floor moves with the version.
   Plugins must switch to the hub.get_user_* accessors and rebuild. */
#define PLUGIN_API_VERSION_MIN 8

struct plugin_handle;

/**
 * An opaque handle to a user on the hub. Plugins receive one in callbacks and
 * pass it back to the hub.* functions; its contents are private to the hub.
 * Read its properties through the hub.get_user_* accessors in
 * struct plugin_hub_funcs.
 *
 * The handle is valid only for the duration of the callback that received it.
 * Do not store it -- use hub.get_user_connection_id() for a key that stays
 * valid, or hub.set_user_data() to attach per-user state.
 */
struct plugin_user;

/* Cleanup callback for per-user plugin data. Invoked with the owning plugin
   handle when the user is destroyed, when the value is replaced, or when the
   plugin is unloaded while users are still connected. */
typedef void (*plugin_user_data_free)(struct plugin_handle*, void* data);

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

/**
 * Flood categories matching the hub's flood_ctl_* thresholds. The hub detects
 * the flood (counting events against the configured limits) and raises an
 * on_flood_detected event with one of these; the plugin decides what to do.
 */
enum plugin_flood_type
{
	flood_type_chat = 1,    /* Too many chat messages. */
	flood_type_connect,     /* Too many connect/revconnect requests. */
	flood_type_search,      /* Too many searches. */
	flood_type_update,      /* Too many INF updates. */
	flood_type_extras,      /* Too many of everything else (handshake, commands, ...). */
};

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

/* Size of a ban reason buffer, shared by struct ban_info and the auth_is_banned
   reason out-parameter. */
#define MAX_BAN_REASON 128

struct ban_info
{
	unsigned int flags;                 /* See enum ban_flags. */
	char nickname[MAX_NICK_LEN+1];      /* Nickname - only defined if (ban_nickname & flags). */
	char cid[MAX_CID_LEN+1];            /* CID - only defined if (ban_cid & flags). */
	struct ip_addr_encap ip_addr_lo;    /* Low IP address of an IP range */
	struct ip_addr_encap ip_addr_hi;    /* High IP address of an IP range */
	time_t expiry;                      /* Time when the ban record expires */
	char reason[MAX_BAN_REASON];        /* Human-readable ban reason ("" if none) */
};



#endif /* HAVE_UHUB_PLUGIN_TYPES_H */
