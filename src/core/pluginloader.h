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

#ifndef HAVE_UHUB_PLUGIN_LOADER_H
#define HAVE_UHUB_PLUGIN_LOADER_H

#include "plugin_api/handle.h"

struct hub_config;
struct hub_info;
struct linked_list;
struct plugin_handle;

struct uhub_plugin
{
	void* handle;
	plugin_unregister_f unregister;
	char* filename;
	void* internals;      // Hub-internal stuff (struct plugin_hub_internals)
};

struct uhub_plugins
{
	struct linked_list* loaded;
};

// High level plugin loader code
extern struct plugin_handle* plugin_load(const char* filename, const char* config, struct hub_info* hub);
extern void plugin_unload(struct plugin_handle* plugin);

// extern void plugin_unload(struct plugin_handle*);
extern int plugin_initialize(struct hub_config* config, struct hub_info* hub);
extern void plugin_shutdown(struct uhub_plugins* handle);

// Low level plugin loader code (used internally)
extern struct uhub_plugin* plugin_open(const char* filename);
extern void plugin_close(struct uhub_plugin*);
extern void* plugin_lookup_symbol(struct uhub_plugin*, const char* symbol);

// Used internally only
struct plugin_hub_internals
{
	struct hub_info* hub;
	plugin_unregister_f unregister;             /* The unregister function. */
	struct plugin_callback_data* callback_data; /* callback data that is unique for the plugin */
};

extern struct plugin_hub_internals* get_internals(struct plugin_handle*);
extern struct hub_info* plugin_get_hub(struct plugin_handle*);

#endif /* HAVE_UHUB_PLUGIN_LOADER_H */
