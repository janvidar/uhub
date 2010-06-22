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

#ifndef HAVE_UHUB_PLUGIN_LOADER_H
#define HAVE_UHUB_PLUGIN_LOADER_H

#ifdef PLUGIN_SUPPORT

struct hub_config;
struct linked_list;
struct uhub_plugin_handle;

struct uhub_plugin
{
#ifdef HAVE_DLOPEN
	void* handle;
#endif
};

struct uhub_plugins
{
	struct linked_list* loaded;
	char* plugin_dir;
};

// High level plugin loader ode
extern struct uhub_plugin_handle* plugin_load(const char* filename, const char* config);
extern void plugin_unload(struct uhub_plugin_handle* plugin);

// extern void plugin_unload(struct uhub_plugin_handle*);
extern int plugin_initialize(struct hub_config* config, struct uhub_plugins* handle);

// Low level plugin loader code (used internally)
extern struct uhub_plugin* plugin_open(const char* filename);
extern void plugin_close(struct uhub_plugin*);
extern void* plugin_lookup_symbol(struct uhub_plugin*, const char* symbol);



#endif /* PLUGIN_SUPPORT */

#endif /* HAVE_UHUB_PLUGIN_LOADER_H */

