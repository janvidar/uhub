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

#ifndef HAVE_UHUB_PLUGIN_CALLBACK_H
#define HAVE_UHUB_PLUGIN_CALLBACK_H

struct plugin_handle;
struct uhub_plugin;

extern struct plugin_callback_data* plugin_callback_data_create();
extern void plugin_callback_data_destroy(struct plugin_handle* plugin, struct plugin_callback_data* data);

extern void plugin_register_callback_functions(struct plugin_handle* plugin);
extern void plugin_unregister_callback_functions(struct plugin_handle* plugin);

#endif /* HAVE_UHUB_PLUGIN_CALLBACK_H */
