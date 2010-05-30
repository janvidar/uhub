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

struct uhub_plugin
{
#ifdef HAVE_DLOPEN
	void* handle;
#endif
};

extern struct uhub_plugin* uhub_plugin_open(const char* filename);

extern void uhub_plugin_close(struct uhub_plugin*);

extern void* uhub_plugin_lookup_symbol(struct uhub_plugin*, const char* symbol);

#endif /* PLUGIN_SUPPORT */

#endif /* HAVE_UHUB_PLUGIN_LOADER_H */

