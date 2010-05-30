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

#include "uhub.h"

#ifdef PLUGIN_SUPPORT

struct uhub_plugin* uhub_plugin_open(const char* filename)
{
#ifdef HAVE_DLOPEN
	struct uhub_plugin* plugin = (struct uhub_plugin*) hub_malloc_zero(sizeof(struct uhub_plugin));
	if (!plugin)
	{
		return 0;
	}

	plugin->handle = dlopen(filename, RTLD_LAZY);

	if (!plugin->handle)
	{
		LOG_ERROR("Unable to open plugin %s: %s", filename, dlerror());
		hub_free(plugin);
		return 0;
	}

	return plugin;
#else
	return 0;
#endif
}

void uhub_plugin_close(struct uhub_plugin* plugin)
{
#ifdef HAVE_DLOPEN
	dlclose(plugin->handle);
	hub_free(plugin);
#endif
}

void* uhub_plugin_lookup_symbol(struct uhub_plugin* plugin, const char* symbol)
{
#ifdef HAVE_DLOPEN
	void* addr = dlsym(plugin->handle, symbol);
	return addr;
#else
	return 0;
#endif
}

#endif /* PLUGIN_SUPPORT */
