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
#include "plugin_api/handle.h"

struct uhub_plugin* plugin_open(const char* filename)
{
	LOG_TRACE("plugin_open: \"%s\"", filename);
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

void plugin_close(struct uhub_plugin* plugin)
{
#ifdef HAVE_DLOPEN
	dlclose(plugin->handle);
	hub_free(plugin);
#endif
}

void* plugin_lookup_symbol(struct uhub_plugin* plugin, const char* symbol)
{
#ifdef HAVE_DLOPEN
	void* addr = dlsym(plugin->handle, symbol);
	return addr;
#else
	return 0;
#endif
}

struct uhub_plugin_handle* plugin_load(const char* filename, const char* config)
{
	plugin_register_f register_f;
	plugin_unregister_f unregister_f;
	int ret;
	struct uhub_plugin_handle* handle = hub_malloc_zero(sizeof(struct uhub_plugin_handle));
	struct uhub_plugin* plugin = plugin_open(filename);

	if (!plugin)
		return NULL;

	if (!handle)
	{
		plugin_close(plugin);
		return NULL;
	}

	handle->handle = plugin;
	register_f = plugin_lookup_symbol(plugin, "plugin_register");
	unregister_f = plugin_lookup_symbol(plugin, "plugin_unregister");

	if (register_f && unregister_f)
	{
		ret = register_f(handle, config);
		if (ret == 0)
		{
			if (handle->plugin_api_version == PLUGIN_API_VERSION && handle->plugin_funcs_size == sizeof(struct plugin_funcs))
			{
				LOG_INFO("Loaded plugin: %s: %s, version %s.", filename, handle->name, handle->version);
				LOG_TRACE("Plugin API version: %d (func table size: " PRINTF_SIZE_T ")", handle->plugin_api_version, handle->plugin_funcs_size);
				plugin->unregister = unregister_f;
				return handle;
			}
			else
			{
				LOG_ERROR("Unable to load plugin: %s - API version mistmatch", filename);
			}
		}
		else
		{
			LOG_ERROR("Unable to load plugin: %s - Failed to initialize: %s", filename, handle->error_msg);
		}
	}

	plugin_close(plugin);
	hub_free(handle);
	return NULL;
}

void plugin_unload(struct uhub_plugin_handle* plugin)
{
	plugin->handle->unregister(plugin);
	plugin_close(plugin->handle);
}

static int plugin_parse_line(char* line, int line_count, void* ptr_data)
{
	struct uhub_plugins* handle = (struct uhub_plugins*) ptr_data;
	struct cfg_tokens* tokens = cfg_tokenize(line);
	char *directive, *soname, *params;

	if (cfg_token_count(tokens) == 0)
	{
		cfg_tokens_free(tokens);
		return 0;
	}

	if (cfg_token_count(tokens) < 2)
	{
		cfg_tokens_free(tokens);
		return -1;
	}

	directive = cfg_token_get_first(tokens);
	soname    = cfg_token_get_next(tokens);
	params    = cfg_token_get_next(tokens);

	if (strcmp(directive, "plugin") == 0 && soname && *soname)
	{
		if (!params)
			params = "";

		LOG_TRACE("Load plugin: \"%s\", params=\"%s\"", soname, params);
		struct uhub_plugin_handle* plugin = plugin_load(soname, params);
		if (plugin)
		{
			list_append(handle->loaded, plugin);
			cfg_tokens_free(tokens);
			return 0;
		}
	}

	cfg_tokens_free(tokens);
	return -1;
}

int plugin_initialize(struct hub_config* config, struct uhub_plugins* handle)
{
	int ret;

	handle->loaded = list_create();
	if (!handle->loaded)
		return -1;

	if (config)
	{
		if (!*config->file_plugins)
			return 0;

		ret = file_read_lines(config->file_plugins, handle, &plugin_parse_line);
		if (ret == -1)
			return -1;
	}
	return 0;
}

void plugin_shutdown(struct uhub_plugins* handle)
{
	struct uhub_plugin_handle* plugin = (struct uhub_plugin_handle*) list_get_first(handle->loaded);
	while (plugin)
	{
		list_remove(handle->loaded, plugin);
		plugin_unload(plugin);
		plugin = (struct uhub_plugin_handle*) list_get_first(handle->loaded);
	}

	list_destroy(handle->loaded);
}

#endif /* PLUGIN_SUPPORT */
