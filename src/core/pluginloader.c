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

#include "uhub.h"

#include "plugin_api/handle.h"

struct plugin_callback_data;

struct plugin_hub_internals* get_internals(struct plugin_handle* handle)
{
	struct plugin_hub_internals* internals;
	uhub_assert(handle && handle->handle && handle->handle->internals);
	internals = (struct plugin_hub_internals*) handle->handle->internals;
	return internals;
}

struct uhub_plugin* plugin_open(const char* filename)
{
	struct uhub_plugin* plugin;
	LOG_PLUGIN("plugin_open: \"%s\"", filename);

	plugin = (struct uhub_plugin*) hub_malloc_zero(sizeof(struct uhub_plugin));
	if (!plugin)
	{
		return 0;
	}

#ifdef HAVE_DLOPEN
	plugin->handle = dlopen(filename, RTLD_LAZY);
#else
	plugin->handle = LoadLibraryExA(filename, NULL, 0);
#endif

	if (!plugin->handle)
	{
#ifdef HAVE_DLOPEN
		LOG_ERROR("Unable to open plugin %s: %s", filename, dlerror());
#else
		LOG_ERROR("Unable to open plugin %s: %d", filename, GetLastError());
#endif
		hub_free(plugin);
		return 0;
	}

	plugin->filename = strdup(filename);
	plugin->internals = hub_malloc_zero(sizeof(struct plugin_hub_internals));
	return plugin;
}

void plugin_close(struct uhub_plugin* plugin)
{
	struct plugin_hub_internals* internals = (struct plugin_hub_internals*) plugin->internals;

	LOG_PLUGIN("plugin_close: \"%s\"", plugin->filename);
	plugin_callback_data_destroy(plugin->handle, internals->callback_data);
	hub_free(internals);
	plugin->internals = NULL;

#ifdef HAVE_DLOPEN
	dlclose(plugin->handle);
#else
	FreeLibrary((HMODULE) plugin->handle);
#endif
	hub_free(plugin->filename);
	hub_free(plugin);
}

void* plugin_lookup_symbol(struct uhub_plugin* plugin, const char* symbol)
{
#ifdef HAVE_DLOPEN
	void* addr = dlsym(plugin->handle, symbol);
	return addr;
#else
	FARPROC addr = GetProcAddress((HMODULE) plugin->handle, symbol);
	return (void*) addr;
#endif
}



struct plugin_handle* plugin_load(const char* filename, const char* config, struct hub_info* hub)
{
	plugin_register_f register_f;
	plugin_unregister_f unregister_f;
	int ret;
	struct plugin_handle* handle = (struct plugin_handle*) hub_malloc_zero(sizeof(struct plugin_handle));
	struct uhub_plugin* plugin = plugin_open(filename);
	struct plugin_hub_internals* internals = (struct plugin_hub_internals*) plugin->internals;

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

	// register hub internals
	internals->unregister = unregister_f;
	internals->hub = hub;
	internals->callback_data = plugin_callback_data_create();

	// setup callback functions, where the plugin can contact the hub.
	plugin_register_callback_functions(handle);

	if (register_f && unregister_f)
	{
		ret = register_f(handle, config);
		if (ret == 0)
		{
			if (handle->plugin_api_version == PLUGIN_API_VERSION && handle->plugin_funcs_size == sizeof(struct plugin_funcs))
			{
				LOG_INFO("Loaded plugin: %s: %s, version %s.", filename, handle->name, handle->version);
				LOG_PLUGIN("Plugin API version: %d (func table size: " PRINTF_SIZE_T ")", handle->plugin_api_version, handle->plugin_funcs_size);
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

void plugin_unload(struct plugin_handle* plugin)
{
	struct plugin_hub_internals* internals = get_internals(plugin);
	internals->unregister(plugin);
	plugin_unregister_callback_functions(plugin);
	plugin_close(plugin->handle);
	hub_free(plugin);
}

static int plugin_parse_line(char* line, int line_count, void* ptr_data)
{
	struct hub_info* hub = (struct hub_info*) ptr_data;
	struct uhub_plugins* handle = hub->plugins;
	struct cfg_tokens* tokens = cfg_tokenize(line);
	struct plugin_handle* plugin;
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

		LOG_PLUGIN("Load plugin: \"%s\", params=\"%s\"", soname, params);
		plugin = plugin_load(soname, params, hub);
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

int plugin_initialize(struct hub_config* config, struct hub_info* hub)
{
	int ret;

	hub->plugins->loaded = list_create();
	if (!hub->plugins->loaded)
		return -1;

	if (config)
	{
		if (!*config->file_plugins)
			return 0;

		ret = file_read_lines(config->file_plugins, hub, &plugin_parse_line);
		if (ret == -1)
		{
			list_clear(hub->plugins->loaded, hub_free);
			list_destroy(hub->plugins->loaded);
			hub->plugins->loaded = 0;
			return -1;
		}
	}
	return 0;
}

static void plugin_unload_ptr(void* ptr)
{
	struct plugin_handle* plugin = (struct plugin_handle*) ptr;
	plugin_unload(plugin);
}


void plugin_shutdown(struct uhub_plugins* handle)
{
	list_clear(handle->loaded, plugin_unload_ptr);
	list_destroy(handle->loaded);
}

// Used internally only
struct hub_info* plugin_get_hub(struct plugin_handle* plugin)
{
	struct plugin_hub_internals* data = get_internals(plugin);
	return data->hub;
}

