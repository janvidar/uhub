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

#include "system.h"
#include "util/config_token.h"
#include "util/list.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/plugincallback.h"
#include "core/pluginloader.h"

#include "plugin_api/handle.h"

#ifdef HAVE_DLOPEN
#include <sys/stat.h> /* stat(), S_ISREG, S_IWGRP/S_IWOTH for the plugin perm check */
#endif

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

#ifdef HAVE_DLOPEN
	/*
	 * The plugin is loaded into the hub's own address space, so a .so that any
	 * non-owner can rewrite is a local code-execution vector. Refuse to load
	 * one that is group- or world-writable (a correctly installed plugin is
	 * 0644/0755). Also require it to be a regular file.
	 */
	{
		struct stat st;
		if (stat(filename, &st) != 0)
		{
			LOG_ERROR("Unable to stat plugin %s: %s", filename, strerror(errno));
			return 0;
		}
		if (!S_ISREG(st.st_mode))
		{
			LOG_ERROR("Refusing to load plugin %s: not a regular file.", filename);
			return 0;
		}
		if (st.st_mode & (S_IWGRP | S_IWOTH))
		{
			LOG_ERROR("Refusing to load plugin %s: it is group- or world-writable.", filename);
			return 0;
		}
	}
#endif

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

	plugin->filename = hub_strdup(filename);
	if (!plugin->filename)
	{
		LOG_ERROR("Unable to allocate memory for plugin filename");
#ifdef HAVE_DLOPEN
		dlclose(plugin->handle);
#else
		FreeLibrary((HMODULE) plugin->handle);
#endif
		hub_free(plugin);
		return 0;
	}

	plugin->internals = hub_malloc_zero(sizeof(struct plugin_hub_internals));
	if (!plugin->internals)
	{
		LOG_ERROR("Unable to allocate memory for plugin internals");
#ifdef HAVE_DLOPEN
		dlclose(plugin->handle);
#else
		FreeLibrary((HMODULE) plugin->handle);
#endif
		hub_free(plugin->filename);
		hub_free(plugin);
		return 0;
	}

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
	struct plugin_hub_internals* internals = (struct plugin_hub_internals*) plugin->internals;
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

/*
 * Is the given plugin path absolute? A relative path is resolved against the
 * configured plugin_dir (if any); an absolute one is always used verbatim.
 */
static int plugin_path_is_absolute(const char* path)
{
#ifdef HAVE_DLOPEN
	return path[0] == '/';
#else
	/* Windows: "\foo", "/foo" or a drive-qualified path such as "C:\foo". */
	if (path[0] == '\\' || path[0] == '/')
		return 1;
	if (path[0] && path[1] == ':')
		return 1;
	return 0;
#endif
}

/* Join a directory and a plugin name, inserting a separator if needed. */
static char* plugin_join_path(const char* dir, const char* name)
{
	size_t dlen = strlen(dir);
	int need_sep = (dlen > 0 && dir[dlen - 1] != '/' && dir[dlen - 1] != '\\');
	size_t len = dlen + (need_sep ? 1 : 0) + strlen(name) + 1;
	char* full = hub_malloc(len);
	if (!full)
		return NULL;
	snprintf(full, len, need_sep ? "%s/%s" : "%s%s", dir, name);
	return full;
}

static int plugin_parse_line(char* line, int line_count, void* ptr_data)
{
	(void) line_count;
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

	/*
	 * "plugin_dir <path>" sets the base directory prepended to any subsequent
	 * plugin given by a relative soname. It applies to plugin directives that
	 * follow it in the file, so place it before them.
	 */
	if (strcmp(directive, "plugin_dir") == 0 && soname && *soname)
	{
		hub_free(handle->plugin_dir);
		handle->plugin_dir = hub_strdup(soname);
		cfg_tokens_free(tokens);
		return handle->plugin_dir ? 0 : -1;
	}

	if (strcmp(directive, "plugin") == 0 && soname && *soname)
	{
		char* resolved = NULL;
		const char* path = soname;

		if (handle->plugin_dir && !plugin_path_is_absolute(soname))
		{
			resolved = plugin_join_path(handle->plugin_dir, soname);
			if (!resolved)
			{
				cfg_tokens_free(tokens);
				return -1;
			}
			path = resolved;
		}

		if (!params)
			params = "";

		LOG_PLUGIN("Load plugin: \"%s\", params=\"%s\"", path, params);
		plugin = plugin_load(path, params, hub);
		hub_free(resolved);
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
			list_clear(hub->plugins->loaded, hub_free_handle);
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
	hub_free(handle->plugin_dir);
	handle->plugin_dir = NULL;
}

// Used internally only
struct hub_info* plugin_get_hub(struct plugin_handle* plugin)
{
	struct plugin_hub_internals* data = get_internals(plugin);
	return data->hub;
}

