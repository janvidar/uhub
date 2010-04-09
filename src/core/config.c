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


#ifndef INT_MAX
#define INT_MAX 0x7fffffff
#endif

#ifndef INT_MIN
#define INT_MIN (-0x7fffffff - 1)
#endif

#define CFG_APPLY_BOOLEAN(KEY, TARGET) \
	if (strcmp(KEY, key) == 0) \
	{ \
		if      (strlen(data) == 1 && (data[0] == '1')) TARGET = 1; \
		else if (strlen(data) == 1 && (data[0] == '0')) TARGET = 0; \
		else if (strncasecmp(data, "true",  4) == 0) TARGET = 1; \
		else if (strncasecmp(data, "false", 5) == 0) TARGET = 0; \
		else if (strncasecmp(data, "yes",   3) == 0) TARGET = 1; \
		else if (strncasecmp(data, "no",    2) == 0) TARGET = 0; \
		else if (strncasecmp(data, "on",    2) == 0) TARGET = 1; \
		else if (strncasecmp(data, "off",   3) == 0) TARGET = 0; \
		else\
		{ \
			LOG_FATAL("Configuration error on line %d: '%s' must be either '1' or '0'", line_count, key); \
			return -1; \
		} \
		TARGET |= 0x80000000; \
		return 0; \
	}

#define CFG_APPLY_STRING(KEY, TARGET) \
	if (strcmp(KEY, key) == 0) \
	{ \
		TARGET = hub_strdup(data); \
		return 0; \
	}


#define CFG_APPLY_INTEGER(KEY, TARGET) \
	if (strcmp(KEY, key) == 0) \
	{ \
		char* endptr; \
		int val; \
		errno = 0; \
		val = strtol(data, &endptr, 10); \
		if (((errno == ERANGE && (val == INT_MAX || val == INT_MIN)) || (errno != 0 && val == 0)) || endptr == data) { \
			LOG_FATAL("Configuration error on line %d: '%s' must be a number", line_count, key); \
			return -1; \
		} \
		TARGET = val; \
		return 0; \
	}


#define DEFAULT_STRING(KEY, VALUE) \
{ \
	if (config->KEY == 0) \
		config->KEY = hub_strdup(VALUE); \
}

#define DEFAULT_INTEGER(KEY, VALUE) \
{ \
	if (config->KEY == 0) \
		config->KEY = VALUE; \
}

#define DEFAULT_BOOLEAN(KEY, VALUE) \
{ \
	if (config->KEY & 0x80000000) \
	{ \
		config->KEY = config->KEY & 0x000000ff; \
	} \
	else \
	{ \
		config->KEY = VALUE; \
	} \
}

#define GET_STR(NAME)  CFG_APPLY_STRING ( #NAME , config->NAME )
#define GET_INT(NAME)  CFG_APPLY_INTEGER( #NAME , config->NAME )
#define GET_BOOL(NAME) CFG_APPLY_BOOLEAN( #NAME , config->NAME )
#define IGNORED(NAME) \
    if (strcmp(#NAME, key) == 0) \
    { \
        LOG_WARN("Configuration option %s deprecated and ingnored.", key); \
        return 0; \
    }

#define DUMP_STR(NAME, DEFAULT) \
	if (ignore_defaults) \
	{ \
		if (strcmp(config->NAME, DEFAULT) != 0) \
			fprintf(stdout, "%s = \"%s\"\n", #NAME , config->NAME); \
	} \
	else \
		fprintf(stdout, "%s = \"%s\"\n", #NAME , config->NAME); \
		
#define DUMP_INT(NAME, DEFAULT) \
	if (ignore_defaults) \
	{ \
		if (config->NAME != DEFAULT) \
			fprintf(stdout, "%s = %d\n", #NAME , config->NAME); \
	} \
	else \
		fprintf(stdout, "%s = %d\n", #NAME , config->NAME); \

#define DUMP_BOOL(NAME, DEFAULT) \
	if (ignore_defaults) \
	{ \
		if (config->NAME != DEFAULT) \
			fprintf(stdout, "%s = %s\n", #NAME , (config->NAME ? "yes" : "no")); \
	} \
	else \
		fprintf(stdout, "%s = %s\n", #NAME , (config->NAME ? "yes" : "no"));


#include "gen_config.c"

static int config_parse_line(char* line, int line_count, void* ptr_data)
{
	char* pos;
	char* key;
	char* data;
	struct hub_config* config = (struct hub_config*) ptr_data;

	if ((pos = strchr(line, '#')) != NULL)
	{
		pos[0] = 0;
	}

	if (!*line) return 0;

	LOG_DUMP("config_parse_line(): '%s'", line);

	if (!is_valid_utf8(line))
	{
		LOG_WARN("Invalid utf-8 characters on line %d", line_count);
	}

	if ((pos = strchr(line, '=')) != NULL)
	{
		pos[0] = 0;
	}
	else
	{
		return 0;
	}

	key = line;
	data = &pos[1];

	key = strip_white_space(key);
	data = strip_white_space(data);

	if (!*key || !*data)
	{
		LOG_FATAL("Configuration parse error on line %d", line_count);
		return -1;
	}

	LOG_DUMP("config_parse_line: '%s' => '%s'", key, data);

	return apply_config(config, key, data, line_count);
}


int read_config(const char* file, struct hub_config* config, int allow_missing)
{
	int ret;

	memset(config, 0, sizeof(struct hub_config));
	config_defaults(config);

	ret = file_read_lines(file, config, &config_parse_line);
	if (ret < 0)
	{
		if (allow_missing && ret == -2)
		{
			LOG_DUMP("Using default configuration.");
		}
		else
		{
			return -1;
		}
	}

	return 0;
}


