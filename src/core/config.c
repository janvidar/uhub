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


#ifndef INT_MAX
#define INT_MAX 0x7fffffff
#endif

#ifndef INT_MIN
#define INT_MIN (-0x7fffffff - 1)
#endif

static int apply_boolean(const char* key, const char* data, int* target)
{
	return string_to_boolean(data, target);
}

static int apply_string(const char* key, const char* data, char** target, char* regexp)
{
	(void) regexp;
	// FIXME: Add regexp checks for correct data

	if (*target)
		hub_free(*target);

	*target = hub_strdup(data);
	return 1;
}

static int apply_integer(const char* key, const char* data, int* target, int* min, int* max)
{
	char* endptr;
	int val;
	errno = 0;
	val = strtol(data, &endptr, 10);

	if (((errno == ERANGE && (val == INT_MAX || val == INT_MIN)) || (errno != 0 && val == 0)) || endptr == data)
			return 0;

	if (min && val < *min)
		return 0;

	if (max && val > *max)
		return 0;

	*target = val;
	return 1;
}

#include "gen_config.c"

static int config_parse_line(char* line, int line_count, void* ptr_data)
{
	char* pos;
	char* key;
	char* data;
	struct hub_config* config = (struct hub_config*) ptr_data;

	strip_off_ini_line_comments(line, line_count);

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
	data = strip_off_quotes(data);

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


