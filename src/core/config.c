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
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "core/config.h"


#ifndef INT_MAX
#define INT_MAX 0x7fffffff
#endif

#ifndef INT_MIN
#define INT_MIN (-0x7fffffff - 1)
#endif

static int apply_boolean(const char* key, const char* data, int* target)
{
	(void) key;
	return string_to_boolean(data, target);
}

#ifndef WIN32
#include <regex.h>

/*
 * Validate a string config value against a POSIX extended regular expression.
 * The pattern is anchored so the entire value must match, not just a substring.
 * Returns 1 on match, 0 on mismatch (or on an internal pattern-compile error).
 */
static int config_check_regexp(const char* key, const char* data, const char* regexp)
{
	regex_t preg;
	char* pattern;
	size_t pattern_sz = strlen(regexp) + 5; /* "^(" + regexp + ")$" + NUL */
	int rc;

	pattern = hub_malloc(pattern_sz);
	if (!pattern)
	{
		LOG_ERROR("Out of memory validating config key '%s'", key);
		return 0;
	}
	snprintf(pattern, pattern_sz, "^(%s)$", regexp);

	rc = regcomp(&preg, pattern, REG_EXTENDED | REG_NOSUB);
	hub_free(pattern);
	if (rc != 0)
	{
		LOG_ERROR("Internal error: invalid validation pattern for config key '%s'", key);
		return 0;
	}

	rc = regexec(&preg, data, 0, NULL, 0);
	regfree(&preg);

	if (rc != 0)
	{
		LOG_ERROR("Invalid value for configuration key '%s': \"%s\"", key, data);
		return 0;
	}
	return 1;
}
#else
/* POSIX <regex.h> is not available on Windows; skip value validation there. */
static int config_check_regexp(const char* key, const char* data, const char* regexp)
{
	(void) key; (void) data; (void) regexp;
	return 1;
}
#endif

static int apply_string(const char* key, const char* data, char** target, const char* regexp)
{
	if (regexp && *regexp && !config_check_regexp(key, data, regexp))
		return 0;

	if (*target)
		hub_free(*target);

	*target = hub_strdup(data);
	return 1;
}

static int apply_integer(const char* key, const char* data, int* target, int* min, int* max)
{
	(void) key;
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

/*
 * Splits one "key = value" line into its two halves in place.
 *
 * Returns 1 when a key/value pair was extracted, 0 when the line holds nothing
 * to apply (blank, or comment-only), and -1 on a malformed line. A line with no
 * '=' is deliberately ignored rather than rejected -- see the note in
 * config_parse_line().
 */
static int config_split_line(char* line, int line_count, char** key, char** data)
{
	char* pos;
	int quoted_empty;

	strip_off_ini_line_comments(line, line_count);

	if (!*line) return 0;

	LOG_DUMP("config_split_line(): '%s'", line);

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

	*key = strip_white_space(line);
	*data = strip_white_space(&pos[1]);

	/* An explicitly quoted empty value ("") is a value: it sets a string option
	   to the empty string. A key with nothing after the '=' at all is not.
	   Checked before the quotes come off, since afterwards the two look alike.
	   This is what makes the output of "uhub -s" -- which writes every empty
	   string option as key = "" -- parse back in as a configuration file. */
	quoted_empty = !strcmp(*data, "\"\"") || !strcmp(*data, "''");
	*data = strip_off_quotes(*data);

	if (!**key || (!**data && !quoted_empty))
	{
		LOG_FATAL("Configuration parse error on line %d", line_count);
		return -1;
	}

	LOG_DUMP("config_split_line: '%s' => '%s'", *key, *data);
	return 1;
}

static int config_parse_line(char* line, int line_count, void* ptr_data)
{
	char* key;
	char* data;
	struct hub_config* config = (struct hub_config*) ptr_data;
	int ret = config_split_line(line, line_count, &key, &data);

	if (ret <= 0)
		return ret;

	return apply_config(config, key, data, line_count);
}

/*
 * Same shape as config_parse_line(), but backed by apply_message_config(),
 * which knows only the msg_* status strings. Anything else in a messages file
 * is an error -- that file exists to hold messages and nothing else.
 */
static int config_parse_message_line(char* line, int line_count, void* ptr_data)
{
	char* key;
	char* data;
	struct hub_config* config = (struct hub_config*) ptr_data;
	int ret = config_split_line(line, line_count, &key, &data);

	if (ret <= 0)
		return ret;

	return apply_message_config(config, key, data, line_count);
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


int read_messages(const char* file, struct hub_config* config)
{
	/* Applied on top of an already-populated config, so the defaults and
	   anything the main configuration file set are both already in place. */
	int ret = file_read_lines(file, config, &config_parse_message_line);

	if (ret == -2)
	{
		LOG_WARN("Unable to open status message file \"%s\", using the configured messages.", file);
		return 0;
	}

	return (ret < 0) ? -1 : 0;
}
