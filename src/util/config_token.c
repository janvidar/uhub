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

#define ADD_CHAR(X) do { *out = X; out++; token_size++; } while(0)
#define RESET_TOKEN do { ADD_CHAR('\0'); out = buffer; if (cfg_token_add(tokens, out)) token_count++; token_size = 0; buffer[0] = '\0'; } while (0)

struct cfg_tokens
{
    struct linked_list* list;
};

struct cfg_tokens* cfg_tokenize(const char* line)
{
	struct cfg_tokens* tokens = (struct cfg_tokens*) hub_malloc_zero(sizeof(struct cfg_tokens));
	char* buffer = (char*) hub_malloc_zero(strlen(line) + 1);
	char* out = buffer;
	const char* p = line;
	int backslash = 0;
	char quote = 0;
	size_t token_count = 0;
	size_t token_size = 0;
	tokens->list = list_create();

	for (; *p; p++)
	{
		switch (*p)
		{
			case '\\':
				if (backslash)
				{
					ADD_CHAR('\\');
					backslash = 0;
				}
				else
				{
					backslash = 1;
				}
				break;

			case '#':
				if (backslash)
				{
					ADD_CHAR('#');
					backslash = 0;
				}
				else if (quote)
				{
					ADD_CHAR('#');
				}
				else
				{
					RESET_TOKEN;
					hub_free(buffer);
					return tokens;
				}
				break;

			case '"':
				if (backslash)
				{
					ADD_CHAR('"');
					backslash = 0;
				}
				else if (quote)
				{
					quote = 0;
				}
				else
				{
					quote = 1;
				}
				break;

			case '\r':
				/* Pretend it does not exist! */
				break;

			case ' ':
			case '\t':
				if (quote)
				{
					ADD_CHAR(*p);
				}
				else if (backslash)
				{
					ADD_CHAR(*p);
					backslash = 0;
				}
				else
				{
					RESET_TOKEN;
				}
				break;

			default:
				ADD_CHAR(*p);
		}
	}

	RESET_TOKEN;
	hub_free(buffer);
	return tokens;
}

void cfg_tokens_free(struct cfg_tokens* tokens)
{
	if (tokens)
	{
		list_clear(tokens->list, hub_free);
		list_destroy(tokens->list);
		hub_free(tokens);
	}
}

int cfg_token_add(struct cfg_tokens* tokens, char* new_token)
{
	if (*new_token)
	{
		list_append(tokens->list, hub_strdup(new_token));
		return 1;
	}
	return 0;
}

size_t cfg_token_count(struct cfg_tokens* tokens)
{
	return list_size(tokens->list);
}

char* cfg_token_get(struct cfg_tokens* tokens, size_t offset)
{
	return list_get_index(tokens->list, offset);
}

char* cfg_token_get_first(struct cfg_tokens* tokens)
{
	return list_get_first(tokens->list);
}

char* cfg_token_get_next(struct cfg_tokens* tokens)
{
	return list_get_next(tokens->list);
}

struct cfg_settings
{
	char* key;
	char* value;
};

struct cfg_settings* cfg_settings_split(const char* line)
{
	struct cfg_settings* s = NULL;
	struct cfg_tokens* tok = NULL;
	char* pos = NULL;

	if (   !line
		|| !*line
		|| ((pos = (char*) strchr(line, '=')) == NULL)
		|| ((s = hub_malloc_zero(sizeof(struct cfg_settings))) == NULL)
		|| ((tok = cfg_tokenize(line)) == NULL)
		|| (cfg_token_count(tok) < 1)
		|| (cfg_token_count(tok) > 3)
		|| (cfg_token_count(tok) == 3 && strcmp(cfg_token_get(tok, 1), "="))
		)
	{
		cfg_tokens_free(tok);
		cfg_settings_free(s);
		return NULL;
	}

	if (cfg_token_count(tok) == 1)
	{
		char* key = cfg_token_get_first(tok);
		pos = strchr(key, '=');
		if (!pos)
		{
			cfg_tokens_free(tok);
			cfg_settings_free(s);
			return NULL;
		}

		pos[0] = 0;
		key = strip_white_space(key);

		if (!*key)
		{
			cfg_tokens_free(tok);
			cfg_settings_free(s);
			return NULL;
		}

		s->key = strdup(key);
		s->value = strdup(strip_white_space(pos+1));
	}
	else if (cfg_token_count(tok) == 2)
	{
		char* key = cfg_token_get_first(tok);
		char* val = cfg_token_get_next(tok);

                if ((pos = strchr(key, '=')))
		{
			pos[0] = 0;
			key = strip_white_space(key);
		}
		else if ((pos = strchr(val, '=')))
		{
			val = strip_white_space(pos+1);
		}
		else
		{
			cfg_tokens_free(tok);
			cfg_settings_free(s);
			return NULL;
		}

		if (!*key)
		{
			cfg_tokens_free(tok);
			cfg_settings_free(s);
			return NULL;
		}

		s->key = strdup(key);
		s->value = strdup(val);
	}
	else
	{
		s->key = strdup(strip_white_space(cfg_token_get(tok, 0)));
		s->value = strdup(strip_white_space(cfg_token_get(tok, 2)));
	}
	cfg_tokens_free(tok);
	return s;
}

const char* cfg_settings_get_key(struct cfg_settings* s)
{
	return s->key;
}

const char* cfg_settings_get_value(struct cfg_settings* s)
{
	return s->value;
}

void cfg_settings_free(struct cfg_settings* s)
{
	if (s)
	{
		hub_free(s->key);
		hub_free(s->value);
		hub_free(s);
	}
}

