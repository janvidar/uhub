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

#define ADD_CHAR(X) do { *out = X; out++; token_size++; } while(0)
#define RESET_TOKEN do { ADD_CHAR('\0'); out = buffer; if (add_token(tokens, out)) token_count++; token_size = 0; buffer[0] = '\0'; } while (0)

static int add_token(struct linked_list* list, const char* token)
{
	if (*token)
	{
		list_append(list, hub_strdup(token));
		return 1;
	}
	return 0;
}

struct linked_list* cfg_tokenize(const char* line)
{
	struct linked_list* tokens = list_create();
	char* buffer = hub_malloc_zero(strlen(line));
	char* out = buffer;
	const char* p = line;
	int backslash = 0;
	char quote = 0;
	size_t token_count = 0;
	size_t token_size = 0;

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
					return tokens;
				}
				break;

			case '\"':
				if (backslash)
				{
					ADD_CHAR('\"');
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
	return tokens;
}

void cfg_tokens_free(struct linked_list* list)
{
	list_clear(list, hub_free);
	list_destroy(list);
}

/*
size_t cfg_token_count(const char* line)
{
	if (!line || !*line)
		return 0;


	
}

char* cfg_token_get(const char* line, size_t token)
{
}

char* cfg_token_add(const char* line, char* new_token)
{
}
*/
