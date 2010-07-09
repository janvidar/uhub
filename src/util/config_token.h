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

#ifndef HAVE_UHUB_CONFIG_TOKEN_H
#define HAVE_UHUB_CONFIG_TOKEN_H

struct linked_list;

struct linked_list* cfg_tokenize(const char* line);
void cfg_tokens_free(struct linked_list*);

size_t cfg_token_count(const char* line);
char* cfg_token_get(const char* line, size_t token);
char* cfg_token_add(const char* line, char* new_token);

#endif /* HAVE_UHUB_CONFIG_TOKEN_H */

