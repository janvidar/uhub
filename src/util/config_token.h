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

#ifndef HAVE_UHUB_CONFIG_TOKEN_H
#define HAVE_UHUB_CONFIG_TOKEN_H

struct cfg_tokens;

struct cfg_tokens* cfg_tokenize(const char* line);
void cfg_tokens_free(struct cfg_tokens*);

int cfg_token_add(struct cfg_tokens*, char* new_token);

size_t cfg_token_count(struct cfg_tokens*);

char* cfg_token_get(struct cfg_tokens*, size_t offset);
char* cfg_token_get_first(struct cfg_tokens*);
char* cfg_token_get_next(struct cfg_tokens*);


struct cfg_settings;
struct cfg_settings* cfg_settings_split(const char* line);
const char* cfg_settings_get_key(struct cfg_settings*);
const char* cfg_settings_get_value(struct cfg_settings*);
void cfg_settings_free(struct cfg_settings*);

#endif /* HAVE_UHUB_CONFIG_TOKEN_H */

