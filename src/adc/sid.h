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

#ifndef HAVE_UHUB_SID_H
#define HAVE_UHUB_SID_H

#define SID_MAX 1048576

struct sid_pool;
struct hub_user;

extern char* sid_to_string(sid_t sid_);
extern sid_t string_to_sid(const char* sid);

extern struct sid_pool* sid_pool_create(sid_t max);
extern void sid_pool_destroy(struct sid_pool*);

extern sid_t sid_alloc(struct sid_pool*, struct hub_user*);
extern void sid_free(struct sid_pool*, sid_t);
extern struct hub_user* sid_lookup(struct sid_pool*, sid_t);



#endif /* HAVE_UHUB_SID_H */

