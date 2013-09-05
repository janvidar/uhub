/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2013, Jan Vidar Krey
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

#ifndef HAVE_UTIL_CBUFFER_H
#define HAVE_UTIL_CBUFFER_H

struct cbuffer;

extern struct cbuffer* cbuf_create(size_t capacity);
extern struct cbuffer* cbuf_create_const(const char* buffer);
extern void cbuf_destroy(struct cbuffer* buf);
extern void cbuf_resize(struct cbuffer* buf, size_t capacity);
extern void cbuf_append_bytes(struct cbuffer* buf, const char* msg, size_t len);
extern void cbuf_append(struct cbuffer* buf, const char* msg);
extern void cbuf_append_format(struct cbuffer* buf, const char* format, ...);
extern void cbuf_append_strftime(struct cbuffer* buf, const char* format, const struct tm* tm);

extern const char* cbuf_get(struct cbuffer* buf);
extern size_t cbuf_size(struct cbuffer* buf);


#endif /* HAVE_UTIL_CBUFFER_H */
