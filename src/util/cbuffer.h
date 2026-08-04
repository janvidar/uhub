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

#ifndef HAVE_UTIL_CBUFFER_H
#define HAVE_UTIL_CBUFFER_H

#include <stddef.h>
#include <time.h>

struct cbuffer;

extern struct cbuffer* cbuf_create(size_t capacity);
extern struct cbuffer* cbuf_create_const(const char* buffer);
extern void cbuf_destroy(struct cbuffer* buf);
extern void cbuf_resize(struct cbuffer* buf, size_t capacity);
extern void cbuf_append_bytes(struct cbuffer* buf, const char* msg, size_t len);
extern void cbuf_append(struct cbuffer* buf, const char* msg);
extern void cbuf_append_format(struct cbuffer* buf, const char* format, ...);
extern void cbuf_append_strftime(struct cbuffer* buf, const char* format, const struct tm* tm);

/**
 * Append @p text with the CommonMark inline markup characters escaped, for use
 * in a message marked as rich text by the ADC RTF0 extension. Text that a user
 * controls -- nicks, chat messages, plugin supplied strings -- must go through
 * this, or it can alter the formatting and break out of a table cell.
 *
 * Only inline constructs are parsed inside a table cell, so the block level
 * markers ('#', '-', '1.', ...) are left alone; '>' is escaped regardless, as
 * the closing half of an autolink. Note that a markdown backslash escape goes
 * on the wire as "\\", which is exactly what adc_msg_escape() turns the single
 * '\' written here into.
 */
extern void cbuf_append_markdown(struct cbuffer* buf, const char* text);

/**
 * Append @p text as a markdown code span.
 *
 * Only for hub generated tokens -- addresses, counts, version strings. A code
 * span has no escape mechanism, so a backtick in the text would end the span
 * early; anything a user controls must go through cbuf_append_markdown().
 */
extern void cbuf_append_markdown_code(struct cbuffer* buf, const char* text);

extern const char* cbuf_get(struct cbuffer* buf);
extern size_t cbuf_size(struct cbuffer* buf);


#endif /* HAVE_UTIL_CBUFFER_H */
