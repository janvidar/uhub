/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2009, Jan Vidar Krey
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

#ifndef HAVE_UHUB_MISC_H
#define HAVE_UHUB_MISC_H

typedef int (*file_line_handler_t)(char* line, int line_number, void* data);

extern const char* get_timestamp(time_t time);

extern int is_num(char c);
extern int is_space(char c);
extern int is_white_space(char c);
extern int is_valid_utf8(const char* string);
extern int is_printable_utf8(const char* string, size_t length);
extern int is_valid_base32_char(char c);
extern void base32_encode(const unsigned char* buffer, size_t len, char* result);
extern void base32_decode(const char* src, unsigned char* dst, size_t len);
extern char* strip_white_space(char* string);

extern int file_read_lines(const char* file, void* data, file_line_handler_t handler);

extern const char* uhub_itoa(int val);
extern const char* uhub_ulltoa(uint64_t val);

extern int uhub_atoi(const char* value);

#ifdef NEED_ATOLL
extern int atoll(const char* value);
#endif


#ifndef HAVE_STRNDUP
extern char* strndup(const char* string, size_t n);
#endif

#ifndef HAVE_MEMMEM
void* memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
#endif

/**
 * Split the string based on split, and place the different parts into list.
 * @return the number of items in the list after split, or -1 if an error occured.
 */
struct linked_list;
extern int split_string(const char* string, const char* split, struct linked_list* list, int allow_empty);


#endif /* HAVE_UHUB_MISC_H */


