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

static const char* BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int is_space(char c)
{
	if (c == ' ') return 1;
	return 0;
}

int is_white_space(char c)
{
	if (c == ' ' || c == '\t' || c == '\r') return 1;
	return 0;
}

static int is_printable(unsigned char c)
{
	if (c >= 32)
		return 1;

	if (c == '\t' || c == '\r' || c == '\n')
		return 1;
	return 0;
}


char* strip_white_space(char* string)
{
	char* pos;

	if (!string)
		return "";

	while (string[0] && is_white_space(string[0])) string++;

	if (!*string)
		return string;

	/* Strip appending whitespace */
	pos = &string[strlen(string)-1];
	while (&string[0] < &pos[0] && is_white_space(pos[0])) { pos[0] = 0; pos--; }

	return string;
}

static int is_valid_utf8_str(const char* string, size_t length)
{
	int expect = 0;
	char div = 0;
	size_t pos = 0;

	if (length == 0) return 1;

	for (pos = 0; pos < length; pos++)
	{
		if (expect)
		{
			if ((string[pos] & 0xC0) == 0x80) expect--;
			else return 0;
		}
		else
		{
			if (string[pos] & 0x80)
			{
				for (div = 0x40; div > 0x10; div /= 2)
				{
					if (string[pos] & div) expect++;
					else break;
				}
				if ((string[pos] & div) || (pos+expect >= length)) return 0;
			}
		}
	}
	return 1;
}

int is_valid_utf8(const char* string)
{
	return is_valid_utf8_str(string, strlen(string));
}

int is_printable_utf8(const char* string, size_t length)
{
	size_t pos = 0;
	for (pos = 0; pos < length; pos++)
	{
		if (!is_printable(string[pos]))
			return 0;
	}
	return is_valid_utf8_str(string, length);
}

int is_valid_base32_char(char c)
{
	if ((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) return 1;
	return 0;
}


int is_num(char c)
{
	if (c >= '0' && c <= '9') return 1;
	return 0;
}


void base32_encode(const unsigned char* buffer, size_t len, char* result) {
	unsigned char word = 0;
	size_t n = 0;
	size_t i = 0;
	size_t index = 0;
	for (; i < len;) {
		if (index > 3) {
			word = (buffer[i] & (0xFF >> index));
			index = (index + 5) % 8;
			word <<= index;
			if (i < len - 1)
				word |= buffer[i + 1] >> (8 - index);
			i++;
		} else {
			word = (buffer[i] >> (8 - (index + 5))) & 0x1F;
			index = (index + 5) % 8;
			if (index == 0) i++;
		}
		result[n++] = BASE32_ALPHABET[word];
	}
	result[n] = '\0';
}

void base32_decode(const char* src, unsigned char* dst, size_t len) {
	size_t index = 0;
	size_t offset = 0;
	size_t i = 0;
	memset(dst, 0, len);
	for (i = 0; src[i]; i++) {
		unsigned char n = 0;
		for (; n < 32; n++) if (src[i] == BASE32_ALPHABET[n]) break;
		if (n == 32) continue;
		if (index <= 3) {
			index = (index + 5) % 8;
			if (index == 0) {
				dst[offset++] |= n;
				if (offset == len) break;
			} else {
				dst[offset] |= n << (8 - index);
			}
		} else {
			index = (index + 5) % 8;
			dst[offset++] |= (n >> index);
			if (offset == len) break;
			dst[offset] |= n << (8 - index);
		}
	}
}

int string_split(const char* string, const char* split, void* data, string_split_handler_t handler)
{
	char* buf = strdup(string);
	char* start;
	char* pos;
	int count = 0;

	start = buf;
	while ((pos = strstr(start, split)))
	{
		pos[0] = '\0';
		start = strip_white_space(start);
		if (*start)
		{
			if (handler(start, count, data) < 0)
			{
				hub_free(buf);
				return -1;
			}
		}
		start = &pos[1];
		count++;
	}

	start = strip_white_space(start);
	if (*start)
	{
		if (handler(start, count, data) < 0)
		{
			hub_free(buf);
			return -1;
		}
	}
	hub_free(buf);
	return count+1;
}

struct file_read_line_data
{
	file_line_handler_t handler;
	void* data;
};

static int file_read_line_handler(char* line, int count, void* ptr)
{
	struct file_read_line_data* data = (struct file_read_line_data*) ptr;

	LOG_DUMP("Line: %s", line);
	if (data->handler(line, count+1, data->data) < 0)
		return -1;
	return 0;
}

int file_read_lines(const char* file, void* data, file_line_handler_t handler)
{
	int fd;
	ssize_t ret;
	char buf[MAX_RECV_BUF];
	struct file_read_line_data split_data;

	memset(buf, 0, MAX_RECV_BUF);

	LOG_TRACE("Opening file %s for line reading.", file);

	fd = open(file, 0);
	if (fd == -1)
	{
		LOG_ERROR("Unable to open file %s: %s", file, strerror(errno));
		return -2;
	}

	ret = read(fd, buf, MAX_RECV_BUF-1);
	close(fd);

	if (ret < 0)
	{
		LOG_ERROR("Unable to read from file %s: %s", file, strerror(errno));
		return -1;
	}
	else  if (ret == 0)
	{
		LOG_WARN("File is empty.");
		return 0;
	}

	buf[ret] = 0;

	/* Parse configuration */
	split_data.handler = handler;
	split_data.data = data;

	return string_split(buf, "\n", &split_data, file_read_line_handler);
}


int uhub_atoi(const char* value) {
	int len = strlen(value);
	int offset = 0;
	int val = 0;
	int i = 0;
	for (; i < len; i++)
		if (value[i] > '9' || value[i] < '0')
			offset++;

	for (i = offset; i< len; i++)
		val = val*10 + (value[i] - '0');

	return value[0] == '-' ? -val : val;
}

int is_number(const char* value, int* num)
{
	int len = strlen(value);
	int offset = (value[0] == '-') ? 1 : 0;
	int val = 0;
	int i = offset;

	if (!*(value + offset))
		return 0;

	for (; i < len; i++)
		if (value[i] > '9' || value[i] < '0')
			return 0;

	for (i = offset; i< len; i++)
		val = val*10 + (value[i] - '0');
	*num = value[0] == '-' ? -val : val;

	return 1;
}


const char* format_size(size_t bytes, char* buf, size_t bufsize)
{
	static const char* quant[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" };
	size_t b = bytes;
	size_t factor = 0;
	size_t divisor = 1;
	while (b > 1024)
	{
		factor++;
		b = (b >> 10);
		divisor = (divisor << 10);
	}
	uhub_assert(factor < (sizeof(quant) / sizeof(const char*)));
	if (factor >= 2)
		snprintf(buf, bufsize, "%.1f %s", (double) bytes / (double) divisor, quant[factor]);
	else
		snprintf(buf, bufsize, PRINTF_SIZE_T " %s", bytes / divisor, quant[factor]);
	return buf;
}


const char* uhub_itoa(int val)
{
	static char buf[22];

	return snprintf(buf, sizeof(buf), "%d", val) < 0 ? NULL : buf;
}


const char* uhub_ulltoa(uint64_t val)
{
	static char buf[22];

	return snprintf(buf, sizeof(buf), PRINTF_UINT64_T, val) < 0 ? NULL : buf;
}



#ifndef HAVE_STRNDUP
char* strndup(const char* string, size_t n)
{
	size_t max = MIN(strlen(string), n);
	char* tmp = hub_malloc(max+1);
	memcpy(tmp, string, max);
	tmp[max] = 0;
	return tmp;
}
#endif

#ifndef HAVE_MEMMEM
void* memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
	char* c_buf = (char*) haystack;
	char* c_pat = (char*) needle;
	char* ptr = memchr(c_buf, c_pat[0], haystacklen);

	while (ptr && ((size_t) (&ptr[0] - &c_buf[0]) < haystacklen))
	{
		if (!memcmp(ptr, c_pat, needlelen))
			return ptr;
		ptr = memchr(&ptr[1], c_pat[0], &c_buf[haystacklen] - &ptr[0]);
	}
	return 0;
}
#endif

int split_string(const char* string, const char* split, struct linked_list* list, int allow_empty)
{
	char* tmp1, *tmp2;
	int n = 0;

	if (!string || !*string || !split || !*split || !list)
		return -1;

	for (;;)
	{
		tmp1 = strstr(string, split);

		if (tmp1) tmp2 = hub_strndup(string, tmp1 - string);
		else      tmp2 = hub_strdup(string);

		if (!tmp2)
		{
			list_clear(list, &hub_free);
			return -1;
		}

		if (*tmp2 || allow_empty)
		{
			/* store in list */
			list_append(list, tmp2);
			n++;
		}
		else
		{
			/* ignore element */
			hub_free(tmp2);
		}

		if (!tmp1) break; /* last element found */

		string = tmp1;
		string += strlen(split);
	}

	return n;
}

const char* get_timestamp(time_t now)
{
	static char ts[32] = {0, };
	struct tm* t  = localtime(&now);
	snprintf(ts, sizeof(ts), "[%02d:%02d]", t->tm_hour, t->tm_min);
	return ts;
}

void strip_off_ini_line_comments(char* line, int line_count)
{
	char* p = line;
	char* out = line;
	int backslash = 0;

	if (!*line)
		return;

	for (; *p; p++)
	{
		if (!backslash)
		{
			if (*p == '\\')
			{
				backslash = 1;
			}
			else if (*p == '#')
			{
				*out = '\0';
				out++;
				break;
			}
			else
			{
				*out = *p;
				out++;
			}
		}
		else
		{
			if (*p == '\\' || *p == '#' || *p == '\"')
			{
				*out = *p;
				out++;
			}
			else
			{
				LOG_WARN("Invalid backslash escape on line %d", line_count);
				*out = *p;
				out++;
			}
			backslash = 0;
		}
	}
	*out = '\0';
}

int string_to_boolean(const char* str, int* boolean)
{
	if (!str || !*str || !boolean)
		return 0;

	switch (strlen(str))
	{
		case 1:
			if      (str[0] == '1') { *boolean = 1; return 1; }
			else if (str[0] == '0') { *boolean = 0; return 1; }
			return 0;

		case 2:
			if (!strcasecmp(str, "on")) { *boolean = 1; return 1; }
			if (!strcasecmp(str, "no")) { *boolean = 0; return 1; }
			return 0;

		case 3:
			if (!strcasecmp(str, "yes")) { *boolean = 1; return 1; }
			if (!strcasecmp(str, "off")) { *boolean = 0; return 1; }
			return 0;

		case 4:
			if (!strcasecmp(str, "true")) { *boolean = 1; return 1; }
			return 0;

		case 5:
			if (!strcasecmp(str, "false")) { *boolean = 0; return 1; }
			return 0;

		default:
			return 0;
	}
}

char* strip_off_quotes(char* line)
{
	size_t len;

	if (!*line)
		return line;

	len = strlen(line);
	if (len < 2)
		return line;

	if ((line[0] == '"' && line[len - 1] == '"') ||
	    (line[0] == '\'' && line[len - 1] == '\''))
	{
		line[len-1] = '\0';
		return line + 1;
	}
	return line;
}

