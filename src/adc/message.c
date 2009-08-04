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

#include "uhub.h"

#ifdef DEBUG
#define ADC_MSG_ASSERT(X) \
	uhub_assert(X); \
	uhub_assert(X->cache); \
	uhub_assert(X->capacity); \
	uhub_assert(X->length); \
	uhub_assert(X->length <= X->capacity); \
	uhub_assert(X->length == strlen(X->cache)); \
	uhub_assert(X->references >= 0);
#else
#define ADC_MSG_ASSERT(X) do { } while(0)
#endif /* DEBUG */

#ifdef MSG_MEMORY_DEBUG
#undef msg_malloc
#undef msg_malloc_zero
#undef msg_free

static void* msg_malloc(size_t size)
{
	void* ptr = valloc(size);
	LOG_MEMORY("msg_malloc: %p %d", ptr, (int) size);
	return ptr;
}

static void* msg_malloc_zero(size_t size)
{
	void* ptr = msg_malloc(size);
	memset(ptr, 0, size);
	return ptr;
}

static void msg_free(void* ptr)
{
	LOG_MEMORY("msg_free:   %p", ptr);
	// hub_free(ptr);
}

#include <sys/mman.h>
static void adc_msg_protect(struct adc_message* cmd)
{
	LOG_MEMORY("msg_prot:   %p %d", cmd, cmd->capacity);
	mprotect(cmd,        sizeof(cmd),           PROT_READ);
	mprotect(cmd->cache, sizeof(cmd->capacity), PROT_READ);
}

static void adc_msg_unprotect(struct adc_message* cmd)
{
	LOG_MEMORY("msg_unprot: %p %d", cmd, cmd->capacity);
	mprotect(cmd,        sizeof(cmd),           PROT_READ | PROT_WRITE);
	mprotect(cmd->cache, sizeof(cmd->capacity), PROT_READ | PROT_WRITE);
}

#else

#define msg_malloc(X)       hub_malloc(X)
#define msg_malloc_zero(X)  hub_malloc_zero(X)
#define msg_free(X)         hub_free(X)

#endif /* MSG_MEMORY_DEBUG */


struct adc_message* adc_msg_incref(struct adc_message* msg)
{
	if (!msg) return 0;
#ifndef ADC_MESSAGE_INCREF
#ifdef MSG_MEMORY_DEBUG
	adc_msg_unprotect(msg);
#endif
	msg->references++;
#ifdef MSG_MEMORY_DEBUG
	adc_msg_protect(msg);
#endif
	return msg;
#else
	struct adc_message* copy = adc_msg_copy(msg);
	return copy;
#endif
}

static void adc_msg_set_length(struct adc_message* msg, size_t len)
{
	msg->length = len;
}

static int adc_msg_grow(struct adc_message* msg, size_t size)
{
	char* buf;
	size_t newsize = 0;

	if (msg->capacity > size)
		return 1;
	
	/* Make sure we align our data */
	newsize = size;
	newsize += 2; /* termination */
	newsize += (newsize % sizeof(size_t)); /* alignment padding */
	
	buf = msg_malloc_zero(newsize);
	if (!buf)
		return 0;

	if (msg->cache)
	{
		memcpy(buf, msg->cache, msg->length);
		msg_free(msg->cache);
	}
	
	msg->cache = buf;
	msg->capacity = newsize;

	return 1;
}

/* NOTE: msg must be unterminated here */
static int adc_msg_cache_append(struct adc_message* msg, const char* string, size_t len)
{
	if (!adc_msg_grow(msg, msg->length + len))
	{
		/* FIXME: OOM! */
		return 0;
	}

	memcpy(&msg->cache[msg->length], string, len);
	adc_msg_set_length(msg, msg->length + len);
	
	assert(msg->capacity > msg->length);
	msg->cache[msg->length] = 0;
	return 1;
}

/**
 * Returns position of the first argument of the message.
 * Excludes mandatory arguments for the given type of message
 * like source and target.
 */
int adc_msg_get_arg_offset(struct adc_message* msg)
{
	if (!msg || !msg->cache)
		return -1;
	
	switch (msg->cache[0])
	{
		/* These *SHOULD* never be seen on a hub */
		case 'U':
		case 'C':
			return 4; /* Actually: 4 + strlen(cid). */
		
		case 'I':
		case 'H':
			return 4;
			
		case 'B':
			return  9;
			
		case 'F':
			return (10 + (list_size(msg->feature_cast_include)*5) + (list_size(msg->feature_cast_exclude)*5));
			
		case 'D':
		case 'E':
			return 14;
	}
	return -1;
}


int adc_msg_is_empty(struct adc_message* msg)
{
	int offset = adc_msg_get_arg_offset(msg);

	if (offset == -1)
		return -1;
	
	if ((msg->length - 1) == (size_t) offset)
		return 1;
		
	return 0;
}


void adc_msg_free(struct adc_message* msg)
{
	if (!msg) return;
	
	ADC_MSG_ASSERT(msg);

	if (msg->references > 0)
	{
#ifdef MSG_MEMORY_DEBUG
		adc_msg_unprotect(msg);
#endif
		msg->references--;
#ifdef MSG_MEMORY_DEBUG
		adc_msg_protect(msg);
#endif
	}
	else
	{
#ifdef MSG_MEMORY_DEBUG
		adc_msg_unprotect(msg);
#endif
		msg_free(msg->cache);
		
		if (msg->feature_cast_include)
		{
			list_clear(msg->feature_cast_include, &hub_free);
			list_destroy(msg->feature_cast_include);
			msg->feature_cast_include = 0;
		}
		
		if (msg->feature_cast_exclude)
		{
			list_clear(msg->feature_cast_exclude, &hub_free);
			list_destroy(msg->feature_cast_exclude);
			msg->feature_cast_exclude = 0;
		}
		
		msg_free(msg);
	}
}


struct adc_message* adc_msg_copy(const struct adc_message* cmd)
{
	char* tmp = 0;
	struct adc_message* copy = (struct adc_message*) msg_malloc_zero(sizeof(struct adc_message));
	if (!copy) return NULL; /* OOM */

	ADC_MSG_ASSERT(cmd);

	/* deep copy */
	copy->cmd                  = cmd->cmd;
	copy->source               = cmd->source;
	copy->target               = cmd->target;
	copy->cache                = 0;
	copy->length               = cmd->length;
	copy->capacity             = 0;
	copy->priority             = cmd->priority;
	copy->references           = 0;
	copy->feature_cast_include = 0;
	copy->feature_cast_exclude = 0;

	if (cmd->cache)
	{
		if (!adc_msg_grow(copy, copy->length))
		{
			adc_msg_free(copy);
			return NULL; /* OOM */
		}
		memcpy(copy->cache, cmd->cache, cmd->length);
		copy->cache[copy->length] = 0;
	}

	if (cmd->feature_cast_include)
	{
		copy->feature_cast_include = list_create();
		tmp = list_get_first(cmd->feature_cast_include);
		while (tmp)
		{
			list_append(copy->feature_cast_include, hub_strdup(tmp));
			tmp = list_get_next(cmd->feature_cast_include);
		}
	}

	if (cmd->feature_cast_exclude)
	{
		copy->feature_cast_exclude = list_create();
		tmp = list_get_first(cmd->feature_cast_exclude);
		while (tmp)
		{
			list_append(copy->feature_cast_exclude, hub_strdup(tmp));
			tmp = list_get_next(cmd->feature_cast_exclude);
		}
	}

	ADC_MSG_ASSERT(copy);

#ifdef MSG_MEMORY_DEBUG
	adc_msg_protect(copy);
#endif
	return copy;
}


struct adc_message* adc_msg_parse_verify(struct hub_user* u, const char* line, size_t length)
{
	struct adc_message* command = adc_msg_parse(line, length);
	
	if (!command)
		return 0;
	
	if (command->source && (!u || command->source != u->id.sid))
	{
		LOG_DEBUG("Command does not match user's SID (command->source=%d, user->id.sid=%d)", command->source, (u ? u->id.sid : 0));
		adc_msg_free(command);
		return 0;
	}
	
	return command;
}


struct adc_message* adc_msg_parse(const char* line, size_t length)
{
	struct adc_message* command = (struct adc_message*) msg_malloc_zero(sizeof(struct adc_message));
	char prefix = line[0];
	size_t n = 0;
	char temp_sid[5];
	int ok = 1;
	int need_terminate = 0;
	struct linked_list* feature_cast_list;
	
	if (command == NULL)
		return NULL; /* OOM */
		
	if (!is_printable_utf8(line, length))
	{
		LOG_DEBUG("Dropped message with non-printable UTF-8 characters.");
		msg_free(command);
		return NULL;
	}

	if (line[length-1] != '\n')
	{
		need_terminate = 1;
	}

	if (!adc_msg_grow(command, length + need_terminate))
	{
		msg_free(command);
		return NULL; /* OOM */
	}
	
	adc_msg_set_length(command, length + need_terminate);
	memcpy(command->cache, line, length);
	
	/* Ensure we are zero terminated */
	command->cache[length] = 0;
	command->cache[length+need_terminate] = 0;
	
	command->cmd = FOURCC(line[0], line[1], line[2], line[3]);
	command->priority = 0;
	
	switch (prefix)
	{
		case 'U':
		case 'C':
			/* these should never be seen on a hub */
			ok = 0;
			break;
			
		case 'I':
		case 'H':
			ok = (length > 3);
			break;
			
		case 'B':
			ok = (length > 8 &&
					is_space(line[4]) &&
					is_valid_base32_char(line[5]) &&
					is_valid_base32_char(line[6]) &&
					is_valid_base32_char(line[7]) &&
					is_valid_base32_char(line[8]));
			
			if (!ok) break;
			
			temp_sid[0] = line[5];
			temp_sid[1] = line[6];
			temp_sid[2] = line[7];
			temp_sid[3] = line[8];
			temp_sid[4] = '\0';
			
			command->source = string_to_sid(temp_sid);
			break;
			
		case 'F':
			ok = (length > 8 &&
					is_space(line[4]) &&
					is_valid_base32_char(line[5]) &&
					is_valid_base32_char(line[6]) &&
					is_valid_base32_char(line[7]) &&
					is_valid_base32_char(line[8]));
			
			if (!ok) break;
			
			temp_sid[0] = line[5];
			temp_sid[1] = line[6];
			temp_sid[2] = line[7];
			temp_sid[3] = line[8];
			temp_sid[4] = '\0';
			
			command->source = string_to_sid(temp_sid);
			
			/* Create feature cast lists */
			command->feature_cast_include = list_create();
			command->feature_cast_exclude = list_create();
			
			if (!command->feature_cast_include || !command->feature_cast_exclude)
			{
				list_destroy(command->feature_cast_include);
				list_destroy(command->feature_cast_exclude);
				msg_free(command->cache);
				msg_free(command);
				return NULL; /* OOM */
			}
			
			n = 10;
			while (line[n] == '+' || line[n] == '-')
			{
				if (line[n++] == '+')
					feature_cast_list = command->feature_cast_include;
				else
					feature_cast_list = command->feature_cast_exclude;
				
				temp_sid[0] = line[n++];
				temp_sid[1] = line[n++];
				temp_sid[2] = line[n++];
				temp_sid[3] = line[n++];
				temp_sid[4] = '\0';
				
				list_append(feature_cast_list, hub_strdup(temp_sid));
			}
			
			if  (n == 10)
				ok = 0;
			
			break;
			
		case 'D':
		case 'E':
			ok = (length > 13 &&
					is_space(line[4]) &&
					is_valid_base32_char(line[5]) &&
					is_valid_base32_char(line[6]) &&
					is_valid_base32_char(line[7]) &&
					is_valid_base32_char(line[8]) &&
					is_space(line[9]) &&
					is_valid_base32_char(line[10]) &&
					is_valid_base32_char(line[11]) &&
					is_valid_base32_char(line[12]) &&
					is_valid_base32_char(line[13]));
			
			if (!ok) break;
			
			temp_sid[0] = line[5];
			temp_sid[1] = line[6];
			temp_sid[2] = line[7];
			temp_sid[3] = line[8];
			temp_sid[4] = '\0';
			
			command->source = string_to_sid(temp_sid);
			
			temp_sid[0] = line[10];
			temp_sid[1] = line[11];
			temp_sid[2] = line[12];
			temp_sid[3] = line[13];
			temp_sid[4] = '\0';
			
			command->target = string_to_sid(temp_sid);
			break;
			
		default:
			ok = 0;
	}
	
	if (need_terminate)
	{
		command->cache[length] = '\n';
	}
	
	if (!ok)
	{
		adc_msg_free(command);
		return NULL;
	}
	
	/* At this point the arg_offset should point to a space, or the end of message */
	n = adc_msg_get_arg_offset(command);
	if (command->cache[n] == ' ')
	{
		if (command->cache[n+1] == ' ') ok = 0;
	}
	else if (command->cache[n] == '\n') ok = 1;
	else ok = 0;
	
	if (!ok)
	{
		adc_msg_free(command);
		return NULL;
	}
	
	ADC_MSG_ASSERT(command);

#ifdef MSG_MEMORY_DEBUG
	adc_msg_protect(command);
#endif
	return command;
}


struct adc_message* adc_msg_create(const char* line)
{
	return adc_msg_parse_verify(NULL, line, strlen(line));
}


struct adc_message* adc_msg_construct(fourcc_t fourcc, size_t size)
{
	struct adc_message* msg = (struct adc_message*) msg_malloc_zero(sizeof(struct adc_message));
	
	if (!msg)
		return NULL; /* OOM */

	if (size < sizeof(fourcc)) size = sizeof(fourcc);

	if (!adc_msg_grow(msg, size+1))
	{
		msg_free(msg);
		return NULL; /* OOM */
	}
	
	if (fourcc)
	{
		msg->cache[0] = (char) ((fourcc >> 24) & 0xff);
		msg->cache[1] = (char) ((fourcc >> 16) & 0xff);
		msg->cache[2] = (char) ((fourcc >>  8) & 0xff);
		msg->cache[3] = (char) ((fourcc      ) & 0xff);
		msg->cache[4] = '\n';
		
		/* Ensure we are zero terminated */
		adc_msg_set_length(msg, 5);
		msg->cache[msg->length] = 0;
	}
	
	msg->cmd = fourcc;
	msg->priority = 0;

#ifdef MSG_MEMORY_DEBUG
	adc_msg_protect(msg);
#endif

	return msg;
}


int adc_msg_remove_named_argument(struct adc_message* cmd, const char prefix_[2])
{
	char* start;
	char* end;
	char* endInfo;
	size_t endlen;
	char prefix[4] = { ' ', prefix_[0], prefix_[1], '\0' };
	int found = 0;
	int arg_offset = adc_msg_get_arg_offset(cmd);
	size_t temp_len = 0;
	
	adc_msg_unterminate(cmd);
	
	start = memmem(&cmd->cache[arg_offset], (cmd->length - arg_offset), prefix, 3);
	while (start)
	{
		endInfo = &cmd->cache[cmd->length];
	
		if  (&start[0] < &endInfo[0])
		{
			end = memchr(&start[1], ' ', &endInfo[0]-&start[1]);
		}
		else
		{
			end = NULL;
		}
		
		if (end)
		{
			
			temp_len = &end[0] - &start[0]; // strlen(start);
			endlen = strlen(end);
			
			memmove(start, end, endlen);
			start[endlen] = '\0';
			found++;
			adc_msg_set_length(cmd, cmd->length - temp_len);
		}
		else
		{
			found++;
			adc_msg_set_length(cmd, cmd->length - strlen(start));
			start[0] = '\0';
			break;
		}
		start = memmem(&cmd->cache[arg_offset], (cmd->length - arg_offset), prefix, 3);
	}
	
	adc_msg_terminate(cmd);
	
	return found;
}


int adc_msg_has_named_argument(struct adc_message* cmd, const char prefix_[2])
{
	int count = 0;
	char* start;
	char prefix[4] = { ' ', prefix_[0], prefix_[1], '\0' };
	int arg_offset = adc_msg_get_arg_offset(cmd);

	ADC_MSG_ASSERT(cmd);
	
	start = memmem(&cmd->cache[arg_offset], (cmd->length - arg_offset), prefix, 3);
	while (start)
	{
		count++;
		if ((&start[0] - &cmd->cache[0]) < 1+cmd->length)
			start = memmem(&start[1], (&cmd->cache[cmd->length] - &start[0]), prefix, 3);
		else
			start = NULL;
	}
	
	return count;
}


char* adc_msg_get_named_argument(struct adc_message* cmd, const char prefix_[2])
{
	char* start;
	char* end;
	char* argument;
	size_t length;
	char prefix[4] = { ' ', prefix_[0], prefix_[1], '\0' };
	int arg_offset = adc_msg_get_arg_offset(cmd);
	
	ADC_MSG_ASSERT(cmd);
	
	start = memmem(&cmd->cache[arg_offset], cmd->length - arg_offset, prefix, 3);
	if (!start)
		return NULL;
	
	start = &start[3];
	end = strchr(start, ' ');
	if (!end) end = &cmd->cache[cmd->length];
	length = &end[0] - &start[0];
	
	argument = hub_strndup(start, length);
	
	if (length > 0 && argument[length-1] == '\n')
	{
		argument[length-1] = 0;
	}
	
	return argument;
}


int adc_msg_replace_named_argument(struct adc_message* cmd, const char prefix[2], const char* string)
{
	ADC_MSG_ASSERT(cmd);

	while (adc_msg_has_named_argument(cmd, prefix))
	{
		adc_msg_remove_named_argument(cmd, prefix);
	}

	if (adc_msg_add_named_argument(cmd, prefix, string) == -1)
	{
		return -1;
	}
	
	ADC_MSG_ASSERT(cmd);
	
	return 0;
}


void adc_msg_terminate(struct adc_message* cmd)
{
	if (cmd->cache[cmd->length - 1] != '\n')
	{
		adc_msg_cache_append(cmd, "\n", 1);
	}
	ADC_MSG_ASSERT(cmd);

#ifdef MSG_MEMORY_DEBUG
	adc_msg_protect(cmd);
#endif
}

/* FIXME: this looks bogus */
void adc_msg_unterminate(struct adc_message* cmd)
{
	ADC_MSG_ASSERT(cmd);

#ifdef MSG_MEMORY_DEBUG
	adc_msg_unprotect(cmd);
#endif
	
	if (cmd->length > 0 && cmd->cache[cmd->length-1] == '\n')
	{
		cmd->length--;
		cmd->cache[cmd->length] = 0;
	}
}

int adc_msg_add_named_argument(struct adc_message* cmd, const char prefix[2], const char* string)
{
	int ret = 0;
	if (!string)
		return -1;
	
	ADC_MSG_ASSERT(cmd);
	
	adc_msg_unterminate(cmd);
	adc_msg_cache_append(cmd, " ", 1);
	adc_msg_cache_append(cmd, prefix, 2);
	adc_msg_cache_append(cmd, string, strlen(string));
	adc_msg_terminate(cmd);
	return ret;
}


int adc_msg_add_argument(struct adc_message* cmd, const char* string)
{
	ADC_MSG_ASSERT(cmd);
	
	adc_msg_unterminate(cmd);
	adc_msg_cache_append(cmd, " ", 1);
	adc_msg_cache_append(cmd, string, strlen(string));
	adc_msg_terminate(cmd);
	return 0;
}


char* adc_msg_get_argument(struct adc_message* cmd, int offset)
{
	char* start;
	char* end;
	char* argument;
	int count = 0;
	
	ADC_MSG_ASSERT(cmd);
	
	adc_msg_unterminate(cmd);
	
	start = strchr(&cmd->cache[adc_msg_get_arg_offset(cmd)-1], ' ');
	while (start)
	{
		end = strchr(&start[1], ' ');
		
		if (count == offset)
		{
			if (end)
			{
				argument = hub_strndup(&start[1], (&end[0] - &start[1]));
			}
			else
			{
				argument = hub_strdup(&start[1]);
				if (argument[strlen(argument)-1] == '\n')
					argument[strlen(argument)-1] = 0;
			}
			
			if (*argument)
			{
				adc_msg_terminate(cmd);
				return argument;
			}
		}
		
		count++;
		start = end;
	}
	
	adc_msg_terminate(cmd);
	return 0;
}

/**
 * NOTE: Untested code.
 */
int adc_msg_get_argument_index(struct adc_message* cmd, const char prefix[2])
{
	char* start;
	char* end;
	int count = 0;
	
	ADC_MSG_ASSERT(cmd);
	
	adc_msg_unterminate(cmd);
	
	start = strchr(&cmd->cache[adc_msg_get_arg_offset(cmd)-1], ' ');
	while (start)
	{
		end = strchr(&start[1], ' ');
		if (((&end[0] - &start[1]) > 2) && ((start[1] == prefix[0]) && (start[2] == prefix[1])))
		{
			adc_msg_terminate(cmd);
			return count;
		}
		count++;
		start = end;
	}
	adc_msg_terminate(cmd);
	return -1;
}



int adc_msg_escape_length(const char* str)
{
	int add = 0;
	int n = 0;
	for (; str[n]; n++)
		if (str[n] == ' ' || str[n] == '\n' || str[n] == '\\') add++;
	return n + add;
}


int adc_msg_unescape_length(const char* str)
{
	int add = 0;
	int n = 0;
	int escape = 0;
	for (; str[n]; n++)
	{
		if (escape)
		{
			escape = 0;
		}
		else
		{
			if (str[n] == '\\')
			{
				escape = 1;
				add++;
			}
		}
	}
	return n - add;
}





char* adc_msg_unescape(const char* string)
{
	char* new_string = msg_malloc(adc_msg_unescape_length(string)+1);
	char* ptr = (char*) new_string;
	char* str = (char*) string;
	int escaped = 0;
	
	while (*str)
	{
		if (escaped) {
			if (*str == 's')
				*ptr++ = ' ';
			else if (*str == '\\')
				*ptr++ = '\\';
			else if (*str == 'n')
				*ptr++ = '\n';
			else
				*ptr++ = *str;
			
			escaped = 0;
		} else {
			if (*str == '\\')
				escaped = 1;
			else
				*ptr++ = *str;
				
		}
		str++;
	}
	*ptr = 0;
	return new_string;
}


char* adc_msg_escape(const char* string)
{
	char* str = hub_malloc(adc_msg_escape_length(string)+1);
	int n = 0;
	int i = 0;
	for (i = 0; i < strlen(string); i++)
	{
		switch (string[i]) {
			case '\\': /* fall through */
					str[n++] = '\\';
					str[n++] = '\\';
					break;
			case '\n':
					str[n++] = '\\';
					str[n++] = 'n';
					break;
			case ' ':
					str[n++] = '\\';
					str[n++] = 's';
					break;
			default:
					str[n++] = string[i];
					break;
		}
	}
	str[n] = '\0';
	return str;
}

