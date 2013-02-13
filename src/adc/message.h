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

#ifndef HAVE_UHUB_COMMAND_H
#define HAVE_UHUB_COMMAND_H

struct hub_user;

struct adc_message
{
	fourcc_t cmd;
	sid_t source;
	sid_t target;
	char* cache;
	size_t length;
	size_t capacity;
	size_t priority;
	size_t references;
	struct linked_list*  feature_cast_include;
	struct linked_list*  feature_cast_exclude;
};

enum msg_status_level
{
	status_level_info  = 0, /* Success/informative status message */
	status_level_error = 1, /* Recoverable error */
	status_level_fatal = 2, /* Fatal error (disconnect) */
};

/**
 * Increase the reference counter for an ADC message struct.
 * NOTE: Always use the returned value, and not the passed value, as
 * it ensures we can actually copy the value if needed.
 */
extern struct adc_message* adc_msg_incref(struct adc_message* msg);

/**
 * Decrease the reference counter, and free the memory when apropriate.
 */
extern void adc_msg_free(struct adc_message* msg);

/**
 * Perform deep copy a command.
 * NOTE: 'references' will be zero for the copied command.
 * @return a copy of cmd or NULL if not able to allocate memory.
 */
extern struct adc_message* adc_msg_copy(const struct adc_message* cmd);

/**
 * This will parse 'string' and return it as a adc_message struct, or
 * NULL if not able to allocate memory or 'string' does not contain
 * a valid ADC command.
 *
 * The message is only considered valid if the user who sent it
 * is the rightful origin of the message.
 */
extern struct adc_message* adc_msg_parse_verify(struct hub_user* u, const char* string, size_t length);

/**
 * This will parse 'string' and return it as a adc_message struct, or
 * NULL if not able to allocate memory or 'string' does not contain
 * a valid ADC command.
 */
extern struct adc_message* adc_msg_parse(const char* string, size_t length);

/**
 * This will construct a adc_message based on 'string'.
 * Only to be used for server generated commands.
 */
extern struct adc_message* adc_msg_create(const char* string);

/**
 * Construct a message with the given 'fourcc' and allocate
 * 'size' bytes for later use.
 */
extern struct adc_message* adc_msg_construct(fourcc_t fourcc, size_t size);

/**
 * Construct a message for the given 'fourcc' and add a source SID to it,
 * in addition pre-allocate 'size' bytes at the end of the message.
 */
extern struct adc_message* adc_msg_construct_source(fourcc_t fourcc, sid_t source, size_t size);
extern struct adc_message* adc_msg_construct_source_dest(fourcc_t fourcc, sid_t source, sid_t dest, size_t size);

/**
 * Remove a named argument from the command.
 *
 * @arg prefix a 2 character argument prefix
 * @return the number of named arguments removed.
 */
extern int adc_msg_remove_named_argument(struct adc_message* cmd, const char prefix[2]);

/**
 * Count the number of arguments matching the given 2 character prefix.
 *
 * @arg prefix a 2 character argument prefix
 * @return the number of matching arguments
 */
extern int adc_msg_has_named_argument(struct adc_message* cmd, const char prefix[2]);

/**
 * Returns a named arguments based on the 2 character prefix.
 * If multiple matching arguments exists, only the first one will be returned
 * by this function.
 *
 * NOTE: Returned memory must be free'd with hub_free().
 *
 * @arg prefix a 2 character argument prefix
 * @return the argument or NULL if OOM/not found.
 */
extern char* adc_msg_get_named_argument(struct adc_message* cmd, const char prefix[2]);

/**
 * Returns a offset of an argument based on the 2 character prefix.
 * If multiple matching arguments exists, only the first one will be returned
 * by this function.
 *
 * @arg prefix a 2 character argument prefix
 * @return the offset or -1 if the argument is not found.
 */
extern int adc_msg_get_named_argument_index(struct adc_message* cmd, const char prefix[2]);

/**
 * @param cmd command to be checked
 * @return 1 if the command does not have any arguments (parameters), 0 otherwise, -1 if cmd is invalid.
 */
extern int adc_msg_is_empty(struct adc_message* cmd);

/**
 * Returns the argument on the offset position in the command.
 * If offset is invalid NULL is returned.
 *
 * NOTE: Returned memory must be free'd with hub_free().
 *
 * @return the argument or NULL if OOM/not found.
 */
extern char* adc_msg_get_argument(struct adc_message* cmd, int offset);

/**
 * Replace a named argument in the command.
 * This will remove any matching arguments (multiple, or none),
 * then add 'string' as an argument using the given prefix.
 *
 * @arg prefix a 2 character argument prefix
 * @arg string must be escaped (see adc_msg_escape).
 * @return  0 if successful, or -1 if an error occured.
 */
extern int adc_msg_replace_named_argument(struct adc_message* cmd, const char prefix[2], const char* string);

/**
 * Append an argument
 *
 * @arg string must be escaped (see adc_msg_escape).
 * @return  0 if successful, or -1 if an error occured (out of memory).
 */
extern int adc_msg_add_argument(struct adc_message* cmd, const char* string);

/**
 * Add an argument string, the string will be automatcally escaped.
 * @return  0 if successful, or -1 if an error occured (out of memory).
 */
extern int adc_msg_add_argument_string(struct adc_message* cmd, const char* string);

/**
 * Append a named argument
 *
 * @arg prefix a 2 character argument prefix
 * @arg string must be escaped (see adc_msg_escape).
 * @return  0 if successful, or -1 if an error occured (out of memory).
 */
extern int adc_msg_add_named_argument(struct adc_message* cmd, const char prefix[2], const char* string);

/**
 * Append a string as a named argument.
 * The string will automatcally be escaped, if you do not wish to escape th string use adc_msg_add_named_argument() instead.
 *
 * @arg prefix a 2 character argument prefix
 * @arg string must NOT be escaped
 * @return  0 if successful, or -1 if an error occured (out of memory).
 */
extern int adc_msg_add_named_argument_string(struct adc_message* cmd, const char prefix[2], const char* string);

/**
 * Append an integer as a named argument.
 */
extern int adc_msg_add_named_argument_int(struct adc_message* cmd, const char prefix[2], int integer);
extern int adc_msg_add_named_argument_uint64(struct adc_message* cmd, const char prefix[2], uint64_t num);

/**
 * Convert a ADC command escaped string to a regular string.
 * @return string or NULL if out of memory
 */
extern char* adc_msg_unescape(const char* string);

/**
 * Convert a ADC command escaped string to a regular string.
 * @return The number of bytes written to target. If the target is not large enough then
 * the -1 is returned, but the string is guaranteed to always be \0 terminated.
 */
extern int adc_msg_unescape_to_target(const char* string, char* target, size_t target_size);

/**
 * Returns the length of the string once escaped with
 * adc_msg_escape().
 *
 * The string must be NULL terminated.
 */
extern int adc_msg_escape_length(const char* str);

/**
 * Convert a string to a ADC command escaped string.
 * @return adc command escaped string or NULL if out of memory.
 */
extern char* adc_msg_escape(const char* string);

/**
 * This will ensure a newline is at the end of the command.
 */
void adc_msg_terminate(struct adc_message* cmd);

/**
 * This will remove any newline from the end of the command
 */
void adc_msg_unterminate(struct adc_message* cmd);

/**
 * @return the offset for the first command argument in msg->cache.
 * or -1 if the command is not understood.
 * NOTE: for 'U' and 'C' commands (normally not seen by hubs), 
 * this returns 4. Should be 4 + lengthOf(cid).
 */
int adc_msg_get_arg_offset(struct adc_message* msg);


#endif /* HAVE_UHUB_COMMAND_H */
