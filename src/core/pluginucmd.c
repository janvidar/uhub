/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2011, Jan Vidar Krey
 * Copyright (C) 2012, Blair Bonnett
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

/* Internal helper function - expand the ucmd->tt member to accomodate the
 * given number of byes size. Copies and then frees any existing data.  All
 * unused bytes will be set to zero. Returns 1 on success, 0 if the memory
 * could not be allocated.
 *
 * If size is less than the existing capacity, no change is made.
 *
 * NB. one extra byte is always allocated to act as the end-of-string
 * terminator, i.e., the size can be the length of the string ignoring the
 * terminator. Since unused bytes are set to zero, there should always be a
 * terminator.
 */
int ucmd_expand_tt(struct plugin_ucmd* ucmd, size_t size)
{
	if(size < ucmd->capacity) return 1;

	/* Try to allocate the space. NB we add one to the space to enforce a null
	 * byte. */
	char* newtt = (char*)malloc(size+1);
	if(newtt == NULL) return 0;

	/* Empty the contents. */
	memset(newtt, 0, size+1);

	/* Copy any existing data. */
	if(ucmd->tt != NULL)
	{
		memcpy(newtt, ucmd->tt, ucmd->length);
		free(ucmd->tt);
	}

	/* Update the structure. */
	ucmd->tt = newtt;
	ucmd->capacity = size;
	return 1;
}

/* Calculate the number of characters needed to store the escaped message. */
size_t ucmd_msg_escape_length(const char* message)
{
	size_t extra = 0;
	size_t i;
	int insub = 0;
	for(i = 0; message[i]; i++)
	{
		/* In a substitution block, no escaping needed. */
		if(insub == 2)
		{
			if(message[i] == ']') insub = 0;
		}

		/* Not in a substitution block. */
		else{
			/* A character that needs escaping. */
			if(message[i] == ' ' || message[i] == '\n' || message[i] == '\\'){
				extra++;
				insub = 0;
			}

			/* See if we're heading into a substitution block. */
			else if(message[i] == '%') insub = 1;
			else if(message[i] == '[' && insub == 1) insub = 2;
			else insub = 0;
		}
	}

	/* Done. */
	return i + extra;
}

/* Escape a message that is being put into a user command. We cannot use
 * adc_msg_escape for this as keyword substitutions should not be escaped while
 * general text should be. */
char* ucmd_msg_escape(const char* message)
{
	/* Allocate the memory we need. */
	size_t esclen = ucmd_msg_escape_length(message);
	char *escaped = malloc(esclen + 1);

	int insub = 0;
	size_t i;
	size_t n = 0;

	for(i = 0; message[i]; i++)
	{
		/* In a substitution block, no escaping needed. */
		if(insub == 2)
		{
			if(message[i] == ']') insub = 0;
			escaped[n++] = message[i];
		}

		/* Not in a substitution block. */
		else
		{
			switch(message[i])
			{
				/* Deal with characters that need escaping. */
				case '\\':
					escaped[n++] = '\\';
					escaped[n++] = '\\';
					insub = 0;
					break;
				case '\n':
					escaped[n++] = '\\';
					escaped[n++] = 'n';
					insub = 0;
					break;
				case ' ':
					escaped[n++] = '\\';
					escaped[n++] = 's';
					insub = 0;
					break;

				/* Characters that start a substitution block. */
				case '%':
					escaped[n++] = message[i];
					insub = 1;
					break;
				case '[':
					escaped[n++] = message[i];
					if(insub == 1) insub = 2;
					break;

				/* Standard character. */
				default:
					escaped[n++] = message[i];
					insub = 0;
					break;
			}
		}
	}

	/* Done. */
	escaped[n] = 0;
	return escaped;
}

struct plugin_ucmd* cbfunc_ucmd_create(struct plugin_handle* plugin, const char* name, size_t length){
	/* Need a name. */
	if(name == NULL)
	{
		plugin->error_msg = "Each user command needs a name.";
		return NULL;
	}

	/* Allocate space for the command structure. */
	struct plugin_ucmd* cmd = (struct plugin_ucmd*)malloc(sizeof(struct plugin_ucmd));
	if(cmd == NULL)
	{
		plugin->error_msg = "Not enough memory to create user command.";
		return NULL;
	}

	/* Store the name and initialise the flags. */
	cmd->categories = 0;
	cmd->remove = 0;
	cmd->separator = 0;
	cmd->constrained = 0;
	cmd->name = adc_msg_escape(name);
	cmd->namelen = strlen(cmd->name);
	cmd->tt = NULL;
	cmd->length = 0;
	cmd->capacity = 0;

	/* Allocate space for the command data. 18 bytes is the overhead for a chat
	 * message so we need to add space for this. */
	length = ((length < 0) ? 0 : length) + 18;
	int result = ucmd_expand_tt(cmd, length);
	if(result == 0)
	{
		plugin->error_msg = "Not enough memory to store user command data.";
		cbfunc_ucmd_free(plugin, cmd);
		return NULL;
	}

	/* Done. */
	return cmd;
}

int cbfunc_ucmd_add_chat(struct plugin_handle* plugin, struct plugin_ucmd* ucmd, const char* message, int me)
{
	/* Double-escape the message - once for when the client sends it back, and
	 * then again to insert it into the user command message we send to them.
	 * Note the two different escape functions used for the different escapes -
	 * the UCMD escape is needed to handle substitution blocks correctly. */
	char* temp = ucmd_msg_escape(message);
	char* escmsg = adc_msg_escape(temp);
	free(temp);
	size_t msglen = strlen(escmsg);

	/* Format of a chat message: "BMSG\s%[mySID]\s<double-escaped message>\n".
	 * Format of a 'me' chat message: "BMSG\s%[mySID]\s<double-escaped message>\sME1\n". */
	size_t required = 18 + msglen + (me ? 5 : 0);
	if(required > (ucmd->capacity - ucmd->length))
	{
		if(ucmd_expand_tt(ucmd, ucmd->capacity + required) == 0)
		{
			plugin->error_msg = "Could not expand memory to store chat message.";
			free(escmsg);
			return 0;
		}
	}

	/* Add in the chat command and placeholder for the client SID. */
	strncpy(ucmd->tt + ucmd->length, "BMSG\\s%[mySID]\\s", 16);
	ucmd->length += 16;

	/* Copy the message. */
	strncpy(ucmd->tt + ucmd->length, escmsg, msglen);
	ucmd->length += msglen;
	free(escmsg);

	/* If it is a 'me' message, add the flag. */
	if(me)
	{
		strncpy(ucmd->tt + ucmd->length, "\\sME1", 5);
		ucmd->length += 5;
	}

	/* Add the (escaped) line break. */
	ucmd->tt[ucmd->length++] = '\\';
	ucmd->tt[ucmd->length++] = 'n';

	/* Done. */
	return 1;
}

int cbfunc_ucmd_add_pm(struct plugin_handle* plugin, struct plugin_ucmd* ucmd, const char* to, const char* message, int echo)
{
	/* Double-escape the message - once for when the client sends it back, and
	 * then again to insert it into the user command message we send to them.
	 * Note the two different escape functions used for the different escapes -
	 * the UCMD escape is needed to handle substitution blocks correctly. */
	char* temp = ucmd_msg_escape(message);
	char* escmsg = adc_msg_escape(temp);
	free(temp);
	size_t msglen = strlen(escmsg);

	/* If no target SID is given, use the keyword expansion %[userSID] for the
	 * client to fill in with the currently selected user. */
	size_t tolen = (to == NULL) ? 10 : 4;

	/* Format of an echoed PM: "EMSG\s%[mySID]\s<target SID>\s<double-escaped message>\sPM%[mySID]\n".
	 * Format of a non-echoed PM: "DMSG\s%[mySID]\s<target SID>\s<double-escaped message>\sPM%[mySID]\n". */
	size_t required = 32 + tolen + msglen;
	if(required > (ucmd->capacity - ucmd->length))
	{
		if(ucmd_expand_tt(ucmd, ucmd->capacity + required) == 0)
		{
			plugin->error_msg = "Could not expand memory to store private message.";
			free(escmsg);
			return 0;
		}
	}

	/* Start with the appropriate ADC command plus the client SID placeholder. */
	if(echo) strncpy(ucmd->tt + ucmd->length, "EMSG\\s%[mySID]\\s", 16);
	else strncpy(ucmd->tt + ucmd->length, "DMSG\\s%[mySID]\\s", 16);
	ucmd->length += 16;

	/* Copy the target ID. */
	if(to != NULL) strncpy(ucmd->tt + ucmd->length, to, tolen);
	else strncpy(ucmd->tt + ucmd->length, "%[userSID]", tolen);
	ucmd->length += tolen;

	/* Space between target and message. */
	ucmd->tt[ucmd->length++] = '\\';
	ucmd->tt[ucmd->length++] = 's';

	/* Message. */
	strncpy(ucmd->tt + ucmd->length, escmsg, msglen);
	ucmd->length += msglen;
	free(escmsg);

	/* Add the PM flag and final line break. */
	strncpy(ucmd->tt + ucmd->length, "\\sPM%[mySID]\\n", 14);
	ucmd->length += 14;

	/* Done. */
	return 1;
}

int cbfunc_ucmd_send(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_ucmd* ucmd)
{
	/* Check the user is still connected. */
	struct hub_info* hub = plugin_get_hub(plugin);
	struct hub_user* huser = uman_get_user_by_sid(hub, user->sid);
	if(huser == NULL)
	{
		plugin->error_msg = "User is not connected to the hub.";
		return 0;
	}

	/* Make sure we have a command. */
	if(!ucmd->length && !(ucmd->separator || ucmd->remove))
	{
		plugin->error_msg = "Cannot send without adding a message.";
		return 0;
	}

	/* Make sure the category is valid. */
	if(!ucmd->remove)
	{
		if(ucmd->categories < 1 || ucmd->categories > 15)
		{
			plugin->error_msg = "Need a valid category to send.";
			return 0;
		}
	}

	/* Calculate the size needed for the message. */
	size_t length = ucmd->namelen;
	if(ucmd->remove || ucmd->separator) length += 4;
	else
	{
		length += 10 + ucmd->length; /* "_TT<arg>\n CTnn" = 10 extra chars. */
		if(ucmd->constrained) length += 4;
	}

	/* Create the message structure. */
	struct adc_message* message = adc_msg_construct(ADC_CMD_ICMD, length);
	if(message == NULL)
	{
		plugin->error_msg = "Cannot allocate space for ADC message.";
		return 0;
	}

	/* Always have the name. */
	adc_msg_add_argument(message, ucmd->name);

	/* Remove / separator. */
	if(ucmd->remove) adc_msg_add_argument(message, "RM1");
	if(ucmd->separator)
	{
		adc_msg_add_argument(message, "SP1");
		adc_msg_add_named_argument_int(message, "CT", ucmd->categories);
	}

	/* Add in the message. */
	else
	{
		adc_msg_add_named_argument(message, "TT", ucmd->tt);
		if(ucmd->constrained) adc_msg_add_argument(message, "CO1");
		adc_msg_add_named_argument_int(message, "CT", ucmd->categories);
	}

	/* Send it. */
	route_to_user(hub, huser, message);

	/* Success. */
	adc_msg_free(message);
	return 1;
}

void cbfunc_ucmd_free(struct plugin_handle* plugin, struct plugin_ucmd* ucmd){
	if(ucmd->name != NULL)
	{
		free(ucmd->name);
		ucmd->name = NULL;
	}
	if(ucmd->tt != NULL)
	{
		free(ucmd->tt);
		ucmd->tt = NULL;
	}
	free(ucmd);
}
