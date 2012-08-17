/*
 * uhub - A tiny ADC p2p connection hub
 *
 * User command plugin
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

#include "plugin_api/handle.h"
#include "plugin_api/types.h"
#include "util/list.h"
#include "util/memory.h"
#include "util/misc.h"
#include "util/config_token.h"

/* Plugin data. Stores a linked list of the commands for each credential level. */
struct ucmd_data{
	struct linked_list* commands[auth_cred_admin]; /* Don't need to store commands for auth_cred_none. */
};

/* State used to keep track of where we are in parsing the user command file. */
struct parse_state
{
	struct plugin_handle* plugin;
	struct ucmd_data* data;
	struct plugin_ucmd* ucmd;          /* Command we are currently parsing. */
	enum auth_credentials credentials; /* Credentials the command requires. */
	int actions;                       /* How many actions have been added to the command so far. */
};

/* Callback run when a user logs in. */
void on_user_login(struct plugin_handle* plugin, struct plugin_user* user){
	struct plugin_ucmd* ucmd;

	/* 0 = auth_cred_none. Should never be called with a non-logged-in user but
	 * do a sanity check to be sure. */
	if(!user->credentials) return;

	/* Get the list of commands for this credential level. NB the offset of -1
	 * caused by not storing a list for auth_cred_none. */
	struct ucmd_data *data = (struct ucmd_data *)plugin->ptr;
	struct linked_list* clist = data->commands[user->credentials - 1];

	/* Loop through and send all commands to the new user. */
	ucmd = list_get_first(clist);
	while(ucmd)
	{
		plugin->hub.ucmd_send(plugin, user, ucmd);
		ucmd = list_get_next(clist);
	}
}

/* Adds a parsed command to the lists for the credential levels that can access it. */
void add_command(struct ucmd_data* data, struct plugin_ucmd* ucmd, enum auth_credentials min_credential)
{
	/* Don't store auth_cred_none but we can accept it here to mean everybody,
	 * so fake it as the next level up. */
	if(min_credential == auth_cred_none) min_credential = auth_cred_bot;

	/* Add it to the lists of all matching credentials. */
	int i;
	for(i = min_credential - 1; i < auth_cred_admin; i++){
		list_append(data->commands[i], (void*)ucmd);
	}
}

/* Frees up all the memory used in the plugin data structure, including the
 * structure itself. */
void free_data(struct plugin_handle* plugin, struct ucmd_data* data)
{
	if(data != NULL){
		/* Clear up the linked lists. */
		int i, j;
		for(i = 0; i < auth_cred_admin; i++)
		{
			struct plugin_ucmd* ucmd = list_get_first(data->commands[i]);
			while(ucmd != NULL)
			{
				/* Remove the commands in this list from the higher lists (they are
				 * bound to exist in them due to the way the credentials are
				 * ordered). This is neccessary to avoid a double-free when
				 * clearing the higher lists. */
				for(j = i + 1; j < auth_cred_admin; j++) list_remove(data->commands[j], ucmd);

				/* Free the command memory. */
				plugin->hub.ucmd_free(plugin, ucmd);

				/* Remove it from the list and move on to the next one. */
				list_remove(data->commands[i], ucmd);
				ucmd = list_get_next(data->commands[i]);
			}

			/* Done with this list. */
			list_destroy(data->commands[i]);
		}

		/* Done with the data structure. */
		hub_free(data);
	}
}

/* Parses the first line of a command entry, and creates a new user command
 * object (if possible) in the state structure. Any existing object is
 * overwritten - it is up to the calling function to handle this first. If an
 * error occurs, sets an appropriate message and returns -1. Returns 1 on
 * success. */
int parse_first_line(struct parse_state* state, char* line)
{
	/* Check the credential level. */
	if(line[0] < '0' || line[0] > '7')
	{
		state->plugin->error_msg = "Command must start with a valid credential level.";
		return -1;
	}
	state->credentials = line[0] - '0';

	/* Check for proper formatting. */
	if(line[1] != ' ')
	{
		state->plugin->error_msg = "No context (or misformed context) given.";
		return -1;
	}

	/* Parse the context string. */
	char *start = line + 2;
	char *end = start;
	enum plugin_ucmd_categories category = 0;
	while(1)
	{
		/* Move to (a) end of string, (b) next space, or (c) next comma. */
		while(*end && *end != ' ' && *end != ',') end++;

		/* Check what category this token corresponds to and OR it into the
		 * overall category. */
		if(strncasecmp(start, "all", end-start) == 0) category = ucmd_category_all;
		else if(strncasecmp(start, "hub", end-start) == 0) category |= ucmd_category_hub;
		else if(strncasecmp(start, "user", end-start) == 0) category |= ucmd_category_user;
		else if(strncasecmp(start, "search", end-start) == 0) category |= ucmd_category_search;
		else if(strncasecmp(start, "file", end-start) == 0) category |= ucmd_category_file;
		else
		{
			state->plugin->error_msg = "Invalid context for command.";
			return -1;
		}

		/* End of the string ==> no name was given on this line. */
		if(!*end)
		{
			state->plugin->error_msg = "No name for command.";
			return -1;
		}

		/* Token ended with a space ==> end of list, next up is the command name. */
		if(*end == ' '){
			start = ++end;
			break;
		}

		/* Must have been a comma, go through and process the next category given. */
		start = ++end;
	}

	/* What is left is the name, so we can create the command. */
	state->ucmd = state->plugin->hub.ucmd_create(state->plugin, start, 50);
	state->ucmd->categories = category;

	/* Success. */
	return 1;
}

/* Parses a chat message action and updates the current user command object.
 * Sets an appropriate error message and returns -1 if an error occurs. Returns
 * 1 on success. */
int parse_chat(struct parse_state* state, char* args)
{
	/* Check for 'me' parameter. */
	if(args[0] < '0' || args[0] > '1' || args[1] != ' ')
	{
		state->plugin->error_msg = "'Me' parameter in chat action must be 0 or 1";
		return -1;
	}
	int me = args[0] - '0';

	/* Check for a message. */
	char* message = args + 2;
	if(strlen(message) == 0)
	{
		state->plugin->error_msg = "Chat action requires a message to send";
		return -1;
	}

	/* Add the message to the command. */
	int retval = state->plugin->hub.ucmd_add_chat(state->plugin, state->ucmd, message, me);
	if(retval)
	{
		state->actions++;
		return 1;
	}
	return -1;
}

/* Parses a private message action and adds it to the current user command.
 * Sets an appropriate message and returns -1 if an error occurs. Returns 1 on
 * success. */
int parse_pm(struct parse_state* state, char* args)
{
	/* Check for 'echo' parameter. */
	if(args[0] < '0' || args[0] > '1' || args[1] != ' ')
	{
		state->plugin->error_msg = "'Echo' parameter in PM action must be 0 or 1";
		return -1;
	}
	int echo = args[0] - '0';

	/* Decide upon the target. */
	args += 2;
	char* target;
	if(strncasecmp(args, "selected ", 9) == 0)
	{
		target = NULL;
		args += 9;
	}
	else
	{
		/* Check it is a valid SID. */
		if(!is_valid_base32_char(args[0]) || !is_valid_base32_char(args[1]) ||
		   !is_valid_base32_char(args[2]) || !is_valid_base32_char(args[3]) || args[4] != ' ')
		{
			state->plugin->error_msg = "Invalid target in PM action";
			return -1;
		}
		args[4] = 0;
		target = hub_strdup(args);
		args += 5;
	}

	/* Add the message. */
	int retval = state->plugin->hub.ucmd_add_pm(state->plugin, state->ucmd, target, args, echo);
	if(target != NULL) hub_free(target);

	/* Done. */
	if(retval)
	{
		state->actions++;
		return 1;
	}
	return -1;
}

/* Parses a line - designed as a callback for the file_read_lines() function.
 * Does not handle blank lines as they are not passed to callbacks. Sets
 * appropriate error message and returns -1 on error. Returns 1 on success. The
 * data parameter should be a pointer to a parse_state structure. */
int parse_line(char *line, int line_number, void* data)
{
	struct parse_state* state = (struct parse_state*)data;

	/* Strip off any whitespace and check we still have something to process. */
	line = strip_white_space(line);
	if(strlen(line) == 0) return 1;

	/* Ignore comment lines. */
	if(line[0] == '#') return 1;

	/* New command. */
	if(line[0] >= '0' && line[0] <= '9')
	{
		/* Existing command we need to finish and add. */
		if(state->ucmd != NULL)
		{
			/* Need at least one action. */
			if(!state->actions)
			{
				state->plugin->error_msg = "A command needs at least one action to perform.";
				return -1;
			}

			/* Add the command. */
			add_command(state->data, state->ucmd, state->credentials);
			state->ucmd = NULL;
		}

		/* Reset the flags. */
		state->actions = 0;
		state->credentials = auth_cred_none;

		/* Start the new command. */
		return parse_first_line(state, line);
	}

	/* New chat message action. */
	else if(strncasecmp(line, "Chat ", 5) == 0)
	{
		if(state->ucmd == NULL)
		{
			state->plugin->error_msg = "Command must be defined before an action.";
			return -1;
		}
		if(!state->ucmd->separator) return parse_chat(state, line+5);
		else return 1;
	}

	/* New private message action. */
	else if(strncasecmp(line, "PM ", 3) == 0)
	{
		if(state->ucmd == NULL)
		{
			state->plugin->error_msg = "Command must be defined before an action.";
			return -1;
		}
		if(!state->ucmd->separator) return parse_pm(state, line+3);
		else return 1;
	}

	/* Command is actually a separator. */
	else if(strncasecmp(line, "Separator", 9) == 0)
	{
		if(state->ucmd == NULL)
		{
			state->plugin->error_msg = "Command must be defined before an action.";
			return -1;
		}
		state->ucmd->separator = 1;
		state->actions++;
		return 1;
	}

	/* Unknown line. */
	else
	{
		state->plugin->error_msg = "Unknown line in user command file.";
		return -1;
	}
}

/* Parses a user command file, creates the user commands, and stores them in
 * the given data structure. Returns 1 on success, or -1 (with an appropriate
 * error message set in the plugin) on error. */
int parse_file(struct plugin_handle* plugin, struct ucmd_data* data, const char* filename)
{
	/* Create the parser state. */
	struct parse_state* state = (struct parse_state*)hub_malloc(sizeof(struct parse_state));
	state->plugin = plugin;
	state->data = data;
	state->ucmd = NULL;
	state->credentials = auth_cred_none;
	state->actions = 0;

	/* Try to parse the file line by line. */
	int retval = file_read_lines(filename, (void*)state, &parse_line);

	/* Default error message. This probably means the file doesn't exist or we
	 * do not have permission to open it - our parsing functions all set error
	 * messages. */
	if(retval < 0 && plugin->error_msg == NULL) plugin->error_msg = "Could not load user commands from file.";

	/* Success; the final command needs to be added to the linked list. */
	if(retval > 0 && state->ucmd != NULL)
	{
		if(state->actions)
		{
			add_command(data, state->ucmd, state->credentials);
			state->ucmd = NULL;
		}
		else{
			plugin->error_msg = "A command needs at least one action to perform.";
			retval = -1;
		}
	}

	/* Clean up memory from the state. If ucmd is not null, then there was an
	 * error and it is a partially-processed object we also need to free. */
	if(state->ucmd != NULL) plugin->hub.ucmd_free(plugin, state->ucmd);
	hub_free(state);

	/* Done. */
	return retval;
}

/* Parse the configuration the plugin was started with and save the
 * corresponding ucmd_data structure in the plugin structure. Returns 1 on
 * success or -1 (with an appropriate error message set) on failure. */
int parse_config(struct plugin_handle* plugin, const char* config)
{
	int got_file = 0;

	/* Create space for the data we need. */
	struct ucmd_data *data = (struct ucmd_data *)hub_malloc(sizeof(struct ucmd_data));
	if(data == NULL){
		plugin->error_msg = "Could not allocate data storage.";
		return -1;
	}

	/* Initialise the linked lists for the commands. */
	int i;
	for(i = 0; i < auth_cred_admin; i++)
	{
		data->commands[i] = list_create();
		if(data->commands[i] == NULL)
		{
			/* We cannot call the free_data() function here as not all the
			 * lists have been initialised. */
			int j;
			for(j = 0; j < i; j++) list_destroy(data->commands[j]);
			hub_free(data);
			plugin->error_msg = "Could not allocate data storage.";
			return -1;
		}
	}

	/* Tokenize the config file and loop over each token. */
	struct cfg_tokens* tokens = cfg_tokenize(config);
	char* token = cfg_token_get_first(tokens);
	while(token)
	{
		/* Try to split the setting into key and value. */
		struct cfg_settings* setting = cfg_settings_split(token);
		if(!setting)
		{
			plugin->error_msg = "Unable to parse plugin config";
			cfg_tokens_free(tokens);
			free_data(plugin, data);
			return -1;
		}
		const char* key = cfg_settings_get_key(setting);
		const char* value = cfg_settings_get_value(setting);

		/* Name of file containing user commands. */
		if (strncmp(key, "file", 4) == 0)
		{
			got_file = 1;
			if(parse_file(plugin, data, value) < 0)
			{
				cfg_settings_free(setting);
				cfg_tokens_free(tokens);
				free_data(plugin, data);
				return -1;
			}
		}

		/* Unknown setting. */
		else
		{
			plugin->error_msg = "Unknown setting when parsing plugin config";
			cfg_settings_free(setting);
			cfg_tokens_free(tokens);
			free_data(plugin, data);
			return -1;
		}

		/* Move onto next token. */
		cfg_settings_free(setting);
		token = cfg_token_get_next(tokens);
	}
	cfg_tokens_free(tokens);

	/* Make sure we were given at least one user command file. */
	if(!got_file)
	{
		plugin->error_msg = "No command file given, use file=<filename>";
		free_data(plugin, data);
		return -1;
	}

	/* Save the data with the plugin and we're done. */
	plugin->ptr = (void *)data;
	return 1;
}

/* Attempt to load the plugin. Called by the hub when appropriate. */
int plugin_register(struct plugin_handle *plugin, const char *config){
	PLUGIN_INITIALIZE(plugin, "User command plugin", "0.1", "Provide custom commands to users.");

	/* Attempt to parse the config we were given. */
	if(parse_config(plugin, config) == -1) return -1;

	/* Register our callbacks. */
	plugin->funcs.on_user_login = on_user_login;

	/* Done. */
	return 0;
}

/* Unload the plugin. Called by the hub when appropriate. */
int plugin_unregister(struct plugin_handle *plugin){
	free_data(plugin, (struct ucmd_data *)plugin->ptr);
	return 0;
}
