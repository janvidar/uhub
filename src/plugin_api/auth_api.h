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

#ifndef HAVE_UHUB_PLUGIN_AUTH_H
#define HAVE_UHUB_PLUGIN_AUTH_H

enum user_credentials
{
	cred_none,                 /**<<< "User has no credentials (not yet logged in)" */
 	cred_bot,                  /**<<< "User is a robot" */
	cred_guest,                /**<<< "User is a guest (unregistered user)" */
 	cred_user,                 /**<<< "User is identified as a registered user" */
	cred_operator,             /**<<< "User is identified as a hub operator" */
	cred_super,                /**<<< "User is a super user" (not used) */
	cred_link,                 /**<<< "User is a link (not used currently)" */
	cred_admin,                /**<<< "User is identified as a hub administrator/owner" */
};

struct uhub_plugin_auth_info
{
	char* nickname;
	char* password;
	enum user_credentials credentials;
};

#define UHUB_AUTH_PLUGIN_VERSION 0

/**
 * Returns the version number of the uhub auth plugin.
 */
extern int uhub_plugin_auth_version();

/**
 * Returns a struct user_plugin_auth_info with nickname, password and credentials
 * for a given user's nickname.
 * In case the user is not registered NULL is returned.
 *
 * @returns A relevant uhub_plugin_auth_info with password and credentials, or NULL
 *          if the user is not found in the auth database.
 */
extern struct uhub_plugin_auth_info* uhub_plugin_auth_get_user(const char* nickname);

/**
 * Register a new user.
 * 
 * @param user contains nickname, password and credentials for a user.
 * @returns 0 on success
 *          <0 if an error occured
 */
extern int uhub_plugin_auth_register_user(struct uhub_plugin_auth_info* user);

/**
 * Update password and user credentials.
 *
 * @param user contains nickname and new password.
 * @returns 0 on success
 *          <0 if an error occured
 */
extern int uhub_plugin_auth_update_info(struct uhub_plugin_auth_info* user);


#endif /* HAVE_UHUB_PLUGIN_AUTH_H */