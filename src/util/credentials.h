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

#ifndef HAVE_UHUB_CREDENTIALS_H
#define HAVE_UHUB_CREDENTIALS_H

enum auth_credentials
{
	auth_cred_none,                 /**<<< "User has no credentials (not yet logged in)" */
	auth_cred_guest,                /**<<< "User is a guest (unregistered user)" */
	auth_cred_user,                 /**<<< "User is identified as a registered user" */
	auth_cred_bot,                  /**<<< "User is a robot" */
	auth_cred_ubot,                 /**<<< "User is an unrestricted robot" */
	auth_cred_operator,             /**<<< "User is identified as a hub operator" */
	auth_cred_opbot,                /**<<< "User is a operator robot" */
	auth_cred_opubot,               /**<<< "User is an unrestricted operator robot" */
	auth_cred_super,                /**<<< "User is a super user" (not used) */
	auth_cred_link,                 /**<<< "User is a link (not used currently)" */
	auth_cred_admin,                /**<<< "User is identified as a hub administrator/owner" */
};

/**
 * Returns 1 if the credentials means that a user is unrestricted.
 * Returns 0 otherwise.
 */
int auth_cred_is_unrestricted(enum auth_credentials cred);

/**
 * Returns 1 if the credentials means that a user is protected.
 * Returns 0 otherwise.
 */
int auth_cred_is_protected(enum auth_credentials cred);

/**
 * Returns 1 if a user is registered.
 * Returns 0 otherwise.
 * Only registered users will be let in if the hub is configured for registered
 * users only.
 */
int auth_cred_is_registered(enum auth_credentials cred);

/**
 * Returns a string representation of the credentials enum.
 */
const char* auth_cred_to_string(enum auth_credentials cred);


int auth_string_to_cred(const char* str, enum auth_credentials* out);

#endif /* HAVE_UHUB_CREDENTIALS_H */
