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

/**
 * Returns 1 if a user is unrestricted.
 * Unrestricted users override the limits of flood and can send messages in
 * the name of other users.
 * This is useful for amongst other external chatrooms.
 */
int auth_cred_is_unrestricted(enum auth_credentials cred)
{
	switch (cred)
	{
		case auth_cred_ubot:
		case auth_cred_opubot:
			return 1;
		default:
			break;
	}
	return 0;
}

int auth_cred_is_protected(enum auth_credentials cred)
{
	switch (cred)
	{
		case auth_cred_bot:
		case auth_cred_ubot:
		case auth_cred_opbot:
		case auth_cred_opubot:
		case auth_cred_operator:
		case auth_cred_super:
		case auth_cred_admin:
		case auth_cred_link:
			return 1;
		default:
			break;
	}
	return 0;
}

/**
 * Returns 1 if a user is registered.
 * Only registered users will be let in if the hub is configured for registered
 * users only.
 */
int auth_cred_is_registered(enum auth_credentials cred)
{
	switch (cred)
	{
		case auth_cred_bot:
		case auth_cred_ubot:
		case auth_cred_opbot:
		case auth_cred_opubot:
		case auth_cred_user:
		case auth_cred_operator:
		case auth_cred_super:
		case auth_cred_admin:
		case auth_cred_link:
			return 1;
		default:
			break;
	}
	return 0;
}


const char* auth_cred_to_string(enum auth_credentials cred)
{
	switch (cred)
	{
		case auth_cred_none:         return "none";
		case auth_cred_bot:          return "bot";
		case auth_cred_ubot:         return "ubot";
		case auth_cred_opbot:        return "opbot";
		case auth_cred_opubot:       return "opubot";
		case auth_cred_guest:        return "guest";
		case auth_cred_user:         return "user";
		case auth_cred_operator:     return "operator";
		case auth_cred_super:        return "super";
		case auth_cred_link:         return "link";
		case auth_cred_admin:        return "admin";
	}

	return "";
};

int auth_string_to_cred(const char* str, enum auth_credentials* out)
{
	if (!str || !*str || !out)
		return 0;

	switch (strlen(str))
	{
		case 2:
			if (!strcasecmp(str, "op")) { *out = auth_cred_operator; return 1; }
			return 0;

		case 3:
			if (!strcasecmp(str, "bot")) { *out = auth_cred_bot; return 1; }
			if (!strcasecmp(str, "reg")) { *out = auth_cred_user; return 1; }
			return 0;

		case 4:
			if (!strcasecmp(str, "none")) { *out = auth_cred_none; return 1; }
			if (!strcasecmp(str, "user")) { *out = auth_cred_user; return 1; }
			if (!strcasecmp(str, "link")) { *out = auth_cred_link; return 1; }
			if (!strcasecmp(str, "ubot")) { *out = auth_cred_ubot; return 1; }
			return 0;

		case 5:
			if (!strcasecmp(str, "admin")) { *out = auth_cred_admin; return 1; }
			if (!strcasecmp(str, "super")) { *out = auth_cred_super; return 1; }
			if (!strcasecmp(str, "opbot")) { *out = auth_cred_opbot; return 1; }
			if (!strcasecmp(str, "guest")) { *out = auth_cred_guest; return 1; }
			return 0;

		case 6:
			if (!strcasecmp(str, "opubot")) { *out = auth_cred_opubot; return 1; }
			return 0;

		case 8:
			if (!strcasecmp(str, "operator")) { *out = auth_cred_operator; return 1; }
			return 0;

		default:
			return 0;
	}
}
