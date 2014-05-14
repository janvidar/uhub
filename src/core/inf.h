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

#ifndef HAVE_UHUB_INF_PARSER_H
#define HAVE_UHUB_INF_PARSER_H

enum nick_status
{
	nick_ok                =  0,
	nick_invalid_short     = -1,
	nick_invalid_long      = -2,
	nick_invalid_spaces    = -3,
	nick_invalid_bad_ascii = -4,
	nick_invalid_bad_utf8  = -5,
	nick_invalid           = -6, /* some unknown reason */
	nick_not_allowed       = -7, /* Not allowed according to configuration */
	nick_banned            = -8, /* Nickname is banned */
};

/**
 * Handle info messages as received from clients.
 * This can be an initial info message, which might end up requiring password
 * authentication, etc.
 * All sorts of validation is performed here.
 * - Nickname valid?
 * - CID/PID valid?
 * - Network IP address valid?
 *
 * This can be triggered multiple times, as users can update their information,
 * in such case nickname and CID/PID changes are not allowed.
 *
 * @return 0 on success, -1 on error
 */
extern int hub_handle_info(struct hub_info* hub, struct hub_user* u, const struct adc_message* cmd);


#endif /* HAVE_UHUB_INF_PARSER_H */

