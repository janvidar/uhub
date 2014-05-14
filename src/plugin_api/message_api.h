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

#ifndef HAVE_UHUB_PLUGIN_MESSAGE_API_H
#define HAVE_UHUB_PLUGIN_MESSAGE_API_H

/**
 * Send an informal message to a user.
 * The user will see the message as if the hub sent it.
 */
extern int plugin_send_message(struct plugin_handle*, struct plugin_user* to, const char* message);

/**
 * Send a status message to a user.
 */
extern int plugin_send_status(struct plugin_handle* struct plugin_user* to, int code, const char* message);

#endif /* HAVE_UHUB_PLUGIN_API_H */
