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

#ifndef HAVE_UHUB_PLUGIN_UCMD_H
#define HAVE_UHUB_PLUGIN_UCMD_H

/* Create a new user command object.
 * Name: name of the entry in the clients user command menu - must be unique
 *       within a hub.
 * Length: approximate length of message to be sent. Other functions can
 *         increase memory allocation as needed but having a sufficient size
 *         now removes the time taken for this resizing. Allow a factor of ~1/3
 *         for the neccesary escaping.
 */
extern struct plugin_ucmd* cbfunc_ucmd_create(struct plugin_handle* plugin, const char* name, size_t length);

/* Add a message to be sent in the main chat window when the user command is
 * clicked.
 * Me: If true, makes the message displayed in the same style as a '/me'
 *     message in IRC (and most hub clients).
 */
extern int cbfunc_ucmd_add_chat(struct plugin_handle* plugin, struct plugin_ucmd* ucmd, const char* message, int me);

/* Send the user command to a user. */
extern int cbfunc_ucmd_send(struct plugin_handle* plugin, struct plugin_user* user, struct plugin_ucmd* ucmd);

/* Free the space used by a user command object. */
extern void cbfunc_ucmd_free(struct plugin_handle* plugin, struct plugin_ucmd* command);

#endif /* HAVE_UHUB_PLUGIN_UCMD_H */
