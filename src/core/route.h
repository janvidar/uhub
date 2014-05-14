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

#ifndef HAVE_UHUB_ROUTE_H
#define HAVE_UHUB_ROUTE_H

/**
 * Route a message by sending it to it's final destination.
 */
extern int route_message(struct hub_info* hub, struct hub_user* u, struct adc_message* msg);

/**
 * Send queued messages.
 */
extern int route_flush_pipeline(struct hub_info* hub, struct hub_user* u);

/**
 * Transmit message directly to one user.
 */
extern int route_to_user(struct hub_info* hub, struct hub_user*, struct adc_message* command);

/**
 * Broadcast message to all users.
 */
extern int route_to_all(struct hub_info* hub, struct adc_message* command);

/**
 * Broadcast message to all users subscribing to the type of message.
 */
extern int route_to_subscribers(struct hub_info* hub, struct adc_message* command);

/**
 * Broadcast initial info message to all users.
 * This will ensure the correct IP is seen by other users
 * in case nat override is in use.
 */
extern int route_info_message(struct hub_info* hub, struct hub_user* user);


#endif /* HAVE_UHUB_ROUTE_H */
