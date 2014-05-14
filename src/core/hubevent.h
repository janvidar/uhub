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

#ifndef HAVE_UHUB_HUB_EVENT_H
#define HAVE_UHUB_HUB_EVENT_H

/**
 * This event is triggered whenever a user successfully logs in to the hub.
 */
extern void on_login_success(struct hub_info* hub, struct hub_user* u);

/**
 * This event is triggered whenever a user failed to log in to the hub.
 */
extern void on_login_failure(struct hub_info* hub, struct hub_user* u, enum status_message msg);
extern void on_update_failure(struct hub_info* hub, struct hub_user* u, enum status_message msg);

/**
 * This event is triggered whenever a previously logged in user leaves the hub.
 */
extern void on_logout_user(struct hub_info* hub, struct hub_user* u);

/**
 * This event is triggered whenever a user changes his/her nickname.
 */
extern void on_nick_change(struct hub_info* hub, struct hub_user* u, const char* nick);


#endif /* HAVE_UHUB_HUB_EVENT_H */

