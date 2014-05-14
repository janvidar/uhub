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

#ifndef HAVE_UHUB_EVENT_ID_H
#define HAVE_UHUB_EVENT_ID_H

/* User join or quit messages */
#define UHUB_EVENT_USER_JOIN         0x1001
#define UHUB_EVENT_USER_QUIT         0x1002
#define UHUB_EVENT_USER_DESTROY      0x1003

/* Send a broadcast message */
#define UHUB_EVENT_BROADCAST         0x2000

/* Shutdown hub */
#define UHUB_EVENT_HUB_SHUTDOWN      0x3001

/* Statistics, OOM, reconfigure */
#define UHUB_EVENT_STATISTICS        0x4000
#define UHUB_EVENT_OUT_OF_MEMORY     0x4001
#define UHUB_EVENT_RECONFIGURE       0x4002


#endif /* HAVE_UHUB_EVENT_ID_H */

