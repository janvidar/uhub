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

#ifndef HAVE_UHUB_FLOOD_CTL_H
#define HAVE_UHUB_FLOOD_CTL_H

struct flood_control
{
	time_t time;
	size_t count;
};

/**
 * Reset flood control statistics
 */
void flood_control_reset(struct flood_control*);

/**
 * @param ctl Flood control data structure
 * @param max_count Max count for flood control
 * @param window Time window for max_count to appear.
 * @param now The current time.
 *
 * @return 0 if flood no flood detected.
 *         1 if flood detected.
 */
int  flood_control_check(struct flood_control* ctl, size_t max_count, size_t window, time_t now);


#endif /* HAVE_UHUB_FLOOD_CTL_H */

