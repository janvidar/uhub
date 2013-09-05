/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2013, Jan Vidar Krey
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

void flood_control_reset(struct flood_control* data)
{
	memset(data, 0, sizeof(struct flood_control));
}

int  flood_control_check(struct flood_control* data, size_t max_count, size_t time_delay, time_t now)
{
	// Is flood control disabled?
	if (!time_delay || !max_count)
		return 0;

	if (!data->time)
	{
		data->time = now;
		data->count = 0;
		return 0;
	}

	if ((now - data->time) > time_delay)
	{
		data->time = now;
		data->count = 0;
		return 0;
	}

	if (data->count <= max_count)
	{
		data->count++;
		return 0;
	}

	return 1;
}

