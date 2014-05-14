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

#ifndef HAVE_UHUB_CONFIG_H
#define HAVE_UHUB_CONFIG_H

#include "gen_config.h"

/**
 * This initializes the configuration variables, and sets the default
 * variables.
 *
 * NOTE: Any variable is set to it's default variable if zero.
 * This function is automatically called in read_config to set any
 * configuration that was missing there.
 */
extern void config_defaults(struct hub_config* config);

/**
 * Read configuration from file, and use the default variables for
 * the missing variables.
 *
 * @return -1 on error, 0 on success.
 */
extern int read_config(const char* file, struct hub_config* config, int allow_missing);

/**
 * Free the configuration data (allocated by read_config, or config_defaults).
 */
extern void free_config(struct hub_config* config);

/**
 * Print all configuration data to standard out.
 */
extern void dump_config(struct hub_config* config, int ignore_defaults);


#endif /* HAVE_UHUB_CONFIG_H */

