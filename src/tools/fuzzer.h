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

enum commandMode
{
	cm_bcast    = 0x01, /* B - broadcast */
	cm_dir      = 0x02, /* D - direct message */
	cm_echo     = 0x04, /* E - echo message */
	cm_fcast    = 0x08, /* F - feature cast message */
	cm_c2h      = 0x10, /* H - client to hub message */
	cm_h2c      = 0x20, /* I - hub to client message */
	cm_c2c      = 0x40, /* C - client to client message */
	cm_udp      = 0x80, /* U - udp message (client to client) */
};

enum commandValidity
{
	cv_protocol = 0x01,
	cv_identify = 0x02,
	cv_verify   = 0x04,
 	cv_normal   = 0x08,
};

const struct commandPattern patterns[] =
{
	{ cm_c2h | cm_c2c | cm_h2c,                     "SUP", cv_protocol | cv_normal }, /* protocol support */
	{ cm_bcast | cm_h2c | cm_c2c,                   "INF", cv_identify | cv_verify | cv_normal }, /* info message */
	{ cm_bcast | cm_h2c | cm_c2c | cm_c2h | cm_udp, "STA", cv_protocol | cv_identify | cv_verify | cv_normal }, /* status message */
	{ cm_bcast | cm_dir | cm_echo | cm_h2c,         "MSG", cv_normal },   /* chat message */
	{ cm_bcast | cm_dir | cm_echo | cm_fcast,       "SCH", cv_normal },   /* search */
	{ cm_dir | cm_udp,                              "RES", cv_normal },   /* search result */
	{ cm_dir | cm_echo,                             "CTM", cv_normal },   /* connect to me */
	{ cm_dir | cm_echo,                             "RCM", cv_normal },   /* reversed, connect to me */
	{ cm_h2c,                                       "QUI", cv_normal },   /* quit message */
	{ cm_h2c,                                       "GPA", cv_identify }, /* password request */
	{ cm_c2h,                                       "PAS", cv_verify }    /* password response */
};

