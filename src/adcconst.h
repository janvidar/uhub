/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2009, Jan Vidar Krey
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

#ifndef HAVE_UHUB_ADC_CONSTANTS_H
#define HAVE_UHUB_ADC_CONSTANTS_H

typedef uint32_t sid_t;
typedef uint32_t fourcc_t;

/* Internal uhub limit */
#define MAX_ADC_CMD_LEN 4096

#define FOURCC(a,b,c,d) (fourcc_t) ((a << 24) | (b << 16) | (c << 8) | d)

/* default welcome protocol support message, as sent by this server */
#define ADC_PROTO_SUPPORT "ADBASE ADTIGR ADPING"

/* Server sent commands */
#define ADC_CMD_ISID FOURCC('I','S','I','D')
#define ADC_CMD_ISUP FOURCC('I','S','U','P')
#define ADC_CMD_IGPA FOURCC('I','G','P','A')
#define ADC_CMD_ISTA FOURCC('I','S','T','A')
#define ADC_CMD_IINF FOURCC('I','I','N','F')
#define ADC_CMD_IMSG FOURCC('I','M','S','G')
#define ADC_CMD_IQUI FOURCC('I','Q','U','I')

/* Handshake and login/passwordstuff */
#define ADC_CMD_HSUP FOURCC('H','S','U','P')
#define ADC_CMD_HPAS FOURCC('H','P','A','S')
#define ADC_CMD_HINF FOURCC('H','I','N','F')
#define ADC_CMD_BINF FOURCC('B','I','N','F')

/* This is a Admin extension */
#define ADC_CMD_HDSC FOURCC('H','D','S','C')

/* Status/error messages */
#define ADC_CMD_HSTA FOURCC('H','S','T','A')
#define ADC_CMD_DSTA FOURCC('D','S','T','A')

/* searches */
#define ADC_CMD_BSCH FOURCC('B','S','C','H')
#define ADC_CMD_DSCH FOURCC('D','S','C','H')
#define ADC_CMD_ESCH FOURCC('E','S','C','H')
#define ADC_CMD_FSCH FOURCC('F','S','C','H')
#define ADC_CMD_DRES FOURCC('D','R','E','S')

/* connection setup */
#define ADC_CMD_DCTM FOURCC('D','C','T','M')
#define ADC_CMD_DRCM FOURCC('D','R','C','M')
#define ADC_CMD_ECTM FOURCC('E','C','T','M')
#define ADC_CMD_ERCM FOURCC('E','R','C','M')

/* chat messages */
#define ADC_CMD_BMSG FOURCC('B','M','S','G')
#define ADC_CMD_DMSG FOURCC('D','M','S','G')
#define ADC_CMD_EMSG FOURCC('E','M','S','G')
#define ADC_CMD_FMSG FOURCC('F','M','S','G')

/* disallowed messages */
#define ADC_CMD_DINF FOURCC('D','I','N','F')
#define ADC_CMD_EINF FOURCC('E','I','N','F')
#define ADC_CMD_FINF FOURCC('F','I','N','F')

/* Extension messages */
#define ADC_CMD_HCHK FOURCC('H','C','H','K')

#define ADC_INF_FLAG_IPV4_ADDR          "I4" /* ipv4 address */
#define ADC_INF_FLAG_IPV6_ADDR          "I6" /* ipv6 address */
#define ADC_INF_FLAG_IPV4_UDP_PORT      "U4" /* port number */
#define ADC_INF_FLAG_IPV6_UDP_PORT      "U6" /* port number */
#define ADC_INF_FLAG_CLIENT_TYPE        "CT" /* client type */
#define ADC_INF_FLAG_PRIVATE_ID         "PD" /* private id, aka PID */
#define ADC_INF_FLAG_CLIENT_ID          "ID" /* client id, aka CID */
#define ADC_INF_FLAG_NICK               "NI" /* nick name */
#define ADC_INF_FLAG_DESCRIPTION        "DE" /* user description */
#define ADC_INF_FLAG_USER_AGENT         "VE" /* software version */
#define ADC_INF_FLAG_SUPPORT            "SU" /* support (extensions, feature cast) */
#define ADC_INF_FLAG_SHARED_SIZE        "SS" /* size of total files shared in bytes */
#define ADC_INF_FLAG_SHARED_FILES       "SF" /* number of files shared */
#define ADC_INF_FLAG_UPLOAD_SPEED       "US" /* maximum upload speed acheived in bytes/sec */
#define ADC_INF_FLAG_DOWNLOAD_SPEED     "DS" /* maximum download speed acheived in bytes/sec */
#define ADC_INF_FLAG_UPLOAD_SLOTS       "SL" /* maximum upload slots (concurrent uploads) */
#define ADC_INF_FLAG_AUTO_SLOTS         "AS" /* automatic slot if upload speed is less than this in bytes/sec */
#define ADC_INF_FLAG_AUTO_SLOTS_MAX     "AM" /* maximum number of automatic slots */
#define ADC_INF_FLAG_COUNT_HUB_NORMAL   "HN" /* user is logged into this amount of hubs as a normal user (guest) */
#define ADC_INF_FLAG_COUNT_HUB_REGISTER "HR" /* user is logged into this amount of hubs as a registered user (password) */
#define ADC_INF_FLAG_COUNT_HUB_OPERATOR "HO" /* user is logged into this amount of hubs as an operator */
#define ADC_INF_FLAG_AWAY               "AW" /* away flag, 1=away, 2=extended away */
#define ADC_INF_FLAG_REFERER            "RF" /* URL to referer in case of hub redirect */
#define ADC_INF_FLAG_EMAIL              "EM" /* E-mail address */

#define ADC_MSG_FLAG_ACTION             "ME" /* message is an *action* message */
#define ADC_MSG_FLAG_PRIVATE            "PM" /* message is a private message */

#define ADC_SCH_FLAG_INCLUDE            "AN" /* include given search term */
#define ADC_SCH_FLAG_EXCLUDE            "NO" /* exclude given serach term */
#define ADC_SCH_FLAG_FILE_EXTENSION     "EX" /* search only for files with the given file extension */
#define ADC_SCH_FLAG_FILE_TYPE          "TY" /* search only for files with this file type (separate type) */
#define ADC_SCH_FLAG_LESS_THAN          "LE" /* search for files with this size or less */
#define ADC_SCH_FLAG_GREATER_THAN       "GE" /* search for files with this size or greater */
#define ADC_SCH_FLAG_EQUAL              "EQ" /* search only for files with this exact size */
#define ADC_SCH_FLAG_TOKEN              "TO" /* use this token for search replies */

#define ADC_RES_FLAG_FILE_NAME          "FN" /* file name */
#define ADC_RES_FLAG_FILE_SIZE          "SI" /* file size */
#define ADC_RES_FLAG_UPLOAD_SLOTS       "SL" /* number of upload slots available (if > 0, download is possible) */
#define ADC_RES_FLAG_TOKEN              "TO" /* token, same as the token in the search request */

#define ADC_QUI_FLAG_TIME_LEFT          "TL" /* time in seconds before reconnect is allowed, or -1 forever */
#define ADC_QUI_FLAG_MESSAGE            "MS" /* kick/leave message */
#define ADC_QUI_FLAG_DISCONNECT         "DI" /* all further transfers with this user should be disconnected */
#define ADC_QUI_FLAG_REDIRECT           "RD" /* redirect to URL */
#define ADC_QUI_FLAG_KICK_OPERATOR      "ID" /* SID of operator who disconnected the user */

#define ADC_SUP_FLAG_ADD                "AD"
#define ADC_SUP_FLAG_REMOVE             "RM"

#define ADC_CLIENT_TYPE_BOT             "1"
#define ADC_CLIENT_TYPE_REGISTERED_USER "2"
#define ADC_CLIENT_TYPE_OPERATOR        "4"
#define ADC_CLIENT_TYPE_SUPER_USER      "8"
#define ADC_CLIENT_TYPE_ADMIN           "16"  /* hub owner */
#define ADC_CLIENT_TYPE_HUB             "32"  /* the hub itself */


#endif /* HAVE_UHUB_ADC_CONSTANTS_H */
