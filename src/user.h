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

#ifndef HAVE_UHUB_USER_H
#define HAVE_UHUB_USER_H

struct hub_info;
struct hub_iobuf;

enum user_state
{
	state_protocol     = 0,      /**<< "User must send a valid protocol handshake" */
	state_identify     = 1,      /**<< "User must send identification message (INF) " */
	state_verify       = 2,      /**<< "User must send password to verify identification" */
	state_normal       = 3,      /**<< "User is logged in." */
	state_cleanup      = 4,      /**<< "User is disconnected, but other users need to be notified." */
	state_disconnected = 5,      /**<< "User is disconnected" */
};

enum user_flags
{
	feature_base    = 0x00000001, /** BASE: Basic configuration (required by all clients) */
	feature_auto    = 0x00000002, /** AUT0: Automatic nat detection traversal */
	feature_bbs     = 0x00000004, /** BBS0: Bulletin board system (not supported) */
	feature_ucmd    = 0x00000008, /** UCMD: User commands (not supported by this software) */
	feature_zlif    = 0x00000010, /** ZLIF: gzip stream compression (not supported) */
	feature_tiger   = 0x00000020, /** TIGR: Client supports the tiger hash algorithm */
	feature_bloom   = 0x00000040, /** BLO0: Bloom filter (not supported) */
	feature_ping    = 0x00000080, /** PING: Hub pinger information extension */
	feature_link    = 0x00000100, /** LINK: Hub link (not supported) */
	flag_ignore     = 0x01000000, /** Ignore further reads */
	flag_maxbuf     = 0x02000000, /** Hit max buf read, ignore msg */
	flag_choke      = 0x04000000, /** Choked: Cannot send, waiting for write event */ 
	flag_want_read  = 0x08000000, /** Need to read (SSL) */
	flag_want_write = 0x10000000, /** Need to write (SSL) */
	flag_user_list  = 0x20000000, /** Send queue bypass (when receiving the send queue) */
	flag_nat        = 0x40000000, /** nat override enabled */
};

enum user_quit_reason
{
	quit_unknown        = 0,
	quit_disconnected   = 1,     /** User disconnected */
	quit_kicked         = 2,     /** User was kicked */
	quit_banned         = 3,     /** User was banned */
	quit_timeout        = 4,     /** User timed out (no data for a while) */
	quit_send_queue     = 5,     /** User's send queue was overflowed */
	quit_memory_error   = 6,     /** Not enough memory available */
	quit_socket_error   = 7,     /** A socket error occured */
	quit_protocol_error = 8,     /** Fatal protocol error */
	quit_logon_error    = 9,     /** Unable to login (wrong password, CID/PID, etc) */
	quit_hub_disabled   = 10,    /** Hub is disabled. No new connections allowed */
	quit_ghost_timeout  = 11,    /** The user is a ghost, and trying to login from another connection */
};

struct user_info
{
	sid_t sid;                    /** session ID */
	char cid[MAX_CID_LEN+1];      /** global client ID */
	char nick[MAX_NICK_LEN+1];    /** User's nick name */
};

/**
 * This struct contains additional information about the user, such
 * as the number of bytes and files shared, and the number of hubs the
 * user is connected to, etc.
 */
struct user_limits
{
	uint64_t             shared_size;             /** Shared size in bytes */
	size_t               shared_files;            /** The number of shared files */
	size_t               upload_slots;            /** The number of upload slots */
	size_t               hub_count_user;          /** The number of hubs connected as user */
	size_t               hub_count_registered;    /** The number of hubs connected as registered user */
	size_t               hub_count_operator;      /** The number of hubs connected as operator */
	size_t               hub_count_total;         /** The number of hubs connected to in total */
};

struct user_net_io
{
	int                  sd;                      /** socket descriptor */
	struct event*        ev_read;                 /** libevent struct for read events */

	struct hub_recvq*    recv_queue;
	struct hub_sendq*    send_queue;

	time_t               tm_connected;            /** time when user connected */
	time_t               tm_last_read;            /** time the user last received something from the hub */
	time_t               tm_last_write;           /** time the user last sent something to the hub */

	struct ip_addr_encap ipaddr;                  /** IP address of connected user */

#ifdef SSL_SUPPORT
	SSL*                 ssl;                     /** SSL handle */
#endif /*  SSL_SUPPORT */
};

struct user
{
	struct user_net_io   net;                     /** Network information data */
	enum user_state      state;                   /** see enum user_state */
	enum user_credentials credentials;            /** see enum user_credentials */
	struct user_info     id;                      /** Contains nick name and CID */
	int                  flags;                   /** see enum user_features */
	char                 user_agent[MAX_UA_LEN+1];/** User agent string */
	struct linked_list*  feature_cast;            /** Features supported by feature cast */
	struct adc_message*  info;                    /** ADC 'INF' message (broadcasted to everyone joining the hub) */
	struct hub_info*     hub;                     /** The hub instance this user belong to */
	struct user_limits   limits;                  /** Data used for limitation */
	int                  quit_reason;             /** Quit reason (see user_quit_reason) */

};


/**
 * Create a user with the given socket descriptor.
 * This basically only allocates memory and initializes all variables
 * to an initial state.
 *
 * state is set to state_protocol.
 *
 * @param sd socket descriptor associated with the user
 * @return User object or NULL if not enough memory is available.
 */
extern struct user* user_create(struct hub_info* hub, int sd);

/**
 * Delete a user.
 *
 * !WRONG! If the user is logged in a quit message is issued.
 */
extern void user_destroy(struct user* user);

/**
 * Disconnect a user.
 * This will mark the user connection ready for being terminated.
 * A reason can be given using the enum user_quit_reason.
 *
 * Things to be done when calling this:
 * - Mark the user with state_cleanup
 *
 * If the user is logged in to the hub:
 * - post message: UHUB_EVENT_USER_QUIT
 *
 * @param user User to disconnect
 * @param reason See enum user_quit_reason
 */
extern void user_disconnect(struct user* user, int reason);

/**
 * This associates a INF message to the user.
 * If the user already has a INF message associated, then this is
 * released before setting the new one.
 * 
 * @param info new inf message (can be NULL)
 */
extern void user_set_info(struct user* user, struct adc_message* info);

/**
 * Update a user's INF message.
 * Will parse replace all ellements in the user's inf message with
 * the parameters from the cmd (merge operation).
 */
extern void user_update_info(struct user* user, struct adc_message* cmd);

/**
 * Specify a user's state.
 * NOTE: DON'T, unless you know what you are doing.
 */
extern void user_set_state(struct user* user, enum user_state);

/**
 * Returns 1 if the user is in state state_normal, or 0 otherwise.
 */
extern int user_is_logged_in(struct user* user);

/**
 * Returns 1 if the user is in state_protocol.
 * Returns 0 otherwise.
 */
extern int user_is_protocol_negotiating(struct user* user);

/**
 * Returns 1 if the user is in state_protocol, state_identify or state_verify.
 * Returns 0 otherwise.
 */
extern int user_is_connecting(struct user* user);

/**
 * Returns 1 only if the user is in state_cleanup or state_disconnected.
 */
extern int user_is_disconnecting(struct user* user);

/**
 * Returns 1 if a user is protected, which includes users
 * having any form of elevated privileges.
 */
extern int user_is_protected(struct user* user);

/**
 * Returns 1 if a user is registered, with or without privileges.
 */
extern int user_is_registered(struct user* user);

/**
 * User supports the protocol extension as given in fourcc.
 * This is usually set while the user is connecting, but can
 * also be used to subscribe to a new class of messages from the
 * hub.
 *
 * @see enum user_flags
 */
extern void user_support_add(struct user* user, int fourcc);

/**
 * User no longer supports the protocol extension as given in fourcc.
 * This can be used to unsubscribe to certain messages generated by
 * the hub.
 * @see enum user_flags
 */
extern void user_support_remove(struct user* user, int fourcc);

/**
 * Sets the nat override flag for a user, this allows users on the same
 * subnet as a natted hub to spoof their IP in order to use active mode
 * on a natted hub.
 */
extern void user_set_nat_override(struct user* user);
extern int user_is_nat_override(struct user* user);

/**
 * Set a flag. @see enum user_flags
 */
extern void user_flag_set(struct user* user, enum user_flags flag);
extern void user_flag_unset(struct user* user, enum user_flags flag);

/**
 * Get a flag. @see enum user_flags
 */
extern int user_flag_get(struct user* user, enum user_flags flag);

/**
 * Check if a user supports 'feature' for feature casting (basis for 'Fxxx' messages)
 * The feature cast is specified as the 'SU' argument to the user's
 * INF-message.
 * 
 * @param feature a feature to lookup (example: 'TCP4' or 'UDP4')
 * @return 1 if 'feature' supported, or 0 otherwise
 */
extern int user_have_feature_cast_support(struct user* user, char feature[4]);

/**
 * Set feature cast support for feature.
 *
 * @param feature a feature to lookup (example: 'TCP4' or 'UDP4')
 * @return 1 if 'feature' supported, or 0 otherwise
 */
extern int user_set_feature_cast_support(struct user* u, char feature[4]);

/**
 * Remove all feature cast support features.
 */
extern void user_clear_feature_cast_support(struct user* u);

/**
 * Mark the user with a want-write flag, meaning it should poll for writability.
 */
extern void user_net_io_want_write(struct user* user);

/**
 * Mark the user with a want read flag, meaning it should poll for readability.
 */
extern void user_net_io_want_read(struct user* user, int timeout_s);

/**
 * Reset the last-write timer.
 */
extern void user_reset_last_write(struct user* user);

/**
 * Reset the last-write timer.
 */
extern void user_reset_last_read(struct user* user);

#endif /* HAVE_UHUB_USER_H */


