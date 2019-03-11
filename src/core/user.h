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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#ifndef HAVE_UHUB_USER_H
#define HAVE_UHUB_USER_H

struct hub_info;
struct hub_iobuf;
struct flood_control;

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
	feature_adcs    = 0x00000200, /** ADCS: ADC over TLS/SSL */
	feature_bas0    = 0x00000400, /** BAS0: Obsolete pre-ADC/1.0 protocol version */
	flag_flood      = 0x00400000, /** User has been notified about flooding. */
	flag_muted      = 0x00800000, /** User is muted (cannot chat) */
	flag_ignore     = 0x01000000, /** Ignore further reads */
	flag_maxbuf     = 0x02000000, /** Hit max buf read, ignore msg */
	flag_choke      = 0x04000000, /** Choked: Cannot send, waiting for write event */
	flag_want_read  = 0x08000000, /** Need to read (SSL) */
	flag_want_write = 0x10000000, /** Need to write (SSL) */
	flag_user_list  = 0x20000000, /** Send queue bypass (when receiving the send queue) */
	flag_pipeline   = 0x40000000, /** Hub message pipelining */
	flag_nat        = 0x80000000, /** nat override enabled */
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
	quit_socket_error   = 7,     /** A socket error occurred */
	quit_protocol_error = 8,     /** Fatal protocol error */
	quit_logon_error    = 9,     /** Unable to login (wrong password, CID/PID, etc) */
	quit_update_error   = 10,    /** Update error. INF update changed share/slot info and no longer satisfies the hub limits. */
	quit_hub_disabled   = 11,    /** Hub is disabled. No new connections allowed */
	quit_ghost_timeout  = 12,    /** The user is a ghost, and trying to login from another connection */
};

/** Returns an appropriate string for the given quit reason */
extern const char* user_get_quit_reason_string(enum user_quit_reason);

struct hub_user_info
{
	sid_t sid;                    /** session ID */
	char nick[MAX_NICK_LEN+1];    /** User's nick name */
	char cid[MAX_CID_LEN+1];      /** global client ID */
	char user_agent[MAX_UA_LEN+1];/** User agent string */
	struct ip_addr_encap addr;    /** User's IP address */
};

/**
 * This struct contains additional information about the user, such
 * as the number of bytes and files shared, and the number of hubs the
 * user is connected to, etc.
 */
struct hub_user_limits
{
	uint64_t            shared_size;           /** Shared size in bytes */
	size_t              shared_files;          /** The number of shared files */
	size_t              upload_slots;          /** The number of upload slots */
	size_t              hub_count_user;        /** The number of hubs connected as user */
	size_t              hub_count_registered;  /** The number of hubs connected as registered user */
	size_t              hub_count_operator;    /** The number of hubs connected as operator */
	size_t              hub_count_total;       /** The number of hubs connected to in total */
};

struct hub_user
{
	struct hub_user_info    id;                 /** Contains nick name and CID */
	enum auth_credentials   credentials;        /** see enum user_credentials */
	enum user_state         state;              /** see enum user_state */
	uint32_t                flags;              /** see enum user_flags */
	struct linked_list*     feature_cast;       /** Features supported by feature cast */
	struct adc_message*     info;               /** ADC 'INF' message (broadcasted to everyone joining the hub) */
	struct hub_info*        hub;                /** The hub instance this user belong to */
	struct ioq_recv*        recv_queue;
	struct ioq_send*        send_queue;
	struct net_connection*  connection;         /** Connection data */
	struct hub_user_limits  limits;             /** Data used for limitation */
	enum user_quit_reason   quit_reason;        /** Quit reason (see user_quit_reason) */

	struct flood_control   flood_chat;
	struct flood_control   flood_connect;
	struct flood_control   flood_search;
	struct flood_control   flood_update;
	struct flood_control   flood_extras;
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
extern struct hub_user* user_create(struct hub_info* hub, struct net_connection* con, struct ip_addr_encap* addr);

/**
 * Delete a user.
 *
 * !WRONG! If the user is logged in a quit message is issued.
 */
extern void user_destroy(struct hub_user* user);

/**
 * This associates a INF message to the user.
 * If the user already has a INF message associated, then this is
 * released before setting the new one.
 *
 * @param info new inf message (can be NULL)
 */
extern void user_set_info(struct hub_user* user, struct adc_message* info);

/**
 * Update a user's INF message.
 * Will parse replace all ellements in the user's inf message with
 * the parameters from the cmd (merge operation).
 */
extern void user_update_info(struct hub_user* user, struct adc_message* cmd);

/**
 * Specify a user's state.
 * NOTE: DON'T, unless you know what you are doing.
 */
extern void user_set_state(struct hub_user* user, enum user_state);

/**
 * Returns 1 if the user is in state state_normal, or 0 otherwise.
 */
extern int user_is_logged_in(struct hub_user* user);

/**
 * Returns 1 if the user is in state_protocol.
 * Returns 0 otherwise.
 */
extern int user_is_protocol_negotiating(struct hub_user* user);

/**
 * Returns 1 if the user is in state_protocol, state_identify or state_verify.
 * Returns 0 otherwise.
 */
extern int user_is_connecting(struct hub_user* user);

/**
 * Returns 1 only if the user is in state_cleanup or state_disconnected.
 */
extern int user_is_disconnecting(struct hub_user* user);

/**
 * Returns 1 if a user is protected, which includes users
 * having any form of elevated privileges.
 */
extern int user_is_protected(struct hub_user* user);

/**
 * Returns 1 if a user is registered, with or without privileges.
 */
extern int user_is_registered(struct hub_user* user);

/**
 * User supports the protocol extension as given in fourcc.
 * This is usually set while the user is connecting, but can
 * also be used to subscribe to a new class of messages from the
 * hub.
 *
 * @see enum user_flags
 */
extern void user_support_add(struct hub_user* user, int fourcc);

/**
 * User no longer supports the protocol extension as given in fourcc.
 * This can be used to unsubscribe to certain messages generated by
 * the hub.
 * @see enum user_flags
 */
extern void user_support_remove(struct hub_user* user, int fourcc);

extern const char* user_get_address(struct hub_user* user);

/**
 * Sets the nat override flag for a user, this allows users on the same
 * subnet as a natted hub to spoof their IP in order to use active mode
 * on a natted hub.
 */
extern void user_set_nat_override(struct hub_user* user);
extern int user_is_nat_override(struct hub_user* user);

/**
 * Set a flag. @see enum user_flags
 */
extern void user_flag_set(struct hub_user* user, enum user_flags flag);
extern void user_flag_unset(struct hub_user* user, enum user_flags flag);

/**
 * Get a flag. @see enum user_flags
 */
extern int user_flag_get(struct hub_user* user, enum user_flags flag);

/**
 * Check if a user supports 'feature' for feature casting (basis for 'Fxxx' messages)
 * The feature cast is specified as the 'SU' argument to the user's
 * INF-message.
 *
 * @param feature a feature to lookup (example: 'TCP4' or 'UDP4')
 * @return 1 if 'feature' supported, or 0 otherwise
 */
extern int user_have_feature_cast_support(struct hub_user* user, char feature[4]);

/**
 * Set feature cast support for feature.
 *
 * @param feature a feature to lookup (example: 'TCP4' or 'UDP4')
 * @return 1 if 'feature' supported, or 0 otherwise
 */
extern int user_set_feature_cast_support(struct hub_user* u, char feature[4]);

/**
 * Remove all feature cast support features.
 */
extern void user_clear_feature_cast_support(struct hub_user* u);

/**
 * Mark the user with a want-write flag, meaning it should poll for writability.
 */
extern void user_net_io_want_write(struct hub_user* user);

/**
 * Mark the user with a want read flag, meaning it should poll for readability.
 */
extern void user_net_io_want_read(struct hub_user* user);

#endif /* HAVE_UHUB_USER_H */


