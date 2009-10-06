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

#ifndef HAVE_UHUB_CONFIG_H
#define HAVE_UHUB_CONFIG_H

struct hub_config
{
	int server_port;             /**<<< "Server port to bind to (default: 1511)" */
	char* server_bind_addr;      /**<<< "Server bind address (default: '0.0.0.0' or '::')" */
	int server_listen_backlog;   /**<<< "Server listen backlog (default: 50)" */
	int hub_enabled;             /**<<< "Is server enabled (default: 1)" */
	int show_banner;             /**<<< "Show banner on connect (default: 1)" */
	int max_users;               /**<<< "Maximum number of users allowed on the hub (default: 500)" */
	int registered_users_only;   /**<<< "Allow registered users only (default: 0)" */
	int chat_only;               /**<<< "Allow chat only operation on hub (default: 0)" */
	int chat_is_privileged;      /**<<< "Allow chat for operators and above only (default: 0) */
	char* file_motd;             /**<<< "File containing the 'message of the day' (default: '' - no motd)" */
	char* file_acl;              /**<<< "File containing user database (default: '' - no known users)" */
	char* hub_name;              /**<<< "Name of hub (default: 'My uhub hub')" */
	char* hub_description;       /**<<< "Name of hub (default: 'no description')" */
	int max_recv_buffer;         /**<<< "Max read buffer before parse, per user (default: 4096)" */
	int max_send_buffer;         /**<<< "Max send buffer before disconnect, per user (default: 128K)" */
	int max_send_buffer_soft;    /**<<< "Max send buffer before message drops, per user (default: 96K)" */
	int low_bandwidth_mode;      /**<<< "If this is enabled, the hub will strip off elements from each user's info message to reduce bandwidth usage" */

	int max_chat_history;        /**<<< "Number of chat messages kept in history (default: 20)" */
	int max_logout_log;          /**<<< "Number of log entries for people leaving the hub. (default: 100) */

	/* Limits enforced on users */
	int limit_max_hubs_user;     /**<<< "Max concurrent hubs as a user. (0=off, default: 10)" */
	int limit_max_hubs_reg;      /**<<< "Max concurrent hubs as registered user. (0=off, default: 10)" */
	int limit_max_hubs_op;       /**<<< "Max concurrent hubs as operator. (0=off, default: 10)" */
	int limit_min_hubs_user;     /**<<< "Min concurrent hubs as a user. (0=off, default: 0)" */
	int limit_min_hubs_reg;      /**<<< "Min concurrent hubs as registered user. (0=off, default: 0)" */
	int limit_min_hubs_op;       /**<<< "Min concurrent hubs as operator. (0=off, default: 0)" */
	int limit_max_hubs;          /**<<< "Max total hub connections allowed, user/reg/op combined. (0=off, default: 25)" */
	int limit_min_share;         /**<<< "Limit minimum share size in megabytes (MiB) (0=off, default: 0)" */
	int limit_max_share;         /**<<< "Limit maximum share size in megabytes (MiB) (0=off, default: 0)" */
	int limit_min_slots;         /**<<< "Limit minimum number of slots open per user (0=off, default: 0)" */
	int limit_max_slots;         /**<<< "Limit maximum number of slots open per user (0=off, default: 0)" */

	/* Messages that can be sent to a user */
	char* msg_hub_full;                   /**<<< "hub is full" */
	char* msg_hub_disabled;               /**<<< "hub is disabled" */
	char* msg_hub_registered_users_only;  /**<<< "hub is for registered users only" */
	char* msg_inf_error_nick_missing;     /**<<< "no nickname given" */
	char* msg_inf_error_nick_multiple;    /**<<< "multiple nicknames given" */
	char* msg_inf_error_nick_invalid;     /**<<< "generic/unkown" */
	char* msg_inf_error_nick_long;        /**<<< "nickname too long" */
	char* msg_inf_error_nick_short;       /**<<< "nickname too short" */
	char* msg_inf_error_nick_spaces;      /**<<< "nickname cannot start with spaces" */
	char* msg_inf_error_nick_bad_chars;   /**<<< "nickname contains chars below ascii 32" */
	char* msg_inf_error_nick_not_utf8;    /**<<< "nickname is not valid utf8" */
	char* msg_inf_error_nick_taken;       /**<<< "nickname is in use" */
	char* msg_inf_error_nick_restricted;  /**<<< "nickname cannot be used on this hub" */
	char* msg_inf_error_cid_invalid;      /**<<< "CID is not valid" */
	char* msg_inf_error_cid_missing;      /**<<< "CID is not specified" */
	char* msg_inf_error_cid_taken;        /**<<< "CID is taken" */
	char* msg_inf_error_pid_missing;      /**<<< "PID is not specified" */
	char* msg_inf_error_pid_invalid;      /**<<< "PID is invalid" */
	char* msg_ban_permanently;            /**<<< "Banned permanently" */
	char* msg_ban_temporarily;            /**<<< "Banned temporarily" */
	char* msg_auth_invalid_password;      /**<<< "Password is wrong" */
	char* msg_auth_user_not_found;        /**<<< "User not found in password database" */
	char* msg_error_no_memory;            /**<<< "No memory" */
	char* msg_user_share_size_low;        /**<<< "User is not sharing enough" */
	char* msg_user_share_size_high;       /**<<< "User is sharing too much" */
	char* msg_user_slots_low;             /**<<< "User have too few upload slots." */
	char* msg_user_slots_high;            /**<<< "User have too many upload slots." */
	char* msg_user_hub_limit_low;         /**<<< "User is on too few hubs." */
	char* msg_user_hub_limit_high;        /**<<< "User is on too many hubs." */

	int tls_enable;                      /**<<< "Enable SSL/TLS support (default: 0)" */
	int tls_require;                     /**<<< "If SSL/TLS enabled, should it be required (default: 0) */
	char* tls_certificate;               /**<<< "Certificate file (PEM)" */
	char* tls_private_key;               /**<<< "Private key" */
};

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

