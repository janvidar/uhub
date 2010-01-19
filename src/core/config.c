/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2010, Jan Vidar Krey
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


#ifndef INT_MAX
#define INT_MAX 0x7fffffff
#endif

#ifndef INT_MIN
#define INT_MIN (-0x7fffffff - 1)
#endif

#define CFG_APPLY_BOOLEAN(KEY, TARGET) \
	if (strcmp(KEY, key) == 0) \
	{ \
		if      (strlen(data) == 1 && (data[0] == '1')) TARGET = 1; \
		else if (strlen(data) == 1 && (data[0] == '0')) TARGET = 0; \
		else if (strncasecmp(data, "true",  4) == 0) TARGET = 1; \
		else if (strncasecmp(data, "false", 5) == 0) TARGET = 0; \
		else if (strncasecmp(data, "yes",   3) == 0) TARGET = 1; \
		else if (strncasecmp(data, "no",    2) == 0) TARGET = 0; \
		else if (strncasecmp(data, "on",    2) == 0) TARGET = 1; \
		else if (strncasecmp(data, "off",   3) == 0) TARGET = 0; \
		else\
		{ \
			LOG_FATAL("Configuration error on line %d: '%s' must be either '1' or '0'", line_count, key); \
			return -1; \
		} \
		TARGET |= 0x80000000; \
		return 0; \
	}

#define CFG_APPLY_STRING(KEY, TARGET) \
	if (strcmp(KEY, key) == 0) \
	{ \
		TARGET = hub_strdup(data); \
		return 0; \
	}


#define CFG_APPLY_INTEGER(KEY, TARGET) \
	if (strcmp(KEY, key) == 0) \
	{ \
		char* endptr; \
		int val; \
		errno = 0; \
		val = strtol(data, &endptr, 10); \
		if (((errno == ERANGE && (val == INT_MAX || val == INT_MIN)) || (errno != 0 && val == 0)) || endptr == data) { \
			LOG_FATAL("Configuration error on line %d: '%s' must be a number", line_count, key); \
			return -1; \
		} \
		TARGET = val; \
		return 0; \
	}


#define DEFAULT_STRING(KEY, VALUE) \
{ \
	if (config->KEY == 0) \
		config->KEY = hub_strdup(VALUE); \
}

#define DEFAULT_INTEGER(KEY, VALUE) \
{ \
	if (config->KEY == 0) \
		config->KEY = VALUE; \
}

#define DEFAULT_BOOLEAN(KEY, VALUE) \
{ \
	if (config->KEY & 0x80000000) \
	{ \
		config->KEY = config->KEY & 0x000000ff; \
	} \
	else \
	{ \
		config->KEY = VALUE; \
	} \
}

#define GET_STR(NAME)  CFG_APPLY_STRING ( #NAME , config->NAME )
#define GET_INT(NAME)  CFG_APPLY_INTEGER( #NAME , config->NAME )
#define GET_BOOL(NAME) CFG_APPLY_BOOLEAN( #NAME , config->NAME )
#define IGNORED(NAME) \
    if (strcmp(#NAME, key) == 0) \
    { \
        LOG_WARN("Configuration option %s deprecated and ingnored.", key); \
        return 0; \
    } \

/* default configuration values */
#define DEF_SERVER_BIND_ADDR                "any"
#define DEF_SERVER_PORT                     1511
#define DEF_SERVER_BACKLOG                  50
#define DEF_HUB_NAME                        "uhub"
#define DEF_HUB_DESCRIPTION                 ""
#define DEF_HUB_ENABLED                     1
#define DEF_FILE_ACL                        ""
#define DEF_FILE_MOTD                       ""
#define DEF_FILE_RULES                      ""
#define DEF_MAX_USERS                       500
#define DEF_MAX_CHAT_HISTORY                20
#define DEF_MAX_LOGOUT_LOG                  100
#define DEF_MAX_RECV_BUFFER                 4096
#define DEF_MAX_SEND_BUFFER                 131072
#define DEF_MAX_SEND_BUFFER_SOFT            98304
#define DEF_SHOW_BANNER                     1
#define DEF_REGISTERED_USERS_ONLY           0
#define DEF_CHAT_ONLY                       0
#define DEF_CHAT_IS_PRIVILEGED              0
#define DEF_LOW_BANDWIDTH_MODE              0
#define DEF_LIMIT_MAX_HUBS_USER             0
#define DEF_LIMIT_MAX_HUBS_REG              0
#define DEF_LIMIT_MAX_HUBS_OP               0
#define DEF_LIMIT_MAX_HUBS                  0
#define DEF_LIMIT_MIN_HUBS_USER             0
#define DEF_LIMIT_MIN_HUBS_REG              0
#define DEF_LIMIT_MIN_HUBS_OP               0
#define DEF_LIMIT_MIN_SHARE                 0
#define DEF_LIMIT_MAX_SHARE                 0
#define DEF_LIMIT_MIN_SLOTS                 0
#define DEF_LIMIT_MAX_SLOTS                 0
#define DEF_TLS_ENABLE                      0
#define DEF_TLS_REQUIRE                     1
#define DEF_TLS_PRIVATE_KEY                 ""
#define DEF_TLS_CERTIFICATE                 ""
#define DEF_MSG_HUB_FULL                    "Hub is full"
#define DEF_MSG_HUB_DISABLED                "Hub is disabled"
#define DEF_MSG_HUB_REGISTERED_USERS_ONLY   "Hub is for registered users only"
#define DEF_MSG_INF_ERROR_NICK_MISSING      "No nickname given"
#define DEF_MSG_INF_ERROR_NICK_MULTIPLE     "Multiple nicknames given"
#define DEF_MSG_INF_ERROR_NICK_INVALID      "Nickname is invalid"
#define DEF_MSG_INF_ERROR_NICK_LONG         "Nickname too long"
#define DEF_MSG_INF_ERROR_NICK_SHORT        "Nickname too short"
#define DEF_MSG_INF_ERROR_NICK_SPACES       "Nickname cannot start with spaces"
#define DEF_MSG_INF_ERROR_NICK_BAD_CHARS    "Nickname contains invalid characters"
#define DEF_MSG_INF_ERROR_NICK_NOT_UTF8     "Nickname is not valid utf8"
#define DEF_MSG_INF_ERROR_NICK_TAKEN        "Nickname is already in use"
#define DEF_MSG_INF_ERROR_NICK_RESTRICTED   "Nickname cannot be used on this hub"
#define DEF_MSG_INF_ERROR_CID_INVALID       "CID is not valid"
#define DEF_MSG_INF_ERROR_CID_MISSING       "CID is not specified"
#define DEF_MSG_INF_ERROR_CID_TAKEN         "CID is taken"
#define DEF_MSG_INF_ERROR_PID_MISSING       "PID is not specified"
#define DEF_MSG_INF_ERROR_PID_INVALID       "PID is invalid"
#define DEF_MSG_BAN_PERMANENTLY             "Banned permanently"
#define DEF_MSG_BAN_TEMPORARILY             "Banned temporarily"
#define DEF_MSG_AUTH_INVALID_PASSWORD       "Password is wrong"
#define DEF_MSG_AUTH_USER_NOT_FOUND         "User not found in password database"
#define DEF_MSG_ERROR_NO_MEMORY             "No memory"
#define DEF_MSG_USER_SHARE_SIZE_LOW         "User is not sharing enough"
#define DEF_MSG_USER_SHARE_SIZE_HIGH        "User is sharing too much"
#define DEF_MSG_USER_SLOTS_LOW              "User have too few upload slots."
#define DEF_MSG_USER_SLOTS_HIGH             "User have too many upload slots."
#define DEF_MSG_USER_HUB_LIMIT_LOW          "User is on too few hubs."
#define DEF_MSG_USER_HUB_LIMIT_HIGH         "User is on too many hubs."

void config_defaults(struct hub_config* config)
{
	DEFAULT_STRING (server_bind_addr,      DEF_SERVER_BIND_ADDR);
	DEFAULT_STRING (hub_name,              DEF_HUB_NAME);
	DEFAULT_STRING (hub_description,       DEF_HUB_DESCRIPTION);
	DEFAULT_BOOLEAN(hub_enabled,           DEF_HUB_ENABLED);
	DEFAULT_STRING (file_acl,              DEF_FILE_ACL);
	DEFAULT_STRING (file_motd,             DEF_FILE_MOTD);
	DEFAULT_STRING (file_rules,            DEF_FILE_RULES);
	DEFAULT_INTEGER(server_port,           DEF_SERVER_PORT);
	DEFAULT_INTEGER(server_listen_backlog, DEF_SERVER_BACKLOG);
	DEFAULT_INTEGER(max_users,             DEF_MAX_USERS);
	DEFAULT_INTEGER(max_chat_history,      DEF_MAX_CHAT_HISTORY);
	DEFAULT_INTEGER(max_logout_log,        DEF_MAX_LOGOUT_LOG);
	DEFAULT_INTEGER(max_recv_buffer,       DEF_MAX_RECV_BUFFER);
	DEFAULT_INTEGER(max_send_buffer,       DEF_MAX_SEND_BUFFER);
	DEFAULT_INTEGER(max_send_buffer_soft,  DEF_MAX_SEND_BUFFER_SOFT);
	DEFAULT_BOOLEAN(show_banner,           DEF_SHOW_BANNER);
	DEFAULT_BOOLEAN(chat_only,             DEF_CHAT_ONLY);
	DEFAULT_BOOLEAN(chat_is_privileged,    DEF_CHAT_IS_PRIVILEGED);
	DEFAULT_BOOLEAN(low_bandwidth_mode,    DEF_LOW_BANDWIDTH_MODE);
	DEFAULT_BOOLEAN(registered_users_only, DEF_REGISTERED_USERS_ONLY);
	
	/* Limits enforced on users */
	DEFAULT_INTEGER(limit_max_hubs_user,   DEF_LIMIT_MAX_HUBS_USER);
	DEFAULT_INTEGER(limit_max_hubs_reg,    DEF_LIMIT_MAX_HUBS_REG);
	DEFAULT_INTEGER(limit_max_hubs_op,     DEF_LIMIT_MAX_HUBS_OP);
	DEFAULT_INTEGER(limit_min_hubs_user,   DEF_LIMIT_MIN_HUBS_USER);
	DEFAULT_INTEGER(limit_min_hubs_reg,    DEF_LIMIT_MIN_HUBS_REG);
	DEFAULT_INTEGER(limit_min_hubs_op,     DEF_LIMIT_MIN_HUBS_OP);
	DEFAULT_INTEGER(limit_max_hubs,        DEF_LIMIT_MAX_HUBS);
	DEFAULT_INTEGER(limit_min_share,       DEF_LIMIT_MIN_SHARE);
	DEFAULT_INTEGER(limit_max_share,       DEF_LIMIT_MAX_SHARE);
	DEFAULT_INTEGER(limit_min_slots,       DEF_LIMIT_MIN_SLOTS);
	DEFAULT_INTEGER(limit_max_slots,       DEF_LIMIT_MAX_SLOTS);

	/* Status/error strings */
	DEFAULT_STRING (msg_hub_full,                  DEF_MSG_HUB_FULL);
	DEFAULT_STRING (msg_hub_disabled,              DEF_MSG_HUB_DISABLED)
	DEFAULT_STRING (msg_hub_registered_users_only, DEF_MSG_HUB_REGISTERED_USERS_ONLY);
	DEFAULT_STRING (msg_inf_error_nick_missing,    DEF_MSG_INF_ERROR_NICK_MISSING);
	DEFAULT_STRING (msg_inf_error_nick_multiple,   DEF_MSG_INF_ERROR_NICK_MULTIPLE);
	DEFAULT_STRING (msg_inf_error_nick_invalid,    DEF_MSG_INF_ERROR_NICK_INVALID);
	DEFAULT_STRING (msg_inf_error_nick_long,       DEF_MSG_INF_ERROR_NICK_LONG);
	DEFAULT_STRING (msg_inf_error_nick_short,      DEF_MSG_INF_ERROR_NICK_SHORT);
	DEFAULT_STRING (msg_inf_error_nick_spaces,     DEF_MSG_INF_ERROR_NICK_SPACES);
	DEFAULT_STRING (msg_inf_error_nick_bad_chars,  DEF_MSG_INF_ERROR_NICK_BAD_CHARS);
	DEFAULT_STRING (msg_inf_error_nick_not_utf8,   DEF_MSG_INF_ERROR_NICK_NOT_UTF8);
	DEFAULT_STRING (msg_inf_error_nick_taken,      DEF_MSG_INF_ERROR_NICK_TAKEN);
	DEFAULT_STRING (msg_inf_error_nick_restricted, DEF_MSG_INF_ERROR_NICK_RESTRICTED);
	DEFAULT_STRING (msg_inf_error_cid_invalid,     DEF_MSG_INF_ERROR_CID_INVALID);
	DEFAULT_STRING (msg_inf_error_cid_missing,     DEF_MSG_INF_ERROR_CID_MISSING);
	DEFAULT_STRING (msg_inf_error_cid_taken,       DEF_MSG_INF_ERROR_CID_TAKEN);
	DEFAULT_STRING (msg_inf_error_pid_missing,     DEF_MSG_INF_ERROR_PID_MISSING);
	DEFAULT_STRING (msg_inf_error_pid_invalid,     DEF_MSG_INF_ERROR_PID_INVALID);
	DEFAULT_STRING (msg_ban_permanently,           DEF_MSG_BAN_PERMANENTLY);
	DEFAULT_STRING (msg_ban_temporarily,           DEF_MSG_BAN_TEMPORARILY);
	DEFAULT_STRING (msg_auth_invalid_password,     DEF_MSG_AUTH_INVALID_PASSWORD);
	DEFAULT_STRING (msg_auth_user_not_found,       DEF_MSG_AUTH_USER_NOT_FOUND);
	DEFAULT_STRING (msg_error_no_memory,           DEF_MSG_ERROR_NO_MEMORY);
	DEFAULT_STRING (msg_user_share_size_low,       DEF_MSG_USER_SHARE_SIZE_LOW);
	DEFAULT_STRING (msg_user_share_size_high,      DEF_MSG_USER_SHARE_SIZE_HIGH);
	DEFAULT_STRING (msg_user_slots_low,            DEF_MSG_USER_SLOTS_LOW);
	DEFAULT_STRING (msg_user_slots_high,           DEF_MSG_USER_SLOTS_HIGH);
	DEFAULT_STRING (msg_user_hub_limit_low,        DEF_MSG_USER_HUB_LIMIT_LOW);
	DEFAULT_STRING (msg_user_hub_limit_high,       DEF_MSG_USER_HUB_LIMIT_HIGH);

	DEFAULT_INTEGER(tls_enable,                    DEF_TLS_ENABLE);
	DEFAULT_INTEGER(tls_require,                   DEF_TLS_REQUIRE);
	DEFAULT_STRING (tls_certificate,               DEF_TLS_CERTIFICATE);
	DEFAULT_STRING (tls_private_key,               DEF_TLS_PRIVATE_KEY);
}


static int apply_config(struct hub_config* config, char* key, char* data, int line_count)
{
	GET_STR (file_acl);
	GET_STR (file_motd);
	GET_STR (file_rules);
	GET_STR (server_bind_addr);
	GET_INT (server_port);
	GET_INT (server_listen_backlog);
	GET_STR (hub_name);
	GET_STR (hub_description);
	GET_BOOL(hub_enabled);
	GET_INT (max_users);
	GET_INT (max_chat_history);
	GET_INT (max_logout_log);
	GET_INT (max_recv_buffer);
	GET_INT (max_send_buffer);
	GET_INT (max_send_buffer_soft);
	GET_BOOL(show_banner);
	GET_BOOL(chat_only);
	GET_BOOL(chat_is_privileged);
	GET_BOOL(low_bandwidth_mode);
	GET_BOOL(registered_users_only);

	/* Limits enforced on users */
	GET_INT(limit_max_hubs_user);
	GET_INT(limit_max_hubs_reg);
	GET_INT(limit_max_hubs_op);
	GET_INT(limit_min_hubs_user);
	GET_INT(limit_min_hubs_reg);
	GET_INT(limit_min_hubs_op);
	GET_INT(limit_max_hubs);
	GET_INT(limit_min_share);
	GET_INT(limit_max_share);
	GET_INT(limit_min_slots);
	GET_INT(limit_max_slots);
	
	/* Status/error strings */
	GET_STR (msg_hub_full);
	GET_STR (msg_hub_disabled);
	GET_STR (msg_hub_registered_users_only);
	GET_STR (msg_inf_error_nick_missing);
	GET_STR (msg_inf_error_nick_multiple);
	GET_STR (msg_inf_error_nick_invalid);
	GET_STR (msg_inf_error_nick_long);
	GET_STR (msg_inf_error_nick_short);
	GET_STR (msg_inf_error_nick_spaces);
	GET_STR (msg_inf_error_nick_bad_chars);
	GET_STR (msg_inf_error_nick_not_utf8);
	GET_STR (msg_inf_error_nick_taken);
	GET_STR (msg_inf_error_nick_restricted);
	GET_STR (msg_inf_error_cid_invalid);
	GET_STR (msg_inf_error_cid_missing);
	GET_STR (msg_inf_error_cid_taken);
	GET_STR (msg_inf_error_pid_missing);
	GET_STR (msg_inf_error_pid_invalid);
	GET_STR (msg_ban_permanently);
	GET_STR (msg_ban_temporarily);
	GET_STR (msg_auth_invalid_password);
	GET_STR (msg_auth_user_not_found);
	GET_STR (msg_error_no_memory);
	GET_STR (msg_user_share_size_low);
	GET_STR (msg_user_share_size_high);
	GET_STR (msg_user_slots_low);
	GET_STR (msg_user_slots_high);
	GET_STR (msg_user_hub_limit_low);
	GET_STR (msg_user_hub_limit_high);

	GET_BOOL(tls_enable);
	GET_BOOL(tls_require);
	GET_STR (tls_certificate);
	GET_STR (tls_private_key);

    /* Still here -- unknown directive */
	LOG_ERROR("Unknown configuration directive: '%s'", key);
	return -1;
}


void free_config(struct hub_config* config)
{
	hub_free(config->server_bind_addr);
	hub_free(config->file_motd);
	hub_free(config->file_acl);
	hub_free(config->file_rules);
	hub_free(config->hub_name);
	hub_free(config->hub_description);
	
	hub_free(config->msg_hub_full);
	hub_free(config->msg_hub_disabled);
	hub_free(config->msg_hub_registered_users_only);
	hub_free(config->msg_inf_error_nick_missing);
	hub_free(config->msg_inf_error_nick_multiple);
	hub_free(config->msg_inf_error_nick_invalid);
	hub_free(config->msg_inf_error_nick_long);
	hub_free(config->msg_inf_error_nick_short);
	hub_free(config->msg_inf_error_nick_spaces);
	hub_free(config->msg_inf_error_nick_bad_chars);
	hub_free(config->msg_inf_error_nick_not_utf8);
	hub_free(config->msg_inf_error_nick_taken);
	hub_free(config->msg_inf_error_nick_restricted);
	hub_free(config->msg_inf_error_cid_invalid);
	hub_free(config->msg_inf_error_cid_missing);
	hub_free(config->msg_inf_error_cid_taken);
	hub_free(config->msg_inf_error_pid_missing);
	hub_free(config->msg_inf_error_pid_invalid);
	hub_free(config->msg_ban_permanently);
	hub_free(config->msg_ban_temporarily);
	hub_free(config->msg_auth_invalid_password);
	hub_free(config->msg_auth_user_not_found);
	hub_free(config->msg_error_no_memory);
	hub_free(config->msg_user_share_size_low);
	hub_free(config->msg_user_share_size_high);
	hub_free(config->msg_user_slots_low);
	hub_free(config->msg_user_slots_high);
	hub_free(config->msg_user_hub_limit_low);
	hub_free(config->msg_user_hub_limit_high);
	
	hub_free(config->tls_certificate);
	hub_free(config->tls_private_key);
	
	memset(config, 0, sizeof(struct hub_config));
}

#define DUMP_STR(NAME, DEFAULT) \
	if (ignore_defaults) \
	{ \
		if (strcmp(config->NAME, DEFAULT) != 0) \
			fprintf(stdout, "%s = \"%s\"\n", #NAME , config->NAME); \
	} \
	else \
		fprintf(stdout, "%s = \"%s\"\n", #NAME , config->NAME); \
		
#define DUMP_INT(NAME, DEFAULT) \
	if (ignore_defaults) \
	{ \
		if (config->NAME != DEFAULT) \
			fprintf(stdout, "%s = %d\n", #NAME , config->NAME); \
	} \
	else \
		fprintf(stdout, "%s = %d\n", #NAME , config->NAME); \


#define DUMP_BOOL(NAME, DEFAULT) \
	if (ignore_defaults) \
	{ \
		if (config->NAME != DEFAULT) \
			fprintf(stdout, "%s = %s\n", #NAME , (config->NAME ? "yes" : "no")); \
	} \
	else \
		fprintf(stdout, "%s = %s\n", #NAME , (config->NAME ? "yes" : "no"));

void dump_config(struct hub_config* config, int ignore_defaults)
{
	DUMP_STR (file_acl, DEF_FILE_ACL);
	DUMP_STR (file_motd, DEF_FILE_MOTD);
	DUMP_STR (file_rules, DEF_FILE_RULES);
	DUMP_STR (server_bind_addr, DEF_SERVER_BIND_ADDR);
	DUMP_INT (server_port, DEF_SERVER_PORT);
	DUMP_INT (server_listen_backlog, DEF_SERVER_BACKLOG);
	DUMP_STR (hub_name, DEF_HUB_NAME);
	DUMP_STR (hub_description, DEF_HUB_DESCRIPTION);
	DUMP_BOOL(hub_enabled, DEF_HUB_ENABLED);
	DUMP_INT (max_users, DEF_MAX_USERS);
	DUMP_INT (max_chat_history, DEF_MAX_CHAT_HISTORY);
	DUMP_INT (max_logout_log, DEF_MAX_LOGOUT_LOG);
	DUMP_INT (max_recv_buffer, DEF_MAX_RECV_BUFFER);
	DUMP_INT (max_send_buffer, DEF_MAX_SEND_BUFFER);
	DUMP_INT (max_send_buffer_soft, DEF_MAX_SEND_BUFFER_SOFT);
	DUMP_BOOL(show_banner, DEF_SHOW_BANNER);
	DUMP_BOOL(chat_only, DEF_CHAT_ONLY);
	DUMP_BOOL(chat_is_privileged, DEF_CHAT_IS_PRIVILEGED);
	DUMP_BOOL(low_bandwidth_mode, DEF_LOW_BANDWIDTH_MODE);
	DUMP_BOOL(registered_users_only, DEF_REGISTERED_USERS_ONLY);

#ifdef SSL_SUPPORT
	DUMP_BOOL(tls_enable, DEF_TLS_ENABLE);
	DUMP_BOOL(tls_require, DEF_TLS_REQUIRE);
	DUMP_STR (tls_certificate, DEF_TLS_CERTIFICATE);
	DUMP_STR (tls_private_key, DEF_TLS_PRIVATE_KEY);
#endif

	/* Limits enforced on users */
	DUMP_INT(limit_max_hubs_user, DEF_LIMIT_MAX_HUBS_USER);
	DUMP_INT(limit_max_hubs_reg, DEF_LIMIT_MAX_HUBS_REG);
	DUMP_INT(limit_max_hubs_op, DEF_LIMIT_MAX_HUBS_OP);
	DUMP_INT(limit_min_hubs_user, DEF_LIMIT_MIN_HUBS_USER);
	DUMP_INT(limit_min_hubs_reg, DEF_LIMIT_MIN_HUBS_REG);
	DUMP_INT(limit_min_hubs_op, DEF_LIMIT_MIN_HUBS_OP);
	DUMP_INT(limit_max_hubs, DEF_LIMIT_MAX_HUBS);
	DUMP_INT(limit_min_share, DEF_LIMIT_MIN_SHARE);
	DUMP_INT(limit_max_share, DEF_LIMIT_MAX_SHARE);
	DUMP_INT(limit_min_slots, DEF_LIMIT_MIN_SLOTS);
	DUMP_INT(limit_max_slots, DEF_LIMIT_MAX_SLOTS);
	
	/* Status/error strings */
	DUMP_STR (msg_hub_full, DEF_MSG_HUB_FULL);
	DUMP_STR (msg_hub_disabled, DEF_MSG_HUB_DISABLED);
	DUMP_STR (msg_hub_registered_users_only, DEF_MSG_HUB_REGISTERED_USERS_ONLY);
	DUMP_STR (msg_inf_error_nick_missing, DEF_MSG_INF_ERROR_NICK_MISSING);
	DUMP_STR (msg_inf_error_nick_multiple, DEF_MSG_INF_ERROR_NICK_MULTIPLE);
	DUMP_STR (msg_inf_error_nick_invalid, DEF_MSG_INF_ERROR_NICK_INVALID);
	DUMP_STR (msg_inf_error_nick_long, DEF_MSG_INF_ERROR_NICK_LONG);
	DUMP_STR (msg_inf_error_nick_short, DEF_MSG_INF_ERROR_NICK_SHORT);
	DUMP_STR (msg_inf_error_nick_spaces, DEF_MSG_INF_ERROR_NICK_SPACES);
	DUMP_STR (msg_inf_error_nick_bad_chars, DEF_MSG_INF_ERROR_NICK_BAD_CHARS);
	DUMP_STR (msg_inf_error_nick_not_utf8, DEF_MSG_INF_ERROR_NICK_NOT_UTF8);
	DUMP_STR (msg_inf_error_nick_taken, DEF_MSG_INF_ERROR_NICK_TAKEN);
	DUMP_STR (msg_inf_error_nick_restricted, DEF_MSG_INF_ERROR_NICK_RESTRICTED);
	DUMP_STR (msg_inf_error_cid_invalid, DEF_MSG_INF_ERROR_CID_INVALID);
	DUMP_STR (msg_inf_error_cid_missing, DEF_MSG_INF_ERROR_CID_MISSING);
	DUMP_STR (msg_inf_error_cid_taken, DEF_MSG_INF_ERROR_CID_TAKEN);
	DUMP_STR (msg_inf_error_pid_missing, DEF_MSG_INF_ERROR_PID_MISSING);
	DUMP_STR (msg_inf_error_pid_invalid, DEF_MSG_INF_ERROR_PID_INVALID);
	DUMP_STR (msg_ban_permanently, DEF_MSG_BAN_PERMANENTLY);
	DUMP_STR (msg_ban_temporarily, DEF_MSG_BAN_TEMPORARILY);
	DUMP_STR (msg_auth_invalid_password, DEF_MSG_AUTH_INVALID_PASSWORD);
	DUMP_STR (msg_auth_user_not_found, DEF_MSG_AUTH_USER_NOT_FOUND);
	DUMP_STR (msg_error_no_memory, DEF_MSG_ERROR_NO_MEMORY);
	DUMP_STR (msg_user_share_size_low, DEF_MSG_USER_SHARE_SIZE_LOW);
	DUMP_STR (msg_user_share_size_high, DEF_MSG_USER_SHARE_SIZE_HIGH);
	DUMP_STR (msg_user_slots_low, DEF_MSG_USER_SLOTS_LOW);
	DUMP_STR (msg_user_slots_high, DEF_MSG_USER_SLOTS_HIGH);
	DUMP_STR (msg_user_hub_limit_low, DEF_MSG_USER_HUB_LIMIT_LOW);
	DUMP_STR (msg_user_hub_limit_high, DEF_MSG_USER_HUB_LIMIT_HIGH);
}


static int config_parse_line(char* line, int line_count, void* ptr_data)
{
	char* pos;
	char* key;
	char* data;
	struct hub_config* config = (struct hub_config*) ptr_data;

	if ((pos = strchr(line, '#')) != NULL)
	{
		pos[0] = 0;
	}

	if (!*line) return 0;

	LOG_DUMP("config_parse_line(): '%s'", line);

	if (!is_valid_utf8(line))
	{
		LOG_WARN("Invalid utf-8 characters on line %d", line_count);
	}

	if ((pos = strchr(line, '=')) != NULL)
	{
		pos[0] = 0;
	}
	else
	{
		return 0;
	}

	key = line;
	data = &pos[1];

	key = strip_white_space(key);
	data = strip_white_space(data);

	if (!*key || !*data)
	{
		LOG_FATAL("Configuration parse error on line %d", line_count);
		return -1;
	}

	LOG_DUMP("config_parse_line: '%s' => '%s'", key, data);

	return apply_config(config, key, data, line_count);
}


int read_config(const char* file, struct hub_config* config, int allow_missing)
{
	int ret;

	memset(config, 0, sizeof(struct hub_config));

	ret = file_read_lines(file, config, &config_parse_line);
	if (ret < 0)
	{
		if (allow_missing && ret == -2)
		{
			LOG_DUMP("Using default configuration.");
		}
		else
		{
			return -1;
		}
	}

	config_defaults(config);
	return 0;
}


