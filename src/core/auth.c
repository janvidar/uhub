/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
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

#include "util/list.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "util/tiger.h"
#include "network/connection.h"
#include "network/network.h"
#include "core/auth.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/plugininvoke.h"
#include "core/user.h"

#define ACL_ADD_USER(S, L, V) do { ret = check_cmd_user(S, V, L, line, line_count); if (ret != 0) return ret; } while(0)
#define ACL_ADD_BOOL(S, L)    do { ret = check_cmd_bool(S,    L, line, line_count); if (ret != 0) return ret; } while(0)
#define ACL_ADD_ADDR(S, L)    do { ret = check_cmd_addr(S,    L, line, line_count); if (ret != 0) return ret; } while(0)

/*
 * If `line` starts with `cmd` followed by whitespace or end-of-string,
 * NUL-terminate the keyword in place and return a pointer to the
 * trimmed argument. Returns NULL on no match. Sets *err to -1 if the
 * keyword matches but has no argument; otherwise leaves *err alone.
 */
static char* acl_match_keyword(const char* cmd, char* line, int line_count, int* err)
{
	size_t cmd_len = strlen(cmd);
	char* data;

	if (strncmp(line, cmd, cmd_len) != 0)
		return NULL;

	/* Keyword must be a whole token, not a prefix of a longer one. */
	if (line[cmd_len] != ' ' && line[cmd_len] != '\t' && line[cmd_len] != '\0')
		return NULL;

	if (line[cmd_len] == '\0')
	{
		LOG_FATAL("ACL parse error on line %d", line_count);
		*err = -1;
		return NULL;
	}

	line[cmd_len] = '\0';
	data = strip_white_space(&line[cmd_len + 1]);
	if (!*data)
	{
		LOG_FATAL("ACL parse error on line %d", line_count);
		*err = -1;
		return NULL;
	}
	return data;
}

static int check_cmd_bool(const char* cmd, struct linked_list* list, char* line, int line_count)
{
	int err = 0;
	char* data = acl_match_keyword(cmd, line, line_count, &err);
	if (err) return err;
	if (!data) return 0;

	list_append(list, hub_strdup(data));
	LOG_DEBUG("ACL: Deny access for: '%s' (%s)", data, cmd);
	return 1;
}

static int check_cmd_user(const char* cmd, int status, struct linked_list* list, char* line, int line_count)
{
	char* data;
	char* data_extra = 0;
	struct auth_info* info = 0;
	int err = 0;

	data = acl_match_keyword(cmd, line, line_count, &err);
	if (err) return err;
	if (!data) return 0;

	info = hub_malloc_zero(sizeof(struct auth_info));
	if (!info)
	{
		LOG_ERROR("ACL parse error. Out of memory!");
		return -1;
	}

	if (strncmp(cmd, "user_", 5) == 0)
	{
		data_extra = strrchr(data, ':');
		if (data_extra)
		{
			data_extra[0] = 0;
			data_extra++;
		}
	}

	strncpy(info->nickname, data, MAX_NICK_LEN);
	info->nickname[MAX_NICK_LEN] = '\0';
	if (data_extra)
	{
		strncpy(info->password, data_extra, MAX_PASS_LEN);
		info->password[MAX_PASS_LEN] = '\0';
	}
	info->credentials = status;
	list_append(list, info);
	LOG_DEBUG("ACL: Added user '%s' (%s)", info->nickname, auth_cred_to_string(info->credentials));
	return 1;
}


static void add_ip_range(struct linked_list* list, struct ip_range* info)
{
	char buf1[INET6_ADDRSTRLEN+1];
	char buf2[INET6_ADDRSTRLEN+1];

	if (info->lo.af == AF_INET)
	{
		net_address_to_string(AF_INET, &info->lo.internal_ip_data.in.s_addr, buf1, INET6_ADDRSTRLEN);
		net_address_to_string(AF_INET, &info->hi.internal_ip_data.in.s_addr, buf2, INET6_ADDRSTRLEN);
	}
	else if (info->lo.af == AF_INET6)
	{
		net_address_to_string(AF_INET6, &info->lo.internal_ip_data.in6, buf1, INET6_ADDRSTRLEN);
		net_address_to_string(AF_INET6, &info->hi.internal_ip_data.in6, buf2, INET6_ADDRSTRLEN);
	}
	LOG_DEBUG("ACL: Added ip range: %s-%s", buf1, buf2);

	list_append(list, info);
}


static int check_cmd_addr(const char* cmd, struct linked_list* list, char* line, int line_count)
{
	char* data;
	struct ip_range* range = 0;
	int err = 0;

	data = acl_match_keyword(cmd, line, line_count, &err);
	if (err) return err;
	if (!data) return 0;

	range = hub_malloc_zero(sizeof(struct ip_range));
	if (!range)
	{
		LOG_ERROR("ACL parse error. Out of memory!");
		return -1;
	}

	if (ip_convert_address_to_range(data, range))
	{
		add_ip_range(list, range);
		return 1;
	}
	hub_free(range);
	return 0;
}



static int acl_parse_line(char* line, int line_count, void* ptr_data)
{
	struct acl_handle* handle = (struct acl_handle*) ptr_data;
	int ret;

	strip_off_ini_line_comments(line, line_count);

	line = strip_white_space(line);
	if (!*line)
		return 0;

	LOG_DEBUG("acl_parse_line: '%s'", line);

	ACL_ADD_USER("bot",        handle->users, auth_cred_bot);
	ACL_ADD_USER("ubot",        handle->users, auth_cred_ubot);
	ACL_ADD_USER("opbot",        handle->users, auth_cred_opbot);
	ACL_ADD_USER("opubot",        handle->users, auth_cred_opubot);
	ACL_ADD_USER("user_admin", handle->users, auth_cred_admin);
	ACL_ADD_USER("user_super", handle->users, auth_cred_super);
	ACL_ADD_USER("user_op",    handle->users, auth_cred_operator);
	ACL_ADD_USER("user_reg",   handle->users, auth_cred_user);
	ACL_ADD_USER("link",       handle->users, auth_cred_link);
	ACL_ADD_BOOL("deny_nick",  handle->users_denied);
	ACL_ADD_BOOL("ban_nick",   handle->users_banned);
	ACL_ADD_BOOL("ban_cid",    handle->cids);
	ACL_ADD_ADDR("deny_ip",    handle->networks);
	ACL_ADD_ADDR("nat_ip",     handle->nat_override);

	LOG_ERROR("Unknown ACL command on line %d: '%s'", line_count, line);
	return -1;
}


int acl_initialize(struct hub_config* config, struct acl_handle* handle)
{
	int ret;
	memset(handle, 0, sizeof(struct acl_handle));

	handle->users        = list_create();
	handle->users_denied = list_create();
	handle->users_banned = list_create();
	handle->cids         = list_create();
	handle->networks     = list_create();
	handle->nat_override = list_create();

	if (!handle->users || !handle->cids || !handle->networks || !handle->users_denied || !handle->users_banned || !handle->nat_override)
	{
		LOG_FATAL("acl_initialize: Out of memory");

		list_destroy(handle->users);
		list_destroy(handle->users_denied);
		list_destroy(handle->users_banned);
		list_destroy(handle->cids);
		list_destroy(handle->networks);
		list_destroy(handle->nat_override);
		return -1;
	}

	if (config)
	{
		if (!*config->file_acl) return 0;

		ret = file_read_lines(config->file_acl, handle, &acl_parse_line);
		if (ret == -1)
			return -1;
	}
	return 0;
}


static void acl_free_access_info(void* ptr)
{
	struct auth_info* info = (struct auth_info*) ptr;
	if (info)
	{
		hub_free(info);
	}
}


static void acl_free_ip_info(void* ptr)
{
	struct access_info* info = (struct access_info*) ptr;
	if (info)
	{
		hub_free(info);
	}
}

int acl_shutdown(struct acl_handle* handle)
{
	if (handle->users)
	{
		list_clear(handle->users, &acl_free_access_info);
		list_destroy(handle->users);
	}

	if (handle->users_denied)
	{
		list_clear(handle->users_denied, hub_free_handle);
		list_destroy(handle->users_denied);
	}

	if (handle->users_banned)
	{
		list_clear(handle->users_banned, hub_free_handle);
		list_destroy(handle->users_banned);
	}


	if (handle->cids)
	{
		list_clear(handle->cids, hub_free_handle);
		list_destroy(handle->cids);
	}

	if (handle->networks)
	{
		list_clear(handle->networks, &acl_free_ip_info);
		list_destroy(handle->networks);
	}

	if (handle->nat_override)
	{
		list_clear(handle->nat_override, &acl_free_ip_info);
		list_destroy(handle->nat_override);
	}

	memset(handle, 0, sizeof(struct acl_handle));
	return 0;
}

extern int acl_register_user(struct hub_info* hub, struct auth_info* info)
{
	if (plugin_auth_register_user(hub, info) != st_allow)
	{
		return 0;
	}
	return 1;
}

extern int acl_update_user(struct hub_info* hub, struct auth_info* info)
{
	if (plugin_auth_update_user(hub, info) != st_allow)
	{
		return 0;
	}
	return 1;
}

extern int acl_delete_user(struct hub_info* hub, const char* name)
{
	struct auth_info data;
	memset(&data, 0, sizeof(data));
	strncpy(data.nickname, name, MAX_NICK_LEN);
	data.nickname[MAX_NICK_LEN] = '\0';
	data.credentials = auth_cred_none;
	if (plugin_auth_delete_user(hub, &data) != st_allow)
	{
		return 0;
	}
	return 1;
}

struct auth_info* acl_get_access_info(struct hub_info* hub, const char* name)
{
	struct auth_info* info = 0;
	info = (struct auth_info*) hub_malloc_zero(sizeof(struct auth_info));
	if (!info)
		return NULL;
	if (plugin_auth_get_user(hub, name, info) != st_allow)
	{
		hub_free(info);
		return NULL;
	}
	return info;
}

#define STR_LIST_CONTAINS(LIST, STR) \
		LIST_FOREACH(char*, str, LIST, \
		{ \
			if (strcasecmp(str, STR) == 0) \
				return 1; \
		}); \
		return 0

int acl_is_cid_banned(struct acl_handle* handle, const char* data)
{
	char* str;
	if (!handle) return 0;
	STR_LIST_CONTAINS(handle->cids, data);
}

int acl_is_user_banned(struct acl_handle* handle, const char* data)
{
	char* str;
	if (!handle) return 0;
	STR_LIST_CONTAINS(handle->users_banned, data);
}

int acl_is_user_denied(struct acl_handle* handle, const char* data)
{
	char* str;
	if (!handle) return 0;
	STR_LIST_CONTAINS(handle->users_denied, data);
}

int acl_user_ban_nick(struct acl_handle* handle, const char* nick)
{
	char* data = hub_strdup(nick);
	if (!data)
	{
		LOG_ERROR("ACL error: Out of memory!");
		return -1;
	}

	list_append(handle->users_banned, data);
	return 0;
}

int acl_user_ban_cid(struct acl_handle* handle, const char* cid)
{
	char* data = hub_strdup(cid);
	if (!data)
	{
		LOG_ERROR("ACL error: Out of memory!");
		return -1;
	}

	list_append(handle->cids, data);
	return 0;
}

int acl_user_unban_nick(struct acl_handle* handle, const char* nick)
{
	return -1;
}

int acl_user_unban_cid(struct acl_handle* handle, const char* cid)
{
	return -1;
}


int acl_is_ip_banned(struct acl_handle* handle, const char* ip_address)
{
	struct ip_addr_encap raw;
	struct ip_range* info;

	memset(&raw, 0, sizeof(raw));
	if (ip_convert_to_binary(ip_address, &raw) == -1)
		return 0;
	LIST_FOREACH(struct ip_range*, info, handle->networks,
	{
		if (ip_in_range(&raw, info))
			return 1;
	});
	return 0;
}

int acl_is_ip_nat_override(struct acl_handle* handle, const char* ip_address)
{
	struct ip_addr_encap raw;
	struct ip_range* info;

	memset(&raw, 0, sizeof(raw));
	if (ip_convert_to_binary(ip_address, &raw) == -1)
		return 0;
	LIST_FOREACH(struct ip_range*, info, handle->nat_override,
	{
		if (ip_in_range(&raw, info))
			return 1;
	});
	return 0;
}


/*
 * The challenge consists of:
 * - the hub's session entropy (from hub->hub_secret)
 * - the client's time connected, SID and socket descriptor.
 *
 * The challenge will be the same every time called for the
 * exact same user.
 */
const char* acl_password_generate_challenge(struct hub_info* hub, struct hub_user* user)
{
	char buf[sizeof(hub->hub_secret) + 12];
	uint64_t tiger_res[3];
	static char tiger_buf[MAX_CID_LEN+1];

	size_t offset = 0;

	/* Add hub secret */
	memcpy(buf + offset, hub->hub_secret, sizeof(hub->hub_secret));
	offset += sizeof(hub->hub_secret);

	/* Add time connected (4 bytes) */
	uint32_t time_connected = (uint32_t) (user->tm_connected % 1000000);
	memcpy(buf + offset, &time_connected, sizeof(time_connected));
	offset += sizeof(time_connected);

	/* Add SID (4 bytes) */
	uint32_t sid = (uint32_t) user->id.sid;
	memcpy(buf + offset, &sid, sizeof(sid));
	offset += sizeof(sid);

	/* Add socket ID (4 bytes) */
	uint32_t sfd = (uint32_t) net_con_get_sd(user->connection);
	memcpy(buf + offset, &sfd, sizeof(sfd));
	offset += sizeof(sfd);

	tiger((uint64_t*) buf, offset, (uint64_t*) tiger_res);
	base32_encode((unsigned char*) tiger_res, TIGERSIZE, tiger_buf);
	tiger_buf[MAX_CID_LEN] = 0;
	return (const char*) tiger_buf;
}


/*
 * Constant-time, case-insensitive comparison of two length-len buffers. It
 * always inspects all len bytes, so the running time does not reveal how far a
 * guessed password response matched -- closing the timing side channel that a
 * short-circuiting strcasecmp() opens. base32 is case-insensitive, hence the
 * ASCII case fold (the inputs are base32-encoded Tiger digests).
 */
static int const_time_equal_ci(const char* a, const char* b, size_t len)
{
	unsigned char diff = 0;
	size_t i;
	for (i = 0; i < len; i++)
	{
		unsigned char ca = (unsigned char) a[i];
		unsigned char cb = (unsigned char) b[i];
		if (ca >= 'A' && ca <= 'Z') ca = (unsigned char) (ca + 32);
		if (cb >= 'A' && cb <= 'Z') cb = (unsigned char) (cb + 32);
		diff |= (unsigned char) (ca ^ cb);
	}
	return diff == 0;
}

int acl_password_verify(struct hub_info* hub, struct hub_user* user, const char* password)
{
	char buf[1024];
	struct auth_info* access;
	const char* challenge;
	char raw_challenge[64];
	char password_calc[64];
	uint64_t tiger_res[3];
	size_t password_len;

	if (!password || !user || strlen(password) != MAX_CID_LEN)
		return 0;

	access = acl_get_access_info(hub, user->id.nick);
	if (!access)
		return 0;

	challenge = acl_password_generate_challenge(hub, user);

	base32_decode(challenge, (unsigned char*) raw_challenge, MAX_CID_LEN);

	/* access->password is a fixed-size field (MAX_PASS_LEN+1) with a
	 * terminator at the end; use strnlen so a plugin that returned the
	 * field unterminated does not cause us to walk past it. */
	password_len = strnlen(access->password, sizeof(access->password));
	if (password_len + TIGERSIZE > sizeof(buf))
	{
		hub_free(access);
		return 0;
	}

	memcpy(&buf[0], access->password, password_len);
	memcpy(&buf[password_len], raw_challenge, TIGERSIZE);

	tiger((uint64_t*) buf, TIGERSIZE+password_len, (uint64_t*) tiger_res);
	base32_encode((unsigned char*) tiger_res, TIGERSIZE, password_calc);
	password_calc[MAX_CID_LEN] = 0;

	hub_free(access);

	/* password is verified to be exactly MAX_CID_LEN long above, and
	 * password_calc is MAX_CID_LEN base32 chars; compare in constant time. */
	if (const_time_equal_ci(password, password_calc, MAX_CID_LEN))
	{
		return 1;
	}
	return 0;
}
