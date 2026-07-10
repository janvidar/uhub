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

/* Parse a comma-separated list of addresses/CIDRs/ranges (the nat_override hub
   option, formerly the nat_ip acl keyword) and append each as an ip_range to
   target. Returns 0 on success, -1 on OOM or a malformed entry. */
static int acl_add_address_list(struct linked_list* target, const char* csv)
{
	struct linked_list* parts;
	char* token;
	int failed = 0;

	if (!csv || !*csv)
		return 0;

	parts = list_create();
	if (!parts)
	{
		LOG_ERROR("ACL error: Out of memory!");
		return -1;
	}

	if (split_string(csv, ",", parts, 0) < 0)
	{
		list_destroy(parts);
		return -1;
	}

	LIST_FOREACH(char*, token, parts,
	{
		struct ip_range* range = hub_malloc_zero(sizeof(struct ip_range));
		if (!range)
		{
			LOG_ERROR("ACL error: Out of memory!");
			failed = 1;
			break;
		}
		if (ip_convert_address_to_range(strip_white_space(token), range))
		{
			add_ip_range(target, range);
		}
		else
		{
			LOG_ERROR("nat_override: invalid address '%s'", token);
			hub_free(range);
			failed = 1;
			break;
		}
	});

	list_clear(parts, hub_free_handle);
	list_destroy(parts);
	return failed ? -1 : 0;
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



/* Keywords that were once valid in file_acl but have moved or been removed.
   Recognised as whole tokens so existing acl files keep loading; each logs a
   one-line migration warning and is otherwise ignored (non-fatal). */
static int acl_is_obsolete_keyword(const char* line, int line_count)
{
	static const char* const auth_plugin_advice =
		"registered users are configured via an auth plugin (mod_auth_simple / "
		"mod_auth_sqlite), not file_acl";
	static const struct { const char* key; const char* advice; } obsolete[] = {
		{ "nat_ip",     "use the 'nat_override' option in uhub.conf" },
		{ "user_admin", auth_plugin_advice },
		{ "user_super", auth_plugin_advice },
		{ "user_op",    auth_plugin_advice },
		{ "user_reg",   auth_plugin_advice },
		{ "link",       auth_plugin_advice },
		{ "bot",        auth_plugin_advice },
		{ "ubot",       auth_plugin_advice },
		{ "opbot",      auth_plugin_advice },
		{ "opubot",     auth_plugin_advice },
	};
	size_t i;
	for (i = 0; i < sizeof(obsolete) / sizeof(obsolete[0]); i++)
	{
		size_t n = strlen(obsolete[i].key);
		if (strncmp(line, obsolete[i].key, n) == 0 &&
		    (line[n] == ' ' || line[n] == '\t' || line[n] == '\0'))
		{
			LOG_WARN("ACL line %d: '%s' is obsolete and ignored; %s.",
			         line_count, obsolete[i].key, obsolete[i].advice);
			return 1;
		}
	}
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

	ACL_ADD_BOOL("deny_nick",  handle->users_denied);
	ACL_ADD_BOOL("ban_nick",   handle->users_banned);
	ACL_ADD_BOOL("ban_cid",    handle->cids);
	ACL_ADD_ADDR("deny_ip",    handle->networks);

	if (acl_is_obsolete_keyword(line, line_count))
		return 0;

	LOG_ERROR("Unknown ACL command on line %d: '%s'", line_count, line);
	return -1;
}


int acl_initialize(struct hub_config* config, struct acl_handle* handle)
{
	int ret;
	memset(handle, 0, sizeof(struct acl_handle));

	handle->users_denied = list_create();
	handle->users_banned = list_create();
	handle->cids         = list_create();
	handle->networks     = list_create();
	handle->nat_override = list_create();
	handle->timed_bans   = list_create();

	if (!handle->cids || !handle->networks || !handle->users_denied || !handle->users_banned || !handle->nat_override || !handle->timed_bans)
	{
		LOG_FATAL("acl_initialize: Out of memory");

		list_destroy(handle->users_denied);
		list_destroy(handle->users_banned);
		list_destroy(handle->cids);
		list_destroy(handle->networks);
		list_destroy(handle->nat_override);
		list_destroy(handle->timed_bans);
		return -1;
	}

	if (config)
	{
		/* NAT-override ranges come from the hub config (formerly the nat_ip acl
		   keyword); parse them regardless of whether an acl file is set. */
		if (acl_add_address_list(handle->nat_override, config->nat_override) == -1)
			return -1;

		if (!*config->file_acl) return 0;

		ret = file_read_lines(config->file_acl, handle, &acl_parse_line);
		if (ret == -1)
			return -1;
	}
	return 0;
}


static void acl_free_ip_info(void* ptr)
{
	struct access_info* info = (struct access_info*) ptr;
	if (info)
	{
		hub_free(info);
	}
}

/* Defined below (with the timed-ban store); forward-declared for acl_shutdown. */
static void acl_free_timed_ban(void* ptr);

int acl_shutdown(struct acl_handle* handle)
{
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

	if (handle->timed_bans)
	{
		list_clear(handle->timed_bans, &acl_free_timed_ban);
		list_destroy(handle->timed_bans);
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

/* Remove the first case-insensitively matching string from a list of
   hub_strdup'd strings (matching how acl_is_*_banned compares). Frees the
   removed entry. Returns 0 if an entry was removed, -1 if none matched. */
static int acl_list_remove_string(struct linked_list* list, const char* value)
{
	char* str;
	LIST_FOREACH(char*, str, list,
	{
		if (strcasecmp(str, value) == 0)
		{
			list_remove(list, str);
			hub_free(str);
			return 0;
		}
	});
	return -1;
}

int acl_user_unban_nick(struct acl_handle* handle, const char* nick)
{
	return acl_list_remove_string(handle->users_banned, nick);
}

int acl_user_unban_cid(struct acl_handle* handle, const char* cid)
{
	return acl_list_remove_string(handle->cids, cid);
}

int acl_user_unban_ip(struct acl_handle* handle, const char* address)
{
	struct ip_range target;
	struct ip_range* info;

	memset(&target, 0, sizeof(target));
	if (!ip_convert_address_to_range(address, &target))
		return -1;

	LIST_FOREACH(struct ip_range*, info, handle->networks,
	{
		if (ip_compare(&info->lo, &target.lo) == 0 && ip_compare(&info->hi, &target.hi) == 0)
		{
			list_remove(handle->networks, info);
			hub_free(info);
			return 0;
		}
	});
	return -1;
}


/* A runtime ban with an expiry, stored in acl_handle->timed_bans. cid and nick
   are heap strings ("" when that identifier is not part of the ban). */
struct acl_timed_ban
{
	char* cid;
	char* nick;
	time_t expiry;   /* absolute unix time */
};

static void acl_free_timed_ban(void* ptr)
{
	struct acl_timed_ban* tb = (struct acl_timed_ban*) ptr;
	if (tb)
	{
		hub_free(tb->cid);
		hub_free(tb->nick);
		hub_free(tb);
	}
}

static int acl_timed_ban_matches(struct acl_timed_ban* tb, const char* cid, const char* nick)
{
	if (tb->cid[0] && cid && strcasecmp(tb->cid, cid) == 0)
		return 1;
	if (tb->nick[0] && nick && strcasecmp(tb->nick, nick) == 0)
		return 1;
	return 0;
}

int acl_add_timed_ban(struct acl_handle* handle, const char* cid, const char* nick, time_t expiry)
{
	struct acl_timed_ban* tb = hub_malloc_zero(sizeof(struct acl_timed_ban));
	if (!tb)
	{
		LOG_ERROR("ACL error: Out of memory!");
		return -1;
	}
	tb->cid = hub_strdup(cid ? cid : "");
	tb->nick = hub_strdup(nick ? nick : "");
	tb->expiry = expiry;
	if (!tb->cid || !tb->nick)
	{
		acl_free_timed_ban(tb);
		return -1;
	}
	list_append(handle->timed_bans, tb);
	return 0;
}

time_t acl_timed_ban_remaining(struct acl_handle* handle, const char* cid, const char* nick, time_t now)
{
	struct acl_timed_ban* tb;
	struct acl_timed_ban* match = NULL;
	struct linked_list* expired;
	time_t remaining = 0;

	if (!handle->timed_bans)
		return 0;
	expired = list_create();
	if (!expired)
		return 0;

	LIST_FOREACH(struct acl_timed_ban*, tb, handle->timed_bans,
	{
		if (tb->expiry != 0 && tb->expiry <= now)
			list_append(expired, tb);          /* collect; do not remove while iterating */
		else if (!match && acl_timed_ban_matches(tb, cid, nick))
			match = tb;
	});

	while ((tb = (struct acl_timed_ban*) list_get_first(expired)))
	{
		/* Unlink from both lists before freeing (do not touch tb afterwards). */
		list_remove(expired, tb);
		list_remove(handle->timed_bans, tb);
		acl_free_timed_ban(tb);
	}
	list_destroy(expired);

	if (match)
		remaining = match->expiry - now;
	return remaining > 0 ? remaining : 0;
}

int acl_timed_unban(struct acl_handle* handle, const char* target)
{
	struct acl_timed_ban* tb;
	struct linked_list* hits;
	int removed = 0;

	if (!handle->timed_bans || !target)
		return 0;
	hits = list_create();
	if (!hits)
		return 0;

	LIST_FOREACH(struct acl_timed_ban*, tb, handle->timed_bans,
	{
		if ((tb->cid[0] && strcasecmp(tb->cid, target) == 0) ||
		    (tb->nick[0] && strcasecmp(tb->nick, target) == 0))
			list_append(hits, tb);
	});

	while ((tb = (struct acl_timed_ban*) list_get_first(hits)))
	{
		/* Unlink from both lists before freeing (do not touch tb afterwards). */
		list_remove(hits, tb);
		list_remove(handle->timed_bans, tb);
		acl_free_timed_ban(tb);
		removed++;
	}
	list_destroy(hits);
	return removed;
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

int acl_password_verify_raw(const char* password, const char* challenge, const char* response)
{
	char buf[1024];
	char raw_challenge[64];
	char password_calc[64];
	uint64_t tiger_res[3];
	size_t password_len;

	if (!password || !challenge || !response || strlen(response) != MAX_CID_LEN)
		return 0;

	base32_decode(challenge, (unsigned char*) raw_challenge, MAX_CID_LEN);

	/* password may be a fixed-size field with a terminator at the end; use
	 * strnlen so an unterminated field does not walk past it. */
	password_len = strnlen(password, MAX_PASS_LEN);
	if (password_len + TIGERSIZE > sizeof(buf))
		return 0;

	memcpy(&buf[0], password, password_len);
	memcpy(&buf[password_len], raw_challenge, TIGERSIZE);

	tiger((uint64_t*) buf, TIGERSIZE + password_len, (uint64_t*) tiger_res);
	base32_encode((unsigned char*) tiger_res, TIGERSIZE, password_calc);
	password_calc[MAX_CID_LEN] = 0;

	/* response is verified to be exactly MAX_CID_LEN long above, and
	 * password_calc is MAX_CID_LEN base32 chars; compare in constant time so
	 * the running time does not leak how far a guessed response matched. */
	return const_time_equal_ci(response, password_calc, MAX_CID_LEN);
}

int acl_password_verify(struct hub_info* hub, struct hub_user* user, const char* password)
{
	struct auth_info* access;
	int ok;

	if (!password || !user || strlen(password) != MAX_CID_LEN)
		return 0;

	access = acl_get_access_info(hub, user->id.nick);
	if (!access)
		return 0;

	ok = acl_password_verify_raw(access->password, acl_password_generate_challenge(hub, user), password);
	hub_free(access);
	return ok;
}
