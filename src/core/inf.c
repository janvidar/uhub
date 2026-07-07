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

#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "util/tiger.h"
#include "adc/message.h"
#include "core/auth.h"
#include "core/config.h"
#include "core/eventid.h"
#include "core/eventqueue.h"
#include "core/hbri.h"
#include "core/hubevent.h"
#include "core/inf.h"
#include "core/link.h"
#include "core/route.h"
#include "network/connection.h"
#include "core/usermanager.h"
#include "plugin_api/types.h"

/*
 * These flags can only be set by the hub.
 * Make sure we don't allow clients to specify these themselves.
 *
 * NOTE: Some of them are legacy ADC flags and no longer used, these
 * should be removed at some point in the future when functionality no
 * longer depend on them.
 */
static void remove_server_restricted_flags(struct adc_message* cmd)
{
	adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE); /* Client type flag (CT, obsoletes BO, RG, OP, HU) */
	adc_msg_remove_named_argument(cmd, "BO"); /* Obsolete: bot flag (CT) */
	adc_msg_remove_named_argument(cmd, "RG"); /* Obsolete: registered user flag (CT) */
	adc_msg_remove_named_argument(cmd, "OP"); /* Obsolete: operator flag (CT) */
	adc_msg_remove_named_argument(cmd, "HU"); /* Obsolete: hub flag (CT) */
	adc_msg_remove_named_argument(cmd, "HI"); /* Obsolete: hidden user flag */
	adc_msg_remove_named_argument(cmd, "TO"); /* Client to client token - should not be seen here */
	adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_REFERER);
}

static int set_feature_cast_supports(struct hub_user* u, struct adc_message* cmd)
{
	char *it, *tmp;

	if (adc_msg_has_named_argument(cmd, ADC_INF_FLAG_SUPPORT))
	{
		tmp = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_SUPPORT);
		if (!tmp)
			return -1; /* OOM: leave SUPPORT flags unset; login still proceeds */

		user_clear_feature_cast_support(u);

		it = tmp;
		size_t len = strlen(it);
		while (len >= 4)
		{
			char feature[5];
			memcpy(feature, it, 4);
			feature[4] = '\0';
			user_set_feature_cast_support(u, feature);
			/* Skip 4 chars plus optional separator */
			if (len > 4)
			{
				it += 5;
				len -= 5;
			}
			else
			{
				break;
			}
		}
		hub_free(tmp);
	}
	return 0;
}


/*
 * The INF "SU" field is a comma-separated list of 4-character feature tokens
 * (e.g. "ADC0,TCP4,UDP4") that the hub re-broadcasts to other clients. Remove
 * one feature token from that list, rewriting the SU argument in place (or
 * removing it entirely if it becomes empty). Feature tokens contain no
 * ADC-special characters, so the rewritten value needs no re-escaping.
 *
 * Returns 1 if the feature was present (and removed), 0 otherwise.
 */
static int remove_support_feature(struct adc_message* cmd, const char* feature)
{
	char* su;
	char* out;
	char* rd;
	char* wr;
	int removed = 0;

	if (!adc_msg_has_named_argument(cmd, ADC_INF_FLAG_SUPPORT))
		return 0;

	su = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_SUPPORT);
	if (!su)
		return 0;

	out = hub_malloc(strlen(su) + 1);
	if (!out)
	{
		hub_free(su);
		return 0;
	}

	wr = out;
	rd = su;
	while (*rd)
	{
		char* comma = strchr(rd, ',');
		size_t toklen = comma ? (size_t) (comma - rd) : strlen(rd);

		if (toklen == 4 && memcmp(rd, feature, 4) == 0)
		{
			removed = 1;
		}
		else if (toklen > 0)
		{
			if (wr != out)
				*wr++ = ',';
			memcpy(wr, rd, toklen);
			wr += toklen;
		}

		rd += toklen;
		if (*rd == ',')
			rd++;
	}
	*wr = '\0';

	if (removed)
	{
		if (*out)
			adc_msg_replace_named_argument(cmd, ADC_INF_FLAG_SUPPORT, out);
		else
			adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_SUPPORT);
	}

	hub_free(su);
	hub_free(out);
	return removed;
}


static int check_hash_tiger(const char* cid, const char* pid)
{
	char x_pid[64];
	char raw_pid[64];
	uint64_t tiger_res[3];

	memset(x_pid, 0, sizeof(x_pid));
	memset(raw_pid, 0, sizeof(raw_pid));

	base32_decode(pid, (unsigned char*) raw_pid, MAX_CID_LEN);
	tiger((uint64_t*) raw_pid, TIGERSIZE, (uint64_t*) tiger_res);
	base32_encode((unsigned char*) tiger_res, TIGERSIZE, x_pid);
	x_pid[MAX_CID_LEN] = 0;
	if (strncasecmp(x_pid, cid, MAX_CID_LEN) == 0)
		return 1;
	return 0;
}


static int check_cid(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
    (void) hub;
	size_t pos;
	char* cid = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_CLIENT_ID);
	char* pid = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_PRIVATE_ID);

	if (!cid || !pid)
	{
		hub_free(cid);
		hub_free(pid);
		return status_msg_error_no_memory;
	}

	if (strlen(cid) != MAX_CID_LEN)
	{
		hub_free(cid);
		hub_free(pid);
		return status_msg_inf_error_cid_invalid;
	}

	if (strlen(pid) != MAX_CID_LEN)
	{
		hub_free(cid);
		hub_free(pid);
		return status_msg_inf_error_pid_invalid;
	}

	for (pos = 0; pos < MAX_CID_LEN; pos++)
	{
		if (!is_valid_base32_char(cid[pos]))
		{
			hub_free(cid);
			hub_free(pid);
			return status_msg_inf_error_cid_invalid;
		}

		if (!is_valid_base32_char(pid[pos]))
		{
			hub_free(cid);
			hub_free(pid);
			return status_msg_inf_error_pid_invalid;
		}
	}

	if (!check_hash_tiger(cid, pid))
	{
		hub_free(cid);
		hub_free(pid);
		return status_msg_inf_error_cid_invalid;
	}

	/* Set the cid in the user object */
	memcpy(user->id.cid, cid, MAX_CID_LEN);
	user->id.cid[MAX_CID_LEN] = 0;

	hub_free(cid);
	hub_free(pid);
	return 0;
}


static int check_required_login_flags(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
    (void) hub;
    (void) user;
    int num = 0;

	num = adc_msg_has_named_argument(cmd, ADC_INF_FLAG_CLIENT_ID);
	if (num != 1)
	{
		if (!num)
			return status_msg_inf_error_cid_missing;
		return status_msg_inf_error_cid_invalid;
	}

	num = adc_msg_has_named_argument(cmd, ADC_INF_FLAG_PRIVATE_ID);
	if (num != 1)
	{
		if (!num)
			return status_msg_inf_error_pid_missing;
		return status_msg_inf_error_pid_invalid;
	}

	num = adc_msg_has_named_argument(cmd, ADC_INF_FLAG_NICK);
	if (num != 1)
	{
		if (!num)
			return status_msg_inf_error_nick_missing;
		return status_msg_inf_error_nick_multiple;
	}
	return 0;
}


/**
 * This will check the ip address of the user, and
 * remove any wrong address, and replace it with the correct one
 * as seen by the hub.
 */
/*
 * @return 1 if cmd advertises a syntactically valid address in the given
 * protocol family (used to decide whether an HBRI second-family address is
 * worth keeping for later validation).
 */
static int check_network_secondary_ok(struct adc_message* cmd, int af)
{
	const char* flag = (af == AF_INET6) ? ADC_INF_FLAG_IPV6_ADDR : ADC_INF_FLAG_IPV4_ADDR;
	char* addr = adc_msg_get_named_argument(cmd, flag);
	int ok = addr && *addr && (af == AF_INET6 ? ip_is_valid_ipv6(addr) : ip_is_valid_ipv4(addr));
	hub_free(addr);
	return ok;
}

/*
 * When a logged-in HBRI client advertises a new second-family address in an INF
 * update, ask it to prove the address over a secondary connection. Does nothing
 * if HBRI is disabled, the client does not support it, or the advertised
 * address is missing/invalid/unchanged from what we already hold.
 */
static void check_hbri_update(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
	int sec_af;
	const char* flag;
	char* advertised;
	char* current;
	int is_new;

	if (!hbri_is_enabled(hub) || !user_flag_get(user, feature_hbri))
		return;

	sec_af = (user->id.addr.af == AF_INET) ? AF_INET6 : AF_INET;
	if (!check_network_secondary_ok(cmd, sec_af))
		return;

	flag = (sec_af == AF_INET6) ? ADC_INF_FLAG_IPV6_ADDR : ADC_INF_FLAG_IPV4_ADDR;
	advertised = adc_msg_get_named_argument(cmd, flag);
	current = user->info ? adc_msg_get_named_argument(user->info, flag) : 0;

	is_new = advertised && (!current || strcmp(advertised, current) != 0);
	hub_free(advertised);
	hub_free(current);

	if (is_new)
		hbri_send_validation_request(hub, user);
}

static int check_network(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
	const char* address = user_get_address(user);

	/* Check for NAT override address */
	if (acl_is_ip_nat_override(hub->acl, address))
	{
		char* client_given_ip = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR);
		if (client_given_ip && strcmp(client_given_ip, "0.0.0.0") != 0)
		{
			user_set_nat_override(user);
			adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV6_ADDR);
			adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV6_UDP_PORT);
			hub_free(client_given_ip);
			return 0;
		}
		hub_free(client_given_ip);
	}

	/*
	 * The hub overrides the connecting-family address with the one it actually
	 * sees. The other family is normally stripped, since a client cannot prove
	 * an address it did not connect from -- except when HBRI is in play: a
	 * dual-stack client may advertise its second-family address here and prove
	 * it later over a secondary connection (see hbri.c). In that case we keep
	 * the advertised second-family address for now; it is stripped again before
	 * broadcast and only re-added once validated.
	 */
	int hbri = hbri_is_enabled(hub) && user_flag_get(user, feature_hbri);

	if (strchr(address, '.'))
	{
		if (!(hbri && check_network_secondary_ok(cmd, AF_INET6)))
		{
			adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV6_ADDR);
			adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV6_UDP_PORT);
		}
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR);
		adc_msg_add_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR, address);
	}
	else if (strchr(address, ':'))
	{
		if (!(hbri && check_network_secondary_ok(cmd, AF_INET)))
		{
			adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR);
			adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV4_UDP_PORT);
		}
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV6_ADDR);
		adc_msg_add_named_argument(cmd, ADC_INF_FLAG_IPV6_ADDR, address);
	}
	return 0;
}

static void strip_network(struct hub_user* user, struct adc_message* cmd)
{
    (void) user;
	adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV6_ADDR);
	adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR);
}

static int nick_length_ok(const char* nick)
{
	size_t length = strlen(nick);
	if (length <= 1)
	{
		return nick_invalid_short;
	}

	if (length > MAX_NICK_LEN)
	{
		return nick_invalid_long;
	}

	return nick_ok;
}


static int nick_bad_characters(const char* nick)
{
	const char* tmp;

	/* Nick must not start with a space */
	if (nick[0] == ' ')
		return nick_invalid_spaces;

	/* Reject ASCII control characters: values below 32 and DEL (0x7f). High
	   bytes (>= 0x80, the UTF-8 continuation/lead range) are left alone. */
	for (tmp = nick; *tmp; tmp++)
	{
		unsigned char c = (unsigned char) *tmp;
		if (c < 32 || c == 0x7f)
			return nick_invalid_bad_ascii;
	}

	return nick_ok;
}


static int nick_is_utf8(const char* nick)
{
	/*
	 * Nick should be valid utf-8, but
	 * perhaps we should check if the nick is unicode normalized?
	 */
	if (!is_valid_utf8(nick))
		return nick_invalid_bad_utf8;
	return nick_ok;
}


static int check_nick(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
    (void) hub;
	char* nick;
	char* tmp;
	enum nick_status status;

	tmp = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_NICK);
	if (!tmp) return 0;
	nick = adc_msg_unescape(tmp);
	hub_free(tmp); tmp = 0;
	if (!nick) return 0;

	status = nick_length_ok(nick);
	if (status != nick_ok)
	{
		hub_free(nick);
		if (status == nick_invalid_short)
			return status_msg_inf_error_nick_short;
		return status_msg_inf_error_nick_long;
	}

	status = nick_bad_characters(nick);
	if (status != nick_ok)
	{
		hub_free(nick);
		if (status == nick_invalid_spaces)
			return status_msg_inf_error_nick_spaces;
		return status_msg_inf_error_nick_bad_chars;
	}

	status = nick_is_utf8(nick);
	if (status != nick_ok)
	{
		hub_free(nick);
		return status_msg_inf_error_nick_not_utf8;
	}

	if (user_is_connecting(user))
	{
		memcpy(user->id.nick, nick, strlen(nick));
		user->id.nick[strlen(nick)] = 0;
	}

	hub_free(nick);
	return 0;
}


static int check_logged_in(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
    (void) cmd;
	struct hub_user* lookup1 = uman_get_user_by_nick(hub->users, user->id.nick);
	struct hub_user* lookup2 = uman_get_user_by_cid(hub->users, user->id.cid);

	if (lookup1 == user)
	{
		return 0;
	}

	if (lookup1 || lookup2)
	{
		if (lookup1 == lookup2)
		{
			if (user_flag_get(lookup1, flag_choke))
			{
				LOG_DEBUG("check_logged_in: exact same user is already logged in, but likely ghost: %s", user->id.nick);

				// Old user unable to swallow data.
				// Disconnect the existing user, and allow new user to enter.
				hub_disconnect_user(hub, lookup1, quit_ghost_timeout);
			}
			else
			{
				LOG_DEBUG("check_logged_in: exact same user is already logged in: %s", user->id.nick);
				return status_msg_inf_error_cid_taken;
			}
		}
		else
		{
			if (lookup1)
			{
				LOG_DEBUG("check_logged_in: nickname is in use: %s", user->id.nick);
				return status_msg_inf_error_nick_taken;
			}
			else
			{
				LOG_DEBUG("check_logged_in: CID is in use: %s", user->id.cid);
				return status_msg_inf_error_cid_taken;
			}
		}
	}
	return 0;
}


/*
 * It is possible to do user-agent checking here.
 * But this is not something we want to do, and is deprecated in the ADC specification.
 * One should rather look at capabilities/features.
 */
static int check_user_agent(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
    (void) hub;
	char* ua_name_encoded = 0;
	char* ua_version_encoded = 0;
	char* str = 0;
	size_t offset = 0;

	/* Get client user agent version */
	ua_name_encoded = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_USER_AGENT_PRODUCT);
	ua_version_encoded = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_USER_AGENT_VERSION);
	if (ua_name_encoded)
	{
		str = adc_msg_unescape(ua_name_encoded);
		if (str)
		{
			offset = MIN(strlen(str), MAX_UA_LEN);
			memcpy(user->id.user_agent, str, offset);
			hub_free(str);
		}
	}

	if (ua_version_encoded)
	{
		str = adc_msg_unescape(ua_version_encoded);
		if (str)
		{
			memcpy(user->id.user_agent + offset, str, MIN(strlen(str), MAX_UA_LEN - offset));
			hub_free(str);
		}
	}

	/* Ensure the user agent is NUL-terminated regardless of the memcpy lengths above. */
	user->id.user_agent[MAX_UA_LEN] = '\0';

	hub_free(ua_name_encoded);
	hub_free(ua_version_encoded);
	return 0;
}


static int check_acl(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
    (void) cmd;
	if (acl_is_ip_banned(hub->acl, user_get_address(user)))
	{
		return status_msg_ban_permanently;
	}

	if (acl_is_cid_banned(hub->acl, user->id.cid))
	{
		return status_msg_ban_permanently;
	}

	if (acl_is_user_banned(hub->acl, user->id.nick))
	{
		return status_msg_ban_permanently;
	}

	if (acl_is_user_denied(hub->acl, user->id.nick))
	{
		return status_msg_inf_error_nick_restricted;
	}

	return 0;
}

static int check_limits(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
	char* arg = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_SHARED_SIZE);
	char* endptr;
	if (arg)
	{
		int64_t shared_size = strtoll(arg, &endptr, 10);
		if (endptr == arg || shared_size < 0)
			shared_size = 0;

		if (user_is_logged_in(user))
		{
			hub->users->shared_size  -= user->limits.shared_size;
			hub->users->shared_size  += shared_size;
		}
		user->limits.shared_size = shared_size;
		hub_free(arg);
		arg = 0;
	}

	arg = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_SHARED_FILES);
	if (arg)
	{
		long shared_files = strtol(arg, &endptr, 10);
		if (endptr == arg || shared_files < 0 || shared_files > INT_MAX)
			shared_files = 0;

		if (user_is_logged_in(user))
		{
			hub->users->shared_files -= user->limits.shared_files;
			hub->users->shared_files += (int)shared_files;
		}
		user->limits.shared_files = (int)shared_files;
		hub_free(arg);
		arg = 0;
	}

	arg = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_COUNT_HUB_NORMAL);
	if (arg)
	{
		long num = strtol(arg, &endptr, 10);
		if (endptr == arg || num < 0 || num > INT_MAX) num = 0;
		user->limits.hub_count_user = (int)num;
		hub_free(arg);
		arg = 0;
	}

	arg = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_COUNT_HUB_REGISTER);
	if (arg)
	{
		long num = strtol(arg, &endptr, 10);
		if (endptr == arg || num < 0 || num > INT_MAX) num = 0;
		user->limits.hub_count_registered = (int)num;
		hub_free(arg);
		arg = 0;
	}

	arg = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_COUNT_HUB_OPERATOR);
	if (arg)
	{
		long num = strtol(arg, &endptr, 10);
		if (endptr == arg || num < 0 || num > INT_MAX) num = 0;
		user->limits.hub_count_operator = (int)num;
		hub_free(arg);
		arg = 0;
	}

	arg = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_UPLOAD_SLOTS);
	if (arg)
	{
		long num = strtol(arg, &endptr, 10);
		if (endptr == arg || num < 0 || num > INT_MAX) num = 0;
		user->limits.upload_slots = (int)num;
		hub_free(arg);
		arg = 0;
	}

	/* summarize total slots */
	user->limits.hub_count_total = user->limits.hub_count_user + user->limits.hub_count_registered + user->limits.hub_count_operator;

	if (!user_is_protected(user))
	{
		if (user->limits.shared_size < hub_get_min_share(hub) && hub_get_min_share(hub))
		{
			return status_msg_user_share_size_low;
		}

		if (user->limits.shared_size > hub_get_max_share(hub) && hub_get_max_share(hub))
		{
			return status_msg_user_share_size_high;
		}

		if ((user->limits.hub_count_user           > hub_get_max_hubs_user(hub)  && hub_get_max_hubs_user(hub)) ||
			(user->limits.hub_count_registered > hub_get_max_hubs_reg(hub)   && hub_get_max_hubs_reg(hub))  ||
			(user->limits.hub_count_operator   > hub_get_max_hubs_op(hub)    && hub_get_max_hubs_op(hub))   ||
			(user->limits.hub_count_total      > hub_get_max_hubs_total(hub) && hub_get_max_hubs_total(hub)))
		{
			return status_msg_user_hub_limit_high;
		}

		if ((user->limits.hub_count_user           < hub_get_min_hubs_user(hub)  && hub_get_min_hubs_user(hub)) ||
			(user->limits.hub_count_registered < hub_get_min_hubs_reg(hub)   && hub_get_min_hubs_reg(hub))  ||
			(user->limits.hub_count_operator   < hub_get_min_hubs_op(hub)    && hub_get_min_hubs_op(hub)))
		{
			return status_msg_user_hub_limit_low;
		}

		if (user->limits.upload_slots < hub_get_min_slots(hub) && hub_get_min_slots(hub))
		{
			return status_msg_user_slots_low;
		}

		if (user->limits.upload_slots > hub_get_max_slots(hub) && hub_get_max_slots(hub))
		{
			return status_msg_user_slots_high;
		}
	}
	return 0;
}

/*
 * Set the expected credentials, and returns 1 if authentication is needed,
 * or 0 if not.
 * If the hub is configured to allow only registered users and the user
 * is not recognized this will return 1.
 */
static int set_credentials(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
	int ret = 0;

	if (hub->config->auth_proxy)
	{
		/* Slave: the credential was resolved by the master (LACR). A non-guest
		   credential means the account is registered and must prove a password
		   (verified via the master in hub_handle_password). */
		user->credentials = user->auth_proxy_resolved ? user->auth_proxy_cred : auth_cred_guest;
		ret = (user->credentials > auth_cred_guest) ? 1 : 0;
	}
	else
	{
		struct auth_info* info = acl_get_access_info(hub, user->id.nick);
		if (info)
		{
			user->credentials = info->credentials;
			ret = 1;
		}
		else
		{
			user->credentials = auth_cred_guest;
		}
		hub_free(info);
	}

	switch (user->credentials)
	{
		case auth_cred_none:
			break;

		case auth_cred_bot:
			adc_msg_add_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE ADC_CLIENT_TYPE_BOT);
			break;

		case auth_cred_ubot:
			adc_msg_add_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE ADC_CLIENT_TYPE_BOT);
			break;

		case auth_cred_guest:
			/* Nothing to be added to the info message */
			break;

		case auth_cred_user:
			adc_msg_add_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE ADC_CLIENT_TYPE_REGISTERED_USER);
			break;

		case auth_cred_operator:
			adc_msg_add_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE ADC_CLIENT_TYPE_OPERATOR);
			break;

		case auth_cred_opbot:
			adc_msg_add_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE ADC_CLIENT_TYPE_HUBBOT);
			break;

		case auth_cred_opubot:
			adc_msg_add_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE ADC_CLIENT_TYPE_HUBBOT);
			break;

		case auth_cred_super:
			adc_msg_add_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE ADC_CLIENT_TYPE_SUPER_USER);
			break;

		case auth_cred_admin:
			adc_msg_add_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE ADC_CLIENT_TYPE_ADMIN);
			break;

		case auth_cred_link:
			break;
 	}

	return ret;
}



static int check_is_hub_full(struct hub_info* hub, struct hub_user* user)
{
	/*
	 * If hub is full, don't let users in, but we still want to allow
	 * operators and admins to enter the hub.
	 */
	if (hub->config->max_users && hub->users->count >= (size_t) hub->config->max_users && !user_is_protected(user))
	{
		return 1;
	}
	return 0;
}


static int check_registered_users_only(struct hub_info* hub, struct hub_user* user)
{
	if (hub->config->registered_users_only && !user_is_registered(user))
	{
		return 1;
	}
	return 0;
}

int hub_handle_info_common(struct hub_user* user, struct adc_message* cmd)
{
	/* Remove server restricted flags */
	remove_server_restricted_flags(cmd);

	/*
	 * ADC0 in the support cast advertises that the client accepts
	 * TLS client-to-client connections. Only let clients whose hub
	 * connection is confirmed TLS advertise it; otherwise strip it so it is
	 * not re-broadcast to other users. Fail closed: anything not provably TLS
	 * (including a user with no connection) loses the flag.
	 */
	if (!(user->connection && net_con_is_ssl(user->connection)))
		remove_support_feature(cmd, "ADC0");

	/* Update/set the feature cast flags. */
	set_feature_cast_supports(user, cmd);

	return 0;
}

static int hub_handle_info_low_bandwidth(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
    (void) user;

	if (hub->config->low_bandwidth_mode)
	{
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_USER_AGENT_VERSION);
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_USER_AGENT_PRODUCT);
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_SHARED_FILES);
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_COUNT_HUB_NORMAL);
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_COUNT_HUB_REGISTER);
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_COUNT_HUB_OPERATOR);
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_UPLOAD_SPEED);
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_DOWNLOAD_SPEED);
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_AUTO_SLOTS);
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_AUTO_SLOTS_MAX);
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_AWAY);
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_DESCRIPTION);
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_EMAIL);
	}

	return 0;
}

#define INF_CHECK(FUNC, HUB, USER, CMD) \
	do { \
		int ret = FUNC(HUB, USER, CMD); \
		if (ret < 0) \
			return ret; \
	} while(0)

static int hub_perform_login_checks(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
	/* Make syntax checks.  */
	INF_CHECK(check_required_login_flags, hub, user, cmd);
	INF_CHECK(check_cid,                  hub, user, cmd);
	INF_CHECK(check_nick,                 hub, user, cmd);
	INF_CHECK(check_network,              hub, user, cmd);
	INF_CHECK(check_user_agent,           hub, user, cmd);
	INF_CHECK(check_acl,                  hub, user, cmd);
	INF_CHECK(check_logged_in,            hub, user, cmd);
	return 0;
}

/**
 * Perform additional INF checks used at time of login.
 *
 * @return 0 if success, <0 if error, >0 if authentication needed.
 */
int hub_handle_info_login(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
	int code = 0;

	INF_CHECK(hub_perform_login_checks, hub, user, cmd);

	/* Private ID must never be broadcasted - drop it! */
	adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_PRIVATE_ID);

	code = set_credentials(hub, user, cmd);

	/* Note: this must be done *after* set_credentials. */
	if (check_is_hub_full(hub, user))
	{
		return status_msg_hub_full;
	}

	if (check_registered_users_only(hub, user))
	{
		return status_msg_hub_registered_users_only;
	}

	INF_CHECK(check_limits, hub, user, cmd);

	/* strip off stuff if low_bandwidth_mode is enabled */
	hub_handle_info_low_bandwidth(hub, user, cmd);

	/* Set initial user info */
	user_set_info(user, cmd);

	return code;
}

/*
 * Run the login checks for a connecting user's BINF and either fail the login
 * or post the join event. Takes ownership of cmd (frees it). Factored so it can
 * be invoked both inline and when resuming a master-proxied login.
 */
int hub_complete_inf_login(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
	int ret = hub_handle_info_login(hub, user, cmd);
	if (ret < 0)
	{
		on_login_failure(hub, user, ret);
		adc_msg_free(cmd);
		return -1;
	}
	else
	{
		struct event_data post;
		memset(&post, 0, sizeof(post));
		post.id    = UHUB_EVENT_USER_JOIN;
		post.ptr   = user;
		post.flags = ret; /* 0 - all OK, 1 - need authentication */
		event_queue_post(hub->queue, &post);
		adc_msg_free(cmd);
		return 0;
	}
}

/*
 * Master-slave auth: the master replied (LACR) with this nick's credential.
 * Record it and resume the paused login using the held BINF.
 */
void hub_auth_proxy_resolve(struct hub_info* hub, struct hub_user* user, enum auth_credentials cred)
{
	struct adc_message* inf = user->auth_pending_inf;
	user->auth_proxy_cred = cred;
	user->auth_proxy_resolved = 1;
	user->auth_pending_inf = NULL;
	if (inf)
		hub_complete_inf_login(hub, user, inf); /* takes ownership */
}

/*
 * If user is in the connecting state, we need to do fairly
 * strict checking of all arguments.
 * This means we disconnect users when they provide invalid data
 * during the login sequence.
 * When users are merely updating their data after successful login
 * we can just ignore any invalid data and not broadcast it.
 *
 * The data we need to check is:
 * - nick name (valid, not taken, etc)
 * - CID/PID (valid, not taken, etc).
 * - IP addresses (IPv4 and IPv6)
 */
int hub_handle_info(struct hub_info* hub, struct hub_user* user, const struct adc_message* cmd_unmodified)
{
	int ret;
	struct adc_message* cmd = adc_msg_copy(cmd_unmodified);
	if (!cmd) return -1; /* OOM */

	cmd->priority = 1;

	hub_handle_info_common(user, cmd);

	/* If user is logging in, perform more checks,
	   otherwise only a few things need to be checked.
	 */
	if (user_is_connecting(user))
	{
		/*
		 * Don't allow the user to send multiple INF messages in this stage!
		 * Since that can have serious side-effects.
		 */
		if (user->info)
		{
			adc_msg_free(cmd);
			return 0;
		}

		/*
		 * Master-slave auth: a slave holds no accounts, so it must ask the
		 * master whether this nick is registered before deciding to challenge.
		 * Pause the login (holding the BINF) until the master replies (LACR),
		 * at which point hub_auth_proxy_resolve() resumes it. If there is no
		 * master link, fall through and log in locally (as a guest).
		 */
		if (hub->config->auth_proxy && !user->auth_proxy_resolved)
		{
			/* The nick isn't validated/stored on the user yet (that happens in
			   the login checks), so pull it from the BINF for the master query. */
			char* tmp = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_NICK);
			char* nick = tmp ? adc_msg_unescape(tmp) : NULL;
			int sent = nick ? link_auth_query(hub, user, nick) : 0;
			hub_free(tmp);
			hub_free(nick);
			if (sent)
			{
				user->auth_pending_inf = adc_msg_copy(cmd);
				adc_msg_free(cmd);
				return 0;
			}
		}

		return hub_complete_inf_login(hub, user, cmd);
	}
	else
	{
		/* These must not be allowed updated, let's remove them! */
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_PRIVATE_ID);
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_CLIENT_ID);

		/*
		 * If the nick is not accepted, do not relay it.
		 * Otherwise, the nickname will be updated.
		 */
		if (adc_msg_has_named_argument(cmd, ADC_INF_FLAG_NICK))
		{
			adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_NICK);
		}

		ret = check_limits(hub, user, cmd);
		if (ret < 0)
		{
			on_update_failure(hub, user, ret);
			adc_msg_free(cmd);
			return -1;
		}

		/*
		 * HBRI: a logged-in dual-stack client may add or change its
		 * second-family address in an update. The address itself is stripped
		 * from the broadcast below (clients cannot change their IP via an
		 * update), but if it is new we ask the client to prove it; on success
		 * it is broadcast as a validated update. This is detected before
		 * strip_network() removes the address.
		 */
		check_hbri_update(hub, user, cmd);

		strip_network(user, cmd);
		hub_handle_info_low_bandwidth(hub, user, cmd);

		user_update_info(user, cmd);

		if (!adc_msg_is_empty(cmd))
		{
			route_message(hub, user, cmd);
			/* Propagate the updated INF to linked hubs. */
			link_broadcast_local_inf(hub, user);
		}

		adc_msg_free(cmd);
	}

	return 0;
}
