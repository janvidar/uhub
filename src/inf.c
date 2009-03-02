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

#include "uhub.h"

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

static int user_is_protected(struct user* user);

static int set_feature_cast_supports(struct user* u, struct adc_message* cmd)
{
	char *it, *tmp;
	
	if (adc_msg_has_named_argument(cmd, ADC_INF_FLAG_SUPPORT))
	{
		tmp = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_SUPPORT);
		user_clear_feature_cast_support(u);
		
		it = tmp;
		while (strlen(it) > 4)
		{
			it[4] = 0; /* FIXME: Not really needed */
			user_set_feature_cast_support(u, it);
			it = &it[5];
		}
		
		if (*it)
		{
			user_set_feature_cast_support(u, it);
		}
		hub_free(tmp);
	}
	return 0;
}


static int check_hash_tiger(const char* cid, const char* pid)
{
	char x_pid[64];
	char raw_pid[64];
	uint64_t tiger_res[3];
	
	memset(x_pid, 0, MAX_CID_LEN+1);
	
	base32_decode(pid, (unsigned char*) raw_pid, MAX_CID_LEN);
	tiger((uint64_t*) raw_pid, TIGERSIZE, (uint64_t*) tiger_res);
	base32_encode((unsigned char*) tiger_res, TIGERSIZE, x_pid);
	x_pid[MAX_CID_LEN] = 0;
	if (strncasecmp(x_pid, cid, MAX_CID_LEN) == 0)
		return 1;
	return 0;
}


/*
 * FIXME: Only works for tiger hash. If a client doesnt support tiger we cannot let it in!
 */
static int check_cid(struct user* user, struct adc_message* cmd)
{
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


static int check_required_login_flags(struct user* user, struct adc_message* cmd)
{
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
int check_network(struct user* user, struct adc_message* cmd)
{
	int want_ipv4 = 0;
	int want_ipv6 = 0;
	int nat_override = 0;
	const char* address = 0;
	
	if (adc_msg_has_named_argument(cmd, ADC_INF_FLAG_IPV6_ADDR))
	{
		want_ipv6 = 1;
	}
	
	if (adc_msg_has_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR))
	{
		want_ipv4 = 1;
	}
	
	if (!want_ipv4 && !want_ipv6)
		return 0;
	
	/* Add correct/verified IP addresses instead (if requested/stripped) */
	address = (char*) net_get_peer_address(user->sd);
	if (address)
	{
		if (want_ipv4 && strchr(address, '.'))
		{
			want_ipv6 = 0;
		}
		else if (want_ipv6)
		{
			want_ipv4 = 0;
		}
		
		/* check if user can do nat override */
		if (want_ipv4 && acl_is_ip_nat_override(user->hub->acl, address))
		{
			char* client_given_ip = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR);
			if (strcmp(client_given_ip, "0.0.0.0") != 0)
			{
				user_set_nat_override(user);
				nat_override = 1;
			}
			hub_free(client_given_ip);
		}
	}
	
	if (!nat_override)
	{
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR);
		if (!want_ipv4)
			adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV4_UDP_PORT);
		else
			adc_msg_add_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR, address);
		
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV6_ADDR);
		if (!want_ipv6)
			adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV6_UDP_PORT);
		else
			adc_msg_add_named_argument(cmd, ADC_INF_FLAG_IPV6_ADDR, address);
	}
	
	return 0;
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
	
	/* Check for ASCII values below 32 */
	for (tmp = nick; *tmp; tmp++)
		if ((*tmp < 32) && (*tmp > 0))
			return nick_invalid_bad_ascii;
	
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


static int check_nick(struct user* user, struct adc_message* cmd)
{
	char* nick;
	char* tmp;
	enum nick_status status;

	tmp = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_NICK);
	if (!tmp) return 0;
	nick = adc_msg_unescape(tmp);
	free(tmp); tmp = 0;
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


static int check_logged_in(struct user* user, struct adc_message* cmd)
{
	struct user* lookup1 = get_user_by_nick(user->hub, user->id.nick);
	struct user* lookup2 = get_user_by_cid(user->hub,  user->id.cid);
	
	if (lookup1 == user)
	{
		return 0;
	}
	
	if (lookup1 || lookup2)
	{
		if (lookup1 == lookup2)
		{
			hub_log(log_debug, "check_logged_in: exact same user is logged in: %s", user->id.nick);
			user_disconnect(lookup1, quit_timeout);
			return 0;
		}
		else
		{
			if (lookup1)
			{
				hub_log(log_debug, "check_logged_in: nickname is in use: %s", user->id.nick);
				return status_msg_inf_error_nick_taken;
			}
			else
			{
				hub_log(log_debug, "check_logged_in: CID is in use: %s", user->id.cid);
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
static int check_user_agent(struct user* user, struct adc_message* cmd)
{
	char* ua_encoded = 0;
	char* ua = 0;
	
	/* Get client user agent version */
	ua_encoded = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_USER_AGENT);
	if (ua_encoded)
	{
		ua = adc_msg_unescape(ua_encoded);
		if (ua)
		{
			memcpy(user->user_agent, ua, MIN(strlen(ua), MAX_UA_LEN));
			hub_free(ua);
		}
	}
	hub_free(ua_encoded);
	return 0;
}


static int check_acl(struct user* user, struct adc_message* cmd)
{
	if (acl_is_cid_banned(user->hub->acl, user->id.cid))
	{
		return status_msg_ban_permanently;
	}
	
	if (acl_is_user_banned(user->hub->acl, user->id.nick))
	{
		return status_msg_ban_permanently;
	}

	if (acl_is_user_denied(user->hub->acl, user->id.nick))
	{
		return status_msg_inf_error_nick_restricted;
	}
	
	return 0;
}

static int check_limits(struct user* user, struct adc_message* cmd)
{
	char* arg = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_SHARED_SIZE);
	if (arg)
	{
		int64_t shared_size = atoll(arg);
		if (shared_size < 0)
			shared_size = 0;
		
		if (user_is_logged_in(user))
		{
			user->hub->users->shared_size  -= user->limits.shared_size;
			user->hub->users->shared_size  += shared_size;
		}
		user->limits.shared_size = shared_size;
		hub_free(arg);
		arg = 0;
	}
	
	arg = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_SHARED_FILES);
	if (arg)
	{
		ssize_t shared_files = atoll(arg);
		if (shared_files < 0)
			shared_files = 0;
		
		if (user_is_logged_in(user))
		{
			user->hub->users->shared_files -= user->limits.shared_files;
			user->hub->users->shared_files += shared_files;
		}
		user->limits.shared_files = shared_files;
		hub_free(arg);
		arg = 0;
	}
	
	arg = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_COUNT_HUB_NORMAL);
	if (arg)
	{
		ssize_t num = atoll(arg);
		if (num < 0) num = 0;
		user->limits.hub_count_user = num;
		hub_free(arg);
		arg = 0;
	}

	arg = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_COUNT_HUB_REGISTER);
	if (arg)
	{
		ssize_t num = atoll(arg);
		if (num < 0) num = 0;
		user->limits.hub_count_registered = num;
		hub_free(arg);
		arg = 0;
	}

	arg = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_COUNT_HUB_OPERATOR);
	if (arg)
	{
		ssize_t num = atoll(arg);
		if (num < 0) num = 0;
		user->limits.hub_count_operator = num;
		hub_free(arg);
		arg = 0;
	}
	
	arg = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_UPLOAD_SLOTS);
	if (arg)
	{
		ssize_t num = atoll(arg);
		if (num < 0) num = 0;
		user->limits.upload_slots = num;
		hub_free(arg);
		arg = 0;
	}

	/* summarize total slots */
	user->limits.hub_count_total = user->limits.hub_count_user + user->limits.hub_count_registered + user->limits.hub_count_operator;

	if (!user_is_protected(user))
	{
		if (user->limits.shared_size < hub_get_min_share(user->hub) && hub_get_min_share(user->hub))
		{
			return status_msg_user_share_size_low;
		}

		if (user->limits.shared_size > hub_get_max_share(user->hub) && hub_get_max_share(user->hub))
		{
			return status_msg_user_share_size_high;
		}
		
		if ((user->limits.hub_count_user       > hub_get_max_hubs_user(user->hub)  && hub_get_max_hubs_user(user->hub)) ||
			(user->limits.hub_count_registered > hub_get_max_hubs_reg(user->hub)   && hub_get_max_hubs_reg(user->hub)) ||
			(user->limits.hub_count_operator   > hub_get_max_hubs_op(user->hub)    && hub_get_max_hubs_op(user->hub)) ||
			(user->limits.hub_count_total      > hub_get_max_hubs_total(user->hub) && hub_get_max_hubs_total(user->hub)))
		{
			return status_msg_user_hub_limit_high;
		}
		
		if ((user->limits.hub_count_user       < hub_get_min_hubs_user(user->hub)  && hub_get_min_hubs_user(user->hub)) ||
			(user->limits.hub_count_registered < hub_get_min_hubs_reg(user->hub)   && hub_get_min_hubs_reg(user->hub)) ||
			(user->limits.hub_count_operator   < hub_get_min_hubs_op(user->hub)    && hub_get_min_hubs_op(user->hub)))
		{
			return status_msg_user_hub_limit_low;
		}
		
		if (user->limits.upload_slots < hub_get_min_slots(user->hub) && hub_get_min_slots(user->hub))
		{
			return status_msg_user_slots_low;
		}

		if (user->limits.upload_slots > hub_get_max_slots(user->hub) && hub_get_max_slots(user->hub))
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
static int set_credentials(struct user* user, struct adc_message* cmd)
{
	int ret = 0;
	struct user_access_info* info = acl_get_access_info(user->hub->acl, user->id.nick);
	
	if (info)
	{
		user->credentials = info->status;
		ret = 1;
	}
	else
	{
		user->credentials = cred_guest;
	}
	
	switch (user->credentials)
	{
		case cred_none:
			break;
			
		case cred_bot:
			adc_msg_add_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE ADC_CLIENT_TYPE_BOT);
			break;
			
		case cred_guest:
			/* Nothing to be added to the info message */
			break;
		
		case cred_user:
			adc_msg_add_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE ADC_CLIENT_TYPE_REGISTERED_USER);
			break;
		
		case cred_operator:
			adc_msg_add_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE ADC_CLIENT_TYPE_OPERATOR);
			break;
			
		case cred_super:
			adc_msg_add_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE ADC_CLIENT_TYPE_SUPER_USER);
			break;
		
		case cred_admin:
			adc_msg_add_argument(cmd, ADC_INF_FLAG_CLIENT_TYPE ADC_CLIENT_TYPE_ADMIN);
			break;
		
		case cred_link:
			break;
 	}
	
	return ret;
}


/**
 * Determines if a user is to be let into the hub even if the hub is "full".
 */
static int user_is_protected(struct user* user)
{
	switch (user->credentials)
	{
		case cred_bot:
		case cred_operator:
		case cred_super:
		case cred_admin:
		case cred_link:
			return 1;
		default:
			break;
 	}
	return 0;
}

/**
 * Returns 1 if a user is registered.
 * Only registered users will be let in if the hub is configured for registered
 * users only.
 */
static int user_is_registered(struct user* user)
{
	switch (user->credentials)
	{
		case cred_bot:
		case cred_user:
		case cred_operator:
		case cred_super:
		case cred_admin:
		case cred_link:
			return 1;
		default:
			break;
	}
	return 0;
}


void update_user_info(struct user* u, struct adc_message* cmd)
{
	char prefix[2];
	char* argument;
	size_t n = 0;
	struct adc_message* cmd_new = adc_msg_copy(u->info);
	if (!cmd_new)
	{
		/* FIXME: OOM! */
		return;
	}
	
	argument = adc_msg_get_argument(cmd, n++);
	while (argument)
	{
		if (strlen(argument) >= 2)
		{
			prefix[0] = argument[0];
			prefix[1] = argument[1];
			adc_msg_replace_named_argument(cmd_new, prefix, argument+2);
		}
		
		hub_free(argument);
		argument = adc_msg_get_argument(cmd, n++);
	}
	user_set_info(u, cmd_new);
}


static int check_is_hub_full(struct user* user)
{
	/*
	 * If hub is full, don't let users in, but we still want to allow
	 * operators and admins to enter the hub.
	 */
	if (user->hub->config->max_users && user->hub->users->count >= user->hub->config->max_users && !user_is_protected(user))
	{
		return 1;
	}
	return 0;
}


static int check_registered_users_only(struct user* user)
{
	if (user->hub->config->registered_users_only && !user_is_registered(user))
	{
		return 1;
	}
	return 0;
}

#define INF_CHECK(FUNC, USER, CMD) \
	do { \
		int ret = FUNC(USER, CMD); \
		if (ret < 0) \
			return ret; \
	} while(0)

static int hub_handle_info_common(struct user* user, struct adc_message* cmd)
{
	/* Remove server restricted flags */
	remove_server_restricted_flags(cmd);
	
	/* Update/set the feature cast flags. */
	set_feature_cast_supports(user, cmd);
	
	return 0;
}

static int hub_handle_info_low_bandwidth(struct user* user, struct adc_message* cmd)
{
	if (user->hub->config->low_bandwidth_mode)
	{
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_USER_AGENT);
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

int hub_handle_info_login(struct user* user, struct adc_message* cmd)
{
	int need_auth = 0;
	
	/* Make syntax checks.  */
	INF_CHECK(check_required_login_flags,     user, cmd);
	INF_CHECK(check_cid,                      user, cmd);
	INF_CHECK(check_nick,                     user, cmd);
	INF_CHECK(check_network,                  user, cmd);
	INF_CHECK(check_user_agent,               user, cmd);
	INF_CHECK(check_acl,                      user, cmd);
	INF_CHECK(check_logged_in,                user, cmd);
	
	/* Private ID must never be broadcasted - drop it! */
	adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_PRIVATE_ID);
	
	/* FIXME: This needs some cleaning up */
	need_auth = set_credentials(user, cmd);
	
	/* Note: this must be done *after* set_credentials. */
	if (check_is_hub_full(user))
	{
		return status_msg_hub_full;
	}
	
	if (check_registered_users_only(user))
	{
		return status_msg_hub_registered_users_only;
	}
	
	INF_CHECK(check_limits, user, cmd);
	
	/* strip off stuff if low_bandwidth_mode is enabled */
	hub_handle_info_low_bandwidth(user, cmd);
	
	/* Set initial user info */
	user_set_info(user, cmd);
	
	return need_auth;
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
int hub_handle_info(struct user* user, const struct adc_message* cmd_unmodified)
{
	struct adc_message* cmd = adc_msg_copy(cmd_unmodified); /* FIXME: Have a small memory leak here! */
	if (!cmd) return -1; /* OOM */
	
	hub_handle_info_common(user, cmd);

	/* If user is logging in, perform more checks,
	   otherwise only a few things need to be checked.
	 */
	if (user_is_connecting(user))
	{
		int ret = hub_handle_info_login(user, cmd);
		if (ret < 0)
		{
			on_login_failure(user, ret);
			adc_msg_free(cmd);
			return -1;
		}
		else
		{
			/* Post a message, the user has joined */
			struct event_data post;
			memset(&post, 0, sizeof(post));
			post.id    = UHUB_EVENT_USER_JOIN;
			post.ptr   = user;
			post.flags = ret; /* 0 - all OK, 1 - need authentication */
			event_queue_post(user->hub->queue, &post);
			adc_msg_free(cmd);
			return 0;
		}
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
#if ALLOW_CHANGE_NICK
			if (!check_nick(user, cmd))
#endif
				adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_NICK);
		}
		
		/* FIXME - What if limits are not met ? */
		check_limits(user, cmd);
		hub_handle_info_low_bandwidth(user, cmd);
		update_user_info(user, cmd);
		
		if (!adc_msg_is_empty(cmd))
		{
			route_message(user, cmd);
		}
		
		adc_msg_free(cmd);
	}
	
	return 0;
}
