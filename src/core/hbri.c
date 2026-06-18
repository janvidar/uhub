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

#include "system.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "util/tiger.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "network/connection.h"
#include "network/ipcalc.h"
#include "core/config.h"
#include "core/hbri.h"
#include "core/hub.h"
#include "core/route.h"
#include "core/user.h"
#include "core/usermanager.h"
#include <openssl/rand.h>

/*
 * Compute the MAC portion of a token for the given user.
 * out must be at least MAX_CID_LEN+1 bytes.
 */
static void hbri_compute_mac(struct hub_info* hub, struct hub_user* user, char* out)
{
	char buf[sizeof(hub->hub_secret) + 12];
	uint64_t mac[3];

	size_t offset = 0;

	/* Add hub secret */
	memcpy(buf + offset, hub->hub_secret, sizeof(hub->hub_secret));
	offset += sizeof(hub->hub_secret);

	/* Add SID (4 bytes) */
	uint32_t sid = (uint32_t) user->id.sid;
	memcpy(buf + offset, &sid, sizeof(sid));
	offset += sizeof(sid);

	/* Add time connected (8 bytes) */
	uint64_t time_connected = (uint64_t) user->tm_connected;
	memcpy(buf + offset, &time_connected, sizeof(time_connected));
	offset += sizeof(time_connected);

	tiger((uint64_t*) buf, offset, mac);
	base32_encode((unsigned char*) mac, TIGERSIZE, out);
	out[MAX_CID_LEN] = 0;
}

/* Constant-time string compare to avoid leaking the MAC via timing. */
static int hbri_const_time_equal(const char* a, const char* b, size_t len)
{
	unsigned char diff = 0;
	size_t i;
	for (i = 0; i < len; i++)
		diff |= (unsigned char) (a[i] ^ b[i]);
	return diff == 0;
}

int hbri_is_enabled(struct hub_info* hub)
{
	return hub->config->hbri_enable
		&& hub->config->hbri_address4 && *hub->config->hbri_address4
		&& hub->config->hbri_address6 && *hub->config->hbri_address6;
}

/*
 * The protocol family the user did NOT connect over. Returns AF_INET or
 * AF_INET6, or -1 if the connection family is unknown.
 */
static int hbri_secondary_af(struct hub_user* user)
{
	if (user->id.addr.af == AF_INET)
		return AF_INET6;
	if (user->id.addr.af == AF_INET6)
		return AF_INET;
	return -1;
}

static const char* hbri_inf_addr_flag(int af)
{
	return (af == AF_INET6) ? ADC_INF_FLAG_IPV6_ADDR : ADC_INF_FLAG_IPV4_ADDR;
}

static const char* hbri_inf_udp_flag(int af)
{
	return (af == AF_INET6) ? ADC_INF_FLAG_IPV6_UDP_PORT : ADC_INF_FLAG_IPV4_UDP_PORT;
}

static int hbri_addr_is_valid(int af, const char* addr)
{
	if (af == AF_INET6)
		return ip_is_valid_ipv6(addr);
	return ip_is_valid_ipv4(addr);
}

/*
 * Remove the secondary-family address (and matching UDP port) from a stored
 * INF. Used when validation fails or is impossible so the unverified address
 * is never broadcast.
 */
static void hbri_strip_secondary(struct hub_user* user)
{
	int af = hbri_secondary_af(user);
	if (af == -1 || !user->info)
		return;
	adc_msg_remove_named_argument(user->info, hbri_inf_addr_flag(af));
	adc_msg_remove_named_argument(user->info, hbri_inf_udp_flag(af));
}

int hbri_is_candidate(struct hub_info* hub, struct hub_user* user)
{
	int af;
	char* addr;
	int valid;

	if (!hbri_is_enabled(hub))
		return 0;

	if (!user_flag_get(user, feature_hbri))
		return 0;

	if (!user->info)
		return 0;

	af = hbri_secondary_af(user);
	if (af == -1)
		return 0;

	/* The user must advertise an address in the protocol family it did not
	   connect over -- that is the address we will ask it to prove. */
	addr = adc_msg_get_named_argument(user->info, hbri_inf_addr_flag(af));
	if (!addr || !*addr)
	{
		hub_free(addr);
		return 0;
	}

	valid = hbri_addr_is_valid(af, addr);
	hub_free(addr);
	return valid;
}

/*
 * Build a stateless validation token for the user: the SID prefix followed by
 * the MAC. out must be at least HBRI_TOKEN_LEN + 1 bytes.
 */
void hbri_token_make(struct hub_info* hub, struct hub_user* user, char* out)
{
	char mac[MAX_CID_LEN + 1];
	memcpy(out, sid_to_string(user->id.sid), HBRI_SID_LEN);
	hbri_compute_mac(hub, user, mac);
	memcpy(out + HBRI_SID_LEN, mac, MAX_CID_LEN + 1); /* includes terminator */
}

/*
 * @return 1 if 'token' is a valid token for 'user' (correct length, SID prefix
 * matching the user, and a MAC that verifies against the per-hub secret).
 */
int hbri_token_check(struct hub_info* hub, struct hub_user* user, const char* token)
{
	char sidstr[HBRI_SID_LEN + 1];
	char expected[MAX_CID_LEN + 1];

	if (!user || !token || strlen(token) != HBRI_TOKEN_LEN)
		return 0;

	memcpy(sidstr, token, HBRI_SID_LEN);
	sidstr[HBRI_SID_LEN] = 0;
	if (string_to_sid(sidstr) != user->id.sid)
		return 0;

	hbri_compute_mac(hub, user, expected);
	return hbri_const_time_equal(token + HBRI_SID_LEN, expected, MAX_CID_LEN);
}

/*
 * Send a status message to a logged-in or connecting user.
 */
static void hbri_send_status(struct hub_info* hub, struct hub_user* user, const char* code, const char* message)
{
	struct adc_message* sta = adc_msg_construct(ADC_CMD_ISTA, 128);
	char* escaped;
	if (!sta)
		return;
	escaped = adc_msg_escape(message);
	adc_msg_add_argument(sta, code);
	if (escaped)
		adc_msg_add_argument(sta, escaped);
	hub_free(escaped);
	route_to_user(hub, user, sta);
	adc_msg_free(sta);
}

void hbri_send_validation_request(struct hub_info* hub, struct hub_user* user)
{
	int af = hbri_secondary_af(user);
	const char* hub_addr;
	const char* addr_flag;
	const char* port_flag;
	struct adc_message* cmd;
	char token[HBRI_TOKEN_LEN + 1];

	if (af == -1 || !hbri_is_enabled(hub))
		return;

	if (af == AF_INET6)
	{
		hub_addr  = hub->config->hbri_address6;
		addr_flag = ADC_INF_FLAG_IPV6_ADDR;
		port_flag = ADC_INF_FLAG_IPV6_TCP_PORT;
	}
	else
	{
		hub_addr  = hub->config->hbri_address4;
		addr_flag = ADC_INF_FLAG_IPV4_ADDR;
		port_flag = ADC_INF_FLAG_IPV4_TCP_PORT;
	}

	cmd = adc_msg_construct(ADC_CMD_ITCP, 96);
	if (!cmd)
		return;

	hbri_token_make(hub, user, token);

	adc_msg_add_named_argument(cmd, addr_flag, hub_addr);
	adc_msg_add_named_argument(cmd, port_flag, uhub_itoa(hub->config->server_port));
	adc_msg_add_named_argument(cmd, ADC_INF_FLAG_TOKEN, token);

	LOG_DEBUG("HBRI: requesting %s validation (token %s) for %s",
		(af == AF_INET6) ? "IPv6" : "IPv4", token, user->id.nick);

	route_to_user(hub, user, cmd);
	adc_msg_free(cmd);
}

void hbri_on_login(struct hub_info* hub, struct hub_user* user)
{
	/*
	 * The user logs in over its primary protocol now; its INF has already been
	 * broadcast by the caller. Strip the (still unverified) second-family
	 * address from the stored INF so it is not advertised yet, then ask the
	 * client to prove it. If validation later succeeds the address is added
	 * back via an INF update. If it never comes, the user simply stays
	 * primary-only -- no timeout, nothing held.
	 */
	if (!hbri_is_candidate(hub, user))
		return;

	hbri_strip_secondary(user);
	hbri_send_validation_request(hub, user);
}

int hbri_handle_validation(struct hub_info* hub, struct hub_user* vuser, struct adc_message* cmd)
{
	struct hub_user* main_user;
	char* token;
	char sidstr[HBRI_SID_LEN + 1];
	sid_t sid;
	int sec_af;
	const char* real_addr;
	char real_addr_copy[INET6_ADDRSTRLEN + 1];
	char* claimed_addr;
	char* claimed_udp;
	struct adc_message* sta;

	token = adc_msg_get_named_argument(cmd, ADC_INF_FLAG_TOKEN);
	if (!token || strlen(token) != HBRI_TOKEN_LEN)
	{
		LOG_DEBUG("HBRI: validation reply missing or malformed token");
		hbri_send_status(hub, vuser, "150", "Validation token missing");
		hub_free(token);
		return -1;
	}

	/* Parse the SID prefix and find the user it refers to. The user is
	   registered in the SID pool from the moment its SID is assigned, so it is
	   found even while still logging in. */
	memcpy(sidstr, token, HBRI_SID_LEN);
	sidstr[HBRI_SID_LEN] = 0;
	sid = string_to_sid(sidstr);
	main_user = sid ? uman_get_user_by_sid(hub->users, sid) : 0;

	/*
	 * The token must refer to a logged-in user (the main connection is never
	 * held, so by the time the client connects back it is in the normal state)
	 * and must verify against the per-hub secret. The MAC binds the token to a
	 * single SID, so a client cannot validate on another user's behalf.
	 */
	if (!main_user || !user_is_logged_in(main_user) || !hbri_token_check(hub, main_user, token))
	{
		LOG_DEBUG("HBRI: token refers to an unknown user or fails verification (sid %s)", sidstr);
		hbri_send_status(hub, vuser, "150", "Unknown validation token");
		hub_free(token);
		return -1;
	}
	hub_free(token);

	/* The validation connection must arrive over the OTHER protocol than the
	   main connection -- that is the whole point of the exercise. */
	if (vuser->id.addr.af == main_user->id.addr.af)
	{
		LOG_DEBUG("HBRI: validation arrived over the wrong IP protocol");
		hbri_send_status(hub, vuser, "151", "Validation received over the wrong IP protocol");
		return -1;
	}

	sec_af = vuser->id.addr.af;

	/* The authoritative second-family address is the validation connection's
	   real remote IP. If the client also advertised one it must match (unless
	   the advertised value is empty), mirroring the main login IP check. */
	real_addr = ip_convert_to_string(&vuser->id.addr);
	strncpy(real_addr_copy, real_addr ? real_addr : "", sizeof(real_addr_copy) - 1);
	real_addr_copy[sizeof(real_addr_copy) - 1] = 0;

	claimed_addr = adc_msg_get_named_argument(cmd, hbri_inf_addr_flag(sec_af));
	if (claimed_addr && *claimed_addr && strcmp(claimed_addr, real_addr_copy) != 0)
	{
		LOG_DEBUG("HBRI: advertised %s does not match real address %s", claimed_addr, real_addr_copy);
		hbri_send_status(hub, vuser, "152", "Advertised address does not match");
		hub_free(claimed_addr);
		/* The user simply keeps whatever address it already had. */
		return -1;
	}
	hub_free(claimed_addr);

	/* Merge the proven address (and the advertised secondary UDP port) into the
	   main user's INF, and broadcast the update only if it actually changed
	   anything -- this also dedupes repeated validation connections. */
	if (main_user->info)
	{
		char* old_addr = adc_msg_get_named_argument(main_user->info, hbri_inf_addr_flag(sec_af));
		int changed = !old_addr || strcmp(old_addr, real_addr_copy) != 0;
		hub_free(old_addr);

		adc_msg_remove_named_argument(main_user->info, hbri_inf_addr_flag(sec_af));
		adc_msg_add_named_argument(main_user->info, hbri_inf_addr_flag(sec_af), real_addr_copy);

		claimed_udp = adc_msg_get_named_argument(cmd, hbri_inf_udp_flag(sec_af));
		adc_msg_remove_named_argument(main_user->info, hbri_inf_udp_flag(sec_af));
		if (claimed_udp && *claimed_udp)
			adc_msg_add_named_argument(main_user->info, hbri_inf_udp_flag(sec_af), claimed_udp);
		hub_free(claimed_udp);

		LOG_DEBUG("HBRI: validated %s address %s for %s",
			(sec_af == AF_INET6) ? "IPv6" : "IPv4", real_addr_copy, main_user->id.nick);

		if (changed)
			route_info_message(hub, main_user);
	}

	/* Tell the validation connection it succeeded, then close it. We send
	   synchronously because hub_disconnect_user() does not flush the queue. */
	sta = adc_msg_construct(ADC_CMD_ISTA, 64);
	if (sta)
	{
		adc_msg_add_argument(sta, "000");
		adc_msg_add_argument(sta, "Validation\\ssucceeded");
		if (vuser->connection && sta->cache && sta->length)
			net_con_send(vuser->connection, sta->cache, sta->length);
		adc_msg_free(sta);
	}

	/* Always close the validation connection. */
	return -1;
}
