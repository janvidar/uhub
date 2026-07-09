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

#ifndef HAVE_UHUB_ACL_H
#define HAVE_UHUB_ACL_H

#include <time.h>

struct linked_list;
struct auth_info;

struct hub_config;
struct hub_info;
struct hub_user;
struct ip_addr_encap;

struct acl_handle
{
	struct linked_list* cids;           /* Known CIDs */
	struct linked_list* networks;       /* IP ranges, used for banning */
	struct linked_list* nat_override;   /* IPs inside these ranges can provide their false IP. Use with care! */
	struct linked_list* users_banned;   /* Users permanently banned */
	struct linked_list* users_denied;   /* bad nickname */
	struct linked_list* timed_bans;     /* Runtime bans with an expiry (struct acl_timed_ban) */
};


extern int acl_initialize(struct hub_config* config, struct acl_handle* handle);
extern int acl_shutdown(struct acl_handle* handle);

extern struct auth_info* acl_get_access_info(struct hub_info* hub, const char* name);
extern int acl_register_user(struct hub_info* hub, struct auth_info* info);
extern int acl_update_user(struct hub_info* hub, struct auth_info* info);
extern int acl_delete_user(struct hub_info* hub, const char* name);


extern int acl_is_cid_banned(struct acl_handle* handle, const char* cid);
extern int acl_is_ip_banned(struct acl_handle* handle, const char* ip_address);
extern int acl_is_ip_nat_override(struct acl_handle* handle, const char* ip_address);

extern int acl_is_user_banned(struct acl_handle* handle, const char* name);
extern int acl_is_user_denied(struct acl_handle* handle, const char* name);

extern int acl_user_ban_nick(struct acl_handle* handle, const char* nick);
extern int acl_user_ban_cid(struct acl_handle* handle, const char* cid);
extern int acl_user_unban_nick(struct acl_handle* handle, const char* nick);
extern int acl_user_unban_cid(struct acl_handle* handle, const char* cid);
extern int acl_user_unban_ip(struct acl_handle* handle, const char* address);

/* Timed (expiring) runtime bans. expiry is an absolute unix time. */
extern int acl_add_timed_ban(struct acl_handle* handle, const char* cid, const char* nick, time_t expiry);
/* Returns seconds remaining (>0) if cid or nick matches a non-expired timed ban
   at time 'now'; 0 if not banned. Purges entries that have expired. */
extern time_t acl_timed_ban_remaining(struct acl_handle* handle, const char* cid, const char* nick, time_t now);
/* Remove timed bans whose cid or nick equals target. Returns the number removed. */
extern int acl_timed_unban(struct acl_handle* handle, const char* target);

/**
 * Verify a password.
 *
 * @param password the hashed password (based on the nonce).
 * @return 1 if the password matches, or 0 if the password is incorrect.
 */
extern int acl_password_verify(struct hub_info* hub, struct hub_user* user, const char* password);
extern const char* acl_password_generate_challenge(struct hub_info* hub, struct hub_user* user);

/**
 * Verify a password challenge-response without a hub_user: given the stored
 * plaintext password, the base32 challenge that was issued, and the client's
 * base32 response, return 1 if the response is correct. Used by the auth master
 * to verify a login proxied from a slave (which holds no passwords).
 */
extern int acl_password_verify_raw(const char* password, const char* challenge, const char* response);


#endif /* HAVE_UHUB_ACL_H */
