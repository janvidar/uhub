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

#ifndef HAVE_UHUB_ACL_H
#define HAVE_UHUB_ACL_H

struct hub_config;
struct user;
struct ip_addr_encap;

enum password_status
{
	password_invalid  = 0,
	password_ok       = 1,
};

enum acl_status
{
	acl_not_found       = 0,
	acl_found           = 1,
};

enum user_credentials
{
	cred_none,                 /**<<< "User has no credentials (not yet logged in)" */
 	cred_bot,                  /**<<< "User is a robot" */
	cred_guest,                /**<<< "User is a guest (unregistered user)" */
 	cred_user,                 /**<<< "User is identified as a registered user" */
	cred_operator,             /**<<< "User is identified as a hub operator" */
	cred_super,                /**<<< "User is a super user" (not used) */
	cred_admin,                /**<<< "User is identified as a hub administrator/owner" */
 	cred_link,                 /**<<< "User is a link (not used currently)" */
};

const char* get_user_credential_string(enum user_credentials cred);

struct user_access_info
{
	char* username;          /* name of user, cid or IP range */
	char* password;          /* password */
	enum user_credentials status;
};

struct ip_ban_record
{
	struct ip_addr_encap lo;
	struct ip_addr_encap hi;
};

struct acl_handle
{
	struct linked_list* users;          /* Known users. See enum user_status */
	struct linked_list* cids;           /* Known CIDs */
	struct linked_list* networks;       /* IP ranges, used for banning */
	struct linked_list* nat_override;   /* IPs inside these ranges can provide their false IP. Use with care! */
	struct linked_list* users_banned;   /* Users permanently banned */
	struct linked_list* users_denied;   /* bad nickname */
};


extern int acl_initialize(struct hub_config* config, struct acl_handle* handle);
extern int acl_shutdown(struct acl_handle* handle);

extern struct user_access_info* acl_get_access_info(struct acl_handle* handle, const char* name);
extern int acl_is_cid_banned(struct acl_handle* handle, const char* cid);
extern int acl_is_ip_banned(struct acl_handle* handle, const char* ip_address);
extern int acl_is_ip_nat_override(struct acl_handle* handle, const char* ip_address);

extern int acl_is_user_banned(struct acl_handle* handle, const char* name);
extern int acl_is_user_denied(struct acl_handle* handle, const char* name);

extern int acl_check_ip_range(struct ip_addr_encap* addr, struct ip_ban_record* info);

extern const char* acl_password_generate_challenge(struct acl_handle* acl, struct user* user);
extern int acl_password_verify(struct acl_handle* acl, struct user* user, const char* password);

#endif /* HAVE_UHUB_ACL_H */
