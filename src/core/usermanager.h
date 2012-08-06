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

#ifndef HAVE_UHUB_USER_MANAGER_H
#define HAVE_UHUB_USER_MANAGER_H

struct reserved_sid
{
	sid_t sid;                   /**<< "Reserved SID" */
	struct sid_pool* pool;       /**<< "Pool the SID was reserved from" */
	struct hub_user* dummy_user; /**<< "Dummy user account for the reserved SID" */
	struct hub_user* real_user;  /**<< "Real user account the SID links to, or NULL if not logged in" */
};

struct hub_user_manager
{
	size_t count;                   /**<< "Number of all fully connected and logged in users" */
	size_t count_peak;              /**<< "Peak number of users" */
	struct sid_pool* sids;
	uint64_t shared_size;           /**<< "The total number of shared bytes among fully connected users." */
	uint64_t shared_files;          /**<< "The total number of shared files among fully connected users." */
	struct linked_list* list;       /**<< "Contains all logged in users" */
	struct timeout_evt* timeout;    /**<< "Timeout handler for statistics" */
	struct linked_list* reserved;   /**<< "Contains reserved SID information" */
	sid_t reserved_end;             /**<< "Value of last reserved SID" */
};

/**
 * Initializes the user manager.
 * @return 0 on success, or -1 if error (out of memory).
 */
extern int uman_init(struct hub_info* hub);

/**
 * Shuts down the user manager.
 * All users will be disconnected and deleted as part of this.
 *
 * @return 0 on success, or -1 in an error occured (hub is invalid).
 */
extern int uman_shutdown(struct hub_info* hub);

/**
 * Generate statistics for logfiles.
 */
extern void uman_update_stats(struct hub_info* hub);
extern void uman_print_stats(struct hub_info* hub);

/**
 * Add a user to the user manager.
 *
 * @param hub The hub to add the user to
 * @param user The user to be added to the hub.
 */
extern int uman_add(struct hub_info* hub, struct hub_user* user);

/**
 * Remove a user from the user manager.
 * This user is connected, and will be moved to the leaving queue, pending
 * all messages in the message queue, and resource cleanup.
 *
 * @return 0 if successfully removed, -1 if error.
 */
extern int uman_remove(struct hub_info* hub, struct hub_user* user);

/**
 * Returns and allocates an unused session ID (SID).
 */
extern sid_t uman_get_free_sid(struct hub_info* hub, struct hub_user* user);

/**
 * Lookup a user based on the session ID (SID).
 *
 * NOTE: This function will only search connected users, which means
 * that SIDs assigned to users who are not yet completely logged in,
 * or are in the process of being disconnected will result in this 
 * function returning NULL even though the sid is not freely available.
 *
 * FIXME: Is that really safe / sensible ?
 * - Makes sense from a message routing point of view.
 *
 * @return a user if found, or NULL if not found
 */
extern struct hub_user* uman_get_user_by_sid(struct hub_info* hub, sid_t sid);

/**
 * Lookup a user based on the client ID (CID).
 * @return a user if found, or NULL if not found
 */
extern struct hub_user* uman_get_user_by_cid(struct hub_info* hub, const char* cid);

/**
 * Lookup a user based on the nick name.
 * @return a user if found, or NULL if not found
 */
extern struct hub_user* uman_get_user_by_nick(struct hub_info* hub, const char* nick);

/**
 * Lookup users based on an ip address range.
 *
 * @return The number of users matching the addressess, or -1 on error (mask is wrong).
 */
extern size_t uman_get_user_by_addr(struct hub_info* hub, struct linked_list* users, struct ip_range* range);

/**
 * Send the user list of connected clients to 'user'.
 * Usually part of the login process.
 *
 * @return 1 if sending the user list succeeded, 0 otherwise.
 */
extern int uman_send_user_list(struct hub_info* hub, struct hub_user* user);

/**
 * Send a quit message to all connected users when 'user' is
 * leaving the hub (for whatever reason).
 */
extern void uman_send_quit_message(struct hub_info* hub, struct hub_user* user);


#endif /* HAVE_UHUB_USER_MANAGER_H */
