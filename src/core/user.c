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

#ifdef DEBUG_SENDQ
static const char* user_log_str(struct hub_user* user)
{
	static char buf[128];
	if (user)
	{
		snprintf(buf, 128, "user={ %p, \"%s\", %s/%s}", user, user->id.nick, sid_to_string(user->id.sid), user->id.cid);
	}
	else
	{
		snprintf(buf, 128, "user={ %p }", user);
	}
	return buf;
}
#endif

struct hub_user* user_create(struct hub_info* hub, struct net_connection* con, struct ip_addr_encap* addr)
{
	struct hub_user* user = NULL;
	
	LOG_TRACE("user_create(), hub=%p, con[sd=%d]", hub, net_con_get_sd(con));

	user = (struct hub_user*) hub_malloc_zero(sizeof(struct hub_user));

	if (user == NULL)
		return NULL; /* OOM */

	user->send_queue = hub_sendq_create();
	user->recv_queue = hub_recvq_create();

	user->connection = con;
	net_con_reinitialize(user->connection, net_event, user, NET_EVENT_READ);

	memcpy(&user->id.addr, addr, sizeof(struct ip_addr_encap));
	user_set_state(user, state_protocol);

	flood_control_reset(&user->flood_chat);
	flood_control_reset(&user->flood_connect);
	flood_control_reset(&user->flood_search);
	flood_control_reset(&user->flood_update);
	flood_control_reset(&user->flood_extras);

	user->hub = hub;
	return user;
}


void user_destroy(struct hub_user* user)
{
	LOG_TRACE("user_destroy(), user=%p", user);

	hub_recvq_destroy(user->recv_queue);
	hub_sendq_destroy(user->send_queue);

	if (user->connection)
	{
		LOG_TRACE("user_destory() -> net_con_close(%p)", user->connection);
		net_con_close(user->connection);
	}

	adc_msg_free(user->info);
	user_clear_feature_cast_support(user);
	hub_free(user);
}

void user_set_state(struct hub_user* user, enum user_state state)
{
	if ((user->state == state_cleanup && state != state_disconnected) || (user->state == state_disconnected))
	{
		return;
	}
	
	user->state = state;
}

void user_set_info(struct hub_user* user, struct adc_message* cmd)
{
	adc_msg_free(user->info);
	if (cmd)
	{
		user->info = adc_msg_incref(cmd);
	}
	else
	{
		user->info = 0;
	}
}

void user_update_info(struct hub_user* u, struct adc_message* cmd)
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

	/*
	 * FIXME: Optimization potential:
	 *
	 * remove parts of cmd that do not really change anything in cmd_new.
	 * this can save bandwidth if clients send multiple updates for information
	 * that does not really change anything.
	 */
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
	adc_msg_free(cmd_new);
}


static int convert_support_fourcc(int fourcc)
{
	switch (fourcc)
	{
		case FOURCC('B','A','S','0'):
			return feature_bas0;

		case FOURCC('B','A','S','E'):
			return feature_base;

		case FOURCC('A','U','T','0'):
			return  feature_auto;

		case FOURCC('U','C','M','0'):
		case FOURCC('U','C','M','D'):
			return feature_ucmd;

		case FOURCC('Z','L','I','F'):
			return feature_zlif;

		case FOURCC('B','B','S','0'):
			return feature_bbs;

		case FOURCC('T','I','G','R'):
			return feature_tiger;

		case FOURCC('B','L','O','M'):
		case FOURCC('B','L','O','0'):
			return feature_bloom;

		case FOURCC('P','I','N','G'):
			return feature_ping;

		case FOURCC('L','I','N','K'):
			return feature_link;

		case FOURCC('A','D','C','S'):
			return feature_adcs;

		// ignore these extensions, they are not useful for the hub.
		case FOURCC('D','H','T','0'):
			return 0;

		default:
			LOG_DEBUG("Unknown extension: %x", fourcc);
			return 0;
	}
}

void user_support_add(struct hub_user* user, int fourcc)
{
	int feature_mask = convert_support_fourcc(fourcc);
	user->flags |= feature_mask;
}

int user_flag_get(struct hub_user* user, enum user_flags flag)
{
    return user->flags & flag;
}

void user_flag_set(struct hub_user* user, enum user_flags flag)
{
    user->flags |= flag;
}

void user_flag_unset(struct hub_user* user, enum user_flags flag)
{
    user->flags &= ~flag;
}

void user_set_nat_override(struct hub_user* user)
{
	user_flag_set(user, flag_nat);
}

int user_is_nat_override(struct hub_user* user)
{
	return user_flag_get(user, flag_nat);
}

void user_support_remove(struct hub_user* user, int fourcc)
{
	int feature_mask = convert_support_fourcc(fourcc);
	user->flags &= ~feature_mask;
}

int user_have_feature_cast_support(struct hub_user* user, char feature[4])
{
	char* tmp = list_get_first(user->feature_cast);
	while (tmp)
	{
		if (strncmp(tmp, feature, 4) == 0)
			return 1;
	
		tmp = list_get_next(user->feature_cast);
	}
	
	return 0;
}

int user_set_feature_cast_support(struct hub_user* u, char feature[4])
{
	if (!u->feature_cast)
	{
		u->feature_cast = list_create();
	}

	if (!u->feature_cast)
	{
		return 0; /* OOM! */
	}

	list_append(u->feature_cast, hub_strndup(feature, 4));
	return 1;
}

void user_clear_feature_cast_support(struct hub_user* u)
{
	if (u->feature_cast)
	{
		list_clear(u->feature_cast, &hub_free);
		list_destroy(u->feature_cast);
		u->feature_cast = 0;
	}
}

int user_is_logged_in(struct hub_user* user)
{
	if (user->state == state_normal)
		return 1;
	return 0;
}

int user_is_connecting(struct hub_user* user)
{
	if (user->state == state_protocol || user->state == state_identify || user->state == state_verify)
		return 1;
	return 0;
}

int user_is_protocol_negotiating(struct hub_user* user)
{
	if (user->state == state_protocol)
		return 1;
	return 0;
}

int user_is_disconnecting(struct hub_user* user)
{
	if (user->state == state_cleanup || user->state == state_disconnected)
		return 1;
	return 0;
}

int user_is_protected(struct hub_user* user)
{
	return auth_cred_is_protected(user->credentials);
}

/**
 * Returns 1 if a user is registered.
 * Only registered users will be let in if the hub is configured for registered
 * users only.
 */
int user_is_registered(struct hub_user* user)
{
	return auth_cred_is_registered(user->credentials);
}

void user_net_io_want_write(struct hub_user* user)
{
	net_con_update(user->connection, NET_EVENT_READ | NET_EVENT_WRITE);
}

void user_net_io_want_read(struct hub_user* user)
{
	net_con_update(user->connection, NET_EVENT_READ);
}

const char* user_get_quit_reason_string(enum user_quit_reason reason)
{
	switch (reason)
	{
		case quit_unknown:          return "unknown";        break;
		case quit_disconnected:     return "disconnected";   break;
		case quit_kicked:           return "kicked";         break;
		case quit_banned:           return "banned";         break;
		case quit_timeout:          return "timeout";        break;
		case quit_send_queue:       return "send queue";     break;
		case quit_memory_error:     return "out of memory";  break;
		case quit_socket_error:     return "socket error";   break;
		case quit_protocol_error:   return "protocol error"; break;
		case quit_logon_error:      return "login error";    break;
		case quit_update_error:     return "update error";   break;
		case quit_hub_disabled:     return "hub disabled";   break;
		case quit_ghost_timeout:    return "ghost";          break;
	}

	return "unknown";
}

const char* user_get_address(struct hub_user* user)
{
	return ip_convert_to_string(&user->id.addr);
}
