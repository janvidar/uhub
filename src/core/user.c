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

struct hub_user* user_create(struct hub_info* hub, int sd)
{
	struct hub_user* user = NULL;
	
	LOG_TRACE("user_create(), hub=%p, sd=%d", hub, sd);

	user = (struct hub_user*) hub_malloc_zero(sizeof(struct hub_user));

	if (user == NULL)
		return NULL; /* OOM */

	user->net.sd = sd;
	user->net.tm_connected = time(NULL);
	user->net.send_queue = hub_sendq_create();
	user->net.recv_queue = hub_recvq_create();

	event_set(&user->net.event, sd, EV_READ | EV_PERSIST, net_event, user);
	event_base_set(hub->evbase, &user->net.event);
	event_add(&user->net.event, 0);

	evtimer_set(&user->net.timeout, net_event, user);
	event_base_set(hub->evbase, &user->net.timeout);
	

	user_set_timeout(user, TIMEOUT_CONNECTED);

	user_set_state(user, state_protocol);
	return user;
}


void user_destroy(struct hub_user* user)
{
	LOG_TRACE("user_destroy(), user=%p", user);

	event_del(&user->net.event);
	evtimer_del(&user->net.timeout);
	
	hub_recvq_destroy(user->net.recv_queue);
	hub_sendq_destroy(user->net.send_queue);
	net_close(user->net.sd);
	
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
	user->info = adc_msg_incref(cmd);
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
		case FOURCC('B','A','S','0'): /* Obsolete */
#ifndef OLD_ADC_SUPPORT
			return 0;
#endif
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

void user_disconnect(struct hub_user* user, int reason)
{


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
int user_is_registered(struct hub_user* user)
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

void user_net_io_want_write(struct hub_user* user)
{
#ifdef DEBUG_SENDQ
	LOG_TRACE("user_net_io_want_write: %s (pending: %d)", user_log_str(user), event_pending(&user->net.event, EV_READ | EV_WRITE, 0));
#endif
	if (event_pending(&user->net.event, EV_READ | EV_WRITE, 0) == (EV_READ | EV_WRITE))
		return;
	event_del(&user->net.event);
	event_set(&user->net.event,  user->net.sd, EV_READ | EV_WRITE | EV_PERSIST, net_event, user);
	event_add(&user->net.event, 0);
}

void user_net_io_want_read(struct hub_user* user)
{
#ifdef DEBUG_SENDQ
	LOG_TRACE("user_net_io_want_read: %s (pending: %d)", user_log_str(user), event_pending(&user->net.event, EV_READ | EV_WRITE, 0));
#endif
	if (event_pending(&user->net.event, EV_READ | EV_WRITE, 0) == EV_READ)
		return;
	event_del(&user->net.event);
	event_set(&user->net.event,  user->net.sd, EV_READ | EV_PERSIST, net_event, user);
	event_add(&user->net.event, 0);
}

void user_reset_last_write(struct hub_user* user)
{
	user->net.tm_last_write = time(NULL);
}

void user_reset_last_read(struct hub_user* user)
{
	user->net.tm_last_read = time(NULL);
}

void user_set_timeout(struct hub_user* user, int seconds)
{
#ifdef DEBUG_SENDQ
	LOG_TRACE("user_set_timeout to %d seconds: %s", seconds, user_log_str(user));
#endif
	struct timeval timeout = { seconds, 0 };
	evtimer_add(&user->net.timeout, &timeout);
}


