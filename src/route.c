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

int route_message(struct hub_info* hub, struct user* u, struct adc_message* msg)
{
	struct user* target = NULL;

	switch (msg->cache[0])
	{
		case 'B': /* Broadcast to all logged in clients */
			route_to_all(hub, msg);
			break;
			
		case 'D':
			target = uman_get_user_by_sid(hub, msg->target);
			if (target)
			{
				route_to_user(hub, target, msg);
			}
			break;
			
		case 'E':
			target = uman_get_user_by_sid(hub, msg->target);
			if (target)
			{
				route_to_user(hub, target, msg);
				route_to_user(hub, u, msg);
			}
			break;
			
		case 'F':
			route_to_subscribers(hub, msg);
			break;	
		
		default:
			/* Ignore the message */
			break;
	}
	return 0;
}

static inline size_t get_max_send_queue(struct hub_info* hub)
{
	/* TODO: More dynamic send queue limit, for instance:
	 * return MAX(hub->config->max_send_buffer, (hub->config->max_recv_buffer * hub_get_user_count(hub)));
	 */
	return hub->config->max_send_buffer;
}

static inline size_t get_max_send_queue_soft(struct hub_info* hub)
{
	return hub->config->max_send_buffer_soft;
}

/*
 * @return 1 if send queue is OK.
 *         -1 if send queue is overflowed
 *         0 if soft send queue is overflowed (not implemented at the moment)
 */
static inline int check_send_queue(struct hub_info* hub, struct user* user, struct adc_message* msg)
{
	if (user_flag_get(user, flag_user_list))
		return 1;

	if ((user->net.send_queue->size + msg->length) > get_max_send_queue(hub))
		return -1;

	if (user->net.send_queue->size > get_max_send_queue_soft(hub) && msg->priority < 0)
		return 0;

	return 1;
}

int route_to_user(struct hub_info* hub, struct user* user, struct adc_message* msg)
{
#ifdef DEBUG_SENDQ
	char* data = strndup(msg->cache, msg->length-1);
	hub_log(log_protocol, "send %s: \"%s\"", sid_to_string(user->id.sid), data);
	free(data);
#endif

	if (hub_sendq_is_empty(user->net.send_queue))
	{
		/* Perform oportunistic write */
		hub_sendq_add(user->net.send_queue, msg);
		handle_net_write(user);
	}
	else
	{
		if (check_send_queue(hub, user, msg) >= 0)
		{
			user_net_io_want_write(user);
		}
	}
	return 1;
}

int route_to_all(struct hub_info* hub, struct adc_message* command) /* iterate users */
{
	struct user* user = (struct user*) list_get_first(hub->users->list);
	while (user)
	{
		route_to_user(hub, user, command);
		user = (struct user*) list_get_next(hub->users->list);
	}
	
	return 0;
}

int route_to_subscribers(struct hub_info* hub, struct adc_message* command) /* iterate users */
{
	int do_send;
	char* tmp;
	
	struct user* user = (struct user*) list_get_first(hub->users->list);
	while (user)
	{
		if (user->feature_cast)
		{
			do_send = 1;
			
			tmp = list_get_first(command->feature_cast_include);
			while (tmp)
			{
				if (!user_have_feature_cast_support(user, tmp))
				{
					do_send = 0;
					break;
				}
				tmp = list_get_next(command->feature_cast_include);;
			}
			
			if (!do_send) {
				user = (struct user*) list_get_next(hub->users->list);
				continue;
			}
			
			tmp = list_get_first(command->feature_cast_exclude);
			while (tmp)
			{
				if (user_have_feature_cast_support(user, tmp))
				{
					do_send = 0;
					break;
				}
				tmp = list_get_next(command->feature_cast_exclude);
			}
			
			if (do_send)
			{
				route_to_user(hub, user, command);
			}
		}
		user = (struct user*) list_get_next(hub->users->list);
	}
	
	return 0;
}

int route_info_message(struct hub_info* hub, struct user* u)
{
	if (!user_is_nat_override(u))
	{
		return route_to_all(hub, u->info);
	}
	else
	{
		struct adc_message* cmd = adc_msg_copy(u->info);
		const char* address = ip_convert_to_string(&u->net.ipaddr);
		struct user* user = 0;
		
		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR);
		adc_msg_add_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR, address);
	
		user = (struct user*) list_get_first(hub->users->list);
		while (user)
		{
			if (user_is_nat_override(user))
				route_to_user(hub, user, cmd);
			else
				route_to_user(hub, user, u->info);
			
			user = (struct user*) list_get_next(hub->users->list);
		}
		adc_msg_free(cmd);
	}
	return 0;
}
