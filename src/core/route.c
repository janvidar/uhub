/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2014, Jan Vidar Krey
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

#include "uhub.h"

int route_message(struct hub_info* hub, struct hub_user* u, struct adc_message* msg)
{
	struct hub_user* target = NULL;

	switch (msg->cache[0])
	{
		case 'B': /* Broadcast to all logged in clients */
			route_to_all(hub, msg);
			break;

		case 'D':
			target = uman_get_user_by_sid(hub->users, msg->target);
			if (target)
			{
				route_to_user(hub, target, msg);
			}
			break;

		case 'E':
			target = uman_get_user_by_sid(hub->users, msg->target);
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

static size_t get_max_send_queue(struct hub_info* hub)
{
	/* TODO: More dynamic send queue limit, for instance:
	 * return MAX(hub->config->max_send_buffer, (hub->config->max_recv_buffer * hub_get_user_count(hub)));
	 */
	return hub->config->max_send_buffer;
}

static size_t get_max_send_queue_soft(struct hub_info* hub)
{
	return hub->config->max_send_buffer_soft;
}

/*
 * @return 1 if send queue is OK.
 *         -1 if send queue is overflowed
 *         0 if soft send queue is overflowed (not implemented at the moment)
 */
static int check_send_queue(struct hub_info* hub, struct hub_user* user, struct adc_message* msg)
{
	if (user_flag_get(user, flag_user_list))
		return 1;

	if ((user->send_queue->size + msg->length) > get_max_send_queue(hub))
	{
		LOG_WARN("send queue overflowed, message discarded.");
		return -1;
	}

	if (user->send_queue->size > get_max_send_queue_soft(hub))
	{
		LOG_WARN("send queue soft overflowed.");
		return 0;
	}

	return 1;
}

int route_to_user(struct hub_info* hub, struct hub_user* user, struct adc_message* msg)
{
#ifdef DEBUG_SENDQ
	char* data = strndup(msg->cache, msg->length-1);
	LOG_PROTO("send %s: \"%s\"", sid_to_string(user->id.sid), data);
	free(data);
#endif

	if (!user->connection)
		return 0;

	uhub_assert(msg->cache && *msg->cache);

	if (ioq_send_is_empty(user->send_queue) && !user_flag_get(user, flag_pipeline))
	{
		/* Perform oportunistic write */
		ioq_send_add(user->send_queue, msg);
		handle_net_write(user);
	}
	else
	{
		if (check_send_queue(hub, user, msg) >= 0)
		{
			ioq_send_add(user->send_queue, msg);
			if (!user_flag_get(user, flag_pipeline))
				user_net_io_want_write(user);
		}
	}
	return 1;
}

int route_flush_pipeline(struct hub_info* hub, struct hub_user* u)
{
	if (ioq_send_is_empty(u->send_queue))
		return 0;

	handle_net_write(u);
	user_flag_unset(u, flag_pipeline);
	return 1;
}


int route_to_all(struct hub_info* hub, struct adc_message* command) /* iterate users */
{
	struct hub_user* user;
	LIST_FOREACH(struct hub_user*, user, hub->users->list,
	{
		route_to_user(hub, user, command);
	});

	return 0;
}

int route_to_subscribers(struct hub_info* hub, struct adc_message* command) /* iterate users */
{
	int do_send;
	char* tmp;

	struct hub_user* user;
	LIST_FOREACH(struct hub_user*, user, hub->users->list,
	{
		if (user->feature_cast)
		{
			do_send = 1;

			LIST_FOREACH(char*, tmp, command->feature_cast_include,
			{
				if (!user_have_feature_cast_support(user, tmp))
				{
					do_send = 0;
					break;
				}
			});

			if (!do_send)
				continue;

			LIST_FOREACH(char*, tmp, command->feature_cast_exclude,
			{
				if (user_have_feature_cast_support(user, tmp))
				{
					do_send = 0;
					break;
				}
			});

			if (do_send)
				route_to_user(hub, user, command);
		}
	});

	return 0;
}

int route_info_message(struct hub_info* hub, struct hub_user* u)
{
	if (!user_is_nat_override(u))
	{
		return route_to_all(hub, u->info);
	}
	else
	{
		struct adc_message* cmd = adc_msg_copy(u->info);
		const char* address = user_get_address(u);
		struct hub_user* user = 0;

		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR);
		adc_msg_add_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR, address);

		LIST_FOREACH(struct hub_user*, user, hub->users->list,
		{
			if (user_is_nat_override(user))
				route_to_user(hub, user, cmd);
			else
				route_to_user(hub, user, u->info);
		});
		adc_msg_free(cmd);
	}
	return 0;
}
