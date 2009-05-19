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
#include "hubio.h"

/* FIXME: This should not be needed! */
extern struct hub_info* g_hub;

int net_user_send(void* ptr, const void* buf, size_t len)
{
	struct user* user = (struct user*) ptr;
	int ret = net_send(user->sd, buf, len, UHUB_SEND_SIGNAL);
	printf("net_user_send: %d/%d bytes\n", ret, (int) len);
	if (ret == -1)
	{
		printf("    errno: %d - %s\n", errno, strerror(errno));
	}

	return ret;
}

int net_user_recv(void* ptr, void* buf, size_t len)
{
	struct user* user = (struct user*) ptr;
	int ret = net_recv(user->sd, buf, len, 0);
	printf("net_user_recv: %d/%d bytes\n", ret, (int) len);
	if (ret == -1)
	{
		printf("    errno: %d - %s\n", errno, strerror(errno));
	}
	return ret;
}


void net_on_read(int fd, short ev, void *arg)
{
	struct user* user = (struct user*) arg;
	int more = 1;
	int flag_close = 0;
	
	hub_log(log_trace, "net_on_read() : fd=%d, ev=%d, arg=%p", fd, (int) ev, arg);
	
	if (ev == EV_TIMEOUT)
	{
		more = 0;
		if (user_is_connecting(user))
		{
			flag_close = quit_timeout;
		}
		else
		{
			// FIXME: hub is not neccesarily set!
			// hub_send_ping(hub, user);
		}
	}
	
	for (;;)
	{
		ssize_t size = hub_iobuf_recv(user->recv_buf, net_user_recv, user);
		if (size == -1)
		{
			if (net_error() != EWOULDBLOCK)
				flag_close = quit_socket_error;
			break;
		}
		else if (size == 0)
		{
			flag_close = quit_disconnected;
			break;
		}
		else
		{
			size_t offset = 0;
			size_t length;
			char* line = 0;

			while ((line = hub_iobuf_getline(user->recv_buf, &offset, &length, g_hub->config->max_recv_buffer)))
			{
				if (hub_handle_message(g_hub, user, line, length) == -1)
				{
					flag_close = quit_protocol_error;
					break;
				}
			}
			hub_iobuf_remove(user->recv_buf, offset);
		}
	}
	
	if (flag_close)
	{
		hub_disconnect_user(g_hub, user, flag_close);
		return;
	}
	
	if (user_is_logged_in(user))
	{
		if (user->ev_read)
		{
			struct timeval timeout = { TIMEOUT_IDLE, 0 };
			event_add(user->ev_read, &timeout);
		}
	}
	else if (user_is_connecting(user))
	{
		if (user->ev_read)
		{
			struct timeval timeout = { TIMEOUT_HANDSHAKE, 0 };
			event_add(user->ev_read, &timeout);
		}
	}
}


void net_on_write(int fd, short ev, void *arg)
{
	struct user* user = (struct user*) arg;
	struct adc_message* msg;
	int ret;
	int length;
	int close_flag = 0;
	
	msg = list_get_first(user->send_queue);
	while (msg)
	{
		length = msg->length - user->send_queue_offset;
		ret = net_send(user->sd, &msg->cache[user->send_queue_offset], length, UHUB_SEND_SIGNAL);
	
		if (ret == 0 || (ret == -1 && net_error() == EWOULDBLOCK))
		{
			close_flag = 0;
			break;
		}
		else if (ret > 0)
		{
			
			user->tm_last_write = time(NULL);
			
			if (ret == length)
			{
#ifdef DEBUG_SENDQ
				hub_log(log_error, "SENDQ: sent=%d bytes/%d (all), send_queue_size=%d, offset=%d", ret, (int) msg->length, user->send_queue_size, user->send_queue_offset);
#endif
				user->send_queue_size -= ret;
				user->send_queue_offset = 0;
			
#ifdef DEBUG_SENDQ
				if ((user->send_queue_size < 0) || (user->send_queue_offset < 0))
				{
					hub_log(log_error, "INVALID: send_queue_size=%d, send_queue_offset=%d", user->send_queue_size, user->send_queue_offset);
				}
#endif
			
				list_remove(user->send_queue, msg);
				
				if (user_flag_get(user, flag_user_list) && (msg == user->info || user->send_queue_size == 0))
				{
				    user_flag_unset(user, flag_user_list);
				}
				
				adc_msg_free(msg);
				msg = 0;
				
				if (user->send_queue_size == 0)
					break;
			}
			else
			{
#ifdef DEBUG_SENDQ
                                hub_log(log_error, "SENDQ: sent=%d bytes/%d (part), send_queue_size=%d, offset=%d", ret, (int) msg->length, user->send_queue_size, user->send_queue_offset);
#endif
				user->send_queue_size -= ret;
				user->send_queue_offset += ret;
				
#ifdef DEBUG_SENDQ				
				if ((user->send_queue_size < 0) || (user->send_queue_offset < 0) || (user->send_queue_offset > msg->length))
				{
					hub_log(log_error, "INVALID: send_queue_size=%d, send_queue_offset=%d", user->send_queue_size, user->send_queue_offset);
				}
#endif
				break;
			}
		}
		else
		{
			close_flag = quit_socket_error;
			break;
		}
		msg = list_get_first(user->send_queue);
	}
	
	
	if (close_flag)
	{
		hub_disconnect_user(g_hub, user, close_flag);
	}
	else
	{
		if (user->send_queue_size > 0 && user->ev_write)
			event_add(user->ev_write, NULL);
	}
}


void net_on_accept(int server_fd, short ev, void *arg)
{
	struct hub_info* hub = (struct hub_info*) arg;
	struct user* user = 0;
	struct ip_addr_encap ipaddr;
	const char* addr;
	struct timeval timeout = { TIMEOUT_CONNECTED, 0 };
	
	for (;;)
	{
		int fd = net_accept(server_fd, &ipaddr);
		if (fd == -1)
		{
			if (net_error() == EWOULDBLOCK)
			{
				break;
			}
			else
			{
				hub_log(log_error, "Accept error: %d %s", net_error(), strerror(net_error()));
				break;
			}
		}
		
		addr = ip_convert_to_string(&ipaddr); 

		/* FIXME: Should have a plugin log this */
		hub_log(log_trace, "Got connection from %s", addr);
		
		/* FIXME: A plugin should perform this check: is IP banned? */
		if (acl_is_ip_banned(hub->acl, addr))
		{
			hub_log(log_info, "Denied      [%s] (IP banned)", addr);
			net_close(fd);
			continue;
		}
		
		user = user_create(hub, fd);
		if (!user)
		{
			hub_log(log_error, "Unable to create user after socket accepted. Out of memory?");
			net_close(fd);
			break;
		}
		
		/* Store IP address in user object */
		memcpy(&user->ipaddr, &ipaddr, sizeof(ipaddr));
		
		net_set_nonblocking(fd, 1);
		net_set_nosigpipe(fd, 1);
		
		event_set(user->ev_read,  fd, EV_READ | EV_PERSIST, net_on_read,  user);
		event_set(user->ev_write, fd, EV_WRITE,             net_on_write, user);
		event_base_set(hub->evbase, user->ev_read);
		event_base_set(hub->evbase, user->ev_write);
		event_add(user->ev_read,  &timeout);
	}
}

