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


void net_on_read(int fd, short ev, void *arg)
{
	static char buf[MAX_RECV_BUF];
	struct user* user = (struct user*) arg;
	char* pos;
	char* start;
	ssize_t offset;
	ssize_t size;
	ssize_t buflen;
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
			hub_send_ping(user);
		}
	}
	
	while (more)
	{
		offset = 0;
		if (user->recv_buf)
		{
			memcpy(buf, user->recv_buf, user->recv_buf_offset);
			offset = user->recv_buf_offset;
		}
		else
		{
			offset = 0;
		}
			
		size = net_recv(fd, &buf[offset], MAX_RECV_BUF - offset, 0);
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
			buflen = offset + size;
			start = buf;
			while ((pos = strchr(start, '\n')))
			{
				pos[0] = '\0';
				if (strlen(start) > 0 && strlen(start) < user->hub->config->max_recv_buffer)
				{
					if (hub_handle_message(user, start, &pos[0]-&start[0]) == -1)
					{
						flag_close = quit_protocol_error;
						more = 0;
						break;
					}
				}
				start = &pos[1];
			}
			
			if (!more) break;
			
			if (&buf[offset + size] > &start[0])
			{
				if (!user->recv_buf)
				{
					user->recv_buf = hub_malloc(user->hub->config->max_recv_buffer);
				}
				
				if (!user->recv_buf)
				{
					flag_close = quit_memory_error;
					break;
				}
				else
				{
					memcpy(user->recv_buf, start, &buf[offset + size] - &start[0]);
					user->recv_buf_offset = &buf[offset + size] - &start[0];
				}
			}
			else
			{
				if (user->recv_buf)
				{
					hub_free(user->recv_buf);
					user->recv_buf = 0;
					user->recv_buf_offset = 0;
				}
			}
		}
	}
	
	if (flag_close)
	{
		user_disconnect(user, flag_close);
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
				user->send_queue_size -= ret;
				user->send_queue_offset = 0;
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
				user->send_queue_size -= ret;
				user->send_queue_offset += ret;
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
		user_disconnect(user, close_flag);
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
	int accept_more = 1;
	const char* addr;
	struct timeval timeout = { TIMEOUT_CONNECTED, 0 };
	
	while (accept_more)
	{
		int fd = net_accept(server_fd);
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
		
		addr = net_get_peer_address(fd);

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
		ip_convert_to_binary(addr, &user->ipaddr);
		
		net_set_nonblocking(fd, 1);
		net_set_nosigpipe(fd, 1);
		
		event_set(user->ev_read,  fd, EV_READ | EV_PERSIST, net_on_read,  user);
		event_set(user->ev_write, fd, EV_WRITE,             net_on_write, user);
		event_add(user->ev_read,  &timeout);
	}
}

#ifdef ADC_UDP_OPERATION
extern void net_on_packet(int fd, short ev, void *arg)
{
	static char buffer[1024] = {0,};
	// struct hub_info* hub = (struct hub_info*) arg;
	// struct user* user = 0;
	ssize_t size;
	struct sockaddr_storage from;
	socklen_t fromlen;
	
	size = recvfrom(fd, buffer, 1024, 0, (struct sockaddr*) &from, &fromlen);
	
	// FIXME: A plugin should handle this!
	hub_log(log_info, "Datagram    [%s] (%d bytes)", buffer, (int) size);
}
#endif
