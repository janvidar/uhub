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


static int on_read(struct user* user)
{
	static char buf[MAX_RECV_BUF];
	size_t offset;
	size_t buflen;
	ssize_t size;
	int more = 1;
	char* pos;

	while (more)
	{
		offset = 0;
		if (user->recv_buf)
		{
			memcpy(buf, user->recv_buf, user->recv_buf_offset);
			offset = user->recv_buf_offset;
		}
		
		size = net_recv(user->sd, &buf[offset], MAX_RECV_BUF - offset, 0);
		if (size == -1)
		{
			if (net_error() != EWOULDBLOCK)
				return quit_socket_error;
			break;
		}
		else if (size == 0)
		{
			return quit_disconnected;
		}
		else
		{
			buflen = offset + size;
			ssize_t handled = 0;
			
			while ((pos = memchr(&buf[handled], '\n', (buflen - handled))))
			{
				pos[0] = '\0';
				size_t msglen = &pos[0] - &buf[handled];
				
				if (user_flag_get(user, flag_maxbuf))
				{
					user_flag_unset(user, flag_maxbuf);
				}
				else
				{
					if (msglen < user->hub->config->max_recv_buffer)
					{
						if (hub_handle_message(user, &buf[handled], msglen) == -1)
						{
							return quit_protocol_error;
						}
					}
				}
				handled += msglen;
				handled++;
			}
			
			if (handled == 0 && user_flag_get(user, flag_maxbuf))
				handled = buflen;
			
			if (!more)
				break;
			
			if (handled < buflen)
			{
				if ((buflen - handled) > user->hub->config->max_recv_buffer)
				{
					user_flag_set(user, flag_maxbuf);
					hub_free(user->recv_buf);
					user->recv_buf = 0;
					user->recv_buf_offset = 0;
				}
				else
				{
					if (!user->recv_buf)
						user->recv_buf = hub_malloc(user->hub->config->max_recv_buffer);
				
					if (user->recv_buf)
					{
						memcpy(user->recv_buf, &buf[handled], buflen - handled);
						user->recv_buf_offset = buflen - handled;
					}
					else
					{
						return quit_memory_error;
					}
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
	return 0;
}

static int on_write(struct user* user)
{
	struct adc_message* msg;
	int ret;
	int length;
	
	msg = list_get_first(user->send_queue);
	while (msg)
	{
		length = msg->length - user->send_queue_offset;
		ret = net_send(user->sd, &msg->cache[user->send_queue_offset], length, UHUB_SEND_SIGNAL);
	
		if (ret == 0 || (ret == -1 && net_error() == EWOULDBLOCK))
		{
			return 0;
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
			return quit_socket_error;
		}
		msg = list_get_first(user->send_queue);
	}
	return 0;
}


void on_net_event(int fd, short ev, void *arg)
{
	struct user* user = (struct user*) arg;
	int want_close = 0;
	int want_write = 0;
	
	hub_log(log_debug, "on_net_event() : fd=%d, ev=%d, user=%s", fd, (int) ev, user);
	
	if (ev == EV_TIMEOUT)
	{
		
		hub_log(log_debug, "EV_TIMEOUT");
		
		if (user_is_connecting(user))
		{
			want_close = quit_timeout;
		}
		else
		{
			hub_send_ping(user);
		}
	}
	else
	{
		if (ev & EV_WRITE)
		{
			want_close = on_write(user);
			want_write = (user->send_queue_size != 0);
		}
		
		if (!want_close && ev & EV_READ)
		{
			want_close = on_read(user);
		}
	}
		
	if (want_close)
	{
		user_disconnect(user, want_close);
		return;
	}
	
	if (user_is_logged_in(user))
	{
		user_trigger_update(user, want_write, TIMEOUT_IDLE);
	}
	else if (user_is_connecting(user))
	{
		user_trigger_update(user, want_write, TIMEOUT_HANDSHAKE);
	}
}



void net_on_accept(int server_fd, short ev, void *arg)
{
	struct hub_info* hub = (struct hub_info*) arg;
	struct user* user = 0;
	struct ip_addr_encap ipaddr;
	const char* addr;
	
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
		user_trigger_init(user);
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
