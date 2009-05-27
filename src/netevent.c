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

#define DEBUG_SENDQ 1

int net_user_send(void* ptr, const void* buf, size_t len)
{
	struct user* user = (struct user*) ptr;
	int ret = net_send(user->net.sd, buf, len, UHUB_SEND_SIGNAL);
#ifdef DEBUG_SENDQ
	printf("net_user_send: sd=%d, %d/%d bytes\n", user->net.sd, ret, (int) len);
	if (ret == -1)
	{
		printf("    errno: %d - %s\n", errno, strerror(errno));
	}
#endif
	if (ret > 0)
	{
		user->net.tm_last_write = time(NULL);
	}
	else if (ret == -1 && net_error() == EWOULDBLOCK)
	{
		return -2;
	}
	else
	{
		// user->close_flag = quit_socket_error;
		return 0;
	}
	return ret;
}

int net_user_recv(void* ptr, void* buf, size_t len)
{
	struct user* user = (struct user*) ptr;
	int ret = net_recv(user->net.sd, buf, len, 0);	
/*
	hub_log(log_trace, "net_user_recv: sd=%d, len=%d/%d", user->net.sd, ret, (int) len);
*/
	if (ret > 0)
	{
		user->net.tm_last_read = time(NULL);
	}


#ifdef DEBUG_SENDQ
	printf("net_user_recv: %d/%d bytes\n", ret, (int) len);
	if (ret == -1)
	{
		printf("    errno: %d - %s\n", errno, strerror(errno));
	}
	
	if (ret > 0)
	{
		char* data = hub_malloc_zero(ret + 1);
		memcpy(data, buf, ret);
		printf("RECV: \"%s\"\n", data);
		hub_free(data);
	}
#endif
	return ret;
}

void net_on_read(int fd, short ev, void *arg)
{
	static char buf[MAX_RECV_BUF];
	struct user* user = (struct user*) arg;
	struct hub_recvq* q = user->net.recv_queue;
	size_t buf_size;
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
	
	buf_size = hub_recvq_get(q, buf, MAX_RECV_BUF);

	for (;;)
	{
		int size = net_user_recv(user, &buf[buf_size], MAX_RECV_BUF - buf_size);
		if (size > 0)
		{
			buf_size += size;
		}

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
			char* start = buf;
			char* pos = 0;
			while ((pos = memchr(start, '\n', (buf_size - offset))))
			{
				char* line = start;
				length = pos - start;
				pos[0] = '\0';

#ifdef DEBUG_SENDQ
				printf("PROC: \"%s\" (%d)\n", line, (int) length);
#endif

				if (hub_handle_message(g_hub, user, line, length) == -1)
				{
					flag_close = quit_protocol_error;
					break;
				}

				start = pos;
				start++;
				offset += length;
			}
			
			if (start < buf + buf_size)
			{
				hub_recvq_set(q, buf+offset, buf_size); 
			}
			else
			{
				hub_recvq_set(q, 0, 0);
			}
			
		}
	}
	
	if (flag_close)
	{
		hub_disconnect_user(g_hub, user, flag_close);
		return;
	}
	
	if (user_is_logged_in(user))
	{
		if (user->net.ev_read)
		{
			struct timeval timeout = { TIMEOUT_IDLE, 0 };
			event_add(user->net.ev_read, &timeout);
		}
	}
	else if (user_is_connecting(user))
	{
		if (user->net.ev_read)
		{
			struct timeval timeout = { TIMEOUT_HANDSHAKE, 0 };
			event_add(user->net.ev_read, &timeout);
		}
	}
}


void net_on_write(int fd, short ev, void *arg)
{
	struct user* user = (struct user*) arg;
	int sent = 0;

	for (;;)
	{
		int ret = hub_sendq_send(user->net.send_queue, net_user_send, user);
		if (ret > 0)
			sent += ret;
		else
			break;
	}

#if 0
	if (close_flag)
	{
		hub_disconnect_user(g_hub, user, close_flag);
	}
	else
#endif
	if (hub_sendq_get_bytes(user->net.send_queue))
	{
		user_net_io_want_write(user);
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
		memcpy(&user->net.ipaddr, &ipaddr, sizeof(ipaddr));
		
		net_set_nonblocking(fd, 1);
		net_set_nosigpipe(fd, 1);
		
		event_set(user->net.ev_read,  fd, EV_READ | EV_PERSIST, net_on_read,  user);
		event_set(user->net.ev_write, fd, EV_WRITE,             net_on_write, user);
		event_base_set(hub->evbase, user->net.ev_read);
		event_base_set(hub->evbase, user->net.ev_write);
		event_add(user->net.ev_read,  &timeout);
	}
}

