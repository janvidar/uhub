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

static int is_ipv6_supported = -1; /* -1 = CHECK, 0 = NO, 1 = YES */
static int net_initialized = 0;
static struct net_statistics stats;
static struct net_statistics stats_total;

#if defined(IPV6_BINDV6ONLY)
#define SOCK_DUAL_STACK_OPT IPV6_BINDV6ONLY
#elif defined(IPV6_V6ONLY)
#define SOCK_DUAL_STACK_OPT IPV6_V6ONLY
#endif


int net_initialize()
{
	if (!net_initialized)
	{

#ifdef WINSOCK
		struct WSAData wsa;
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != NO_ERROR)
		{
			hub_log(log_error, "Unable to initialize winsock.");
			return -1;
		}
#endif /* WINSOCK */

		hub_log(log_trace, "Initializing network monitor.");
		net_stats_initialize();

#ifdef SSL_SUPPORT
		/* FIXME: Initialize OpenSSL here. */
#endif /*  SSL_SUPPORT */

		net_initialized = 1;
		return 0;
	}
	return -1;
}


int net_shutdown()
{
	if (net_initialized)
	{
		hub_log(log_trace, "Shutting down network monitor");

#ifdef SSL_SUPPORT
		/* FIXME: Shutdown OpenSSL here. */
#endif

#ifdef WINSOCK
		WSACleanup();
#endif
		net_initialized = 0;
		return 0;
	}
	return -1;
}


int net_error()
{
#ifdef WINSOCK
	return WSAGetLastError();
#else
	return errno;
#endif
}


const char* net_error_string(int code)
{
#ifdef WINSOCK
	static char string[32];
	snprintf(string, 32, "error code: %d", code);
	return string;
#else
	return strerror(code);
#endif
}


static int net_setsockopt(int fd, int level, int opt, const void* optval, socklen_t optlen)
{
#ifdef WINSOCK
	return setsockopt(fd, level, opt, (const char*) optval, optlen);
#else
	return setsockopt(fd, level, opt, optval, optlen);
#endif
}


int net_set_nonblocking(int fd, int toggle)
{
	int ret;

#ifdef NETAPI_DUMP
	hub_log(log_dump, "net_set_nonblocking(): fd=%d", fd);
#endif

#ifdef WINSOCK
	u_long on = toggle ? 1 : 0;
	ret = ioctlsocket(fd, FIONBIO, &on);
#else
	ret = ioctl(fd, FIONBIO, &toggle);
#endif
	if (ret == -1)
	{
		hub_log(log_error, "net_set_nonblocking(): ioctl failed (fd=%d): %s", fd, net_error_string(net_error()));
		return -1;
	}
	return 0;
}


/* NOTE: Possibly only supported on BSD and OSX? */
int net_set_nosigpipe(int fd, int toggle)
{
#ifdef SO_NOSIGPIPE
	int ret;
#ifdef NETAPI_DUMP
	hub_log(log_dump, "net_set_nosigpipe(): fd=%d", fd);
#endif
	ret = net_setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &toggle, sizeof(toggle));
	if (ret == -1)
	{
		hub_log(log_error, "net_set_linger(): setsockopt failed (fd=%d): %s", fd, net_error_string(net_error()));
		return -1;
	}
#endif
	return 0;
}

int net_set_close_on_exec(int fd, int toggle)
{
#ifdef NETAPI_DUMP
	hub_log(log_dump, "net_set_close_on_exec(): fd=%d", fd);
#endif
#ifdef WINSOCK
	return -1; /* FIXME: How is this done on Windows? */
#else
	return fcntl(fd, F_SETFD, toggle);
#endif
}


int net_set_linger(int fd, int toggle)
{
	int ret;
#ifdef NETAPI_DUMP
	hub_log(log_dump, "net_set_linger(): fd=%d", fd);
#endif
	ret = net_setsockopt(fd, SOL_SOCKET, SO_LINGER, &toggle, sizeof(toggle));
	if (ret == -1)
	{
		hub_log(log_error, "net_set_linger(): setsockopt failed (fd=%d): %s", fd, net_error_string(net_error()));
		return -1;
	}
	return 0;
}


int net_set_keepalive(int fd, int toggle)
{
	int ret;
#ifdef NETAPI_DUMP
	hub_log(log_dump, "net_set_keepalive(): fd=%d", fd);
#endif
	ret = net_setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &toggle, sizeof(toggle));
	if (ret == -1)
	{
		hub_log(log_error, "net_set_keepalive(): setsockopt failed (fd=%d): %s", fd, net_error_string(net_error()));
		return -1;
	}
	return 0;
}


int net_set_reuseaddress(int fd, int toggle)
{
	int ret;
#ifdef NETAPI_DUMP
	hub_log(log_dump, "net_set_reuseaddress(): fd=%d", fd);
#endif
	ret = net_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &toggle, sizeof(toggle));
	if (ret == -1)
	{
		hub_log(log_error, "net_set_reuseaddress(): setsockopt failed (fd=%d): %s", fd, net_error_string(net_error()));
		return -1;
	}
	return 0;
}


int net_close(int fd)
{
#ifdef WINSOCK
	int ret = closesocket(fd);
#else
	int ret = close(fd);
#endif

	if (ret == 0)
	{
		net_stats_add_close();
	}
	else
	{
		if (fd != -1)
		{
			net_stats_add_error();
		}
	}
	return ret;
}


int net_accept(int fd)
{
	struct sockaddr_storage addr;
	socklen_t addr_size;
	int ret = 0;
	addr_size = sizeof(struct sockaddr_storage);
	memset(&addr, 0, addr_size);
	ret = accept(fd, (struct sockaddr*) &addr, &addr_size);

	if (ret == -1)
	{
		switch (net_error())
		{
#if defined(__linux__)
			case ENETDOWN:
			case EPROTO:
			case ENOPROTOOPT:
			case EHOSTDOWN:
			case ENONET:
			case EHOSTUNREACH:
			case EOPNOTSUPP:
				errno = EWOULDBLOCK;
#endif
			case EWOULDBLOCK:
				break;
			default:
				hub_log(log_error, "net_accept(): accept failed (fd=%d, errno=%d, msg=%s)", fd, net_error(), net_error_string(net_error()));
				net_stats_add_error();
				return -1;
		}
	}
	else
	{
		net_stats_add_accept();
	}

	return ret;
}


int net_connect(int fd, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	int ret = connect(fd, serv_addr, addrlen);
	if (ret == -1)
	{
		if (net_error() != EINPROGRESS)
		{
			hub_log(log_error, "net_connect(): connect failed (fd=%d, errno=%d, msg=%s)", fd, net_error(), net_error_string(net_error()));
			net_stats_add_error();
		}
	}
	return ret;
}



int net_is_ipv6_supported()
{
	if (is_ipv6_supported == -1)
	{
		int ret = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (ret == -1)
		{
#ifdef WINSOCK
			if (net_error() == WSAEAFNOSUPPORT)
#else
			if (net_error() == EAFNOSUPPORT)
#endif
			{
				hub_log(log_trace, "net_is_ipv6_supported(): IPv6 is not supported on this system.");
				is_ipv6_supported = 0;
				return 0;
			}
			
			hub_log(log_error, "net_is_ipv6_supported(): Unknown error (errno=%d, msg=%s)", net_error(), net_error_string(net_error()));

		}
		else
		{
#ifdef SOCK_DUAL_STACK_OPT
			int off = 0;
			if (net_setsockopt(ret, IPPROTO_IPV6, SOCK_DUAL_STACK_OPT, (char*) &off, sizeof(off)) < 0)
			{
				hub_log(log_error, "net_socket_create(): Dual stack IPv6/IPv4 is not supported.");
				is_ipv6_supported = 0;
			}
			else
			{
				is_ipv6_supported = 1;
			}
#else
			is_ipv6_supported = 0;
#endif
			net_close(ret);
		}
	}
	return is_ipv6_supported;
}


int net_socket_create(int af, int type, int protocol)
{
	int sd = socket(af, type, protocol);
	if (sd == -1)
	{
		hub_log(log_error, "net_socket_create(): socket failed (errno=%d, msg=%s)", net_error(), net_error_string(net_error()));
	}

#ifdef SOCK_DUAL_STACK_OPT
	/* BSD style */
	if (af == AF_INET6)
	{
		int off = 0;
		if (net_setsockopt(sd, IPPROTO_IPV6, SOCK_DUAL_STACK_OPT, (char*) &off, sizeof(off)) < 0)
		{
			hub_log(log_error, "net_socket_create():  Cannot set socket to dual stack mode IPv6/IPv4 (%d - %s).", net_error(), net_error_string(net_error()));
		}
	}
#endif

	return sd;
}

const char* net_address_to_string(int af, const void* src, char* dst, socklen_t cnt)
{
#ifdef WINSOCK
	struct sockaddr_in  sin4;
	struct sockaddr_in6 sin6;
	struct in_addr*  addr4 = (struct in_addr*)  src;
	struct in6_addr* addr6 = (struct in6_addr*) src;
	size_t size;
	LPSOCKADDR addr;
	DWORD len = cnt;
	
	switch (af)
	{
		case AF_INET:
			sin4.sin_family  = AF_INET;
			sin4.sin_port    = 0;
			sin4.sin_addr    = *addr4;
			size             = sizeof(sin4);
			addr             = (LPSOCKADDR) &sin4;
			break;

		case AF_INET6:
			sin6.sin6_family = AF_INET6;
			sin6.sin6_port   = 0;
			sin6.sin6_addr   = *addr6;
			size             = sizeof(sin6);
			addr             = (LPSOCKADDR) &sin6;
			break;

		default:
			return NULL;
	}
	
	if (WSAAddressToString(addr, size, NULL, dst, &len) == 0)
	{
		return dst;
	}

	return NULL;
#else
	return inet_ntop(af, src, dst, cnt);
#endif
}

int net_string_to_address(int af, const char* src, void* dst)
{
#ifdef WINSOCK
	int ret, size;
	struct sockaddr_in  addr4;
	struct sockaddr_in6 addr6;
	struct sockaddr* addr = 0;
	if (af == AF_INET6)
	{
		if (net_is_ipv6_supported() != 1) return -1;
		size = sizeof(struct sockaddr_in6);
		addr = (struct sockaddr*) &addr6;
	}
	else
	{
		size = sizeof(struct sockaddr_in);
		addr = (struct sockaddr*) &addr4;
	}

	if (!net_initialized)
		net_initialize();

	ret = WSAStringToAddressA((char*) src, af, NULL, addr, &size);
	if (ret == -1)
	{
		return -1;
	}

	if (af == AF_INET6)
	{
		memcpy(dst, &addr6.sin6_addr, sizeof(addr6.sin6_addr));
	}
	else
	{
		memcpy(dst, &addr4.sin_addr, sizeof(addr4.sin_addr));
	}

	return 1;
#else
	return inet_pton(af, src, dst);
#endif
}




const char* net_get_peer_address(int fd)
{
	static char address[INET6_ADDRSTRLEN+1];
	struct sockaddr_storage storage;
	struct sockaddr_in6* name6;
	struct sockaddr_in*  name4;
	struct sockaddr*     name;
	
	memset(address, 0, INET6_ADDRSTRLEN);
	socklen_t namelen = sizeof(struct sockaddr_storage);
	memset(&storage, 0, namelen);
	
	name6 = (struct sockaddr_in6*) &storage;
	name4 = (struct sockaddr_in*)  &storage;
	name  = (struct sockaddr*)     &storage;
	
	
	int af = net_is_ipv6_supported() ? AF_INET6 : AF_INET;

	if (getpeername(fd, (struct sockaddr*) name, &namelen) != -1)
	{
		if (af == AF_INET6)
		{
			net_address_to_string(af, (void*) &name6->sin6_addr, address, INET6_ADDRSTRLEN);
			if (strncmp(address, "::ffff:", 7) == 0) /* IPv6 mapped IPv4 address. */
			{
				return &address[7];
			}
			hub_log(log_trace, "net_get_peer_address(): address=%s", address);
			return address;
		}
		else
		{
			net_address_to_string(af, (void*) &name4->sin_addr, address, INET6_ADDRSTRLEN);
			hub_log(log_trace, "net_get_peer_address(): address=%s", address);
			return address;
		}
	}
	else
	{
		hub_log(log_error, "net_get_peer_address(): getsockname failed (fd=%d, errno=%d, msg=%s)", fd, net_error(), net_error_string(net_error()));
	}

	return "0.0.0.0";
}


ssize_t net_recv(int fd, void* buf, size_t len, int flags)
{
	ssize_t ret = recv(fd, buf, len, flags);
	if (ret >= 0)
	{
		net_stats_add_rx(ret);
	}
	else
	{
		if (net_error() != EWOULDBLOCK)
		{
			hub_log(log_debug, "net_recv(): failed (fd=%d, errno=%d, msg=%s)", fd, net_error(), net_error_string(net_error()));
			net_stats_add_error();
		}
	}
	return ret;
}


ssize_t net_send(int fd, void* buf, size_t len, int flags)
{
	ssize_t ret = send(fd, buf, len, flags);
	if (ret >= 0)
	{
		net_stats_add_tx(ret);
	}
	else
	{
		if (net_error() != EWOULDBLOCK)
		{
			hub_log(log_debug, "net_send(): failed (fd=%d, errno=%d, msg=%s)", fd, net_error(), net_error_string(net_error()));
			net_stats_add_error();
		}
	}
	return ret;
}


int net_bind(int fd, const struct sockaddr *my_addr, socklen_t addrlen)
{
	int ret = bind(fd, my_addr, addrlen);
	if (ret == -1)
	{
		hub_log(log_error, "net_bind(): failed (fd=%d, errno=%d, msg=%s)", fd, net_error(), net_error_string(net_error()));
		net_stats_add_error();
	}
	return ret;
}


int net_listen(int fd, int backlog)
{
	int ret = listen(fd, backlog);
	if (ret == -1)
	{
		hub_log(log_error, "net_listen(): failed (fd=%d, errno=%d, msg=%s)", fd, net_error(), net_error_string(net_error()));
		net_stats_add_error();
	}
	return ret;
}


void net_stats_initialize()
{
	memset(&stats_total, 0, sizeof(struct net_statistics));
	stats_total.timestamp = time(NULL);

	memset(&stats, 0, sizeof(struct net_statistics));
	stats.timestamp = time(NULL);
}


void net_stats_get(struct net_statistics** intermediate, struct net_statistics** total)
{
	*intermediate = &stats;
	*total = &stats_total;
}


void net_stats_reset()
{
	stats_total.tx += stats.tx;
	stats_total.rx += stats.rx;
	stats_total.accept += stats.accept;
	stats_total.errors += stats.errors;
	stats_total.closed += stats.closed;

	memset(&stats, 0, sizeof(struct net_statistics));
	stats.timestamp = time(NULL);
}


int net_stats_timeout()
{
	return (difftime(time(NULL), stats.timestamp) > TIMEOUT_STATS) ? 1 : 0;
}


void net_stats_add_tx(size_t bytes)
{
	stats.tx += bytes;
}


void net_stats_add_rx(size_t bytes)
{
	stats.rx += bytes;
}


void net_stats_add_accept()
{
	stats.accept++;
}


void net_stats_add_error()
{
	stats.errors++;
}


void net_stats_add_close()
{
	stats.closed++;
}


