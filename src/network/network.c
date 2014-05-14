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
#ifdef WINSOCK
	struct WSAData wsa;
#endif
	if (!net_initialized)
	{
		LOG_TRACE("Initializing network monitor.");

#ifdef WINSOCK
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != NO_ERROR)
		{
			LOG_ERROR("Unable to initialize winsock.");
			return -1;
		}
#endif /* WINSOCK */

		if (!net_backend_init()
#ifdef SSL_SUPPORT
			|| !net_ssl_library_init()
#endif
			)
		{
#ifdef WINSOCK
			WSACleanup();
#endif
			return -1;
		}

		net_dns_initialize();

		net_stats_initialize();
		net_initialized = 1;
		return 0;
	}
	return -1;
}

size_t net_get_max_sockets()
{
#ifdef HAVE_GETRLIMIT
	struct rlimit limits;
	if (getrlimit(RLIMIT_NOFILE, &limits) == 0)
	{
		return MIN(limits.rlim_max, 65536);
	}
	LOG_ERROR("getrlimit() failed");
	return 1024;
#else
#ifdef WIN32
	return FD_SETSIZE;
#else
	LOG_WARN("System does not have getrlimit(): constrained to 1024 sockets");
	return 1024;
#endif
#endif /* HAVE_GETRLIMIT */
}


int net_destroy()
{
	if (net_initialized)
	{
		LOG_TRACE("Shutting down network monitor");

		net_dns_destroy();

		net_backend_shutdown();

#ifdef SSL_SUPPORT
		net_ssl_library_shutdown();
#endif /* SSL_SUPPORT */

#ifdef WINSOCK
		WSACleanup();
#endif
		net_initialized = 0;
		return 0;
	}
	return -1;
}

static void net_error_out(int fd, const char* func)
{
	int err = net_error();
	LOG_ERROR("%s, fd=%d: %s (%d)", func, fd, net_error_string(err), err);
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
	int ret = -1;
#ifdef WINSOCK
	ret = setsockopt(fd, level, opt, (const char*) optval, optlen);
#else
	ret = setsockopt(fd, level, opt, optval, optlen);
#endif

	if (ret == -1)
	{
		net_error_out(fd, "net_setsockopt");
	}

	return ret;
}

static int net_getsockopt(int fd, int level, int opt, void* optval, socklen_t* optlen)
{
	int ret = -1;
#ifdef WINSOCK
	ret = getsockopt(fd, level, opt, (char*) optval, optlen);
#else
	ret = getsockopt(fd, level, opt, optval, optlen);
#endif

	if (ret == -1)
	{
		net_error_out(fd, "net_getsockopt");
	}

	return ret;
}


int net_set_nonblocking(int fd, int toggle)
{
	int ret = -1;
#ifdef WINSOCK
	u_long on = toggle ? 1 : 0;
	ret = ioctlsocket(fd, FIONBIO, &on);
#else
#ifdef __sun__
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags != -1)
	{
		if (toggle) flags |= O_NONBLOCK;
		else        flags &= ~O_NONBLOCK;
		ret = fcntl(fd, F_SETFL, flags);
	}
#else
	ret = ioctl(fd, FIONBIO, &toggle);
#endif
#endif
	if (ret == -1)
	{
		net_error_out(fd, "net_set_nonblocking");
	}
	return ret;
}

/* NOTE: Possibly only supported on BSD and OSX? */
int net_set_nosigpipe(int fd, int toggle)
{
	int ret = -1;
#ifdef SO_NOSIGPIPE
	ret = net_setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &toggle, sizeof(toggle));
	if (ret == -1)
	{
		net_error_out(fd, "net_set_nosigpipe");
	}
#endif
	return ret;
}

int net_set_close_on_exec(int fd, int toggle)
{
#ifdef WINSOCK
	return -1; /* FIXME: How is this done on Windows? */
#else
	return fcntl(fd, F_SETFD, toggle);
#endif
}

int net_set_linger(int fd, int toggle)
{
	int ret;
	ret = net_setsockopt(fd, SOL_SOCKET, SO_LINGER, &toggle, sizeof(toggle));
	if (ret == -1)
	{
		net_error_out(fd, "net_set_linger");
	}
	return ret;
}

int net_set_keepalive(int fd, int toggle)
{
	int ret;
	ret = net_setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &toggle, sizeof(toggle));
	if (ret == -1)
	{
		net_error_out(fd, "net_set_keepalive");
	}
	return ret;
}


int net_set_reuseaddress(int fd, int toggle)
{
	int ret;
	ret = net_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &toggle, sizeof(toggle));
	if (ret == -1)
	{
		net_error_out(fd, "net_set_reuseaddress");
	}
	return ret;
}

int net_set_sendbuf_size(int fd, size_t size)
{
	return net_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
}

int net_get_sendbuf_size(int fd, size_t* size)
{
	socklen_t sz = sizeof(*size);
	return net_getsockopt(fd, SOL_SOCKET, SO_SNDBUF, size, &sz);
}

int net_set_recvbuf_size(int fd, size_t size)
{
	return net_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
}

int net_get_recvbuf_size(int fd, size_t* size)
{
	socklen_t sz = sizeof(*size);
	return net_getsockopt(fd, SOL_SOCKET, SO_RCVBUF, size, &sz);
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
		if (ret != -1)
		{
			net_stats_add_error();
		}
	}
	return ret;
}

int net_shutdown_r(int fd)
{
#ifdef WINSOCK
	return shutdown(fd, SD_RECEIVE);
#else
	return shutdown(fd, SHUT_RD);
#endif
}

int net_shutdown_w(int fd)
{
#ifdef WINSOCK
	return shutdown(fd, SD_SEND);
#else
	return shutdown(fd, SHUT_WR);
#endif
}

int net_shutdown_rw(int fd)
{
#ifdef WINSOCK
	return shutdown(fd, SD_BOTH);
#else
	return shutdown(fd, SHUT_RDWR);
#endif
}

int net_accept(int fd, struct ip_addr_encap* ipaddr)
{
	struct sockaddr_storage addr;
        struct sockaddr_in*  addr4;
        struct sockaddr_in6* addr6;
	socklen_t addr_size;
	int ret = 0;
	addr_size = sizeof(struct sockaddr_storage);

	memset(&addr, 0, addr_size);
	addr4 = (struct sockaddr_in*) &addr;
	addr6 = (struct sockaddr_in6*) &addr;

	ret = accept(fd, (struct sockaddr*) &addr, &addr_size);

	if (ret == -1)
	{
		switch (net_error())
		{
#if defined(__HAIKU__)
			case ETIMEDOUT:
#endif
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
#ifdef WINSOCK
			case WSAEWOULDBLOCK:
				break;
#else
			case EWOULDBLOCK:
				break;
#endif
			default:
				net_error_out(fd, "net_accept");
				net_stats_add_error();
				return -1;
		}
	}
	else
	{
		net_stats_add_accept();

		if (ipaddr)
		{
			memset(ipaddr, 0, sizeof(struct ip_addr_encap));
			ipaddr->af = addr.ss_family;;
			if (ipaddr->af == AF_INET6)
			{
				char address[INET6_ADDRSTRLEN+1] = { 0, };
				net_address_to_string(AF_INET6, (void*) &addr6->sin6_addr, address, INET6_ADDRSTRLEN+1);
				if (strchr(address, '.'))
				{
					/* Hack to convert IPv6 mapped IPv4 addresses to true IPv4 addresses */
					ipaddr->af = AF_INET;
					net_string_to_address(AF_INET, address, (void*) &ipaddr->internal_ip_data.in);
				}
				else
				{
					memcpy(&ipaddr->internal_ip_data.in6, &addr6->sin6_addr, sizeof(struct in6_addr));
				}
			}
			else
			{
				memcpy(&ipaddr->internal_ip_data.in, &addr4->sin_addr, sizeof(struct in_addr));
			}
		}
	}

	return ret;
}


int net_connect(int fd, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	int ret = connect(fd, serv_addr, addrlen);
	if (ret == -1)
	{
#ifdef WINSOCK
		if (net_error() != WSAEINPROGRESS)
#else
		if (net_error() != EINPROGRESS)
#endif
		{
			net_error_out(fd, "net_connect");
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
				LOG_TRACE("net_is_ipv6_supported(): IPv6 is not supported on this system.");
				is_ipv6_supported = 0;
				return 0;
			}

			net_error_out(ret, "net_is_ipv6_supported");
		}
		else
		{
#ifdef SOCK_DUAL_STACK_OPT
			int off = 0;
			if (net_setsockopt(ret, IPPROTO_IPV6, SOCK_DUAL_STACK_OPT, (char*) &off, sizeof(off)) < 0)
			{
				LOG_ERROR("net_socket_create(): Dual stack IPv6/IPv4 is not supported.");
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
		net_error_out(sd, "net_socket_create");
		return -1;
	}

#ifdef SOCK_DUAL_STACK_OPT
	/* BSD style */
	if (af == AF_INET6)
	{
		int off = 0;
		if (net_setsockopt(sd, IPPROTO_IPV6, SOCK_DUAL_STACK_OPT, (char*) &off, sizeof(off)) < 0)
		{
			LOG_ERROR("net_socket_create():  Cannot set socket to dual stack mode IPv6/IPv4 (%d - %s).", net_error(), net_error_string(net_error()));
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
			sin6.sin6_scope_id = 0;
			size             = sizeof(sin6);
			addr             = (LPSOCKADDR) &sin6;
			break;

		default:
			return NULL;
	}

	if (WSAAddressToStringA(addr, size, NULL, dst, &len) == 0)
	{
		return dst;
	}

	return NULL;
#else
	if (inet_ntop(af, src, dst, cnt))
	{
		if (af == AF_INET6 && strncmp(dst, "::ffff:", 7) == 0) /* IPv6 mapped IPv4 address. */
		{
			memmove(dst, dst + 7, cnt - 7);
		}
		return dst;
	}
	return NULL;
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
	socklen_t namelen;

	memset(address, 0, INET6_ADDRSTRLEN);
	namelen = sizeof(struct sockaddr_storage);
	memset(&storage, 0, namelen);

	name6 = (struct sockaddr_in6*) &storage;
	name4 = (struct sockaddr_in*)  &storage;
	name  = (struct sockaddr*)     &storage;

	if (getpeername(fd, (struct sockaddr*) name, &namelen) != -1)
	{
		int af = storage.ss_family;
		if (af == AF_INET6)
		{
			net_address_to_string(af, (void*) &name6->sin6_addr, address, INET6_ADDRSTRLEN);
		}
		else
		{
			net_address_to_string(af, (void*) &name4->sin_addr, address, INET6_ADDRSTRLEN);
		}
		return address;
	}
	else
	{
		net_error_out(fd, "net_get_peer_address");
		net_stats_add_error();
	}

	return "0.0.0.0";
}

const char* net_get_local_address(int fd)
{
	static char address[INET6_ADDRSTRLEN+1];
	struct sockaddr_storage storage;
	struct sockaddr_in6* name6;
	struct sockaddr_in*  name4;
	struct sockaddr*     name;
	socklen_t namelen;

	memset(address, 0, INET6_ADDRSTRLEN);
	namelen = sizeof(struct sockaddr_storage);
	memset(&storage, 0, namelen);

	name6 = (struct sockaddr_in6*) &storage;
	name4 = (struct sockaddr_in*)  &storage;
	name  = (struct sockaddr*)     &storage;

	if (getsockname(fd, (struct sockaddr*) name, &namelen) != -1)
	{
#ifndef WINSOCK
		int af = storage.ss_family;
		if (af == AF_INET6)
		{
			net_address_to_string(af, (void*) &name6->sin6_addr, address, INET6_ADDRSTRLEN);
		}
		else
#else
		int af = AF_INET;
#endif
		{
			net_address_to_string(af, (void*) &name4->sin_addr, address, INET6_ADDRSTRLEN);
		}
		return address;
	}
	else
	{
		net_error_out(fd, "net_get_local_address");
		net_stats_add_error();
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
#ifdef WINSOCK
		if (net_error() != WSAEWOULDBLOCK)
#else
		if (net_error() != EWOULDBLOCK)
#endif
		{
			/* net_error_out(fd, "net_recv"); */
			net_stats_add_error();
		}
	}
	return ret;
}


ssize_t net_send(int fd, const void* buf, size_t len, int flags)
{
	ssize_t ret = send(fd, buf, len, flags);
	if (ret >= 0)
	{
		net_stats_add_tx(ret);
	}
	else
	{
#ifdef WINSOCK
		if (net_error() != WSAEWOULDBLOCK)
#else
		if (net_error() != EWOULDBLOCK)
#endif
		{
			/* net_error_out(fd, "net_send"); */
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
		net_error_out(fd, "net_bind");
		net_stats_add_error();
	}
	return ret;
}


int net_listen(int fd, int backlog)
{
	int ret = listen(fd, backlog);
	if (ret == -1)
	{
		net_error_out(fd, "net_listen");
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


