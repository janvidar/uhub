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

#ifndef HAVE_UHUB_NETWORK_H
#define HAVE_UHUB_NETWORK_H

struct net_statistics
{
	time_t timestamp;
	size_t tx;
	size_t rx;
	size_t accept;
	size_t closed;
	size_t errors;
};

struct net_socket_t;
struct ip_addr_encap;

/**
 * Initialize the socket monitor subsystem.
 * On some operating systems this will also involve loading the TCP/IP stack
 * (needed on Windows at least).
 *
 * @param max_connections The maximum number of sockets the monitor can handle.
 * @return -1 on error, 0 on success
 */
extern int net_initialize();

/**
 * Shutdown the socket monitor.
 * On some operating systems this will also ensure the TCP/IP stack
 * is loaded.
 *
 * @return -1 on error, 0 on success
 */
extern int net_destroy();

/**
 * @return the number of sockets currrently being monitored.
 */
extern int net_monitor_count();

/**
 * @return the monitor's socket capacity.
 */
extern int net_monitor_capacity();

/**
 * @return the last error code occured.
 *
 * NOTE: On Windows this is the last error code from the socket library, but
 *       on UNIX this is the errno variable that can be overwritten by any
 *       libc function.
 *       For this reason, only rely on net_error() immediately after a
 *       socket function call.
 */
extern int net_error();
extern const char* net_error_string(int code);

/**
 * A wrapper for the socket() function call.
 */
extern int net_socket_create(int af, int type, int protocol);

/**
 * Returns the maximum number of file/socket descriptors.
 */
extern size_t net_get_max_sockets();

/**
 * A wrapper for the close() function call.
 */
extern int net_close(int fd);

extern int net_shutdown_r(int fd);
extern int net_shutdown_w(int fd);
extern int net_shutdown_rw(int fd);

/**
 * A wrapper for the accept() function call.
 * @param fd socket descriptor
 * @param ipaddr (in/out) if non-NULL the ip address of the
 * accepted peer is filled in.
 */
extern int net_accept(int fd, struct ip_addr_encap* ipaddr);

/**
 * A wrapper for the connect() call.
 */
extern int net_connect(int fd, const struct sockaddr *serv_addr, socklen_t addrlen);

/**
 * A wrapper for the bind() function call.
 */
extern int net_bind(int fd, const struct sockaddr *my_addr, socklen_t addrlen);

/**
 * A wrapper for the listen() function call.
 */
extern int net_listen(int sockfd, int backlog);

/**
 * This will set the socket to blocking or nonblocking mode.
 * @param fd socket descriptor
 * @param toggle if non-zero nonblocking mode, otherwise blocking mode is assumed
 * @return -1 on error, 0 on success
 */
extern int net_set_nonblocking(int fd, int toggle);

/**
 * This will prevent the socket to generate a SIGPIPE in case the socket goes down.
 * NOTE: Not all operating systems support this feature. In that case this will return success value.
 *
 * @param fd socket descriptor
 * @param toggle if non-zero ignore sigpipe, otherwise disable it.
 * @return -1 on error, 0 on success
 */
extern int net_set_nosigpipe(int fd, int toggle);

/**
 * This will set the close-on-exec flag. This means if any subprocess is
 * started any open file descriptors or sockets will not be inherited if this
 * is turned on. Otherwise, subprocesses invoked via exec() can read/write
 * to these sockets.
 *
 * @param fd socket descriptor
 * @param toggle if non-zero close-on-exec is enabled, otherwise disabled.
 * @return -1 on error, 0 on success.
 */
extern int net_set_close_on_exec(int fd, int toggle);

/**
 * Enable/disable linger on close if data is present.
 *
 * @param fd socket descriptor
 * @param toggle enable if non-zero
 * @return -1 on error, 0 on success.
 */
extern int net_set_linger(int fd, int toggle);

/**
 * This will set or unset the SO_REUSEADDR flag.
 * @param fd socket descriptor
 * @param toggle Set SO_REUSEADDR if non-zero, otherwise unset it.
 * @return -1 on error, 0 on success
 */
extern int net_set_reuseaddress(int fd, int toggle);

/**
 * Set the send buffer size for the socket.
 * @param fd socket descriptor
 * @param size size to set
 * @return -1 on error, 0 on success.
 */
extern int net_set_sendbuf_size(int fd, size_t size);

/**
 * Get the send buffer size for the socket.
 * @param fd socket descriptor
 * @param[out] size existing size, cannot be NULL.
 * @return -1 on error, 0 on success.
 */
extern int net_get_sendbuf_size(int fd, size_t* size);

/**
 * Set the receive buffer size for the socket.
 * @param fd socket descriptor
 * @param size size to set
 * @return -1 on error, 0 on success.
 */
extern int net_set_recvbuf_size(int fd, size_t size);

/**
 * Get the receive buffer size for the socket.
 * @param fd socket descriptor
 * @param[out] size existing size, cannot be NULL.
 * @return -1 on error, 0 on success.
 */
extern int net_get_recvbuf_size(int fd, size_t* size);

/**
 * A wrapper for the recv() function call.
 */
extern ssize_t net_recv(int fd, void* buf, size_t len, int flags);

/**
 * A wrapper for the send() function call.
 */
extern ssize_t net_send(int fd, const void* buf, size_t len, int flags);

/**
 * This tries to create a AF_INET6 socket.
 * If it succeeds it concludes IPv6 is supported on the host operating
 * system. If the call fails with EAFNOSUPPORT the host system
 * does not support IPv6.
 * The result is cached so further calls to this function are cheap.
 */
extern int net_is_ipv6_supported();

/**
 * This will return a string containing the peer IP-address of
 * the connected peer associated with the given socket.
 *
 * @param fd socket descriptor
 * @return IP address (IPv6 or IPv4), or "0.0.0.0" if unable to determine the address.
 */
extern const char* net_get_peer_address(int fd);

extern const char* net_get_local_address(int fd);

/**
 * See man(3) inet_ntop.
 */
extern const char* net_address_to_string(int af, const void *src, char *dst, socklen_t cnt);

/**
 * See man(3) inet_pton.
 */
extern int net_string_to_address(int af, const char *src, void *dst);


/**
 * Network statistics monitor.
 *
 * Keeps track of bandwidth usage, sockets accepted, closed,
 * errors etc.
 */
extern void net_stats_initialize();
extern void net_stats_report();
extern void net_stats_reset();
extern void net_stats_add_tx(size_t bytes);
extern void net_stats_add_rx(size_t bytes);
extern void net_stats_add_accept();
extern void net_stats_add_error();
extern void net_stats_add_close();
extern int net_stats_timeout();
extern void net_stats_get(struct net_statistics** intermediate, struct net_statistics** total);

#endif /* HAVE_UHUB_NETWORK_H */
