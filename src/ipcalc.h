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

/*
 * This file is used for fiddling with IP-addresses, 
 * primarily used for IP-banning in uhub.
 */

#ifndef HAVE_UHUB_IPCALC_H
#define HAVE_UHUB_IPCALC_H

struct ip_addr_encap {
	int af;
	union {
		struct in_addr in;
		struct in6_addr in6;
	} internal_ip_data;
};


extern int ip_convert_to_binary(const char* text_addr, struct ip_addr_encap* raw);

extern char* ip_convert_to_string(struct ip_addr_encap* raw);


/*
 * @return 1 if address is a valid IPv4 address in text notation
 *         0 if invalid
 */
extern int ip_is_valid_ipv4(const char* address);

/*
 * @return 1 if address is a valid IPv6 address in text notation
 *         0 if invalid
 */
extern int ip_is_valid_ipv6(const char* address);


/*
 * This function converts an IP address in text_address to a binary
 * struct sockaddr.
 * This will auto-detect if the IP-address is IPv6 (and that is supported),
 * or if IPv4 should be used.
 * NOTE: Use sockaddr_storage to allocate enough memory for IPv6.
 *
 * @param text_addr is an ipaddress either ipv6 or ipv4.
 *                  Special magic addresses called "any" and "loopback" exist,
 *                  and will work accross IPv6/IPv4.
 * @param port      Fill the struct sockaddr* with the given port, can safely be ignored.
 */
extern int ip_convert_address(const char* text_address, int port, struct sockaddr* addr, socklen_t* addr_len);


extern int ip_mask_create_left(int af, int bits, struct ip_addr_encap* result);
extern int ip_mask_create_right(int af, int bits, struct ip_addr_encap* result);

extern void ip_mask_apply_AND(struct ip_addr_encap* address, struct ip_addr_encap* mask, struct ip_addr_encap* result);
extern void ip_mask_apply_OR(struct ip_addr_encap* address, struct ip_addr_encap* mask, struct ip_addr_encap* result);

/**
 * @return <0 if a is less than b
 * @return >0 if a is greater than b
 * @return  0 if they are equal
 */
extern int ip_compare(struct ip_addr_encap* a, struct ip_addr_encap* b);

#endif /* HAVE_UHUB_IPCALC_H */

