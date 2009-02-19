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


int ip_is_valid_ipv4(const char* address)
{
	int i = 0; /* address index */
	int o = 0; /* octet number */
	int n = 0; /* numbers after each dot */
	int d = 0; /* dots */
	
	if (!address || strlen(address) > 15 || strlen(address) < 7)
		return 0;
	
	for (; i < strlen(address); i++)
	{
		if (is_num(address[i]))
		{
			n++;
			o *= 10;
			o += (address[i] - '0');
		}
		else if (address[i] == '.')
		{
			if (n == 0 || n > 3 || o > 255) return 0;
			n = 0;
			o = 0;
			d++;
		}
		else
		{
			return 0;
		}
	}
	
	if (n == 0 || n > 3 || o > 255 || d != 3) return 0;
	
	return 1;
}


int ip_is_valid_ipv6(const char* address)
{
	unsigned char buf[16];
	int ret = net_string_to_address(AF_INET6, address, buf);
	if (ret <= 0) return 0;
	return 1;
}


int ip_convert_to_binary(const char* taddr, struct ip_addr_encap* raw)
{
	if (ip_is_valid_ipv6(taddr))
	{
		if (net_string_to_address(AF_INET6, taddr, &raw->internal_ip_data.in6) <= 0)
		{
			return -1;
		}
		raw->af = AF_INET6;
		return AF_INET6;
	}
	else if (ip_is_valid_ipv4(taddr))
	{
		if (net_string_to_address(AF_INET, taddr, &raw->internal_ip_data.in) <= 0)
		{
			return -1;
		}
		raw->af = AF_INET;
		return AF_INET;
	}
	return -1;
}


char* ip_convert_to_string(struct ip_addr_encap* raw)
{
	static char address[INET6_ADDRSTRLEN+1];
	memset(address, 0, INET6_ADDRSTRLEN);
	net_address_to_string(raw->af, (void*) &raw->internal_ip_data, address, INET6_ADDRSTRLEN+1);
	if (strncmp(address, "::ffff:", 7) == 0) /* IPv6 mapped IPv4 address. */
	{
		return &address[7];
	}
	return address;
}

int ip_convert_address(const char* text_address, int port, struct sockaddr* addr, socklen_t* addr_len)
{
	struct sockaddr_in6 addr6;
	struct sockaddr_in addr4;
	size_t sockaddr_size;
	const char* taddr = 0;
	
	int ipv6sup = net_is_ipv6_supported();
	
	if (strcmp(text_address, "any") == 0)
	{
		if (ipv6sup)
		{
			taddr = "::";
		}
		else
		{
			taddr = "0.0.0.0";
		}
	}
	else if (strcmp(text_address, "loopback") == 0)
	{
		if (ipv6sup)
		{
			taddr = "::1";
		}
		else
		{
			taddr = "127.0.0.1";
		}
	}
	else
	{
		taddr = text_address;
	}
	
	
	if (ip_is_valid_ipv6(taddr) && ipv6sup)
	{
		sockaddr_size = sizeof(struct sockaddr_in6);
		memset(&addr6, 0, sockaddr_size);
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(port);
		if (net_string_to_address(AF_INET6, taddr, &addr6.sin6_addr) <= 0)
		{
			hub_log(log_fatal, "Unable to convert socket address (ipv6)");
			return 0;
		}

		memcpy(addr, &addr6, sockaddr_size);
		*addr_len = sockaddr_size;
	
	}
	else if (ip_is_valid_ipv4(taddr))
	{
		sockaddr_size = sizeof(struct sockaddr_in);
		memset(&addr4, 0, sockaddr_size);
		addr4.sin_family = AF_INET;
		addr4.sin_port = htons(port);
		if (net_string_to_address(AF_INET, taddr, &addr4.sin_addr) <= 0)
		{
			hub_log(log_fatal, "Unable to convert socket address (ipv4)");
			return 0;
		}
		memcpy(addr, &addr4, sockaddr_size);
		*addr_len = sockaddr_size;
	}
	else
	{
		addr = 0;
		*addr_len = 0;
		return -1;
	}
	return 0;
}


int ip_mask_create_left(int af, int bits, struct ip_addr_encap* result)
{
	uint32_t mask;
	int fill, remain_bits, n;

	memset(result, 0, sizeof(struct ip_addr_encap));
	result->af = af;
	
	if (bits < 0) bits = 0;
	
	if (af == AF_INET)
	{
		if (bits > 32) bits = 32;
		mask = (0xffffffff << (32 - bits));
		if (bits == 0) mask = 0;
		
		result->internal_ip_data.in.s_addr = (((uint8_t*) &mask)[0] << 24) | (((uint8_t*) &mask)[1] << 16) | (((uint8_t*) &mask)[2] << 8) | (((uint8_t*) &mask)[3] << 0);
	}
	else if (af == AF_INET6)
	{
		if (bits > 128) bits = 128;
		
		fill = (128-bits) / 8;
		remain_bits = (128-bits) % 8;
		mask = (0xff << (8 - remain_bits));
		n = 0;
		
		for (n = 0; n < fill; n++)
			((uint8_t*) &result->internal_ip_data.in6)[n] = (uint8_t) 0xff;
		
		if (fill < 16)
			((uint8_t*) &result->internal_ip_data.in6)[fill] = (uint8_t) mask;
	}
	else
	{
		return -1;
	}

#ifdef IP_CALC_DEBUG
	char* r_str = hub_strdup(ip_convert_to_string(result));
	hub_log(log_debug, "Created left mask: %s", r_str);
	hub_free(r_str);
#endif

	return 0;
}


int ip_mask_create_right(int af, int bits, struct ip_addr_encap* result)
{
	uint32_t mask;
	int fill, remain_bits, n, start;
	uint8_t mask8;

	memset(result, 0, sizeof(struct ip_addr_encap));
	result->af = af;
	
	if (bits < 0) bits = 0;
	
	if (af == AF_INET)
	{
		if (bits > 32) bits = 32;
		mask = (0xffffffff >> (32-bits));
		if (bits == 0) mask = 0;
		result->internal_ip_data.in.s_addr = (((uint8_t*) &mask)[0] << 24) | (((uint8_t*) &mask)[1] << 16) | (((uint8_t*) &mask)[2] << 8) | (((uint8_t*) &mask)[3] << 0);
	
	}
	else if (af == AF_INET6)
	{
		if (bits > 128) bits = 128;
		
		fill = (128-bits) / 8;
		remain_bits = (128-bits) % 8;
		mask8 = (0xff >> (8 - remain_bits));
		n = 0;
		start = 16-fill;
		
		for (n = 0; n < start; n++)
			((uint8_t*) &result->internal_ip_data.in6)[n] = (uint8_t) 0x00;
		
		for (n = start; n < 16; n++)
			((uint8_t*) &result->internal_ip_data.in6)[n] = (uint8_t) 0xff;
		
		if (start > 0)
			((uint8_t*) &result->internal_ip_data.in6)[start-1] = (uint8_t) mask8;
	}
	else
	{
		return -1;
	}
	
#ifdef IP_CALC_DEBUG
	char* r_str = hub_strdup(ip_convert_to_string(result));
	hub_log(log_debug, "Created right mask: %s", r_str);
	hub_free(r_str);
#endif
	
	return 0;
}


void ip_mask_apply_AND(struct ip_addr_encap* addr, struct ip_addr_encap* mask, struct ip_addr_encap* result)
{
	memset(result, 0, sizeof(struct ip_addr_encap));
	result->af = addr->af;
	
	if (addr->af == AF_INET)
	{
		result->internal_ip_data.in.s_addr = addr->internal_ip_data.in.s_addr & mask->internal_ip_data.in.s_addr;
	}
	else if (addr->af == AF_INET6)
	{
		uint32_t A, B, C, D;
		int n = 0;
		int offset = 0;
		for (n = 0; n < 4; n++)
		{
			offset = n * 4;
	
			A =	(((uint8_t*) &addr->internal_ip_data.in6)[offset+0] << 24) |
				(((uint8_t*) &addr->internal_ip_data.in6)[offset+1] << 16) |
				(((uint8_t*) &addr->internal_ip_data.in6)[offset+2] <<  8) |
				(((uint8_t*) &addr->internal_ip_data.in6)[offset+3] <<  0);
				
			B =	(((uint8_t*) &mask->internal_ip_data.in6)[offset+0] << 24) |
				(((uint8_t*) &mask->internal_ip_data.in6)[offset+1] << 16) |
				(((uint8_t*) &mask->internal_ip_data.in6)[offset+2] <<  8) |
				(((uint8_t*) &mask->internal_ip_data.in6)[offset+3] <<  0);
			
			C = A & B;
			
			D =	(((uint8_t*) &C)[0] << 24) |
				(((uint8_t*) &C)[1] << 16) |
				(((uint8_t*) &C)[2] <<  8) |
				(((uint8_t*) &C)[3] <<  0);
			((uint32_t*) &result->internal_ip_data.in6)[n] = D;
		}
	}
}


void ip_mask_apply_OR(struct ip_addr_encap* addr, struct ip_addr_encap* mask, struct ip_addr_encap* result)
{
	memset(result, 0, sizeof(struct ip_addr_encap));
	result->af = addr->af;
	
	if (addr->af == AF_INET)
	{
		result->internal_ip_data.in.s_addr = addr->internal_ip_data.in.s_addr | mask->internal_ip_data.in.s_addr;
	}
	else if (addr->af == AF_INET6)
	{
		uint32_t A, B, C, D;
		int n = 0;
		int offset = 0;
		for (n = 0; n < 4; n++)
		{
			offset = n * 4;
	
			A =	(((uint8_t*) &addr->internal_ip_data.in6)[offset+0] << 24) |
				(((uint8_t*) &addr->internal_ip_data.in6)[offset+1] << 16) |
				(((uint8_t*) &addr->internal_ip_data.in6)[offset+2] <<  8) |
				(((uint8_t*) &addr->internal_ip_data.in6)[offset+3] <<  0);
				
			B =	(((uint8_t*) &mask->internal_ip_data.in6)[offset+0] << 24) |
				(((uint8_t*) &mask->internal_ip_data.in6)[offset+1] << 16) |
				(((uint8_t*) &mask->internal_ip_data.in6)[offset+2] <<  8) |
				(((uint8_t*) &mask->internal_ip_data.in6)[offset+3] <<  0);
			
			C = A | B;
			
			D =	(((uint8_t*) &C)[0] << 24) |
				(((uint8_t*) &C)[1] << 16) |
				(((uint8_t*) &C)[2] <<  8) |
				(((uint8_t*) &C)[3] <<  0);
			((uint32_t*) &result->internal_ip_data.in6)[n] = D;
		}
	}
}


int ip_compare(struct ip_addr_encap* a, struct ip_addr_encap* b)
{
	int ret = 0;
	uint32_t A, B;

	if (a->af == AF_INET)
	{
		A =	(((uint8_t*) &a->internal_ip_data.in.s_addr)[0] << 24) |
			(((uint8_t*) &a->internal_ip_data.in.s_addr)[1] << 16) |
			(((uint8_t*) &a->internal_ip_data.in.s_addr)[2] <<  8) |
			(((uint8_t*) &a->internal_ip_data.in.s_addr)[3] <<  0);
			
		B =	(((uint8_t*) &b->internal_ip_data.in.s_addr)[0] << 24) |
			(((uint8_t*) &b->internal_ip_data.in.s_addr)[1] << 16) |
			(((uint8_t*) &b->internal_ip_data.in.s_addr)[2] <<  8) |
			(((uint8_t*) &b->internal_ip_data.in.s_addr)[3] <<  0);
		ret = A - B;
	}
	else if (a->af == AF_INET6)
	{
		int n = 0;
		int offset = 0;
		for (n = 0; n < 4; n++)
		{
			offset = n * 4;
			A =	(((uint8_t*) &a->internal_ip_data.in6)[offset+0] << 24) |
				(((uint8_t*) &a->internal_ip_data.in6)[offset+1] << 16) |
				(((uint8_t*) &a->internal_ip_data.in6)[offset+2] <<  8) |
				(((uint8_t*) &a->internal_ip_data.in6)[offset+3] <<  0);
				
			B =	(((uint8_t*) &b->internal_ip_data.in6)[offset+0] << 24) |
				(((uint8_t*) &b->internal_ip_data.in6)[offset+1] << 16) |
				(((uint8_t*) &b->internal_ip_data.in6)[offset+2] <<  8) |
				(((uint8_t*) &b->internal_ip_data.in6)[offset+3] <<  0);
						 
			if (A == B) continue;
			
			return A - B;
		}
		return 0;
	}
	
#ifdef IP_CALC_DEBUG
	char* a_str = hub_strdup(ip_convert_to_string(a));
	char* b_str = hub_strdup(ip_convert_to_string(b));
	hub_log(log_debug, "Comparing IPs '%s' AND '%s' => %d", a_str, b_str, ret);
	hub_free(a_str);
	hub_free(b_str);
#endif
	
	return ret;
}











