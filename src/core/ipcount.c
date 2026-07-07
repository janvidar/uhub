/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
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

#include "system.h"
#include "util/memory.h"
#include "util/rbtree.h"
#include "network/ipcalc.h"
#include "core/ipcount.h"

struct ip_count
{
	struct rb_tree* tree;
};

/* One tree node per tracked address. The node owns its address, and the tree
   key points into it (rb_tree stores the key pointer, it does not copy). */
struct ip_count_node
{
	struct ip_addr_encap addr;
	size_t count;
};

static int ipcount_compare(const void* a, const void* b)
{
	const struct ip_addr_encap* x = (const struct ip_addr_encap*) a;
	const struct ip_addr_encap* y = (const struct ip_addr_encap*) b;

	if (x->af != y->af)
		return (x->af < y->af) ? -1 : 1;

	if (x->af == AF_INET6)
		return memcmp(&x->internal_ip_data.in6, &y->internal_ip_data.in6, sizeof(struct in6_addr));
	return memcmp(&x->internal_ip_data.in, &y->internal_ip_data.in, sizeof(struct in_addr));
}

struct ip_count* ipcount_create(void)
{
	struct ip_count* c = (struct ip_count*) hub_malloc_zero(sizeof(struct ip_count));
	if (!c)
		return NULL;
	c->tree = rb_tree_create(ipcount_compare, NULL, NULL);
	if (!c->tree)
	{
		hub_free(c);
		return NULL;
	}
	return c;
}

void ipcount_destroy(struct ip_count* c)
{
	struct rb_node* it;
	if (!c)
		return;
	if (c->tree)
	{
		/* Drain any addresses still tracked (there should be none once all
		   connections are gone). rb_tree_remove frees the internal node; the
		   node payload is ours to free. */
		while ((it = rb_tree_first(c->tree)) != NULL)
		{
			struct ip_count_node* node = (struct ip_count_node*) it->value;
			rb_tree_remove(c->tree, &node->addr);
			hub_free(node);
		}
		rb_tree_destroy(c->tree);
	}
	hub_free(c);
}

size_t ipcount_get(struct ip_count* c, const struct ip_addr_encap* addr)
{
	struct ip_count_node* node;
	if (!c)
		return 0;
	node = (struct ip_count_node*) rb_tree_get(c->tree, addr);
	return node ? node->count : 0;
}

void ipcount_increment(struct ip_count* c, const struct ip_addr_encap* addr)
{
	struct ip_count_node* node;
	if (!c)
		return;

	node = (struct ip_count_node*) rb_tree_get(c->tree, addr);
	if (node)
	{
		node->count++;
		return;
	}

	node = (struct ip_count_node*) hub_malloc_zero(sizeof(struct ip_count_node));
	if (!node)
		return; /* OOM: fail open rather than block the connection */
	memcpy(&node->addr, addr, sizeof(struct ip_addr_encap));
	node->count = 1;
	if (!rb_tree_insert(c->tree, &node->addr, node))
		hub_free(node); /* insert only fails on a duplicate key, handled above */
}

void ipcount_decrement(struct ip_count* c, const struct ip_addr_encap* addr)
{
	struct ip_count_node* node;
	if (!c)
		return;

	node = (struct ip_count_node*) rb_tree_get(c->tree, addr);
	if (!node)
		return;

	if (--node->count == 0)
	{
		rb_tree_remove(c->tree, &node->addr);
		hub_free(node);
	}
}
