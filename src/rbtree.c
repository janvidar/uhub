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

#include <sys/types.h>
#include "rbtree.h"

#define RED   0
#define BLACK 1

struct rb_node
{
	const void* key;
	const void* value; /* data */
	int color;
	struct rb_node* parent;
	struct rb_node* left;
	struct rb_node* right;
};

struct rb_tree
{
	struct rb_node* root;
	size_t elements;
	rb_tree_alloc alloc;
	rb_tree_free free;
	rb_tree_compare compare;
};

/* returns the grandparent of a node, if it exits */
static inline struct rb_node* get_grandparent(struct rb_node* n)
{
	if (n->parent)
		return n->parent->parent;
	return 0;
}

static struct rb_node* get_uncle(struct rb_node* n)
{
	struct rb_node* gparent = n->parent ? n->parent->parent : 0;
	if (gparent)
		return (n->parent == gparent->left) ? gparent->right : gparent->left;
	return 0;
}

static struct rb_node* tree_search(struct rb_tree* tree, const void* key)
{
	struct rb_node* node = tree->root;
	while (node)
	{
		int res = tree->compare(key, node->key);
		if (res < 0)      node = node->left;
		else if (res > 0) node = node->right;
		else              return node;
	}
	return 0;
}

static struct rb_node* tree_insert(struct rb_tree* tree, const void* key, const void* value)
{
	struct rb_node* node = tree->root;
	struct rb_node* newnode = tree->alloc(sizeof(struct rb_node));
	newnode->key = key;
	newnode->value = value;
	newnode->color = RED;
	

	while (node)
	{
		int res = tree->compare(key, node->key);
		if (res < 0)      node = node->left;
		else if (res > 0) node = node->right;
		else
		{
			/* key already exists in tree */
			return node;
		}
	}

	return newnode;
}


struct rb_tree* rb_tree_create(rb_tree_compare compare, rb_tree_alloc a, rb_tree_free f)
{
	struct rb_tree* tree = a(sizeof(struct rb_tree));
	tree->compare = compare;
	tree->alloc = a;
	tree->free = f;
	return tree;
}

void rb_tree_destroy(struct rb_tree* tree)
{
	rb_tree_free f = tree->free;
	f(tree);
}

void* rb_tree_insert(struct rb_tree* tree, const void* key, const void* value)
{
	struct rb_node* node = tree_insert(tree, key, value);
	if (node)
		return (void*) node->value;
	return 0;
}

void* rb_tree_remove(struct rb_tree* tree, const void* key)
{

}

void* rb_tree_get(struct rb_tree* tree, const void* key)
{
	struct rb_node* node = tree_search(tree, key);
	if (node)
		return node->value;
	return 0;
}
