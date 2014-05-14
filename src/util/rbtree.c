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
#include "rbtree.h"

// #define RB_TREE_CHECKS

static struct rb_node* tree_search(struct rb_tree* tree, const void* key)
{
	struct rb_node* node = tree->root;
	while (node)
	{
		int res = tree->compare(node->key, key);
		if (!res)
			break;
		node = node->link[res < 0];
	}
	return node;
}

static struct rb_node* create_node(struct rb_tree* tree, const void* key, const void* value)
{
	struct rb_node* node = tree->alloc(sizeof(struct rb_node));
	node->key = key;
	node->value = value;
	node->red = 1;
	node->link[0] = 0;
	node->link[1] = 0;
	return node;
}

static int is_red(struct rb_node* node)
{
	return node && node->red;
}

#ifdef RB_TREE_CHECKS
int rb_tree_check(struct rb_tree* tree, struct rb_node* node)
{
	int lh, rh;

	if (node == NULL)
		return 1;
	else
	{
		struct rb_node *ln = node->link[0];
		struct rb_node *rn = node->link[1];

		/* Consecutive red links */
		if (is_red(node)) {
			if (is_red(ln) || is_red(rn))
			{
				puts("Red violation");
				return 0;
			}
		}

		lh = rb_tree_check(tree, ln);
		rh = rb_tree_check(tree, rn);

		/* Invalid binary search tree - not sorted correctly */
		if ((ln && tree->compare(ln->key, node->key) >= 0) || (rn && tree->compare(rn->key, node->key) <= 0))
		{
			puts("Binary tree violation");
			return 0;
		}

		/* Black height mismatch */
		if ( lh != 0 && rh != 0 && lh != rh ) {
			puts ( "Black violation" );
			return 0;
		}

		/* Only count black links */
		if (lh != 0 && rh != 0)
			return is_red(node) ? lh : lh + 1;
		else
			return 0;
	}
}
#endif // RB_TREE_CHECKS

static struct rb_node* rb_tree_rotate_single(struct rb_node* node, int dir)
{
	struct rb_node* other = node->link[!dir];

	node->link[!dir] = other->link[dir];
	other->link[dir] = node;

	node->red = 1;
	other->red = 0;
	return other;
}

static struct rb_node* rb_tree_rotate_double(struct rb_node* node, int dir)
{
	node->link[!dir] = rb_tree_rotate_single(node->link[!dir], !dir);
	return rb_tree_rotate_single(node, dir);
}

static struct rb_node* rb_tree_insert_r(struct rb_tree* tree, struct rb_node* node, const void* key, const void* value)
{
	int res;
	if (!node)
		return create_node(tree, key, value);

	res = tree->compare(node->key, key);
	if (!res)
	{
		puts("Node already exists!");
		return NULL;
	}
	else
	{
		int dir = res < 0;
		node->link[dir] = rb_tree_insert_r(tree, node->link[dir], key, value);

		if (is_red(node->link[dir]))
		{
			if (is_red(node->link[!dir]))
			{
				/* Case 1 */
				node->red = 1;
				node->link[0]->red = 0;
				node->link[1]->red = 0;
			}
			else
			{
				/* Cases 2 & 3 */
				if (is_red(node->link[dir]->link[dir]))
					node = rb_tree_rotate_single(node, !dir);
				else if (is_red(node->link[dir]->link[!dir]))
					node = rb_tree_rotate_double(node, !dir);
			}
		}
	}
	return node;
}


struct rb_tree* rb_tree_create(rb_tree_compare compare, rb_tree_alloc a, rb_tree_free f)
{
	struct rb_tree* tree = a ? a(sizeof(struct rb_tree)) : hub_malloc(sizeof(struct rb_tree));
	tree->compare = compare;
	tree->alloc = a ? a : hub_malloc;
	tree->free = f ? f : hub_free;
	tree->root = NULL;
	tree->elements = 0;
	tree->iterator.node = NULL;
	tree->iterator.stack = list_create();
	return tree;
}


void rb_tree_destroy(struct rb_tree* tree)
{
	list_destroy(tree->iterator.stack);
	tree->free(tree);
}

int rb_tree_insert(struct rb_tree* tree, const void* key, const void* value)
{
	struct rb_node* node;
	if (tree_search(tree, key))
		return 0;
	node = rb_tree_insert_r(tree, tree->root, key, value);
	tree->root = node;
	tree->root->red = 0;
	tree->elements++;
#ifdef RB_TREE_CHECKS
	rb_tree_check(tree, node);
#endif
	return 1;
}

void null_node_free(struct rb_node* n) { }

int rb_tree_remove(struct rb_tree* tree, const void* key)
{
	return rb_tree_remove_node(tree, key, &null_node_free);
}

int rb_tree_remove_node(struct rb_tree* tree, const void* key, rb_tree_free_node freecb)
{
	struct rb_node head = {0}; /* False tree root */
	struct rb_node *q, *p, *g; /* Helpers */
	struct rb_node *f = NULL;  /* Found item */
	int dir = 1;

	if (!tree->root)
		return 0;

	/* Set up helpers */
	q = &head;
	g = p = NULL;
	q->link[1] = tree->root;

	/* Search and push a red down */
	while (q->link[dir])
	{
		int last = dir;
		int res;

		/* Update helpers */
		g = p, p = q;
		q = q->link[dir];
		res = tree->compare(q->key, key);
		dir = res < 0;

		/* Save found node */
		if (!res)
			f = q;

		/* Push the red node down */
		if (!is_red(q) && !is_red(q->link[dir]))
		{
			if (is_red(q->link[!dir]))
				p = p->link[last] = rb_tree_rotate_single(q, dir);
			else if (!is_red(q->link[!dir]))
			{
				struct rb_node* s = p->link[!last];
				if (s)
				{
					if (!is_red(s->link[!last]) && !is_red (s->link[last]))
					{
						/* Color flip */
						p->red = 0;
						s->red = 1;
						q->red = 1;
					}
					else
					{
						int dir2 = g->link[1] == p;
						if (is_red(s->link[last]))
							g->link[dir2] = rb_tree_rotate_double(p, last);
						else if (is_red(s->link[!last]))
							g->link[dir2] = rb_tree_rotate_single(p, last);

						/* Ensure correct coloring */
						q->red = g->link[dir2]->red = 1;
						g->link[dir2]->link[0]->red = 0;
						g->link[dir2]->link[1]->red = 0;
					}
				}
			}
		}
	}

	/* Replace and remove if found */
	if (f)
	{
		freecb(f);
		f->key = q->key;
		f->value = q->value;
		p->link[p->link[1] == q] = q->link[q->link[0] == NULL];
		tree->free(q);
		tree->elements--;
	 }

	/* Update root and make it black */
	tree->root = head.link[1];
	if (tree->root != NULL)
		tree->root->red = 0;

#ifdef RB_TREE_CHECKS
	rb_tree_check(tree, tree->root);
#endif

	return f != NULL;
}

void* rb_tree_get(struct rb_tree* tree, const void* key)
{
	struct rb_node* node = tree_search(tree, key);
	if (node)
		return (void*) node->value;
	return 0;
}

size_t rb_tree_size(struct rb_tree* tree)
{
	return tree->elements;
}

static void push(struct rb_tree* tree, struct rb_node* n)
{
	list_append(tree->iterator.stack, n);
}

static struct rb_node* pop(struct rb_tree* tree)
{
	struct rb_node* n = list_get_last(tree->iterator.stack);
	if (n)
		list_remove(tree->iterator.stack, n);
	return n;
}

static struct rb_node* rb_it_set(struct rb_tree* tree, struct rb_node* n)
{
	tree->iterator.node = n;
	return n;
}

static void null_free(void* ptr) { }

struct rb_node* rb_tree_first(struct rb_tree* tree)
{
	struct rb_node* n = tree->root;
	list_clear(tree->iterator.stack, &null_free);
	while (n->link[0])
	{
		push(tree, n);
		n = n->link[0];
	}
	return rb_it_set(tree, n);
};


static struct rb_node* rb_tree_traverse(struct rb_tree* tree, int dir)
{
	struct rb_node* n = tree->iterator.node;
	struct rb_node* p; /* parent */

	if (n->link[dir])
	{
		push(tree, n);
		n = n->link[dir];
		while (n->link[!dir])
		{
			list_append(tree->iterator.stack, n);
			n = n->link[!dir];
		}
		return rb_it_set(tree, n);
	}

	// Need to walk upwards to the parent node.
	p = pop(tree);
	if (p)
	{
		// walk up in opposite direction
		if (p->link[!dir] == n)
			return rb_it_set(tree, p);

		// walk up in hte current direction
		while (p->link[dir] == n)
		{
			n = p;
			p = pop(tree);
			if (!p)
				return rb_it_set(tree, NULL);
		}
		return rb_it_set(tree, p);
	}
	return rb_it_set(tree, NULL);
}

struct rb_node* rb_tree_next(struct rb_tree* tree)
{
	return rb_tree_traverse(tree, 1);
}

struct rb_node* rb_tree_prev(struct rb_tree* tree)
{
	return rb_tree_traverse(tree, 0);
}
