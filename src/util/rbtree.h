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

#ifndef HAVE_UHUB_RED_BLACK_TREE_H
#define HAVE_UHUB_RED_BLACK_TREE_H

struct rb_node
{
	const void* key;
	const void* value; /* data */
	int red;
	struct rb_node* link[2];
};

typedef int (*rb_tree_compare)(const void* a, const void* b);
typedef void* (*rb_tree_alloc)(size_t);
typedef void (*rb_tree_free)(void*);
typedef void (*rb_tree_free_node)(struct rb_node*);

struct rb_iterator
{
	struct rb_node* node; // current node.
	struct linked_list* stack; // stack from the top -- needed since we don't have parent pointers.
};

struct rb_tree
{
	struct rb_node* root;
	size_t elements;
	rb_tree_alloc alloc;
	rb_tree_free free;
	rb_tree_compare compare;
	struct rb_iterator iterator;
};



/**
 * Create a tree.
 *
 * @param compare Comparison function
 * @param alloc Allocator (if NULL then hub_malloc() is used)
 * @param dealloc Deallocator (if NULL then hub_free() is used)
 * @return a tree handle.
 */
extern struct rb_tree* rb_tree_create(rb_tree_compare compare, rb_tree_alloc alloc, rb_tree_free dealloc);

/**
 * Deletes the tree and all the nodes.
 * But not the content inside the nodes.
 */
extern void rb_tree_destroy(struct rb_tree*);

/**
 * Insert a key into the tree, returns 1 if successful,
 * or 0 if the key already existed.
 */
extern int rb_tree_insert(struct rb_tree* tree, const void* key, const void* data);

/**
 * Remove a key from the tree.
 * Returns 1 if the node was removed, or 0 if it was not removed (i.e. not found!)
 *
 * NOTE: the content of the node is not freed if it needs to be then use rb_tree_remove_node
 * where you can specify a callback cleanup function.
 */
extern int rb_tree_remove(struct rb_tree* tree, const void* key);

/**
 * Remove the node, but call the free callback before the node is removed.
 * This is useful in cases where you need to deallocate the key and/or value from the node.
 * Returns 1 if the node was removed, or 0 if not found.
 */
extern int rb_tree_remove_node(struct rb_tree* tree, const void* key, rb_tree_free_node free);

/**
 * Returns NULL if the key was not found in the tree.
 */
extern void* rb_tree_get(struct rb_tree* tree, const void* key);

/**
 * Returns the number of elements inside the tree.
 */
extern size_t rb_tree_size(struct rb_tree* tree);

/**
 * Returns the first node in the tree.
 * (leftmost, or lowest value in sorted order).
 *
 * Example:
 *
 * <code>
 * struct rb_node* it;
 * for (it = rb_tree_first(tree); it; it = rb_tree_next())
 * {
 *    void* key = rb_iterator_key(it);
 * 	  void* value = rb_iterator_value(it);
 * }
 * </code>
 */
extern struct rb_node* rb_tree_first(struct rb_tree* tree);

/**
 * Points the iterator at the next node.
 * If the next node is NULL then the iterator becomes NULL too.
 */
extern struct rb_node* rb_tree_next(struct rb_tree* tree);
extern struct rb_node* rb_tree_prev(struct rb_tree* tree);

/**
 * Returnst the key of the node pointed to by the iterator.
 * If this iterator is the same as rb_tree_end() then NULL is returned.
 */
extern void* rb_iterator_key(struct rb_iterator* it);

/**
 * Returnst the value of the node pointed to by the iterator.
 * If this iterator is the same as rb_tree_end() then the behavior is undefined.
 */
extern void* rb_iterator_value(struct rb_iterator* it);



#endif /* HAVE_UHUB_RED_BLACK_TREE_H */

