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

#ifndef HAVE_UHUB_RED_BLACK_TREE_H
#define HAVE_UHUB_RED_BLACK_TREE_H

struct rb_tree;
typedef int (*rb_tree_compare)(const void* a, const void* b);
typedef void* (*rb_tree_alloc)(size_t);
typedef void (*rb_tree_free)(void*);


extern struct rb_tree* rb_tree_create(rb_tree_compare, rb_tree_alloc, rb_tree_free);
extern void rb_tree_destroy(struct rb_tree*);

extern void* rb_tree_insert(struct rb_tree* tree, const void* key, const void* data);
extern void* rb_tree_remove(struct rb_tree* tree, const void* key);
extern void* rb_tree_get(struct rb_tree* tree, const void* key); 


#endif /* HAVE_UHUB_RED_BLACK_TREE_H */

