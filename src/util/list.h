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

#ifndef HAVE_UHUB_LINKED_LIST_H
#define HAVE_UHUB_LINKED_LIST_H

struct linked_list
{
	size_t size;
	struct node* first;
	struct node* last;
	struct node* iterator;
};

struct node
{
	void* ptr;
	struct node* next;
	struct node* prev;
};

extern struct linked_list* list_create();
extern void list_destroy(struct linked_list*);
extern void list_clear(struct linked_list*, void (*free_handle)(void* ptr) );


extern void list_append(struct linked_list* list, void* data_ptr);

/**
 * A special list append that moves all nodes from other_list to list.
 * The other list will be empty.
 */
extern void list_append_list(struct linked_list* list, struct linked_list* other);


/**
 * Remove data_ptr from the list. If multiple versions occur, only the first one is removed.
 */
extern void list_remove(struct linked_list* list, void* data_ptr);
extern size_t list_size(struct linked_list* list);

extern void* list_get_index(struct linked_list*, size_t offset);
extern void* list_get_first(struct linked_list*);
extern void* list_get_last(struct linked_list*);
extern void* list_get_next(struct linked_list*);
extern void* list_get_prev(struct linked_list*);

extern struct node* list_get_first_node(struct linked_list*);
extern struct node* list_get_last_node(struct linked_list*);

/**
 * Remove the first element, and call the free_handle function (if not NULL)
 * to ensure the data is freed also.
 */
extern void list_remove_first(struct linked_list* list, void (*free_handle)(void* ptr));

#define LIST_FOREACH(TYPE, ITEM, LIST, BLOCK) \
		for (ITEM = (TYPE) list_get_first(LIST); ITEM; ITEM = (TYPE) list_get_next(LIST)) \
			BLOCK

#endif /* HAVE_UHUB_LINKED_LIST_H */

