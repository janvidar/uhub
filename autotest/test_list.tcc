#include "util/list.h"

#include <stdarg.h>

/*
 * Every test builds the list it needs with list_of() and destroys it again, so
 * each one runs alone or in any order.
 */

static char A[2] = { 'A', 0 };
static char B[2] = { 'B', 0 };
static char C[2] = { 'C', 0 };
static char A2[2] = { 'a', 0 };
static char B2[2] = { 'b', 0 };
static char C2[2] = { 'c', 0 };

static void null_free(void* ptr)
{
	(void) ptr;
}

/* A new list holding the given items, in order; NULL ends the arguments. */
static struct linked_list* list_of(char* first, ...)
{
	struct linked_list* list = list_create();
	va_list args;
	char* item;

	va_start(args, first);
	for (item = first; item; item = va_arg(args, char*))
		list_append(list, item);
	va_end(args);
	return list;
}

/* The items are not owned by the list, so only the nodes go. */
static void list_done(struct linked_list* list)
{
	list_clear(list, &null_free);
	list_destroy(list);
}

EXO_TEST(list_create_destroy, {
	int ok = 0;
	struct linked_list* alist;
	alist = list_create();
	if (alist) ok = 1;
	list_destroy(alist);
	return ok;
});

EXO_TEST(list_create, {
	struct linked_list* list = list_create();
	int ok = list->size == 0;
	list_destroy(list);
	return ok;
});

EXO_TEST(list_append_1, {
	struct linked_list* list = list_create();
	int ok;
	list_append(list, A);
	ok = list->size == 1;
	list_done(list);
	return ok;
});

EXO_TEST(list_remove_1, {
	struct linked_list* list = list_of(A, NULL);
	int ok;
	list_remove(list, A);
	ok = list->size == 0;
	list_done(list);
	return ok;
});

EXO_TEST(list_append_2, {
	struct linked_list* list = list_create();
	int ok;
	list_append(list, A);
	list_append(list, B);
	ok = list->size == 2;
	list_done(list);
	return ok;
});

EXO_TEST(list_remove_2, {
	struct linked_list* list = list_of(A, B, NULL);
	int ok;
	list_remove(list, A);
	ok = list->size == 1 && list_get_first(list) == B;
	list_done(list);
	return ok;
});

/* Removing an item that is not there has no effect. */
EXO_TEST(list_remove_3, {
	struct linked_list* list = list_of(B, NULL);
	int ok;
	list_remove(list, A);
	ok = list->size == 1;
	list_done(list);
	return ok;
});

EXO_TEST(list_remove_4, {
	struct linked_list* list = list_of(B, NULL);
	int ok;
	list_remove(list, B);
	ok = list->size == 0;
	list_done(list);
	return ok;
});

EXO_TEST(list_append_3, {
	struct linked_list* list = list_create();
	int ok;
	list_append(list, A);
	list_append(list, B);
	list_append(list, C);
	ok = list->size == 3;
	list_done(list);
	return ok;
});

/* The same item can be in the list more than once. */
EXO_TEST(list_append_4, {
	struct linked_list* list = list_of(A, B, C, NULL);
	int ok;
	list_append(list, A);
	ok = list->size == 4;
	list_done(list);
	return ok;
});

/* With an item in twice, the first one is removed. */
EXO_TEST(list_remove_5, {
	struct linked_list* list = list_of(A, B, C, A, NULL);
	int ok;
	list_remove(list, A);
	ok = list->size == 3
		&& list_get_index(list, 0) == B
		&& list_get_index(list, 2) == A;
	list_done(list);
	return ok;
});

/* The list the indexing and iteration tests below look at: B, C, A. */
#define LIST_BCA() list_of(B, C, A, NULL)

EXO_TEST(list_get_index_1, {
	struct linked_list* list = LIST_BCA();
	int ok = list_get_index(list, 0) == B;
	list_done(list);
	return ok;
});

EXO_TEST(list_get_index_2, {
	struct linked_list* list = LIST_BCA();
	int ok = list_get_index(list, 1) == C;
	list_done(list);
	return ok;
});

EXO_TEST(list_get_index_3, {
	struct linked_list* list = LIST_BCA();
	int ok = list_get_index(list, 2) == A;
	list_done(list);
	return ok;
});

EXO_TEST(list_get_index_4, {
	struct linked_list* list = LIST_BCA();
	int ok = list_get_index(list, 3) == NULL;
	list_done(list);
	return ok;
});

EXO_TEST(list_get_first_1, {
	struct linked_list* list = LIST_BCA();
	int ok = list_get_first(list) == B;
	list_done(list);
	return ok;
});

EXO_TEST(list_get_first_next_1, {
	struct linked_list* list = LIST_BCA();
	int ok = list_get_first(list) == B && list_get_next(list) == C;
	list_done(list);
	return ok;
});

EXO_TEST(list_get_first_next_2, {
	struct linked_list* list = LIST_BCA();
	int ok = list_get_first(list) == B && list_get_next(list) == C && list_get_next(list) == A;
	list_done(list);
	return ok;
});

EXO_TEST(list_get_last_1, {
	struct linked_list* list = LIST_BCA();
	int ok = list_get_last(list) == A;
	list_done(list);
	return ok;
});

EXO_TEST(list_get_last_prev_1, {
	struct linked_list* list = LIST_BCA();
	int ok = list_get_last(list) == A && list_get_prev(list) == C;
	list_done(list);
	return ok;
});

EXO_TEST(list_get_last_prev_2, {
	struct linked_list* list = LIST_BCA();
	int ok = list_get_last(list) == A && list_get_prev(list) == C && list_get_prev(list) == B;
	list_done(list);
	return ok;
});

/* The cursor can turn around: back from the end, then forward again. */
EXO_TEST(list_get_last_prev_next_1, {
	struct linked_list* list = LIST_BCA();
	int ok = list_get_last(list) == A
		&& list_get_prev(list) == C
		&& list_get_prev(list) == B
		&& list_get_next(list) == C;
	list_done(list);
	return ok;
});

EXO_TEST(list_clear, {
	struct linked_list* list = LIST_BCA();
	int ok;
	list_get_first(list); /* leave the cursor somewhere */
	list_clear(list, &null_free);
	ok = list->size == 0 && list->first == 0 && list->last == 0 && list->iterator == 0;
	list_destroy(list);
	return ok;
});

static int g_remove_flag = 0;
static void null_free_inc_flag(void* ptr)
{
	(void) ptr;
	g_remove_flag++;
}

EXO_TEST(list_remove_first_1_1, {
	struct linked_list* list = list_create();
	int ok;
	list_append(list, A);
	list_append(list, B);
	list_append(list, C);
	ok = list->size == 3;
	list_done(list);
	return ok;
});

/* The free handle is called for the item removed. */
EXO_TEST(list_remove_first_1_2, {
	struct linked_list* list = list_of(A, B, C, NULL);
	int ok;
	g_remove_flag = 0;
	list_remove_first(list, null_free_inc_flag);
	ok = list->size == 2 && g_remove_flag == 1 && list_get_first(list) == B;
	list_done(list);
	return ok;
});

EXO_TEST(list_remove_first_1_3, {
	struct linked_list* list = list_of(B, C, NULL);
	int ok;
	list_remove_first(list, NULL);
	ok = list->size == 1 && list_get_first(list) == C;
	list_done(list);
	return ok;
});

EXO_TEST(list_remove_first_1_4, {
	struct linked_list* list = list_of(C, NULL);
	int ok;
	list_remove_first(list, NULL);
	ok = list->size == 0;
	list_done(list);
	return ok;
});

/* On an empty list it does nothing. */
EXO_TEST(list_remove_first_1_5, {
	struct linked_list* list = list_create();
	int ok;
	list_remove_first(list, NULL);
	ok = list->size == 0;
	list_destroy(list);
	return ok;
});

EXO_TEST(list_append_list_1, {
	struct linked_list* list = list_of(A, B, C, NULL);
	struct linked_list* list2 = list_of(A2, B2, C2, NULL);
	int ok = list->size == 3 && list2->size == 3;
	list_done(list);
	list_done(list2);
	return ok;
});

/* Appending a list moves its items over and leaves it empty... */
EXO_TEST(list_append_list_2, {
	struct linked_list* list = list_of(A, B, C, NULL);
	struct linked_list* list2 = list_of(A2, B2, C2, NULL);
	int ok;
	list_append_list(list, list2);
	ok = list->size == 6 && list2->size == 0;
	list_done(list);
	list_destroy(list2);
	return ok;
});

/* ...after the items already there, in order. */
EXO_TEST(list_append_list_3, {
	struct linked_list* list = list_of(A, B, C, NULL);
	struct linked_list* list2 = list_of(A2, B2, C2, NULL);
	int ok;
	list_append_list(list, list2);
	list_destroy(list2);
	ok = list_get_index(list, 0) == A &&
			list_get_index(list, 1) == B &&
			list_get_index(list, 2) == C &&
			list_get_index(list, 3) == A2 &&
			list_get_index(list, 4) == B2 &&
			list_get_index(list, 5) == C2;
	list_done(list);
	return ok;
});

EXO_TEST(list_clear_list_last, {
	struct linked_list* list = list_of(A, B, C, A2, B2, C2, NULL);
	int ok;
	list_clear(list, &null_free);
	ok = list->size == 0;
	list_destroy(list);
	return ok;
});

EXO_TEST(list_destroy_1, {
	list_destroy(list_create());
	return 1;
});

EXO_TEST(list_destroy_2, {
	list_destroy(0);
	return 1;
});


/* Stateless (reentrant) iterator: list_iterator_first/next + LIST_FOREACH_SAFE. */

EXO_TEST(list_iterator_empty, {
	struct linked_list* l = list_create();
	struct node* cur;
	int ok = (list_iterator_first(l, &cur) == NULL) && (list_iterator_next(&cur) == NULL);
	list_destroy(l);
	return ok;
});

EXO_TEST(list_iterator_basic, {
	struct linked_list* l = list_create();
	struct node* cur;
	char* item;
	int n = 0;
	int ok = 1;
	list_append(l, A);
	list_append(l, B);
	list_append(l, C);
	LIST_FOREACH_SAFE(char*, item, l, cur, {
		if (n == 0 && item != A) ok = 0;
		if (n == 1 && item != B) ok = 0;
		if (n == 2 && item != C) ok = 0;
		n++;
	});
	list_clear(l, &null_free);
	list_destroy(l);
	return ok && n == 3;
});

/*
 * The reason the reentrant iterator exists: a walk nested inside another walk of
 * the SAME list must not disturb the outer walk. With the old shared-cursor
 * list_get_first/next this re-ran the outer loop from the top (potential infinite
 * loop); LIST_FOREACH_SAFE must visit each outer element exactly once.
 */
EXO_TEST(list_iterator_nested, {
	struct linked_list* l = list_create();
	struct node* outer;
	char* o;
	int outer_visits = 0;
	int inner_total = 0;
	list_append(l, A);
	list_append(l, B);
	list_append(l, C);
	LIST_FOREACH_SAFE(char*, o, l, outer, {
		struct node* inner;
		char* i;
		(void) o;
		outer_visits++;
		LIST_FOREACH_SAFE(char*, i, l, inner, {
			(void) i;
			inner_total++;
		});
	});
	list_clear(l, &null_free);
	list_destroy(l);
	/* outer visits each of 3 once; each drives a full 3-element inner walk. */
	return outer_visits == 3 && inner_total == 9;
});
