#include <uhub.h>

static struct linked_list* list = NULL;

static char A[2] = { 'A', 0 };
static char B[2] = { 'B', 0 };
static char C[2] = { 'C', 0 };

static void null_free(void* ptr)
{
	(void) ptr;
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
	list = list_create();
	return list->size == 0;
});

EXO_TEST(list_append_1, {
	list_append(list, (char*) A);
	return list->size == 1;
});

EXO_TEST(list_remove_1, {
	list_remove(list, (char*) A);
	return list->size == 0;
});


EXO_TEST(list_append_2, {
	list_append(list, A);
	list_append(list, B);
	return list->size == 2;
});

EXO_TEST(list_remove_2, {
	list_remove(list, (char*) A);
	return list->size == 1;
});

EXO_TEST(list_remove_3, {
	list_remove(list, (char*) A); /* already removed, so should have no effect */
	return list->size == 1;
});

EXO_TEST(list_remove_4, {
	list_remove(list, (char*) B); /* already removed, so should have no effect */
	return list->size == 0;
});

EXO_TEST(list_append_3, {
	list_append(list, A);
	list_append(list, B);
	list_append(list, C);
	return list->size == 3;
});

EXO_TEST(list_append_4, {
	list_append(list, A); /* OK. adding the same one *AGAIN* */
	return list->size == 4;
});

EXO_TEST(list_remove_5, {
	list_remove(list, A); /* removing the first one. */
	return list->size == 3;
});

EXO_TEST(list_get_index_1, {
	return list_get_index(list, 0) == B;
});

EXO_TEST(list_get_index_2, {
	return list_get_index(list, 1) == C;
});

EXO_TEST(list_get_index_3, {
	return list_get_index(list, 2) == A;
});

EXO_TEST(list_get_index_4, {
	return list_get_index(list, 3) == NULL;
});

EXO_TEST(list_get_first_1, {
	return list_get_first(list) == B;
});

EXO_TEST(list_get_first_next_1, {
	return list_get_next(list) == C;
});

EXO_TEST(list_get_first_next_2, {
	return list_get_next(list) == A;
});

EXO_TEST(list_get_last_1, {
	return list_get_last(list) == A;
});

EXO_TEST(list_get_last_prev_1, {
	return list_get_prev(list) == C;
});

EXO_TEST(list_get_last_prev_2, {
	return list_get_prev(list) == B;
});

EXO_TEST(list_get_last_prev_next_1, {
	return list_get_next(list) == C;
});

EXO_TEST(list_clear, {
	list_clear(list, &null_free);
	return list->size == 0 && list->first == 0 && list->last == 0 && list->iterator == 0;
});


EXO_TEST(list_destroy_1, {
	list_destroy(list);
	return 1;
});

EXO_TEST(list_destroy_2, {
	list_destroy(0);
	return 1;
});

