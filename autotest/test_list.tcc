#include <uhub.h>

static struct linked_list* list = NULL;
static struct linked_list* list2 = NULL;

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

static int g_remove_flag = 0;
static void null_free_inc_flag(void* ptr)
{
	(void) ptr;
	g_remove_flag++;
}

EXO_TEST(list_remove_first_1_1,
{
	list_append(list, A);
	list_append(list, B);
	list_append(list, C);
	return list->size == 3;
});

EXO_TEST(list_remove_first_1_2,
{
	g_remove_flag = 0;
	list_remove_first(list, null_free_inc_flag);
	return list->size == 2 && g_remove_flag == 1;
});

EXO_TEST(list_remove_first_1_3,
{
	list_remove_first(list, NULL);
	return list->size == 1;
});

EXO_TEST(list_remove_first_1_4,
{
	list_remove_first(list, NULL);
	return list->size == 0;
});


EXO_TEST(list_remove_first_1_5,
{
	list_remove_first(list, NULL);
	return list->size == 0;
});


EXO_TEST(list_append_list_1,
{
	list_append(list, A);
	list_append(list, B);
	list_append(list, C);
	list2 = list_create();
	list_append(list2, A2);
	list_append(list2, B2);
	list_append(list2, C2);
	return list->size == 3 && list2->size == 3;
});

EXO_TEST(list_append_list_2,
{
	list_append_list(list, list2);
	return list->size == 6 && list2->size == 0;
});

EXO_TEST(list_append_list_3,
{
	list_destroy(list2);
	return list_get_index(list, 0) == A &&
			list_get_index(list, 1) == B &&
			list_get_index(list, 2) == C &&
			list_get_index(list, 3) == A2 &&
			list_get_index(list, 4) == B2 &&
			list_get_index(list, 5) == C2;
});

EXO_TEST(list_clear_list_last,
{
	list_clear(list, &null_free);
	return 1;
});


EXO_TEST(list_destroy_1, {
	list_destroy(list);
	return 1;
});

EXO_TEST(list_destroy_2, {
	list_destroy(0);
	return 1;
});

