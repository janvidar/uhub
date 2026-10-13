#include "system.h"
#include "util/memory.h"
#include "util/misc.h"
#include <util/rbtree.h>

/*
 * Every test builds the tree it needs and destroys it again, so each one runs
 * alone or in any order.
 */

#define MAX_NODES 10000

int test_tree_compare(const void* a, const void* b)
{
	return strcmp((const char*) a, (const char*) b);
}

static struct rb_tree* tree_create(void)
{
	return rb_tree_create(test_tree_compare, &hub_malloc, &hub_free);
}

/* one -> 1, two -> 2, three -> 3; the keys and values are literals. */
static struct rb_tree* tree_of_three(void)
{
	struct rb_tree* tree = tree_create();
	rb_tree_insert(tree, "one", "1");
	rb_tree_insert(tree, "two", "2");
	rb_tree_insert(tree, "three", "3");
	return tree;
}

/* rb_tree_destroy() frees the tree but not its nodes, so take out whichever of
   the three keys are still there first. */
static void tree_done(struct rb_tree* tree)
{
	rb_tree_remove(tree, "one");
	rb_tree_remove(tree, "two");
	rb_tree_remove(tree, "three");
	rb_tree_destroy(tree);
}

static int test_check_search(struct rb_tree* tree, const char* key, const char* expect)
{
	const char* value = (const char*) rb_tree_get(tree, key);
	if (!value) return !expect;
	if (!expect) return 0;
	return strcmp(value, expect) == 0;
}

EXO_TEST(rbtree_create_destroy, {
	int ok = 0;
	struct rb_tree* atree;
	atree = rb_tree_create(test_tree_compare, &hub_malloc, &hub_free);
	if (atree) ok = 1;
	rb_tree_destroy(atree);
	return ok;
});

EXO_TEST(rbtree_create_1, {
	struct rb_tree* tree = tree_create();
	int ok = tree != NULL;
	tree_done(tree);
	return ok;
});

EXO_TEST(rbtree_size_0, {
	struct rb_tree* tree = tree_create();
	int ok = rb_tree_size(tree) == 0;
	tree_done(tree);
	return ok;
});

EXO_TEST(rbtree_insert_1, {
	struct rb_tree* tree = tree_create();
	int ok = rb_tree_insert(tree, "one", "1");
	tree_done(tree);
	return ok;
});

EXO_TEST(rbtree_insert_2, {
	struct rb_tree* tree = tree_create();
	int ok = rb_tree_insert(tree, "one", "1") && rb_tree_insert(tree, "two", "2");
	tree_done(tree);
	return ok;
});

EXO_TEST(rbtree_insert_3, {
	struct rb_tree* tree = tree_create();
	int ok = rb_tree_insert(tree, "one", "1") && rb_tree_insert(tree, "two", "2")
		&& rb_tree_insert(tree, "three", "3");
	tree_done(tree);
	return ok;
});

/* A key already present is refused, and keeps its value. */
EXO_TEST(rbtree_insert_3_again, {
	struct rb_tree* tree = tree_of_three();
	int ok = !rb_tree_insert(tree, "three", "3-again") && test_check_search(tree, "three", "3");
	tree_done(tree);
	return ok;
});

EXO_TEST(rbtree_size_1, {
	struct rb_tree* tree = tree_of_three();
	int ok = rb_tree_size(tree) == 3;
	tree_done(tree);
	return ok;
});

#define TREE3_SEARCH(KEY, EXPECT) \
	struct rb_tree* tree = tree_of_three(); \
	int ok = test_check_search(tree, KEY, EXPECT); \
	tree_done(tree); \
	return ok;

EXO_TEST(rbtree_search_1, { TREE3_SEARCH("one", "1") });
EXO_TEST(rbtree_search_2, { TREE3_SEARCH("two", "2") });
EXO_TEST(rbtree_search_3, { TREE3_SEARCH("three", "3") });
EXO_TEST(rbtree_search_4, { TREE3_SEARCH("four", NULL) });

EXO_TEST(rbtree_remove_1, {
	struct rb_tree* tree = tree_of_three();
	int ok = rb_tree_remove(tree, "one");
	tree_done(tree);
	return ok;
});

EXO_TEST(rbtree_size_2, {
	struct rb_tree* tree = tree_of_three();
	int ok;
	rb_tree_remove(tree, "one");
	ok = rb_tree_size(tree) == 2;
	tree_done(tree);
	return ok;
});

EXO_TEST(rbtree_remove_2, {
	struct rb_tree* tree = tree_of_three();
	int ok = rb_tree_remove(tree, "one") && rb_tree_remove(tree, "two");
	tree_done(tree);
	return ok;
});

EXO_TEST(rbtree_remove_3, {
	struct rb_tree* tree = tree_of_three();
	int ok = rb_tree_remove(tree, "one") && rb_tree_remove(tree, "two") && rb_tree_remove(tree, "three");
	tree_done(tree);
	return ok;
});

/* A key that is gone cannot be removed twice. */
EXO_TEST(rbtree_remove_3_again, {
	struct rb_tree* tree = tree_of_three();
	int ok = rb_tree_remove(tree, "three") && !rb_tree_remove(tree, "three");
	tree_done(tree);
	return ok;
});

/* Emptied again: nothing is found, and the size is back to 0. */
static struct rb_tree* tree_emptied(void)
{
	struct rb_tree* tree = tree_of_three();
	rb_tree_remove(tree, "one");
	rb_tree_remove(tree, "two");
	rb_tree_remove(tree, "three");
	return tree;
}

#define EMPTIED_SEARCH(KEY) \
	struct rb_tree* tree = tree_emptied(); \
	int ok = test_check_search(tree, KEY, NULL); \
	tree_done(tree); \
	return ok;

EXO_TEST(rbtree_search_5, { EMPTIED_SEARCH("one") });
EXO_TEST(rbtree_search_6, { EMPTIED_SEARCH("two") });
EXO_TEST(rbtree_search_7, { EMPTIED_SEARCH("three") });
EXO_TEST(rbtree_search_8, { EMPTIED_SEARCH("four") });

EXO_TEST(rbtree_size_3, {
	struct rb_tree* tree = tree_emptied();
	int ok = rb_tree_size(tree) == 0;
	tree_done(tree);
	return ok;
});

/* ---- many nodes: keys and values are allocated, freed by free_node -------- */

static int freed_nodes = 0;
static void free_node(struct rb_node* n)
{
	hub_free((void*) n->key);
	hub_free((void*) n->value);
	freed_nodes += 1;
}

/* Insert "i" -> "i + 16384" for every i below MAX_NODES. */
static int tree_fill(struct rb_tree* tree)
{
	int i;
	for (i = 0; i < MAX_NODES; i++)
	{
		const char* key = strdup(uhub_itoa(i));
		const char* val = strdup(uhub_itoa(i + 16384));
		if (!rb_tree_insert(tree, key, val))
			return 0;
	}
	return 1;
}

/* Remove every node, the even keys first, then the odd ones. */
static void tree_drain(struct rb_tree* tree)
{
	int i;
	int j;
	for (j = 0; j < 2; j++)
		for (i = j; i < MAX_NODES; i += 2)
			rb_tree_remove_node(tree, uhub_itoa(i), &free_node);
}

EXO_TEST(rbtree_insert_10000, {
	struct rb_tree* tree = tree_create();
	int ok = tree_fill(tree);
	tree_drain(tree);
	rb_tree_destroy(tree);
	return ok;
});

EXO_TEST(rbtree_size_4, {
	struct rb_tree* tree = tree_create();
	int ok = tree_fill(tree) && rb_tree_size(tree) == MAX_NODES;
	tree_drain(tree);
	rb_tree_destroy(tree);
	return ok;
});

EXO_TEST(rbtree_check_10000, {
	struct rb_tree* tree = tree_create();
	int ok = tree_fill(tree);
	int i;
	for (i = 0; ok && i < MAX_NODES; i++)
	{
		char* key = strdup(uhub_itoa(i));
		const char* expect = uhub_itoa(i + 16384);
		ok = test_check_search(tree, key, expect);
		hub_free(key);
	}
	tree_drain(tree);
	rb_tree_destroy(tree);
	return ok;
});

EXO_TEST(rbtree_iterate_10000, {
	struct rb_tree* tree = tree_create();
	int i = 0;
	int ok = tree_fill(tree);
	struct rb_node* n = (struct rb_node*) rb_tree_first(tree);
	while (n)
	{
		n = (struct rb_node*) rb_tree_next(tree);
		i++;
	}
	ok = ok && i == MAX_NODES;
	tree_drain(tree);
	rb_tree_destroy(tree);
	return ok;
});

/* Removing them all frees every node exactly once. */
EXO_TEST(rbtree_remove_10000, {
	struct rb_tree* tree = tree_create();
	int ok = tree_fill(tree);
	freed_nodes = 0;
	tree_drain(tree);
	ok = ok && freed_nodes == MAX_NODES && rb_tree_size(tree) == 0;
	rb_tree_destroy(tree);
	return ok;
});

EXO_TEST(rbtree_destroy_1, {
	tree_done(tree_of_three());
	return 1;
});
