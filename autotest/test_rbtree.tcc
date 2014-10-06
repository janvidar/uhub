#include <uhub.h>
#include <util/rbtree.h>

#define MAX_NODES 10000

static struct rb_tree* tree = NULL;

int test_tree_compare(const void* a, const void* b)
{
	return strcmp((const char*) a, (const char*) b);
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
	tree = rb_tree_create(test_tree_compare, &hub_malloc, &hub_free);
	return tree != NULL;
});

EXO_TEST(rbtree_size_0, { return rb_tree_size(tree) == 0; });

EXO_TEST(rbtree_insert_1, {
	return rb_tree_insert(tree, "one", "1");
});

EXO_TEST(rbtree_insert_2, {
	return rb_tree_insert(tree, "two", "2");
});

EXO_TEST(rbtree_insert_3, {
	return rb_tree_insert(tree, "three", "3");
});

EXO_TEST(rbtree_insert_3_again, {
	return !rb_tree_insert(tree, "three", "3-again");
});

EXO_TEST(rbtree_size_1, { return rb_tree_size(tree) == 3; });

static int test_check_search(const char* key, const char* expect)
{
	const char* value = (const char*) rb_tree_get(tree, key);
	if (!value) return !expect;
	if (!expect) return 0;
	return strcmp(value, expect) == 0;
}

EXO_TEST(rbtree_search_1, { return test_check_search("one", "1"); });
EXO_TEST(rbtree_search_2, { return test_check_search("two", "2"); });
EXO_TEST(rbtree_search_3, { return test_check_search("three", "3"); });
EXO_TEST(rbtree_search_4, { return test_check_search("four", NULL); });


EXO_TEST(rbtree_remove_1, {
	return rb_tree_remove(tree, "one");
});

EXO_TEST(rbtree_size_2, { return rb_tree_size(tree) == 2; });

EXO_TEST(rbtree_remove_2, {
	return rb_tree_remove(tree, "two");
});

EXO_TEST(rbtree_remove_3, {
	return rb_tree_remove(tree, "three");
});

EXO_TEST(rbtree_remove_3_again, {
	return !rb_tree_remove(tree, "three");
});

EXO_TEST(rbtree_search_5, { return test_check_search("one", NULL); });
EXO_TEST(rbtree_search_6, { return test_check_search("two", NULL); });
EXO_TEST(rbtree_search_7, { return test_check_search("three", NULL); });
EXO_TEST(rbtree_search_8, { return test_check_search("four", NULL); });

EXO_TEST(rbtree_size_3, { return rb_tree_size(tree) == 0; });

EXO_TEST(rbtree_insert_10000, {
	int i;
	for (i = 0; i < MAX_NODES; i++)
	{
		const char* key = strdup(uhub_itoa(i));
		const char* val = strdup(uhub_itoa(i + 16384));
		if (!rb_tree_insert(tree, key, val))
			return 0;
	}
	return 1;
});

EXO_TEST(rbtree_size_4, { return rb_tree_size(tree) == MAX_NODES; });

EXO_TEST(rbtree_check_10000, {
	int i;
	for (i = 0; i < MAX_NODES; i++)
	{
		char* key = strdup(uhub_itoa(i));
		const char* expect = uhub_itoa(i + 16384);
		if (!test_check_search(key, expect))
			return 0;
		hub_free(key);
	}
	return 1;
});

EXO_TEST(rbtree_iterate_10000, {
	int i = 0;
	struct rb_node* n = (struct rb_node*) rb_tree_first(tree);
	while (n)
	{
		n = (struct rb_node*) rb_tree_next(tree);
		i++;
	}
	return i == MAX_NODES;
});

static int freed_nodes = 0;
static void free_node(struct rb_node* n)
{
	hub_free((void*) n->key);
	hub_free((void*) n->value);
	freed_nodes += 1;
}

EXO_TEST(rbtree_remove_10000, {
	int i;
	int j;
	for (j = 0; j < 2; j++)
	{
		for (i = j; i < MAX_NODES; i += 2)
		{
			const char* key = uhub_itoa(i);
			rb_tree_remove_node(tree, key, &free_node);
		}
	}
	return freed_nodes == MAX_NODES;
});

EXO_TEST(rbtree_destroy_1, {
	rb_tree_destroy(tree);
	return 1;
});
