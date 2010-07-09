#include <uhub.h>

#define SETUP(X, STR) struct linked_list* tokens = cfg_tokenize(STR)
#define CLEANUP(X) do { list_clear(X, hub_free); list_destroy(X); } while(0)

static int match_str(const char* str1, char* str2)
{
	size_t i;
	for (i = 0; i < strlen(str2); i++)
		if (str2[i] == '_')
			str2[i] = ' ';
		else if (str2[i] == '|')
			str2[i] = '\t';

	int ret = strcmp(str1, str2);
	if (ret) {
		fprintf(stderr, "\n    Mismatch: \"%s\" != \"%s\"\n", str1, str2);
	}
	return ret;
}

static int count(const char* STR, size_t EXPECT) {
	SETUP(tokens, STR);
	int pass = list_size(tokens) == EXPECT;
	CLEANUP(tokens);
	return pass;
}

static int compare(const char* str, const char* ref) {
	size_t i, max;
	struct linked_list* compare = list_create();
	SETUP(tokens, str);
	split_string(ref, " ", compare, 0);
	int pass = list_size(tokens) == list_size(compare);
	if (pass) {
		max = list_size(tokens);
		for (i = 0; i < max; i++) {
			char* token = (char*) list_get_index(tokens, i);
			char* refer = (char*) list_get_index(compare, i);
			if (match_str(token, refer)) {
				pass = 0;
				break;
			}
		}
	}
	CLEANUP(tokens);
	CLEANUP(compare);
	return pass;
}

EXO_TEST(tokenizer_basic_0,  { return count("", 0); });
EXO_TEST(tokenizer_basic_1,  { return count("a", 1); });
EXO_TEST(tokenizer_basic_1a, { return count(" a", 1); })
EXO_TEST(tokenizer_basic_1b, { return count("	a", 1); })
EXO_TEST(tokenizer_basic_1c, { return count("      a", 1); })
EXO_TEST(tokenizer_basic_1d, { return count(" a ", 1); })
EXO_TEST(tokenizer_basic_1e, { return count("  a  ", 1); })
EXO_TEST(tokenizer_basic_2,  { return count("a b", 2); });
EXO_TEST(tokenizer_basic_2a, { return count("  a   b  ", 2); });
EXO_TEST(tokenizer_basic_3,  { return count("a b c", 3); });
EXO_TEST(tokenizer_basic_3a, { return count("a b   c", 3); });
EXO_TEST(tokenizer_basic_3b, { return count("a b	c", 3); });
EXO_TEST(tokenizer_basic_3c, { return count("a b c ", 3); });
EXO_TEST(tokenizer_basic_3d, { return count("a b c   ", 3); });

EXO_TEST(tokenizer_basic_compare_0, { return compare("value1 value2 value3", "value1 value2 value3"); });
EXO_TEST(tokenizer_basic_compare_1, { return compare("a b c", "a b c"); });
EXO_TEST(tokenizer_basic_compare_2, { return compare("a b    c", "a b c"); });
EXO_TEST(tokenizer_basic_compare_3, { return compare("   a	 b    c", "a b c"); });
EXO_TEST(tokenizer_basic_compare_4, { return compare("   a	 b    c    ", "a b c"); });
EXO_TEST(tokenizer_basic_compare_5, { return compare("a	b c ", "a b c"); });
EXO_TEST(tokenizer_basic_compare_6, { return compare("a	b c  ", "a b c"); });

EXO_TEST(tokenizer_comment_1, { return compare("value1 value2 # value3", "value1 value2"); });
EXO_TEST(tokenizer_comment_2, { return compare("value1 value2\\# value3", "value1 value2# value3"); });
EXO_TEST(tokenizer_comment_3, { return compare("value1 \"value2#\" value3", "value1 value2# value3"); });

EXO_TEST(tokenizer_escape_1, { return compare("\"value1\" value2", "value1 value2"); });
EXO_TEST(tokenizer_escape_2, { return compare("\"value1\\\"\" value2", "value1\" value2"); });
EXO_TEST(tokenizer_escape_3, { return compare("\"value1\" \"value 2\"", "value1 value_2"); });
EXO_TEST(tokenizer_escape_4, { return compare("\"value1\" value\\ 2", "value1 value_2"); });
EXO_TEST(tokenizer_escape_5, { return compare("\"value1\" value\\\\2", "value1 value\\2"); });
EXO_TEST(tokenizer_escape_6, { return compare("\"value1\" value\\\t2", "value1 value|2"); });
EXO_TEST(tokenizer_escape_7, { return compare("\"value1\" \"value\t2\"", "value1 value|2"); });



