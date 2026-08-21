#include "system.h"
#include "util/memory.h"
#include "fuse/filelist.h"

#include <bzlib.h>

/*
 * The file list parser. Every byte it sees came from a peer over a connection
 * anybody can open, and the names in it become path components in a mounted
 * filesystem, so the tests below are mostly about what it refuses.
 */

static struct fs_filelist* list = NULL;

static struct fs_filelist* parse(const char* xml)
{
	fs_filelist_destroy(list);
	list = fs_filelist_parse(xml, strlen(xml));
	return list;
}

static const char* SIMPLE =
	"<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n"
	"<FileListing Version=\"1\" CID=\"AAAA\" Base=\"/\" Generator=\"DC++ 0.868\">\n"
	"<Directory Name=\"Music\">\n"
	"  <File Name=\"song.flac\" Size=\"41234567\" TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/>\n"
	"  <Directory Name=\"Live\">\n"
	"    <File Name=\"set.mp3\" Size=\"12\" TTH=\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\"/>\n"
	"  </Directory>\n"
	"</Directory>\n"
	"<File Name=\"readme.txt\" Size=\"7\" TTH=\"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\"/>\n"
	"</FileListing>\n";

EXO_TEST(fuse_filelist_parse_simple, { return parse(SIMPLE) != NULL; });

EXO_TEST(fuse_filelist_counts_every_entry, {
	/* Music, song.flac, Live, set.mp3, readme.txt */
	return fs_filelist_count(list) == 5;
});

EXO_TEST(fuse_filelist_root_in_document_order, {
	struct fs_filelist_node* root = fs_filelist_root(list);
	return root && strcmp(root->name, "Music") == 0 && root->is_dir
		&& root->next && strcmp(root->next->name, "readme.txt") == 0 && !root->next->is_dir
		&& !root->next->next;
});

EXO_TEST(fuse_filelist_lookup_file, {
	struct fs_filelist_node* node = fs_filelist_lookup(list, "Music/song.flac");
	return node && !node->is_dir && node->size == 41234567
		&& strcmp(node->tth, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == 0;
});

EXO_TEST(fuse_filelist_lookup_nested, {
	struct fs_filelist_node* node = fs_filelist_lookup(list, "Music/Live/set.mp3");
	return node && node->size == 12;
});

EXO_TEST(fuse_filelist_lookup_directory, {
	struct fs_filelist_node* node = fs_filelist_lookup(list, "Music/Live");
	return node && node->is_dir && node->children
		&& strcmp(node->children->name, "set.mp3") == 0;
});

EXO_TEST(fuse_filelist_lookup_missing, { return fs_filelist_lookup(list, "Nope") == NULL; });
EXO_TEST(fuse_filelist_lookup_missing_nested, { return fs_filelist_lookup(list, "Music/nope") == NULL; });
EXO_TEST(fuse_filelist_lookup_below_a_file, {
	return fs_filelist_lookup(list, "readme.txt/deeper") == NULL;
});
EXO_TEST(fuse_filelist_lookup_empty, { return fs_filelist_lookup(list, "") == NULL; });
EXO_TEST(fuse_filelist_lookup_empty_component, { return fs_filelist_lookup(list, "Music//song.flac") == NULL; });
EXO_TEST(fuse_filelist_lookup_null, { return fs_filelist_lookup(NULL, "x") == NULL; });

EXO_TEST(fuse_filelist_trailing_slash_is_the_directory, {
	struct fs_filelist_node* node = fs_filelist_lookup(list, "Music/");
	return node && node->is_dir;
});

/* --- what is skipped rather than kept ------------------------------------ */

/* A file with no hash cannot be fetched, so listing it would only offer
   something that can never be read. */
EXO_TEST(fuse_filelist_file_without_tth_is_skipped, {
	parse("<FileListing><File Name=\"a.txt\" Size=\"1\"/></FileListing>");
	return fs_filelist_count(list) == 0;
});

EXO_TEST(fuse_filelist_file_with_short_tth_is_skipped, {
	parse("<FileListing><File Name=\"a\" TTH=\"AAA\"/></FileListing>");
	return fs_filelist_count(list) == 0;
});

EXO_TEST(fuse_filelist_file_with_non_base32_tth_is_skipped, {
	parse("<FileListing><File Name=\"a\" TTH=\"1111111111111111111111111111111111111112\"/></FileListing>");
	return fs_filelist_count(list) == 0;
});

EXO_TEST(fuse_filelist_file_without_name_is_skipped, {
	parse("<FileListing><File Size=\"1\" TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></FileListing>");
	return fs_filelist_count(list) == 0;
});

/* One unusable entry is no reason to lose the rest of the list. */
EXO_TEST(fuse_filelist_keeps_going_after_a_bad_entry, {
	parse("<FileListing>"
	      "<File Name=\"bad\"/>"
	      "<File Name=\"good\" Size=\"3\" TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/>"
	      "</FileListing>");
	return fs_filelist_count(list) == 1 && fs_filelist_lookup(list, "good") != NULL;
});

EXO_TEST(fuse_filelist_unknown_elements_are_stepped_over, {
	parse("<FileListing><Whatever attr=\"1\"><File Name=\"a\" Size=\"1\" "
	      "TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></Whatever></FileListing>");
	return fs_filelist_lookup(list, "a") != NULL;
});

EXO_TEST(fuse_filelist_comments_are_stepped_over, {
	parse("<FileListing><!-- <File Name=\"ghost\" TTH=\"x\"/> -->"
	      "<File Name=\"real\" Size=\"1\" TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></FileListing>");
	return fs_filelist_count(list) == 1 && fs_filelist_lookup(list, "real") != NULL;
});

/* A DOCTYPE is where an XML parser starts reading things nobody gave it. */
EXO_TEST(fuse_filelist_doctype_is_stepped_over, {
	parse("<!DOCTYPE FileListing [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
	      "<FileListing><File Name=\"a\" Size=\"1\" "
	      "TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></FileListing>");
	return fs_filelist_count(list) == 1;
});

EXO_TEST(fuse_filelist_entity_is_not_expanded, {
	/* &x; is not one of the five, and there is no table to look it up in. */
	parse("<FileListing><File Name=\"&x;\" Size=\"1\" "
	      "TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></FileListing>");
	return fs_filelist_lookup(list, "&x;") != NULL;
});

/* --- names ---------------------------------------------------------------- */

EXO_TEST(fuse_filelist_named_entities, {
	parse("<FileListing><File Name=\"a&amp;b&lt;c&gt;d&quot;e&apos;f\" Size=\"1\" "
	      "TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></FileListing>");
	return fs_filelist_lookup(list, "a&b<c>d\"e'f") != NULL;
});

EXO_TEST(fuse_filelist_numeric_entity, {
	parse("<FileListing><File Name=\"a&#65;b\" Size=\"1\" "
	      "TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></FileListing>");
	return fs_filelist_lookup(list, "aAb") != NULL;
});

EXO_TEST(fuse_filelist_numeric_entity_utf8, {
	/* &#229; is 'å', which is two bytes in UTF-8. */
	parse("<FileListing><File Name=\"&#229;\" Size=\"1\" "
	      "TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></FileListing>");
	return fs_filelist_lookup(list, "\xc3\xa5") != NULL;
});

/* A name that decodes to a slash would be two path components, and one that
   decodes to ".." would be the directory above. Neither is allowed to happen. */
EXO_TEST(fuse_filelist_encoded_slash_is_neutralised, {
	parse("<FileListing><File Name=\"a&#47;b\" Size=\"1\" "
	      "TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></FileListing>");
	return fs_filelist_lookup(list, "a_b") != NULL && fs_filelist_lookup(list, "a/b") == NULL;
});

EXO_TEST(fuse_filelist_literal_slash_is_neutralised, {
	parse("<FileListing><File Name=\"../../etc/passwd\" Size=\"1\" "
	      "TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></FileListing>");
	return fs_filelist_lookup(list, ".._.._etc_passwd") != NULL;
});

EXO_TEST(fuse_filelist_dotdot_name_is_refused, {
	parse("<FileListing><File Name=\"..\" Size=\"1\" "
	      "TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></FileListing>");
	return fs_filelist_count(list) == 0;
});

EXO_TEST(fuse_filelist_dot_name_is_refused, {
	parse("<FileListing><File Name=\".\" Size=\"1\" "
	      "TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></FileListing>");
	return fs_filelist_count(list) == 0;
});

EXO_TEST(fuse_filelist_empty_name_is_refused, {
	parse("<FileListing><File Name=\"\" Size=\"1\" "
	      "TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></FileListing>");
	return fs_filelist_count(list) == 0;
});

EXO_TEST(fuse_filelist_control_characters_are_neutralised, {
	parse("<FileListing><File Name=\"a&#10;b\" Size=\"1\" "
	      "TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/></FileListing>");
	return fs_filelist_lookup(list, "a_b") != NULL;
});

EXO_TEST(fuse_filelist_safe_name_direct, {
	char buf[64];
	return fs_filelist_safe_name("ok", buf, sizeof(buf)) && strcmp(buf, "ok") == 0
		&& !fs_filelist_safe_name("", buf, sizeof(buf))
		&& !fs_filelist_safe_name("..", buf, sizeof(buf))
		&& !fs_filelist_safe_name(NULL, buf, sizeof(buf));
});

EXO_TEST(fuse_filelist_safe_name_refuses_rather_than_truncates, {
	char buf[4];
	/* Truncating would make two different names into one. */
	return !fs_filelist_safe_name("abcdef", buf, sizeof(buf));
});

/* --- shapes that should not bring it down --------------------------------- */

EXO_TEST(fuse_filelist_empty_document, { return parse("") == NULL; });
EXO_TEST(fuse_filelist_null_document, { return fs_filelist_parse(NULL, 10) == NULL; });
EXO_TEST(fuse_filelist_not_xml, { return parse("hello") != NULL && fs_filelist_count(list) == 0; });
EXO_TEST(fuse_filelist_truncated_tag, { return parse("<FileListing><File Name=\"a") != NULL; });
EXO_TEST(fuse_filelist_unclosed_quote, {
	return parse("<FileListing><File Name=\"abc/></FileListing>") != NULL;
});
EXO_TEST(fuse_filelist_lone_bracket, { return parse("<") != NULL; });
EXO_TEST(fuse_filelist_unbalanced_close, {
	return parse("</Directory></Directory></Directory>") != NULL;
});

EXO_TEST(fuse_filelist_self_closing_directory, {
	parse("<FileListing><Directory Name=\"empty\"/>"
	      "<File Name=\"a\" Size=\"1\" TTH=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/>"
	      "</FileListing>");
	/* The empty directory must not swallow what follows it. */
	return fs_filelist_lookup(list, "empty") != NULL
		&& fs_filelist_lookup(list, "a") != NULL
		&& fs_filelist_lookup(list, "empty/a") == NULL;
});

EXO_TEST(fuse_filelist_deep_nesting_is_refused, {
	/* Deeper than FS_FILELIST_MAX_DEPTH: refused outright rather than
	   truncated, and above all not recursed into. */
	char* xml = hub_malloc(64 * 1024);
	size_t n = 0;
	int i;
	int refused;

	n += sprintf(&xml[n], "<FileListing>");
	for (i = 0; i < FS_FILELIST_MAX_DEPTH + 10; i++)
		n += sprintf(&xml[n], "<Directory Name=\"d%d\">", i);
	for (i = 0; i < FS_FILELIST_MAX_DEPTH + 10; i++)
		n += sprintf(&xml[n], "</Directory>");
	n += sprintf(&xml[n], "</FileListing>");

	refused = (fs_filelist_parse(xml, n) == NULL);
	hub_free(xml);
	return refused;
});

EXO_TEST(fuse_filelist_deep_but_allowed, {
	char* xml = hub_malloc(64 * 1024);
	size_t n = 0;
	int i;
	struct fs_filelist* deep;

	n += sprintf(&xml[n], "<FileListing>");
	for (i = 0; i < 32; i++)
		n += sprintf(&xml[n], "<Directory Name=\"d%d\">", i);
	for (i = 0; i < 32; i++)
		n += sprintf(&xml[n], "</Directory>");
	n += sprintf(&xml[n], "</FileListing>");

	deep = fs_filelist_parse(xml, n);
	hub_free(xml);
	if (!deep)
		return 0;

	i = (fs_filelist_lookup(deep, "d0/d1/d2") != NULL);
	fs_filelist_destroy(deep);
	return i;
});

/* --- decompression -------------------------------------------------------- */

EXO_TEST(fuse_filelist_decompress_garbage, {
	size_t len = 0;
	return fs_filelist_decompress("not a bzip2 stream", 18, &len) == NULL;
});

EXO_TEST(fuse_filelist_decompress_empty, {
	size_t len = 0;
	return fs_filelist_decompress("", 0, &len) == NULL
		&& fs_filelist_decompress(NULL, 10, &len) == NULL;
});

EXO_TEST(fuse_filelist_load_garbage, {
	return fs_filelist_load("not a bzip2 stream", 18) == NULL;
});

/* The real path: a list as it actually arrives, compressed. */
EXO_TEST(fuse_filelist_load_round_trip, {
	unsigned int packed_len = 64 * 1024;
	char* packed = hub_malloc(packed_len);
	struct fs_filelist* loaded;
	int ok;

	if (BZ2_bzBuffToBuffCompress(packed, &packed_len, (char*) SIMPLE,
	                             (unsigned int) strlen(SIMPLE), 9, 0, 30) != BZ_OK)
	{
		hub_free(packed);
		return 0;
	}

	loaded = fs_filelist_load(packed, packed_len);
	hub_free(packed);

	if (!loaded)
		return 0;

	ok = (fs_filelist_count(loaded) == 5)
		&& (fs_filelist_lookup(loaded, "Music/Live/set.mp3") != NULL);

	fs_filelist_destroy(loaded);
	return ok;
});

EXO_TEST(fuse_filelist_load_truncated_stream, {
	unsigned int packed_len = 64 * 1024;
	char* packed = hub_malloc(packed_len);
	int refused;

	if (BZ2_bzBuffToBuffCompress(packed, &packed_len, (char*) SIMPLE,
	                             (unsigned int) strlen(SIMPLE), 9, 0, 30) != BZ_OK)
	{
		hub_free(packed);
		return 0;
	}

	/* Half a stream is not a list, and must not become a partial one. */
	refused = (fs_filelist_load(packed, packed_len / 2) == NULL);
	hub_free(packed);
	return refused;
});

EXO_TEST(fuse_filelist_teardown, {
	fs_filelist_destroy(list);
	list = NULL;
	fs_filelist_destroy(NULL);
	return 1;
});
