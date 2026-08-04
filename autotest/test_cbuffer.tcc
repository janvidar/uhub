#include "system.h"
#include "util/cbuffer.h"

/*
 * Unit tests for the growable char buffer (util/cbuffer.c) used to assemble
 * outgoing messages, status text, the metrics document, etc. Exercises the
 * append variants and, in particular, the grow-on-overflow path (cbuf_resize)
 * and the vsnprintf-length handling in cbuf_append_format that the audit
 * flagged as security-relevant.
 */

EXO_TEST(cbuf_basic, {
	struct cbuffer* b = cbuf_create(16);
	int ok;
	if (!b) return 0;
	cbuf_append(b, "hello");
	ok = cbuf_size(b) == 5 && !strcmp(cbuf_get(b), "hello");
	cbuf_destroy(b);
	return ok;
});

EXO_TEST(cbuf_empty, {
	struct cbuffer* b = cbuf_create(16);
	int ok;
	if (!b) return 0;
	ok = cbuf_size(b) == 0 && !strcmp(cbuf_get(b), "");
	cbuf_destroy(b);
	return ok;
});

/* Appending past the initial capacity must grow the buffer (cbuf_resize). */
EXO_TEST(cbuf_append_grows, {
	struct cbuffer* b = cbuf_create(4);
	int ok;
	if (!b) return 0;
	cbuf_append(b, "hello world");   /* 11 bytes into a 4-byte buffer */
	ok = cbuf_size(b) == 11 && !strcmp(cbuf_get(b), "hello world");
	cbuf_destroy(b);
	return ok;
});

EXO_TEST(cbuf_multiple_appends, {
	struct cbuffer* b = cbuf_create(8);
	int ok;
	if (!b) return 0;
	cbuf_append(b, "aa");
	cbuf_append(b, "bb");
	cbuf_append(b, "cc");
	ok = cbuf_size(b) == 6 && !strcmp(cbuf_get(b), "aabbcc");
	cbuf_destroy(b);
	return ok;
});

/* Explicit length, including bytes past an embedded NUL. */
EXO_TEST(cbuf_append_bytes_with_nul, {
	struct cbuffer* b = cbuf_create(16);
	int ok;
	if (!b) return 0;
	cbuf_append_bytes(b, "abc\0def", 7);
	ok = cbuf_size(b) == 7 && memcmp(cbuf_get(b), "abc\0def", 7) == 0;
	cbuf_destroy(b);
	return ok;
});

EXO_TEST(cbuf_append_format, {
	struct cbuffer* b = cbuf_create(16);
	int ok;
	if (!b) return 0;
	cbuf_append_format(b, "n=%d s=%s", 42, "x");
	ok = cbuf_size(b) == 8 && !strcmp(cbuf_get(b), "n=42 s=x");
	cbuf_destroy(b);
	return ok;
});

/* A formatted result longer than the buffer must grow correctly (exercises the
   would-have-written length handling in cbuf_append_format). */
EXO_TEST(cbuf_append_format_long, {
	struct cbuffer* b = cbuf_create(4);
	int ok;
	if (!b) return 0;
	cbuf_append_format(b, "%0100d", 7);   /* 100 characters into a 4-byte buffer */
	ok = cbuf_size(b) == 100 && cbuf_get(b)[99] == '7' && cbuf_get(b)[0] == '0';
	cbuf_destroy(b);
	return ok;
});

/* cbuf_resize can be called explicitly to reserve capacity. */
EXO_TEST(cbuf_resize_explicit, {
	struct cbuffer* b = cbuf_create(4);
	int ok;
	if (!b) return 0;
	cbuf_resize(b, 128);
	cbuf_append(b, "still works after resize");
	ok = cbuf_size(b) == 24 && !strcmp(cbuf_get(b), "still works after resize");
	cbuf_destroy(b);
	return ok;
});

/* A const buffer wraps an existing string without copying; size is its length. */
EXO_TEST(cbuf_const, {
	struct cbuffer* b = cbuf_create_const("constant");
	int ok;
	if (!b) return 0;
	ok = cbuf_size(b) == 8 && !strcmp(cbuf_get(b), "constant");
	cbuf_destroy(b);
	return ok;
});

/*
 * RTF0 markdown escaping (used to build the rich text variant of !help, !whoip,
 * the topic, ... from text the hub does not control).
 */

static int cbuf_md_is(const char* in, const char* expected)
{
	struct cbuffer* b = cbuf_create(16);
	int ok;
	if (!b) return 0;
	cbuf_append_markdown(b, in);
	ok = !strcmp(cbuf_get(b), expected);
	cbuf_destroy(b);
	return ok;
}

static int cbuf_md_code_is(const char* in, const char* expected)
{
	struct cbuffer* b = cbuf_create(16);
	int ok;
	if (!b) return 0;
	cbuf_append_markdown_code(b, in);
	ok = !strcmp(cbuf_get(b), expected);
	cbuf_destroy(b);
	return ok;
}

EXO_TEST(cbuf_markdown_plain, { return cbuf_md_is("nothing to escape", "nothing to escape"); });
EXO_TEST(cbuf_markdown_empty, { return cbuf_md_is("", ""); });

/* Every inline markup character is neutralised... */
EXO_TEST(cbuf_markdown_emphasis, { return cbuf_md_is("*bold* _em_", "\\*bold\\* \\_em\\_"); });
EXO_TEST(cbuf_markdown_code_span, { return cbuf_md_is("a `b` c", "a \\`b\\` c"); });
EXO_TEST(cbuf_markdown_link, { return cbuf_md_is("[x](y)", "\\[x\\](y)"); });
EXO_TEST(cbuf_markdown_autolink, { return cbuf_md_is("<http://x>", "\\<http://x\\>"); });
EXO_TEST(cbuf_markdown_strike, { return cbuf_md_is("~~gone~~", "\\~\\~gone\\~\\~"); });

/* ... including the backslash itself, so an escape cannot be forged. */
EXO_TEST(cbuf_markdown_backslash, { return cbuf_md_is("a\\*b", "a\\\\\\*b"); });

/* A '|' would otherwise split a table cell. */
EXO_TEST(cbuf_markdown_pipe, { return cbuf_md_is("a|b", "a\\|b"); });

/* Block level markers are inline-safe inside a table cell and stay literal --
 * except '>', which is escaped anyway as the closing half of an autolink. */
EXO_TEST(cbuf_markdown_block_markers, { return cbuf_md_is("# - > 1.", "# - \\> 1."); });

/* An image embed cannot be smuggled in by a user-supplied string. */
EXO_TEST(cbuf_markdown_image, {
	return cbuf_md_is("![x](magnet:?xt=y)", "!\\[x\\](magnet:?xt=y)");
});

EXO_TEST(cbuf_markdown_code_wraps, { return cbuf_md_code_is("1.2.3.4", "`1.2.3.4`"); });
EXO_TEST(cbuf_markdown_code_empty, { return cbuf_md_code_is("", "``"); });

/* Markup inside a code span is literal, so only the cell separator is escaped. */
EXO_TEST(cbuf_markdown_code_literal, { return cbuf_md_code_is("*a* _b_", "`*a* _b_`"); });
EXO_TEST(cbuf_markdown_code_pipe, { return cbuf_md_code_is("a|b", "`a\\|b`"); });
