#include "system.h"
#include "util/memory.h"
#include "fuse/chatlog.h"

static struct fs_chatlog* log = NULL;
static char buf[512];

/* Read at an absolute offset and NUL terminate, for comparison. */
static const char* read_at(uint64_t offset, size_t len)
{
	size_t got;

	if (len >= sizeof(buf))
		len = sizeof(buf) - 1;

	got = fs_chatlog_read(log, offset, buf, len);
	buf[got] = '\0';
	return buf;
}

/* Each test starts from one of these, so none depends on another. */
static int cl_new(size_t capacity)
{
	fs_chatlog_destroy(log);
	log = fs_chatlog_create(capacity);
	return log != NULL;
}

/* "hello" in a 32 byte log. */
static int cl_hello(void)
{
	if (!cl_new(32))
		return 0;
	fs_chatlog_append(log, "hello", 5);
	return 1;
}

/* Ten bytes through an eight byte window: the first two are gone. */
static int cl_wrapped(void)
{
	if (!cl_new(8))
		return 0;
	fs_chatlog_append(log, "abcdefgh", 8);
	fs_chatlog_append(log, "ij", 2);
	return 1;
}

/* The same ten bytes in two halves, so the ring's own start is mid-content. */
static int cl_spanning(void)
{
	if (!cl_new(8))
		return 0;
	fs_chatlog_append(log, "abcde", 5);
	fs_chatlog_append(log, "fghij", 5);
	return 1;
}

EXO_TEARDOWN({
	fs_chatlog_destroy(log);
	log = NULL;
	return 1;
});

EXO_TEST(fuse_chatlog_create, {
	return cl_new(32) && fs_chatlog_size(log) == 0;
});

EXO_TEST(fuse_chatlog_read_empty, { return cl_new(32) && fs_chatlog_read(log, 0, buf, sizeof(buf)) == 0; });

EXO_TEST(fuse_chatlog_append, {
	if (!cl_new(32))
		return 0;
	fs_chatlog_append(log, "hello", 5);
	return fs_chatlog_size(log) == 5 && strcmp(read_at(0, 16), "hello") == 0;
});

EXO_TEST(fuse_chatlog_read_partial, { return cl_hello() && strcmp(read_at(0, 2), "he") == 0; });
EXO_TEST(fuse_chatlog_read_at_offset, { return cl_hello() && strcmp(read_at(2, 16), "llo") == 0; });

/* At the end is end of file, which is what a poller sees between messages. */
EXO_TEST(fuse_chatlog_read_at_end, { return cl_hello() && fs_chatlog_read(log, 5, buf, sizeof(buf)) == 0; });
EXO_TEST(fuse_chatlog_read_past_end, { return cl_hello() && fs_chatlog_read(log, 99, buf, sizeof(buf)) == 0; });

EXO_TEST(fuse_chatlog_append_more, {
	if (!cl_hello())
		return 0;
	fs_chatlog_append(log, "!", 1);
	return fs_chatlog_size(log) == 6 && strcmp(read_at(0, 16), "hello!") == 0;
});

EXO_TEST(fuse_chatlog_line_adds_newline, {
	if (!cl_hello())
		return 0;
	fs_chatlog_append(log, "!", 1);
	fs_chatlog_append_line(log, "one");
	return strcmp(read_at(6, 16), "one\n") == 0;
});

/* One message is one line, whatever the message contains. */
EXO_TEST(fuse_chatlog_line_flattens_newlines, {
	if (!cl_new(32))
		return 0;
	fs_chatlog_clear(log);
	fs_chatlog_append_line(log, "a\nb\r\nc");
	return strcmp(read_at(fs_chatlog_size(log) - 7, 16), "a b  c\n") == 0;
});

EXO_TEST(fuse_chatlog_line_empty, {
	uint64_t before;
	if (!cl_new(32))
		return 0;
	before = fs_chatlog_size(log);
	fs_chatlog_append_line(log, "");
	return fs_chatlog_size(log) == before + 1;
});

/* ------------------------------------------------------------- the window */

EXO_TEST(fuse_chatlog_wraps, {
	/* Ten bytes through an eight byte window: the first two are gone. */
	return cl_wrapped() && fs_chatlog_size(log) == 10 && strcmp(read_at(2, 16), "cdefghij") == 0;
});

EXO_TEST(fuse_chatlog_offsets_keep_going, { return cl_wrapped() && log->base == 2 && log->end == 10; });

/* A reader that fell behind gets the oldest bytes still held, not an error. */
EXO_TEST(fuse_chatlog_behind_the_window, { return cl_wrapped() && strcmp(read_at(0, 16), "cdefghij") == 0; });

EXO_TEST(fuse_chatlog_append_larger_than_capacity, {
	/* Thirteen bytes into an eight byte window keeps the last eight of them,
	   at offsets 15..23. */
	if (!cl_wrapped())
		return 0;
	fs_chatlog_append(log, "0123456789ABC", 13);
	return fs_chatlog_size(log) == 23 && strcmp(read_at(15, 16), "56789ABC") == 0;
});

EXO_TEST(fuse_chatlog_read_spanning_the_wrap, {
	/* Held is "cdefghij", and the ring's own start is in the middle of it. */
	return cl_spanning() && strcmp(read_at(2, 16), "cdefghij") == 0;
});

EXO_TEST(fuse_chatlog_clear_keeps_offsets, {
	uint64_t before;
	if (!cl_spanning())
		return 0;
	before = fs_chatlog_size(log);
	fs_chatlog_clear(log);
	return fs_chatlog_size(log) == before
		&& fs_chatlog_read(log, 0, buf, sizeof(buf)) == 0
		&& log->base == before;
});

EXO_TEST(fuse_chatlog_append_after_clear, {
	if (!cl_spanning())
		return 0;
	fs_chatlog_clear(log);
	fs_chatlog_append(log, "new", 3);
	return strcmp(read_at(fs_chatlog_size(log) - 3, 8), "new") == 0;
});

EXO_TEST(fuse_chatlog_null_safe, {
	fs_chatlog_append(NULL, "x", 1);
	fs_chatlog_append_line(NULL, "x");
	fs_chatlog_clear(NULL);
	fs_chatlog_destroy(NULL);
	return fs_chatlog_read(NULL, 0, buf, sizeof(buf)) == 0 && fs_chatlog_size(NULL) == 0;
});

EXO_TEST(fuse_chatlog_append_zero_length, {
	uint64_t before;
	if (!cl_new(32))
		return 0;
	before = fs_chatlog_size(log);
	fs_chatlog_append(log, "x", 0);
	return fs_chatlog_size(log) == before;
});

EXO_TEST(fuse_chatlog_destroy_test, {
	fs_chatlog_destroy(fs_chatlog_create(8));
	return 1;
});
