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

EXO_TEST(fuse_chatlog_create, {
	log = fs_chatlog_create(32);
	return log != NULL && fs_chatlog_size(log) == 0;
});

EXO_TEST(fuse_chatlog_read_empty, { return fs_chatlog_read(log, 0, buf, sizeof(buf)) == 0; });

EXO_TEST(fuse_chatlog_append, {
	fs_chatlog_append(log, "hello", 5);
	return fs_chatlog_size(log) == 5 && strcmp(read_at(0, 16), "hello") == 0;
});

EXO_TEST(fuse_chatlog_read_partial, { return strcmp(read_at(0, 2), "he") == 0; });
EXO_TEST(fuse_chatlog_read_at_offset, { return strcmp(read_at(2, 16), "llo") == 0; });

/* At the end is end of file, which is what a poller sees between messages. */
EXO_TEST(fuse_chatlog_read_at_end, { return fs_chatlog_read(log, 5, buf, sizeof(buf)) == 0; });
EXO_TEST(fuse_chatlog_read_past_end, { return fs_chatlog_read(log, 99, buf, sizeof(buf)) == 0; });

EXO_TEST(fuse_chatlog_append_more, {
	fs_chatlog_append(log, "!", 1);
	return fs_chatlog_size(log) == 6 && strcmp(read_at(0, 16), "hello!") == 0;
});

EXO_TEST(fuse_chatlog_line_adds_newline, {
	fs_chatlog_append_line(log, "one");
	return strcmp(read_at(6, 16), "one\n") == 0;
});

/* One message is one line, whatever the message contains. */
EXO_TEST(fuse_chatlog_line_flattens_newlines, {
	fs_chatlog_clear(log);
	fs_chatlog_append_line(log, "a\nb\r\nc");
	return strcmp(read_at(fs_chatlog_size(log) - 7, 16), "a b  c\n") == 0;
});

EXO_TEST(fuse_chatlog_line_empty, {
	uint64_t before = fs_chatlog_size(log);
	fs_chatlog_append_line(log, "");
	return fs_chatlog_size(log) == before + 1;
});

/* ------------------------------------------------------------- the window */

EXO_TEST(fuse_chatlog_wraps, {
	fs_chatlog_destroy(log);
	log = fs_chatlog_create(8);
	fs_chatlog_append(log, "abcdefgh", 8);
	fs_chatlog_append(log, "ij", 2);
	/* Ten bytes through an eight byte window: the first two are gone. */
	return fs_chatlog_size(log) == 10 && strcmp(read_at(2, 16), "cdefghij") == 0;
});

EXO_TEST(fuse_chatlog_offsets_keep_going, {
	return log->base == 2 && log->end == 10;
});

/* A reader that fell behind gets the oldest bytes still held, not an error. */
EXO_TEST(fuse_chatlog_behind_the_window, {
	return strcmp(read_at(0, 16), "cdefghij") == 0;
});

EXO_TEST(fuse_chatlog_append_larger_than_capacity, {
	/* Thirteen bytes into an eight byte window keeps the last eight of them,
	   at offsets 15..23. */
	fs_chatlog_append(log, "0123456789ABC", 13);
	return fs_chatlog_size(log) == 23 && strcmp(read_at(15, 16), "56789ABC") == 0;
});

EXO_TEST(fuse_chatlog_read_spanning_the_wrap, {
	fs_chatlog_destroy(log);
	log = fs_chatlog_create(8);
	fs_chatlog_append(log, "abcde", 5);
	fs_chatlog_append(log, "fghij", 5);
	/* Held is "cdefghij", and the ring's own start is in the middle of it. */
	return strcmp(read_at(2, 16), "cdefghij") == 0;
});

EXO_TEST(fuse_chatlog_clear_keeps_offsets, {
	uint64_t before = fs_chatlog_size(log);
	fs_chatlog_clear(log);
	return fs_chatlog_size(log) == before
		&& fs_chatlog_read(log, 0, buf, sizeof(buf)) == 0
		&& log->base == before;
});

EXO_TEST(fuse_chatlog_append_after_clear, {
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
	uint64_t before = fs_chatlog_size(log);
	fs_chatlog_append(log, "x", 0);
	return fs_chatlog_size(log) == before;
});

EXO_TEST(fuse_chatlog_destroy_test, {
	fs_chatlog_destroy(log);
	log = NULL;
	return 1;
});
