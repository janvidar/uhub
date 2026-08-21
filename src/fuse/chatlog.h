/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#ifndef HAVE_UHUB_FUSE_CHATLOG_H
#define HAVE_UHUB_FUSE_CHATLOG_H

#include "system.h"

/**
 * The chat, as a file that grows.
 *
 * Unlike every other file in the mount, chat/main is not a value that is
 * rendered when it is opened: it is a stream, and the whole point of it is
 * that `tail -f` follows it. So it is addressed the way a file being appended
 * to is addressed -- by an offset that only ever increases, with the size
 * reported by stat() being the total number of bytes the log has ever held.
 *
 * What is *kept* is a window of the most recent bytes; a mount that ran for a
 * month would otherwise be a month of chat in memory. A reader that asks for
 * an offset that has been evicted is given the oldest bytes still held rather
 * than an error: a reader that fell that far behind has already lost the gap,
 * and failing its read would only lose the rest as well.
 */

/** Bytes of history kept. Older ones are dropped as new ones arrive. */
#define FS_CHATLOG_SIZE (256 * 1024)

struct fs_chatlog
{
	char* data;        /** Ring of @c capacity bytes. */
	size_t capacity;
	size_t used;       /** Bytes held, <= capacity. */
	size_t head;       /** Index in @c data of the oldest byte held. */
	uint64_t base;     /** Absolute offset of that oldest byte. */
	uint64_t end;      /** Absolute offset just past the newest byte. */
};

/** @return NULL on OOM. @p capacity of 0 selects FS_CHATLOG_SIZE. */
extern struct fs_chatlog* fs_chatlog_create(size_t capacity);

extern void fs_chatlog_destroy(struct fs_chatlog* log);

/**
 * Append @p len bytes.
 *
 * More than the whole capacity at once keeps the tail of it, which is the part
 * a reader would have ended up with anyway.
 */
extern void fs_chatlog_append(struct fs_chatlog* log, const char* data, size_t len);

/**
 * Append a line, adding the terminating newline.
 *
 * Any newline inside @p line is replaced by a space: one message is one line,
 * so that the file can be read a line at a time by anything that reads lines.
 * A hub cannot send an unescaped newline in a chat message anyway -- the ADC
 * grammar has no way to spell one -- but the mount does not depend on that.
 */
extern void fs_chatlog_append_line(struct fs_chatlog* log, const char* line);

/**
 * Copy out at most @p len bytes from absolute offset @p offset.
 *
 * @return the number of bytes copied. 0 means the offset is at or past the end
 *         of the log, which is the end of file a reader polls for.
 */
extern size_t fs_chatlog_read(const struct fs_chatlog* log, uint64_t offset, char* buf, size_t len);

/** The total number of bytes ever appended: what stat() reports as the size. */
extern uint64_t fs_chatlog_size(const struct fs_chatlog* log);

/** Drop everything held. The absolute offsets keep going up. */
extern void fs_chatlog_clear(struct fs_chatlog* log);

#endif /* HAVE_UHUB_FUSE_CHATLOG_H */
