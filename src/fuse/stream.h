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

#ifndef HAVE_UHUB_FUSE_STREAM_H
#define HAVE_UHUB_FUSE_STREAM_H

#include "system.h"
#include "adc/adctypes.h"

struct fs_stream;
struct fs_task;
struct fs_transfer;

/**
 * Reading a file too big to be worth fetching whole.
 *
 * Below the cache's per-file ceiling a file is downloaded in one piece,
 * verified against its TTH and kept -- which is what makes by-tth trustworthy.
 * Above it that is the wrong trade entirely: waiting for a whole film to arrive
 * before the first byte can be read is not a filesystem, and a mount is not a
 * place to store one.
 *
 * So a large file is read through a window instead: the range the reader asked
 * for is requested from the peer, plus some of what it is likely to ask for
 * next, and nothing is written to disk.
 *
 * WHAT THIS GIVES UP, AND WHY IT HAS TO
 *
 * A range cannot be verified. A TTH covers a whole file, and the leaf hashes
 * that would let a part of one be checked (CGET tthl) are not implemented on
 * either side of this codebase. So bytes read this way are what a peer chose to
 * send, and the mount cannot tell you they are what you asked for -- unlike the
 * whole-file path, where content that does not hash to its name is thrown away
 * before any reader sees it.
 *
 * That is why the boundary is the cache's file size ceiling and not, say, a
 * convenience: everything that *can* be verified still is, and streaming
 * applies only where verification was never available. Raising max_file_size
 * moves more content onto the verified path at the cost of holding it.
 */

/** Bytes requested beyond what a reader asked for, in anticipation. */
#define FS_STREAM_READAHEAD (1024 * 1024)

/** The most that is held in memory for one open file. */
#define FS_STREAM_WINDOW (4 * 1024 * 1024)

/**
 * Begin reading @p tth from @p cid.
 *
 * @param size the file's size, as its owner's file list stated it.
 * @return the stream, or NULL.
 */
extern struct fs_stream* fs_stream_open(struct fs_transfer* transfer, const char* tth,
                                        const char* cid, uint64_t size);

/**
 * Read from the stream, fetching what is not already in the window.
 *
 * The byte count comes back through @p out_got rather than the return value,
 * because a count of zero (end of file) and a wake-up meaning "the window
 * moved, ask again" are both zero, and a reader that confused the two would
 * either spin or stop early.
 *
 * @param task    the caller's task, parked while a request is outstanding.
 * @param out_got receives the number of bytes copied, when 0 is returned.
 * @return 0 when @p out_got is set and the read is finished, FS_TASK_PARKED
 *         when a fetch had to be started, or a negative errno. A parked task
 *         completing with 0 means the caller should read again.
 */
extern int fs_stream_read(struct fs_stream* stream, uint64_t offset, void* buf, size_t len,
                          struct fs_task* task, int* out_got);

/**
 * Take a task off the stream, for a reader that has given up.
 * @see fs_transfer_abandon().
 */
extern void fs_stream_abandon(struct fs_stream* stream, struct fs_task* task);

extern void fs_stream_close(struct fs_stream* stream);

/* --- called by the transfer layer --------------------------------------- */

/** Body bytes for an outstanding request. @return 0 to abandon the transfer. */
extern int fs_stream_on_body(struct fs_stream* stream, uint64_t offset,
                             const void* data, size_t len);

/** The outstanding request ended. */
extern void fs_stream_on_done(struct fs_stream* stream, int ok);

/** The token this stream's outstanding request was issued with, or "". */
extern const char* fs_stream_token(struct fs_stream* stream);

/** Give up on whatever is outstanding, and fail its waiters with @p error. */
extern void fs_stream_abort(struct fs_stream* stream, int error);

/** Has this stream's request been outstanding past @p deadline seconds? */
extern int fs_stream_expired(struct fs_stream* stream, time_t now, int timeout);

#endif /* HAVE_UHUB_FUSE_STREAM_H */
