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

#include "fuse/stream.h"
#include "fuse/bridge.h"
#include "fuse/transfer.h"
#include "util/log.h"
#include "util/memory.h"

/**
 * One open large file.
 *
 * The window is a single contiguous run of bytes: [have_start, have_end). A
 * read inside it is a memcpy; a read outside it throws it away and asks for a
 * new one starting where the reader is. That is deliberately the simplest
 * thing that works -- a filesystem read is almost always either the next
 * sequential chunk or a seek to somewhere else entirely, and a cache of
 * scattered fragments would cost more bookkeeping than it saves.
 */
struct fs_stream
{
	struct fs_transfer* transfer;
	char tth[MAX_CID_LEN + 1];
	char cid[MAX_CID_LEN + 1];
	uint64_t size;

	char* window;
	uint64_t have_start;
	uint64_t have_end;

	/* The request in flight, if any. */
	char token[SEED_TOKEN_MAX + 1];
	uint64_t want_start;
	uint64_t want_end;
	uint64_t got;          /** Bytes of it that have arrived. */
	time_t started;

	struct fs_task* waiters;
	int failed;
};

struct fs_stream* fs_stream_open(struct fs_transfer* transfer, const char* tth,
                                 const char* cid, uint64_t size)
{
	struct fs_stream* stream;

	if (!transfer || !tth || !cid || !size)
		return NULL;

	stream = (struct fs_stream*) hub_malloc_zero(sizeof(struct fs_stream));
	if (!stream)
		return NULL;

	stream->window = (char*) hub_malloc(FS_STREAM_WINDOW);
	if (!stream->window)
	{
		hub_free(stream);
		return NULL;
	}

	stream->transfer = transfer;
	stream->size = size;
	snprintf(stream->tth, sizeof(stream->tth), "%s", tth);
	snprintf(stream->cid, sizeof(stream->cid), "%s", cid);
	return stream;
}

void fs_stream_close(struct fs_stream* stream)
{
	if (!stream)
		return;

	/* Anything still waiting is waiting on a descriptor that is being closed. */
	fs_stream_abort(stream, -EBADF);

	hub_free(stream->window);
	hub_free(stream);
}

const char* fs_stream_token(struct fs_stream* stream)
{
	return stream ? stream->token : "";
}

static void stream_wake(struct fs_stream* stream, int result)
{
	struct fs_task* task = stream->waiters;

	stream->waiters = NULL;

	while (task)
	{
		struct fs_task* next = task->next;

		task->next = NULL;
		fs_transfer_complete_task(stream->transfer, task, result);
		task = next;
	}
}

void fs_stream_abandon(struct fs_stream* stream, struct fs_task* task)
{
	struct fs_task** link;

	if (!stream)
		return;

	for (link = &stream->waiters; *link; link = &(*link)->next)
	{
		if (*link == task)
		{
			*link = task->next;
			task->next = NULL;
			return;
		}
	}
}

void fs_stream_abort(struct fs_stream* stream, int error)
{
	if (!stream)
		return;

	stream->token[0] = '\0';
	stream->want_start = stream->want_end = 0;
	stream->got = 0;
	stream_wake(stream, error);
}

int fs_stream_expired(struct fs_stream* stream, time_t now, int timeout)
{
	return stream && *stream->token && (now - stream->started) >= timeout;
}

int fs_stream_on_body(struct fs_stream* stream, uint64_t offset, const void* data, size_t len)
{
	uint64_t end;

	if (!stream || !*stream->token)
		return 0;

	/* Exactly where the next bytes were expected, and no further than what was
	   asked for: a peer that answers something else is answering a question
	   nobody put to it. */
	if (offset != stream->want_start + stream->got)
		return 0;

	end = offset + (uint64_t) len;
	if (end > stream->want_end)
		return 0;

	memcpy(&stream->window[offset - stream->want_start], data, len);
	stream->got += (uint64_t) len;
	return 1;
}

void fs_stream_on_done(struct fs_stream* stream, int ok)
{
	if (!stream || !*stream->token)
		return;

	stream->token[0] = '\0';

	if (!ok || stream->got != (stream->want_end - stream->want_start))
	{
		/* A short answer is not a short file: the size came from the file list
		   and the request was inside it, so this is a peer that stopped. */
		stream->have_start = stream->have_end = 0;
		stream_wake(stream, -EIO);
		return;
	}

	stream->have_start = stream->want_start;
	stream->have_end = stream->want_end;

	/* Woken with 0: "look again", not "no bytes". The waiter re-reads from the
	   window, which now holds what it was waiting for. */
	stream_wake(stream, 0);
}

/** Ask the peer for the window this read wants. @return 0 or a negative errno. */
static int stream_request(struct fs_stream* stream, uint64_t offset, size_t len)
{
	uint64_t end = offset + (uint64_t) len + FS_STREAM_READAHEAD;
	int result;

	if (end > stream->size)
		end = stream->size;

	if (end - offset > FS_STREAM_WINDOW)
		end = offset + FS_STREAM_WINDOW;

	if (end <= offset)
		return -EINVAL;

	result = fs_transfer_request_range(stream->transfer, stream->cid, stream->tth,
	                                   offset, end - offset, stream->token);
	if (result < 0)
		return result;

	stream->want_start = offset;
	stream->want_end = end;
	stream->got = 0;
	stream->started = time(NULL);
	return 0;
}

int fs_stream_read(struct fs_stream* stream, uint64_t offset, void* buf, size_t len,
                   struct fs_task* task, int* out_got)
{
	uint64_t available;

	*out_got = 0;

	if (!stream || !buf)
		return -EBADF;

	if (offset >= stream->size)
		return 0;   /* End of file, with out_got left at zero. */

	if ((uint64_t) len > stream->size - offset)
		len = (size_t) (stream->size - offset);

	/* Already here. */
	if (offset >= stream->have_start && offset < stream->have_end)
	{
		available = stream->have_end - offset;

		if ((uint64_t) len > available)
			len = (size_t) available;

		memcpy(buf, &stream->window[offset - stream->have_start], len);
		*out_got = (int) len;
		return 0;
	}

	/* A request is out. If it covers this read, wait for it rather than
	   cancelling it and asking again. */
	if (*stream->token)
	{
		if (offset >= stream->want_start && offset < stream->want_end)
		{
			task->next = stream->waiters;
			stream->waiters = task;
			return FS_TASK_PARKED;
		}

		/* A seek somewhere else: the outstanding range is no longer wanted,
		   but it cannot be un-asked, so it is left to arrive and be discarded
		   rather than tangling the connection. */
		fs_stream_abort(stream, -EAGAIN);
	}

	{
		int result = stream_request(stream, offset, len);

		if (result < 0)
			return result;
	}

	task->next = stream->waiters;
	stream->waiters = task;
	return FS_TASK_PARKED;
}
