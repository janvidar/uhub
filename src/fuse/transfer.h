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

#ifndef HAVE_UHUB_FUSE_TRANSFER_H
#define HAVE_UHUB_FUSE_TRANSFER_H

#include "system.h"
#include "adc/adctypes.h"

#include "seeder/grant.h"

struct fs_config;
struct fs_filelist;
struct fs_session;
struct fs_stream;
struct fs_task;
struct fs_transfer;
struct seed_cache;

/**
 * Getting the bytes.
 *
 * A read of by-tth/<hash> has to end up asking somebody on the hub for a file,
 * which is an ADC conversation lasting seconds or minutes, on a thread the
 * reader is not on. So an open() that misses the cache is *parked*: the FUSE
 * thread stays blocked inside the bridge, the task is put on the want queue,
 * and it is completed when the content arrives, when the search comes back
 * empty, or when the clock runs out.
 *
 * None of the machinery under this is new. The client-to-client protocol, the
 * TTH verification and the cache are uhub-seeder's (src/seeder/cc.c, cache.c,
 * grant.c) and are driven here exactly as the seeder drives them: the mount
 * listens, asks a peer to connect to it with a CTM naming a token, and CGETs
 * the file over the connection the peer opens. That arrangement is what makes
 * a passive peer reachable, and it is why the mount needs a port of its own.
 *
 * Everything here belongs to the ADC thread, with one deliberate exception
 * documented on fs_transfer_read().
 */

/**
 * Create the cache, the transfer port and the want queue.
 *
 * @param session the hub connection to ask through. Not owned.
 * @param config  the settings. Copied where needed; need not outlive the call
 *                except for the strings named in the cc policy, which are.
 * @return NULL if the cache could not be opened or the port could not be bound,
 *         with the reason logged. A mount without transfers still works; it
 *         just cannot serve by-tth.
 */
extern struct fs_transfer* fs_transfer_create(struct fs_session* session,
                                              const struct fs_config* config);

extern void fs_transfer_destroy(struct fs_transfer* transfer);

/**
 * The SU feature list this mount may honestly advertise, e.g. "TCP4,ADCS".
 *
 * Claim only what is true: TCP4/TCP6 for the family the listener actually
 * bound, and ADCS only when the port has a certificate to complete a handshake
 * with. A peer that acts on a false claim gets a transfer that never connects
 * rather than one that falls back.
 *
 * @return the list, valid for the lifetime of @p transfer.
 */
extern const char* fs_transfer_support(struct fs_transfer* transfer);

/**
 * Ask for @p tth, on behalf of a parked FUSE task.
 *
 * @return 0 when the content is already cached and @p task may be answered at
 *         once, FS_TASK_PARKED when it has been queued, or a negative errno.
 */
extern int fs_transfer_want(struct fs_transfer* transfer, const char* tth, struct fs_task* task);

/**
 * Ask for @p tth, starting with the peer known to have it.
 *
 * Reading a file out of somebody's share is not the same question as reading
 * one by hash: here we know whose it is, and asking them is both quicker and
 * the only thing that works when nobody else on the hub holds a copy. A
 * broadcast search is still the fallback, for a peer who has gone or will not
 * answer.
 *
 * @param cid whom to ask first, or NULL to search straight away.
 */
extern int fs_transfer_want_from(struct fs_transfer* transfer, const char* tth,
                                 const char* cid, struct fs_task* task);

/**
 * Take one waiter off the queue, for a reader that has given up.
 *
 * The task is the FUSE thread's stack and is about to go away, so it must not
 * be left where a completion could still write to it. If it was the only thing
 * waiting for that hash, the fetch is left running: the bytes are likely on
 * their way, and the next reader will find them cached.
 */
extern void fs_transfer_abandon(struct fs_transfer* transfer, struct fs_task* task);

/**
 * Make sure we hold @p cid's file list, fetching it if we do not.
 *
 * A file list is asked for by name rather than by hash -- its hash cannot be
 * known until it has arrived -- and it is asked of one peer rather than of the
 * hub, since only they have it. Otherwise this behaves exactly like
 * fs_transfer_want(): 0 when it is already here, FS_TASK_PARKED when the task
 * has been queued behind a fetch, or a negative errno.
 */
extern int fs_transfer_want_filelist(struct fs_transfer* transfer, const char* cid,
                                     struct fs_task* task);

/**
 * The parsed file list for @p cid, or NULL if none has been fetched.
 *
 * Owned by the transfer layer and valid until the list is replaced, which only
 * happens on a later fetch.
 */
extern struct fs_filelist* fs_transfer_filelist(struct fs_transfer* transfer, const char* cid);

/**
 * Open a cached file for reading, and pin it so it cannot be evicted while the
 * descriptor is open.
 *
 * @param out_size receives the size the cache recorded.
 * @return a descriptor, or a negative errno.
 */
extern int fs_transfer_open_file(struct fs_transfer* transfer, const char* tth, uint64_t* out_size);

/** Close a descriptor from fs_transfer_open_file() and release its pin. */
extern void fs_transfer_close_file(struct fs_transfer* transfer, const char* tth, int fd);

/**
 * Read from such a descriptor.
 *
 * This one call is safe on a FUSE thread, and is the exception to the rule that
 * the ADC thread owns everything: it is a pread() on a descriptor the caller
 * already holds, clamped to a size the caller already has, and it touches no
 * shared state (see seed_cache_read()). Keeping it off the bridge is what makes
 * a large read cost one system call instead of a thread handover.
 */
extern ssize_t fs_transfer_read(struct fs_transfer* transfer, int fd, uint64_t size,
                                uint64_t offset, void* buf, size_t len);

/* --- large files, read through a window --------------------------------- */

/**
 * The largest file this mount will fetch whole, verify and cache.
 *
 * Anything above it is read through a stream instead, which cannot be
 * verified; see fuse/stream.h for why that boundary is where it is.
 */
extern uint64_t fs_transfer_max_cached_size(struct fs_transfer* transfer);

/** Open a stream for a file too large to cache. @return NULL on failure. */
extern struct fs_stream* fs_transfer_stream_open(struct fs_transfer* transfer, const char* tth,
                                                 const char* cid, uint64_t size);

extern void fs_transfer_stream_close(struct fs_transfer* transfer, struct fs_stream* stream);

/**
 * Ask @p cid for bytes [start, start+len) of @p tth.
 *
 * @param out_token receives the token the answer will carry.
 * @return 0, or a negative errno.
 */
extern int fs_transfer_request_range(struct fs_transfer* transfer, const char* cid,
                                     const char* tth, uint64_t start, uint64_t len,
                                     char out_token[SEED_TOKEN_MAX + 1]);

/** Complete a parked task. For fuse/stream.c, which has no bridge of its own. */
extern void fs_transfer_complete_task(struct fs_transfer* transfer, struct fs_task* task, int result);

/** Is @p tth in the cache, and how big is it? @return 1 if it is. */
extern int fs_transfer_peek(struct fs_transfer* transfer, const char* tth, uint64_t* out_size);

/* --- events routed in from the hub connection ---------------------------- */

/** A DRES answering one of our searches. */
extern void fs_transfer_on_search_result(struct fs_transfer* transfer, sid_t from,
                                         const char* tth, uint64_t size);

/** A peer is asking us to dial it (CTM), or to dial it back (RCM). */
extern void fs_transfer_on_connect_req(struct fs_transfer* transfer, sid_t from,
                                       const char* protocol, uint16_t port, const char* token);

/** Once a second: retries, deadlines and grant expiry. */
extern void fs_transfer_tick(struct fs_transfer* transfer);

/**
 * Fail every parked task with @p error.
 *
 * Called when the mount is going away. A FUSE thread waiting for a download
 * that will now never happen would otherwise keep the filesystem busy and the
 * unmount blocked.
 */
extern void fs_transfer_abort_all(struct fs_transfer* transfer, int error);

#endif /* HAVE_UHUB_FUSE_TRANSFER_H */
