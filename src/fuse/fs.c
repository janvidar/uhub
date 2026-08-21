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

#include "fuse/fs.h"
#include "fuse/bridge.h"
#include "fuse/chatlog.h"
#include "fuse/filelist.h"
#include "fuse/stream.h"
#include "fuse/transfer.h"
#include "fuse/nodes.h"
#include "fuse/render.h"
#include "fuse/roster.h"
#include "fuse/session.h"
#include "util/memory.h"

/*
 * The kernel side of the mount.
 *
 * Every function in here runs on a FUSE thread and may touch nothing but the
 * path it was handed: hub state is reached by submitting a task to the ADC
 * thread and waiting for it. The pattern is the same each time -- resolve the
 * path (pure, no hub involved), pack the operation into a struct that embeds a
 * struct fs_task, submit, return the result.
 *
 * A metadata file is snapshotted at open() and read() serves the snapshot, so
 * a read never crosses threads and never sees a value change underneath it.
 */

/**
 * What an open descriptor holds.
 *
 * A metadata file is a snapshot taken at open(); a chat file is a stream read
 * live by offset; a message file collects what is written to it until a line
 * is complete. One struct covers all three because a chat file is both of the
 * first two at once -- it can be read and written on the same descriptor.
 */
struct fs_handle
{
	enum fs_node_type type;
	char cid[MAX_CID_LEN + 1];

	char* snapshot;         /** Metadata files: the bytes read() serves. */
	size_t snapshot_size;

	char* pending;          /** Written bytes not yet ending in a newline. */
	size_t pending_len;

	/* by-tth: an open descriptor into the cache, and the pin that keeps the
	   file there for as long as it is held. */
	int fd;
	uint64_t file_size;
	char tth[MAX_CID_LEN + 1];

	/* Or, for a file too large to hold, the window it is read through. */
	struct fs_stream* stream;
};

/* Defined with the readlink operation below; getattr needs a symlink's length
   and that is the same string. */
static int readlink_target(struct fs_session* session, const char* name, char* buf, size_t size);

static struct fs_session* g_session = NULL;

void fs_set_session(struct fs_session* session)
{
	g_session = session;

	/* How a waiter finds out its reader has gone away. Told to the bridge
	   rather than called from it, so bridge.c needs to know nothing about
	   libfuse. */
	if (session)
		fs_bridge_set_interrupt_check(session->bridge, fuse_interrupted);
}

static struct fs_session* current_session(void)
{
	return g_session;
}

static void stat_dir(struct stat* st, time_t when, nlink_t links)
{
	st->st_mode = S_IFDIR | 0555;
	st->st_nlink = links;
	st->st_mtime = st->st_ctime = st->st_atime = when;
}

static void stat_file(struct stat* st, time_t when, mode_t mode, off_t size)
{
	st->st_mode = S_IFREG | mode;
	st->st_nlink = 1;
	st->st_size = size;
	st->st_mtime = st->st_ctime = st->st_atime = when;
}

/* --------------------------------------------------- a peer's shared files */

/**
 * Everything under users/<cid>/files needs that user's file list first, and
 * fetching one takes as long as a download does. So each such operation is two
 * tasks on one struct: the first makes sure the list is here (parking if it is
 * not), the second does the work now that it is.
 */
struct task_files
{
	struct fs_task task;
	const struct fs_node* node;

	/* Stage two fills in whichever of these the operation wanted. */
	struct stat* st;
	void* buf;
	fuse_fill_dir_t filler;
	char tth[MAX_CID_LEN + 1];
	uint64_t size;
};

static int run_files_fetch(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_files* op = (struct task_files*) task;

	if (!session->transfer)
		return -ENOENT;

	if (!fs_roster_by_cid(session->roster, op->node->cid))
		return -ENOENT;

	return fs_transfer_want_filelist(session->transfer, op->node->cid, task);
}

static int run_files_abandon(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;

	if (session->transfer)
		fs_transfer_abandon(session->transfer, task);

	return 0;
}

/** The entry a files/ path names, or NULL for the files/ directory itself. */
static struct fs_filelist_node* files_lookup(struct fs_session* session,
                                             const struct fs_node* node,
                                             struct fs_filelist** out_list)
{
	struct fs_filelist* list = fs_transfer_filelist(session->transfer, node->cid);

	if (out_list)
		*out_list = list;

	if (!list)
		return NULL;

	if (node->type == FS_NODE_USER_FILES_DIR)
		return NULL;

	return fs_filelist_lookup(list, node->tail);
}

static int run_files_getattr(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_files* op = (struct task_files*) task;
	struct fs_filelist* list = NULL;
	struct fs_filelist_node* entry;
	struct fs_roster_user* user = fs_roster_by_cid(session->roster, op->node->cid);
	time_t when = user ? user->since : session->mounted;

	entry = files_lookup(session, op->node, &list);

	if (op->node->type == FS_NODE_USER_FILES_DIR)
	{
		if (!list)
			return -ENOENT;

		stat_dir(op->st, when, 2);
		return 0;
	}

	if (!entry)
		return -ENOENT;

	if (entry->is_dir)
		stat_dir(op->st, when, 2);
	else
		stat_file(op->st, when, 0444, (off_t) entry->size);

	return 0;
}

static int run_files_readdir(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_files* op = (struct task_files*) task;
	struct fs_filelist* list = NULL;
	struct fs_filelist_node* entry;

	if (op->node->type == FS_NODE_USER_FILES_DIR)
	{
		struct fs_filelist* root_list = fs_transfer_filelist(session->transfer, op->node->cid);

		if (!root_list)
			return -ENOENT;

		entry = fs_filelist_root(root_list);
	}
	else
	{
		struct fs_filelist_node* node = files_lookup(session, op->node, &list);

		if (!node)
			return -ENOENT;

		if (!node->is_dir)
			return -ENOTDIR;

		entry = node->children;
	}

	op->filler(op->buf, ".", NULL, 0, 0);
	op->filler(op->buf, "..", NULL, 0, 0);

	for (; entry; entry = entry->next)
		op->filler(op->buf, entry->name, NULL, 0, 0);

	return 0;
}

/** Resolve a files/ path to the hash a download would ask for. */
static int run_files_resolve(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_files* op = (struct task_files*) task;
	struct fs_filelist_node* entry = files_lookup(session, op->node, NULL);

	if (!entry)
		return -ENOENT;

	if (entry->is_dir)
		return -EISDIR;

	memcpy(op->tth, entry->tth, sizeof(op->tth));
	op->size = entry->size;
	return 0;
}

/**
 * Run a files/ operation: fetch the list if needed, then do the work.
 *
 * @param op   zeroed by the caller, with whatever the operation needs -- the
 *             stat to fill in, the directory buffer to fill -- already set.
 *             This does not clear it: doing so would throw those away.
 * @param work the stage-two task function.
 */
static int files_operation(const struct fs_node* node, struct task_files* op, fs_task_fn work)
{
	struct fs_bridge* bridge = current_session()->bridge;
	int result;

	op->node = node;

	fs_task_init(&op->task, run_files_fetch);
	op->task.abandon = run_files_abandon;

	result = fs_bridge_submit(bridge, &op->task);
	if (result < 0)
		return result;

	fs_task_init(&op->task, work);
	return fs_bridge_submit(bridge, &op->task);
}

/* ----------------------------------------------------------------- getattr */

struct task_getattr
{
	struct fs_task task;
	const struct fs_node* node;
	struct stat* st;
};

static int run_getattr(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_getattr* op = (struct task_getattr*) task;
	const struct fs_node* node = op->node;
	struct fs_roster_user* user = NULL;
	struct fs_render_ctx ctx;
	ssize_t size;

	if (node->type == FS_NODE_USER_DIR || node->type == FS_NODE_USER_FILE ||
	    node->type == FS_NODE_USER_MSG || node->type == FS_NODE_USER_FILES_DIR ||
	    node->type == FS_NODE_USER_FILES_ENTRY)
	{
		user = fs_roster_by_cid(session->roster, node->cid);
		if (!user)
			return -ENOENT;
	}

	switch (node->type)
	{
		case FS_NODE_ROOT:
		case FS_NODE_HUB_DIR:
		case FS_NODE_ME_DIR:
		case FS_NODE_CHAT_DIR:
		case FS_NODE_USERS_DIR:
		case FS_NODE_BY_NICK_DIR:
			stat_dir(op->st, session->mounted, 2);
			return 0;

		/* A stream, so the size is how much has ever been said -- which is
		   what makes `tail -f` able to follow it. */
		case FS_NODE_CHAT_MAIN:
			stat_file(op->st, session->mounted, 0644,
			          (off_t) fs_chatlog_size(session->chat_main));
			return 0;

		case FS_NODE_CHAT_PRIVATE:
			stat_file(op->st, session->mounted, 0444,
			          (off_t) fs_chatlog_size(session->chat_private));
			return 0;

		case FS_NODE_USER_DIR:
			stat_dir(op->st, user->since, 2);
			return 0;

		/*
		 * A directory, said without asking anybody. Fetching the list to
		 * answer a stat would mean `ls -l users/<cid>/` downloaded a share
		 * list; the list is fetched when the directory is actually listed.
		 */
		case FS_NODE_USER_FILES_DIR:
			if (!session->transfer)
				return -ENOENT;
			stat_dir(op->st, user->since, 2);
			return 0;

		case FS_NODE_HUB_FILE:
		case FS_NODE_ME_FILE:
		case FS_NODE_USER_FILE:
			fs_session_render_ctx(session, &ctx);
			if (user)
			{
				ctx.inf = user->inf;
				ctx.sid = user->sid;
				ctx.since = user->since;
			}

			/* Measured, not guessed: st_size has to agree with what read()
			   will hand over, or every reader that trusts stat() truncates. */
			size = fs_render(node, &ctx, NULL, 0);
			if (size < 0)
				return -EIO;

			stat_file(op->st, user ? user->since : session->mounted, 0444, size);
			return 0;

		case FS_NODE_USER_MSG:
			/* Write-only: there is no such thing as reading a message you
			   have not sent. */
			stat_file(op->st, user->since, 0200, 0);
			return 0;

		case FS_NODE_BY_NICK_LINK:
		{
			char target[MAX_CID_LEN + 16];
			int len = readlink_target(session, node->name, target, sizeof(target));

			if (len < 0)
				return len;

			op->st->st_mode = S_IFLNK | 0777;
			op->st->st_nlink = 1;
			op->st->st_size = len;
			op->st->st_mtime = op->st->st_ctime = op->st->st_atime = session->mounted;
			return 0;
		}

		case FS_NODE_BY_TTH_DIR:
			stat_dir(op->st, session->mounted, 2);
			return 0;

		/*
		 * Content addressed: every hash is a name here, whether or not anybody
		 * on the hub has the file. The size is known only once it is cached,
		 * and 0 before that -- so a reader should open it and read rather than
		 * trust stat(), which is what cat does anyway.
		 */
		case FS_NODE_BY_TTH_FILE:
		{
			uint64_t size = 0;

			if (!session->transfer)
				return -ENOENT;

			fs_transfer_peek(session->transfer, op->node->name, &size);
			stat_file(op->st, session->mounted, 0444, (off_t) size);
			return 0;
		}

		/* Resolvable, not yet served: a user's share arrives with the phase
		   that implements it. Reporting it as absent is the honest answer
		   until then. */
		default:
			return -ENOENT;
	}
}

static int fs_getattr(const char* path, struct stat* st, struct fuse_file_info* fi)
{
	struct task_getattr op;
	struct fs_node node;

	(void) fi;

	memset(st, 0, sizeof(*st));
	st->st_uid = getuid();
	st->st_gid = getgid();

	if (!fs_node_resolve(path, &node))
		return -ENOENT;

	/*
	 * Only a path *below* files/ needs the list. Stat'ing files/ itself must
	 * not fetch one: `ls -l users/<cid>/` stats every entry in that directory,
	 * and nobody asking who is online meant to start downloading share lists.
	 */
	if (node.type == FS_NODE_USER_FILES_ENTRY)
	{
		struct task_files files;

		memset(&files, 0, sizeof(files));
		files.st = st;
		return files_operation(&node, &files, run_files_getattr);
	}

	fs_task_init(&op.task, run_getattr);
	op.node = &node;
	op.st = st;

	return fs_bridge_submit(current_session()->bridge, &op.task);
}

/* ----------------------------------------------------------------- readdir */

struct task_readdir
{
	struct fs_task task;
	const struct fs_node* node;
	void* buf;
	fuse_fill_dir_t filler;
};

static void fill(struct task_readdir* op, const char* name)
{
	/* The FUSE thread is blocked inside fs_bridge_submit() for the duration,
	   so its buffer has exactly one writer even though this is the other
	   thread doing the writing. */
	op->filler(op->buf, name, NULL, 0, 0);
}

static void fill_fields(struct task_readdir* op, const struct fs_field* table)
{
	size_t n;

	for (n = 0; table[n].name; n++)
		fill(op, table[n].name);
}

static int fill_name(void* ptr, const char* name, struct fs_roster_user* user)
{
	(void) user;
	fill((struct task_readdir*) ptr, name);
	return 0;
}

static int run_readdir(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_readdir* op = (struct task_readdir*) task;
	struct fs_roster_user* user;

	fill(op, ".");
	fill(op, "..");

	switch (op->node->type)
	{
		case FS_NODE_ROOT:
			fill(op, "hub");
			fill(op, "me");
			fill(op, "chat");
			fill(op, "users");
			fill(op, "by-nick");
			if (session->transfer)
				fill(op, "by-tth");
			return 0;

		case FS_NODE_CHAT_DIR:
			fill(op, "main");
			fill(op, "private");
			return 0;

		/*
		 * Deliberately empty. A content addressed directory has no listing:
		 * there is no set of hashes to enumerate, only the one you already
		 * know. Listing what happens to be cached would suggest otherwise.
		 */
		case FS_NODE_BY_TTH_DIR:
			return 0;

		case FS_NODE_HUB_DIR:
			fill_fields(op, fs_hub_fields);
			return 0;

		case FS_NODE_ME_DIR:
			fill_fields(op, fs_me_fields);
			return 0;

		case FS_NODE_USERS_DIR:
			for (user = fs_roster_first(session->roster); user; user = fs_roster_next(session->roster))
				fill(op, user->cid);
			return 0;

		case FS_NODE_USER_DIR:
			if (!fs_roster_by_cid(session->roster, op->node->cid))
				return -ENOENT;
			fill_fields(op, fs_user_fields);
			if (session->transfer)
				fill(op, "files");
			return 0;

		case FS_NODE_BY_NICK_DIR:
			fs_roster_walk_names(session->roster, fill_name, op);
			return 0;

		default:
			return -ENOENT;
	}
}

static int fs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset,
                      struct fuse_file_info* fi, enum fuse_readdir_flags flags)
{
	struct task_readdir op;
	struct fs_node node;

	(void) offset;
	(void) fi;
	(void) flags;

	if (!fs_node_resolve(path, &node))
		return -ENOENT;

	/* Listing a share is where the file list is actually needed, and where the
	   wait for it belongs. */
	if (node.type == FS_NODE_USER_FILES_DIR || node.type == FS_NODE_USER_FILES_ENTRY)
	{
		struct task_files files;

		memset(&files, 0, sizeof(files));
		files.buf = buf;
		files.filler = filler;
		return files_operation(&node, &files, run_files_readdir);
	}

	fs_task_init(&op.task, run_readdir);
	op.node = &node;
	op.buf = buf;
	op.filler = filler;

	return fs_bridge_submit(current_session()->bridge, &op.task);
}

/* -------------------------------------------------------------- open / read */

struct task_open
{
	struct fs_task task;
	const struct fs_node* node;
	struct fs_handle* handle;
};

static int run_open(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_open* op = (struct task_open*) task;
	struct fs_roster_user* user = NULL;
	struct fs_render_ctx ctx;
	ssize_t size;

	if (op->node->type == FS_NODE_USER_FILE)
	{
		user = fs_roster_by_cid(session->roster, op->node->cid);
		if (!user)
			return -ENOENT;
	}

	fs_session_render_ctx(session, &ctx);
	if (user)
	{
		ctx.inf = user->inf;
		ctx.sid = user->sid;
		ctx.since = user->since;
	}

	size = fs_render(op->node, &ctx, NULL, 0);
	if (size < 0)
		return -EIO;

	op->handle->snapshot = (char*) hub_malloc((size_t) size + 1);
	if (!op->handle->snapshot)
		return -ENOMEM;

	if (fs_render(op->node, &ctx, op->handle->snapshot, (size_t) size + 1) != size)
	{
		hub_free(op->handle->snapshot);
		op->handle->snapshot = NULL;
		return -EIO;
	}

	op->handle->snapshot_size = (size_t) size;
	return 0;
}

/**
 * Fetch a hash, then open it.
 *
 * Two stages on the same task. The first runs on the ADC thread and usually
 * parks: the content has to be asked for, and a peer takes as long as it takes.
 * The second runs once the answer is in, and turns the cached file into a
 * descriptor the reader can use. They are separate because between them the
 * FUSE thread is asleep and the ADC thread is doing other work.
 */
struct task_tth_open
{
	struct fs_task task;
	const char* tth;

	/** Whose share it came out of, when it came out of one. */
	const char* from_cid;

	struct fs_handle* handle;
};

/** Detach this reader from the want queue; the ADC thread's side of a ^C. */
static int run_tth_abandon(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;

	if (session->transfer)
		fs_transfer_abandon(session->transfer, task);

	return 0;
}

static int run_tth_open(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_tth_open* op = (struct task_tth_open*) task;

	if (!session->transfer)
		return -ENOENT;

	return fs_transfer_want_from(session->transfer, op->tth, op->from_cid, task);
}

/** The second stage: the content is cached, so open it and hold it there. */
static int run_tth_attach(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_tth_open* op = (struct task_tth_open*) task;
	int fd;

	if (!session->transfer)
		return -ENOENT;

	fd = fs_transfer_open_file(session->transfer, op->tth, &op->handle->file_size);
	if (fd < 0)
		return fd;

	op->handle->fd = fd;
	return 0;
}

struct task_tth_close
{
	struct fs_task task;
	const char* tth;
	int fd;
};

static int run_tth_close(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_tth_close* op = (struct task_tth_close*) task;

	if (session->transfer)
		fs_transfer_close_file(session->transfer, op->tth, op->fd);

	return 0;
}

/* --- reading a file too large to hold ------------------------------------ */

struct task_stream_open
{
	struct fs_task task;
	struct fs_handle* handle;
	uint64_t size;
};

static int run_stream_open(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_stream_open* op = (struct task_stream_open*) task;

	if (!session->transfer)
		return -ENOENT;

	/* Only above the ceiling. Everything that can be fetched whole still is,
	   because only that path can check what arrived against its hash. */
	if (op->size <= fs_transfer_max_cached_size(session->transfer))
		return 0;

	op->handle->stream = fs_transfer_stream_open(session->transfer, op->handle->tth,
	                                             op->handle->cid, op->size);
	return op->handle->stream ? 0 : -ENFILE;
}

struct task_stream_read
{
	struct fs_task task;
	struct fs_stream* stream;
	uint64_t offset;
	void* buf;
	size_t len;

	int done;   /** The read finished; @c got is how much of it there was. */
	int got;
};

static int run_stream_read(void* ptr, struct fs_task* task)
{
	struct task_stream_read* op = (struct task_stream_read*) task;
	int result;

	(void) ptr;

	result = fs_stream_read(op->stream, op->offset, op->buf, op->len, task, &op->got);

	if (result == 0)
		op->done = 1;

	return result;
}

static int run_stream_abandon(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;

	if (session->transfer)
		fs_transfer_abandon(session->transfer, task);

	return 0;
}

struct task_stream_close
{
	struct fs_task task;
	struct fs_stream* stream;
};

static int run_stream_close(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_stream_close* op = (struct task_stream_close*) task;

	if (session->transfer)
		fs_transfer_stream_close(session->transfer, op->stream);

	return 0;
}

/** Does the user this path names still exist? Nothing else to check. */
struct task_user_exists
{
	struct fs_task task;
	const char* cid;
};

static int run_user_exists(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_user_exists* op = (struct task_user_exists*) task;

	return fs_roster_by_cid(session->roster, op->cid) ? 0 : -ENOENT;
}

static int fs_open(const char* path, struct fuse_file_info* fi)
{
	struct fs_handle* handle;
	struct fs_node node;
	int writable;
	int result;

	if (!fs_node_resolve(path, &node))
		return -ENOENT;

	writable = (node.type == FS_NODE_CHAT_MAIN || node.type == FS_NODE_USER_MSG);

	switch (node.type)
	{
		case FS_NODE_HUB_FILE:
		case FS_NODE_ME_FILE:
		case FS_NODE_USER_FILE:
		case FS_NODE_CHAT_MAIN:
		case FS_NODE_CHAT_PRIVATE:
		case FS_NODE_USER_MSG:
		case FS_NODE_BY_TTH_FILE:
		case FS_NODE_USER_FILES_ENTRY:
			break;

		default:
			return -ENOENT;
	}

	if ((fi->flags & O_ACCMODE) != O_RDONLY && !writable)
		return -EACCES;

	/* Write-only, so there is nothing to hand back to a reader. */
	if ((fi->flags & O_ACCMODE) != O_WRONLY && node.type == FS_NODE_USER_MSG)
		return -EACCES;

	handle = (struct fs_handle*) hub_malloc_zero(sizeof(struct fs_handle));
	if (!handle)
		return -ENOMEM;

	handle->type = node.type;
	handle->fd = -1;
	memcpy(handle->cid, node.cid, sizeof(handle->cid));
	/* Only a by-tth node names a hash, and a hash is exactly MAX_CID_LEN
	   characters; node.name is the wider buffer because a nick can be longer,
	   and anything that does not fit here was never a hash. */
	if (node.type == FS_NODE_BY_TTH_FILE)
		memcpy(handle->tth, node.name, sizeof(handle->tth));

	/*
	 * A shared file is by-tth wearing a name. The list says which hash the path
	 * stands for; from there it is the same fetch, the same cache and the same
	 * descriptor -- which is also why a file already fetched by hash opens
	 * instantly under its name.
	 */
	if (node.type == FS_NODE_USER_FILES_ENTRY)
	{
		struct task_files files;

		memset(&files, 0, sizeof(files));
		result = files_operation(&node, &files, run_files_resolve);

		/*
		 * Too big to fetch whole: read it through a window instead. The size
		 * comes from the owner's file list, so this decision is made before a
		 * single byte has been asked for -- which is the point, since fetching
		 * it whole is exactly what must not happen.
		 */
		if (result == 0 && files.size > 0)
		{
			struct task_stream_open sop;

			memcpy(handle->tth, files.tth, sizeof(handle->tth));

			fs_task_init(&sop.task, run_stream_open);
			sop.handle = handle;
			sop.size = files.size;

			result = fs_bridge_submit(current_session()->bridge, &sop.task);

			if (result >= 0 && handle->stream)
			{
				handle->file_size = files.size;
				goto opened;
			}

			if (result < 0)
			{
				hub_free(handle);
				return result;
			}
		}

		if (result == 0)
		{
			struct task_tth_open op;

			memcpy(handle->tth, files.tth, sizeof(handle->tth));

			fs_task_init(&op.task, run_tth_open);
			op.task.abandon = run_tth_abandon;
			op.tth = handle->tth;
			op.from_cid = handle->cid;   /* whose share this path is in */
			op.handle = handle;

			result = fs_bridge_submit(current_session()->bridge, &op.task);

			if (result == 0)
			{
				fs_task_init(&op.task, run_tth_attach);
				result = fs_bridge_submit(current_session()->bridge, &op.task);
			}
		}
	}
	else if (node.type == FS_NODE_USER_MSG)
	{
		/* Nothing to render, but an open on a user who is not here must still
		   fail -- otherwise the message goes nowhere and nobody is told. */
		struct task_user_exists check;

		fs_task_init(&check.task, run_user_exists);
		check.cid = handle->cid;
		result = fs_bridge_submit(current_session()->bridge, &check.task);
	}
	else if (node.type == FS_NODE_BY_TTH_FILE)
	{
		struct task_tth_open op;

		fs_task_init(&op.task, run_tth_open);
		op.task.abandon = run_tth_abandon;
		op.tth = handle->tth;
		op.from_cid = NULL;   /* by-tth names no owner: the hub is asked. */
		op.handle = handle;

		/* Blocks for as long as the fetch takes -- which is the point: an
		   open() that returned before the bytes existed would only move the
		   waiting to the first read, where there is nowhere to report a peer
		   that never answered. */
		result = fs_bridge_submit(current_session()->bridge, &op.task);

		if (result == 0)
		{
			fs_task_init(&op.task, run_tth_attach);
			result = fs_bridge_submit(current_session()->bridge, &op.task);
		}
	}
	else if (node.type == FS_NODE_CHAT_MAIN || node.type == FS_NODE_CHAT_PRIVATE)
	{
		/* A stream: read() goes to the log itself, at whatever offset the
		   reader has got to, so there is nothing to snapshot. */
		result = 0;
	}
	else
	{
		struct task_open op;

		fs_task_init(&op.task, run_open);
		op.node = &node;
		op.handle = handle;
		result = fs_bridge_submit(current_session()->bridge, &op.task);
	}

	if (result < 0)
	{
		hub_free(handle->snapshot);
		hub_free(handle);
		return result;
	}

opened:
	/*
	 * The kernel must not answer a read out of what it thinks it knows about
	 * these files. A by-tth file has no size until it has been fetched, so the
	 * getattr that preceded this open said zero -- and against a cached size of
	 * zero the kernel returns EOF without ever calling read(). A chat file is a
	 * stream that grows between one read and the next, which the page cache
	 * would likewise hold stale.
	 *
	 * direct_io turns both off: every read reaches this filesystem, and the
	 * size in stat() goes back to being what it is for a growing file --
	 * information rather than a limit.
	 */
	if (node.type == FS_NODE_BY_TTH_FILE || node.type == FS_NODE_USER_FILES_ENTRY ||
	    node.type == FS_NODE_CHAT_MAIN || node.type == FS_NODE_CHAT_PRIVATE)
		fi->direct_io = 1;

	fi->fh = (uint64_t) (uintptr_t) handle;
	return 0;
}

/* ------------------------------------------------------------------ read */

struct task_chat_read
{
	struct fs_task task;
	int private_log;
	uint64_t offset;
	char* buf;
	size_t size;
	size_t got;
};

static int run_chat_read(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_chat_read* op = (struct task_chat_read*) task;

	op->got = fs_chatlog_read(op->private_log ? session->chat_private : session->chat_main,
	                          op->offset, op->buf, op->size);
	return 0;
}

static int fs_read(const char* path, char* buf, size_t size, off_t offset,
                   struct fuse_file_info* fi)
{
	struct fs_handle* handle = (struct fs_handle*) (uintptr_t) fi->fh;

	(void) path;

	if (!handle || offset < 0)
		return -EBADF;

	if (handle->type == FS_NODE_CHAT_MAIN || handle->type == FS_NODE_CHAT_PRIVATE)
	{
		struct task_chat_read op;
		int result;

		fs_task_init(&op.task, run_chat_read);
		op.private_log = (handle->type == FS_NODE_CHAT_PRIVATE);
		op.offset = (uint64_t) offset;
		op.buf = buf;
		op.size = size;
		op.got = 0;

		result = fs_bridge_submit(current_session()->bridge, &op.task);
		return (result < 0) ? result : (int) op.got;
	}

	if (handle->stream)
	{
		/*
		 * A read may have to fetch, and a fetch may have to be waited for --
		 * possibly more than once, since the window it asks for is not always
		 * the window the reader ends up needing. Waking with 0 means "the
		 * window moved, look again", so this loops rather than returning it.
		 */
		struct task_stream_read op;

		memset(&op, 0, sizeof(op));
		op.stream = handle->stream;
		op.offset = (uint64_t) offset;
		op.buf = buf;
		op.len = size;

		for (;;)
		{
			int result;

			op.done = 0;
			fs_task_init(&op.task, run_stream_read);
			op.task.abandon = run_stream_abandon;

			result = fs_bridge_submit(current_session()->bridge, &op.task);

			if (result < 0)
				return result;

			if (op.done)
				return op.got;

			/* Woken because the window moved: read it again. */
		}
	}

	if (handle->type == FS_NODE_BY_TTH_FILE || handle->type == FS_NODE_USER_FILES_ENTRY)
	{
		ssize_t got;

		if (handle->fd < 0)
			return -EBADF;

		/* Straight to the file, on this thread: see fs_transfer_read(). */
		got = fs_transfer_read(current_session()->transfer, handle->fd, handle->file_size,
		                       (uint64_t) offset, buf, size);
		return (got < 0) ? -EIO : (int) got;
	}

	if (!handle->snapshot)
		return -EBADF;

	if ((size_t) offset >= handle->snapshot_size)
		return 0;

	if (size > handle->snapshot_size - (size_t) offset)
		size = handle->snapshot_size - (size_t) offset;

	memcpy(buf, &handle->snapshot[offset], size);
	return (int) size;
}

/* ----------------------------------------------------------------- write */

struct task_send
{
	struct fs_task task;
	enum fs_node_type type;
	const char* cid;
	const char* text;
};

static int run_send(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_send* op = (struct task_send*) task;

	if (op->type == FS_NODE_USER_MSG)
		return fs_session_send_pm(session, op->cid, op->text);

	return fs_session_send_chat(session, op->text);
}

/** Hand one complete message to the ADC thread. */
static int handle_send(struct fs_handle* handle, const char* text)
{
	struct task_send op;

	fs_task_init(&op.task, run_send);
	op.type = handle->type;
	op.cid = handle->cid;
	op.text = text;

	return fs_bridge_submit(current_session()->bridge, &op.task);
}

/** Send whatever has been collected, and start again. */
static int handle_flush(struct fs_handle* handle)
{
	int result;

	if (!handle->pending || !handle->pending_len)
		return 0;

	handle->pending[handle->pending_len] = '\0';
	handle->pending_len = 0;

	result = handle_send(handle, handle->pending);
	return result;
}

static int fs_write(const char* path, const char* buf, size_t size, off_t offset,
                    struct fuse_file_info* fi)
{
	struct fs_handle* handle = (struct fs_handle*) (uintptr_t) fi->fh;
	size_t n;

	(void) path;
	(void) offset;   /* A message is not a byte at a position. */

	if (!handle)
		return -EBADF;

	if (handle->type != FS_NODE_CHAT_MAIN && handle->type != FS_NODE_USER_MSG)
		return -EACCES;

	if (!handle->pending)
	{
		handle->pending = (char*) hub_malloc(FS_CHAT_MAX + 1);
		if (!handle->pending)
			return -ENOMEM;
	}

	/*
	 * A write is not a message: `echo` delivers one line with its newline, a
	 * program writing in chunks delivers a fraction of one, and a here-document
	 * delivers several at once. So bytes are collected and a message is sent
	 * for each newline -- and for whatever is left when the descriptor is
	 * closed, which is what makes `echo -n` work.
	 */
	for (n = 0; n < size; n++)
	{
		if (buf[n] == '\n')
		{
			int result = handle_flush(handle);
			if (result < 0)
				return result;
			continue;
		}

		if (handle->pending_len >= FS_CHAT_MAX)
		{
			/* Drop the oversized line rather than send a truncated one: the
			   hub would refuse it anyway, and half a message is worse than
			   none. */
			handle->pending_len = 0;
			return -EMSGSIZE;
		}

		handle->pending[handle->pending_len++] = buf[n];
	}

	return (int) size;
}

/**
 * Accept a truncation without doing anything.
 *
 * `> chat/main` opens with O_TRUNC, and refusing that would make the ordinary
 * way of writing to a file in a shell fail. There is nothing to truncate: what
 * has already been said cannot be unsaid, and the log is a record rather than
 * a file.
 */
static int fs_truncate(const char* path, off_t size, struct fuse_file_info* fi)
{
	struct fs_node node;

	(void) size;
	(void) fi;

	if (!fs_node_resolve(path, &node))
		return -ENOENT;

	if (node.type != FS_NODE_CHAT_MAIN && node.type != FS_NODE_USER_MSG)
		return -EACCES;

	return 0;
}

static int fs_release(const char* path, struct fuse_file_info* fi)
{
	struct fs_handle* handle = (struct fs_handle*) (uintptr_t) fi->fh;

	(void) path;

	if (handle)
	{
		/* Anything written without a closing newline is a message too. */
		handle_flush(handle);

		if (handle->stream)
		{
			struct task_stream_close op;

			fs_task_init(&op.task, run_stream_close);
			op.stream = handle->stream;
			fs_bridge_submit(current_session()->bridge, &op.task);
			handle->stream = NULL;
		}

		if (handle->fd >= 0)
		{
			struct task_tth_close op;

			fs_task_init(&op.task, run_tth_close);
			op.tth = handle->tth;
			op.fd = handle->fd;
			fs_bridge_submit(current_session()->bridge, &op.task);
		}

		hub_free(handle->snapshot);
		hub_free(handle->pending);
		hub_free(handle);
		fi->fh = 0;
	}

	return 0;
}

/* ---------------------------------------------------------------- readlink */

struct name_match
{
	const char* wanted;
	char cid[MAX_CID_LEN + 1];
	int found;
};

static int match_name(void* ptr, const char* name, struct fs_roster_user* user)
{
	struct name_match* match = (struct name_match*) ptr;

	if (strcmp(name, match->wanted) != 0)
		return 0;

	memcpy(match->cid, user->cid, sizeof(match->cid));
	match->found = 1;
	return 1;
}

static int readlink_target(struct fs_session* session, const char* name, char* buf, size_t size)
{
	struct name_match match;
	int len;

	match.wanted = name;
	match.found = 0;
	match.cid[0] = '\0';

	fs_roster_walk_names(session->roster, match_name, &match);

	if (!match.found)
		return -ENOENT;

	len = snprintf(buf, size, "../users/%s", match.cid);
	if (len < 0 || (size_t) len >= size)
		return -ENAMETOOLONG;

	return len;
}

struct task_readlink
{
	struct fs_task task;
	const struct fs_node* node;
	char* buf;
	size_t size;
};

static int run_readlink(void* ptr, struct fs_task* task)
{
	struct fs_session* session = (struct fs_session*) ptr;
	struct task_readlink* op = (struct task_readlink*) task;
	int len = readlink_target(session, op->node->name, op->buf, op->size);

	return (len < 0) ? len : 0;
}

static int fs_readlink(const char* path, char* buf, size_t size)
{
	struct task_readlink op;
	struct fs_node node;

	if (!fs_node_resolve(path, &node))
		return -ENOENT;

	if (node.type != FS_NODE_BY_NICK_LINK)
		return -EINVAL;

	if (!size)
		return -EINVAL;

	fs_task_init(&op.task, run_readlink);
	op.node = &node;
	op.buf = buf;
	op.size = size;

	return fs_bridge_submit(current_session()->bridge, &op.task);
}

/* --------------------------------------------------------------------------- */

/**
 * Turn the kernel's caches off.
 *
 * Everything here changes without the filesystem being told: a user's INF is
 * replaced, somebody leaves, the chat grows, and a by-tth file goes from "no
 * such size" to its real one the moment it has been fetched. With the default
 * one second attribute cache, a stat() taken before a download would still be
 * answered from afterwards -- and a size of zero cached that way makes the
 * kernel return EOF without ever asking this filesystem to read.
 *
 * The cost is a round trip per stat, on a filesystem whose files are a few
 * bytes each and whose directories are held in memory. Correctness is worth
 * more than that here.
 */
static void* fs_init(struct fuse_conn_info* conn, struct fuse_config* cfg)
{
	(void) conn;

	cfg->attr_timeout = 0;
	cfg->entry_timeout = 0;
	cfg->negative_timeout = 0;

	return NULL;
}

static const struct fuse_operations fs_operations = {
	.init     = fs_init,
	.getattr  = fs_getattr,
	.readdir  = fs_readdir,
	.readlink = fs_readlink,
	.open     = fs_open,
	.read     = fs_read,
	.write    = fs_write,
	.truncate = fs_truncate,
	.release  = fs_release,
};

const struct fuse_operations* fs_get_operations(void)
{
	return &fs_operations;
}
