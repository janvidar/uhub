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

#ifndef HAVE_UHUB_FUSE_FS_H
#define HAVE_UHUB_FUSE_FS_H

/* The API this is written against. libfuse's headers refuse to compile without
   it, and it must be set before <fuse.h> is included anywhere. */
#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <fuse_lowlevel.h>

#include "system.h"

struct fs_session;

/** The operation table, for main() to hand to fuse_new(). */
extern const struct fuse_operations* fs_get_operations(void);

/**
 * Name the session the operations work against.
 *
 * Not fuse_new()'s user_data: the session cannot exist that early. It is built
 * after fuse_daemonize(), because a thread does not survive the fork, and by
 * then fuse_new() has long returned. One mount per process, so one session.
 */
extern void fs_set_session(struct fs_session* session);

#endif /* HAVE_UHUB_FUSE_FS_H */
