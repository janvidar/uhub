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

#ifndef HAVE_UHUB_FUSE_RENDER_H
#define HAVE_UHUB_FUSE_RENDER_H

#include "system.h"
#include "adc/adctypes.h"
#include "fuse/nodes.h"

struct adc_message;

/**
 * Turning hub state into the bytes of a file.
 *
 * A metadata file is rendered once, at open(), and the snapshot is what the
 * reader sees for as long as the descriptor is open. That is deliberate: a
 * user's INF can be replaced between two read() calls of the same file, and a
 * reader that got the first half of one nick and the second half of another
 * would have no way to tell. A new open() sees the new value.
 *
 * The rendering is one value per file, terminated by a newline, so the mount
 * is usable from a shell without a parser. A field the user did not advertise
 * renders as an empty file -- except for the numeric ones (FS_FIELD_NUMERIC),
 * where "absent" and "zero" mean the same thing to every client that sends
 * them, and an empty file would only be a worse spelling of 0.
 */

/**
 * Everything the renderer may read.
 *
 * All strings may be NULL, which renders as absent. The caller fills in the
 * part that matches the node being rendered and leaves the rest zeroed.
 */
struct fs_render_ctx
{
	/* hub/ */
	const char* hub_state;       /** offline, connecting or online */
	const char* hub_name;
	const char* hub_description;
	const char* hub_version;
	const char* hub_address;
	const char* hub_support;     /** the hub's ISUP list */
	const char* tls_version;     /** NULL when the hub connection is plaintext */
	const char* tls_cipher;
	size_t      hub_users;

	/* me/ */
	const char* my_nick;
	const char* my_cid;
	const char* my_support;
	sid_t       my_sid;

	/* users/<cid>/ */
	struct adc_message* inf;     /** the stored BINF; may be NULL */
	sid_t               sid;
	time_t              since;   /** when this user was first seen */
};

/**
 * Render one metadata file.
 *
 * @param node  a resolved FS_NODE_{HUB,ME,USER}_FILE.
 * @param ctx   the state to render from.
 * @param buf   receives the contents; not NUL terminated, and untouched on
 *              failure. May be NULL together with a @p size of 0 to measure.
 * @param size  the space in @p buf.
 * @return the number of bytes the file holds, which may exceed @p size (in
 *         which case nothing was written), or -1 if @p node is not a file this
 *         module renders.
 */
extern ssize_t fs_render(const struct fs_node* node, const struct fs_render_ctx* ctx,
                         char* buf, size_t size);

/**
 * Format @p when as "2026-08-20T21:15:03Z", in UTC.
 * @return the number of bytes written, excluding the NUL, or 0 if it did not fit.
 */
extern size_t fs_render_timestamp(time_t when, char* buf, size_t size);

#endif /* HAVE_UHUB_FUSE_RENDER_H */
