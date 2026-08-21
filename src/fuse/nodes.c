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

#include "fuse/nodes.h"
#include "adc/adcconst.h"
#include "util/misc.h"

const struct fs_field fs_hub_fields[] = {
	{ "state",       NULL,                     FS_FIELD_READ },
	{ "name",        NULL,                     FS_FIELD_READ },
	{ "description", NULL,                     FS_FIELD_READ },
	{ "version",     NULL,                     FS_FIELD_READ },
	{ "address",     NULL,                     FS_FIELD_READ },
	{ "support",     NULL,                     FS_FIELD_READ },
	{ "users",       NULL,                     FS_FIELD_READ | FS_FIELD_NUMERIC },
	{ "sid",         NULL,                     FS_FIELD_READ },
	{ "tls",         NULL,                     FS_FIELD_READ },
	{ NULL,          NULL,                     0 }
};

const struct fs_field fs_me_fields[] = {
	{ "nick",        NULL, FS_FIELD_READ },
	{ "cid",         NULL, FS_FIELD_READ },
	{ "sid",         NULL, FS_FIELD_READ },
	{ "support",     NULL, FS_FIELD_READ },
	{ NULL,          NULL, 0 }
};

const struct fs_field fs_user_fields[] = {
	{ "nick",         ADC_INF_FLAG_NICK,               FS_FIELD_READ },
	{ "description",  ADC_INF_FLAG_DESCRIPTION,        FS_FIELD_READ },
	{ "share_size",   ADC_INF_FLAG_SHARED_SIZE,        FS_FIELD_READ | FS_FIELD_NUMERIC },
	{ "shared_files", ADC_INF_FLAG_SHARED_FILES,       FS_FIELD_READ | FS_FIELD_NUMERIC },
	{ "slots",        ADC_INF_FLAG_UPLOAD_SLOTS,       FS_FIELD_READ | FS_FIELD_NUMERIC },
	{ "ip",           NULL,                            FS_FIELD_READ },
	{ "user_agent",   ADC_INF_FLAG_USER_AGENT_PRODUCT, FS_FIELD_READ },
	{ "version",      ADC_INF_FLAG_USER_AGENT_VERSION, FS_FIELD_READ },
	{ "client_type",  ADC_INF_FLAG_CLIENT_TYPE,        FS_FIELD_READ | FS_FIELD_NUMERIC },
	{ "support",      ADC_INF_FLAG_SUPPORT,            FS_FIELD_READ },
	{ "sid",          NULL,                            FS_FIELD_READ },
	{ "connected",    NULL,                            FS_FIELD_READ },
	{ "inf",          NULL,                            FS_FIELD_READ | FS_FIELD_RAW_INF },
	{ "msg",          NULL,                            FS_FIELD_WRITE },
	{ NULL,           NULL,                            0 }
};

const struct fs_field* fs_field_lookup(const struct fs_field* table, const char* name)
{
	size_t n;

	if (!table || !name)
		return NULL;

	for (n = 0; table[n].name; n++)
		if (strcmp(table[n].name, name) == 0)
			return &table[n];

	return NULL;
}

int fs_is_base32_hash(const char* name)
{
	size_t n;

	if (!name)
		return 0;

	for (n = 0; n < MAX_CID_LEN; n++)
		if (!name[n] || !is_valid_base32_char(name[n]))
			return 0;

	return name[MAX_CID_LEN] == '\0';
}

size_t fs_sanitize_nick(const char* nick, char* buf, size_t size)
{
	size_t n = 0;

	if (!buf || !size)
		return 0;

	if (nick)
	{
		for (; nick[n] && n + 1 < size; n++)
		{
			unsigned char c = (unsigned char) nick[n];

			/* A path separator, a control character or DEL would either split
			   the name in two or render as a hole in a terminal. Bytes >= 0x80
			   are left alone: a nick is UTF-8 and so is the mount. */
			if (c == '/' || c < 0x20 || c == 0x7f)
				buf[n] = '_';
			else
				buf[n] = (char) c;
		}
	}
	buf[n] = '\0';

	/* "" cannot be a name at all, and "." and ".." already mean something. */
	if (n == 0 || strcmp(buf, ".") == 0 || strcmp(buf, "..") == 0)
	{
		n = (size > 4) ? 4 : size - 1;
		memcpy(buf, "user", n);
		buf[n] = '\0';
	}

	return n;
}

/* -------------------------------------------------------------- path walking */

struct path_iter
{
	const char* p;   /** At a '/' separator, or at the terminating NUL. */
	int bad;         /** An empty, "." or ".." component was seen. */
};

/**
 * Take the next component.
 *
 * A trailing slash ends the walk ("/hub/" is "/hub"); an embedded empty
 * component, "." or ".." sets @c bad and ends it. @return 1 on success.
 */
static int path_next(struct path_iter* it, const char** out, size_t* len)
{
	const char* s = it->p;
	const char* e;

	if (it->bad || !s || *s != '/')
		return 0;

	s++;
	if (*s == '\0')
	{
		it->p = s;
		return 0;
	}

	if (*s == '/')
	{
		it->bad = 1;
		return 0;
	}

	e = strchr(s, '/');
	if (!e)
		e = s + strlen(s);

	if ((e - s) == 1 && s[0] == '.')
	{
		it->bad = 1;
		return 0;
	}

	if ((e - s) == 2 && s[0] == '.' && s[1] == '.')
	{
		it->bad = 1;
		return 0;
	}

	*out = s;
	*len = (size_t) (e - s);
	it->p = e;
	return 1;
}

/** Is @p comp, which is not NUL terminated, equal to @p str? */
static int comp_is(const char* comp, size_t len, const char* str)
{
	return strlen(str) == len && memcmp(comp, str, len) == 0;
}

/**
 * Copy a component out, refusing one that does not fit.
 * @return 1 on success.
 */
static int comp_copy(const char* comp, size_t len, char* buf, size_t size)
{
	if (len >= size)
		return 0;

	memcpy(buf, comp, len);
	buf[len] = '\0';
	return 1;
}

/** Walk what is left, so a bad component anywhere in it is refused. */
static int path_tail_ok(struct path_iter* it)
{
	const char* comp;
	size_t len;

	while (path_next(it, &comp, &len))
		; /* nothing: path_next does the checking */

	return !it->bad;
}

/* Everything below files/ resolves to one node type; the difference is only
   whether there is anything below it at all. */
static void resolve_user_files(struct path_iter* it, struct fs_node* out)
{
	const char* tail = it->p;

	if (*tail == '\0' || (tail[0] == '/' && tail[1] == '\0'))
	{
		out->type = FS_NODE_USER_FILES_DIR;
		return;
	}

	if (!path_tail_ok(it))
		return;

	out->type = FS_NODE_USER_FILES_ENTRY;
	out->tail = tail + 1;
}

static void resolve_user(struct path_iter* it, struct fs_node* out)
{
	const struct fs_field* field;
	const char* comp;
	size_t len;
	char name[MAX_NICK_LEN + 1];

	if (!path_next(it, &comp, &len))
	{
		if (!it->bad)
			out->type = FS_NODE_USER_DIR;
		return;
	}

	if (comp_is(comp, len, "files"))
	{
		resolve_user_files(it, out);
		return;
	}

	if (!comp_copy(comp, len, name, sizeof(name)))
		return;

	/* Nothing may follow a metadata file. */
	if (path_next(it, &comp, &len) || it->bad)
		return;

	field = fs_field_lookup(fs_user_fields, name);
	if (!field)
		return;

	out->field = field;
	out->type = (field->flags & FS_FIELD_WRITE) ? FS_NODE_USER_MSG : FS_NODE_USER_FILE;
}

/** hub/ and me/: a directory of metadata files and nothing else. */
static void resolve_field_dir(struct path_iter* it, struct fs_node* out,
                              const struct fs_field* table,
                              enum fs_node_type dir_type, enum fs_node_type file_type)
{
	const struct fs_field* field;
	const char* comp;
	size_t len;
	char name[MAX_NICK_LEN + 1];

	if (!path_next(it, &comp, &len))
	{
		if (!it->bad)
			out->type = dir_type;
		return;
	}

	if (!comp_copy(comp, len, name, sizeof(name)))
		return;

	if (path_next(it, &comp, &len) || it->bad)
		return;

	field = fs_field_lookup(table, name);
	if (!field)
		return;

	out->field = field;
	out->type = file_type;
}

int fs_node_resolve(const char* path, struct fs_node* out)
{
	struct path_iter it;
	const char* comp;
	size_t len;

	if (!out)
		return 0;

	memset(out, 0, sizeof(*out));

	if (!path || path[0] != '/')
		return 0;

	it.p = path;
	it.bad = 0;

	if (!path_next(&it, &comp, &len))
	{
		if (!it.bad)
			out->type = FS_NODE_ROOT;
		return out->type != FS_NODE_NONE;
	}

	if (comp_is(comp, len, "hub"))
	{
		resolve_field_dir(&it, out, fs_hub_fields, FS_NODE_HUB_DIR, FS_NODE_HUB_FILE);
	}
	else if (comp_is(comp, len, "me"))
	{
		resolve_field_dir(&it, out, fs_me_fields, FS_NODE_ME_DIR, FS_NODE_ME_FILE);
	}
	else if (comp_is(comp, len, "chat"))
	{
		if (!path_next(&it, &comp, &len))
		{
			if (!it.bad)
				out->type = FS_NODE_CHAT_DIR;
		}
		else if (comp_is(comp, len, "main") && !path_next(&it, &comp, &len) && !it.bad)
		{
			out->type = FS_NODE_CHAT_MAIN;
		}
		else if (comp_is(comp, len, "private") && !path_next(&it, &comp, &len) && !it.bad)
		{
			out->type = FS_NODE_CHAT_PRIVATE;
		}
	}
	else if (comp_is(comp, len, "users"))
	{
		if (!path_next(&it, &comp, &len))
		{
			if (!it.bad)
				out->type = FS_NODE_USERS_DIR;
		}
		else if (comp_copy(comp, len, out->cid, sizeof(out->cid)) && fs_is_base32_hash(out->cid))
		{
			resolve_user(&it, out);
		}
	}
	else if (comp_is(comp, len, "by-nick"))
	{
		if (!path_next(&it, &comp, &len))
		{
			if (!it.bad)
				out->type = FS_NODE_BY_NICK_DIR;
		}
		else if (comp_copy(comp, len, out->name, sizeof(out->name)))
		{
			if (!path_next(&it, &comp, &len) && !it.bad)
				out->type = FS_NODE_BY_NICK_LINK;
		}
	}
	else if (comp_is(comp, len, "by-tth"))
	{
		if (!path_next(&it, &comp, &len))
		{
			if (!it.bad)
				out->type = FS_NODE_BY_TTH_DIR;
		}
		else if (comp_copy(comp, len, out->name, sizeof(out->name)) && fs_is_base32_hash(out->name))
		{
			if (!path_next(&it, &comp, &len) && !it.bad)
				out->type = FS_NODE_BY_TTH_FILE;
		}
	}

	if (out->type == FS_NODE_NONE)
	{
		memset(out, 0, sizeof(*out));
		return 0;
	}

	return 1;
}
