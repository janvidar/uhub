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

#include "fuse/filelist.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"

#include <bzlib.h>
#include <ctype.h>

/** Growth step while decompressing, and the initial buffer. */
#define FS_FILELIST_CHUNK (256 * 1024)

struct fs_filelist
{
	struct fs_filelist_node* root;   /** First entry at the top level. */
	size_t count;
};

/* ------------------------------------------------------------ names */

int fs_filelist_safe_name(const char* name, char* buf, size_t size)
{
	size_t n = 0;

	if (!name || !buf || size < 2)
		return 0;

	for (; name[n]; n++)
	{
		unsigned char c = (unsigned char) name[n];

		if (n + 1 >= size)
			return 0;   /* Refused, not truncated: two long names would collide. */

		/* A separator would make one name into two path components, and a
		   control character is not something a filesystem should hand back. */
		if (c == '/' || c < 0x20 || c == 0x7f)
			buf[n] = '_';
		else
			buf[n] = (char) c;
	}

	buf[n] = '\0';

	if (n == 0 || strcmp(buf, ".") == 0 || strcmp(buf, "..") == 0)
		return 0;

	return 1;
}

/* ------------------------------------------------------- decompression */

char* fs_filelist_decompress(const void* data, size_t len, size_t* out_len)
{
	bz_stream stream;
	char* out;
	size_t capacity = FS_FILELIST_CHUNK;
	size_t used = 0;
	int rc;

	if (!data || !len)
		return NULL;

	/* bzlib speaks unsigned int, and a file list arriving in one piece is
	   bounded by the cache's per-file ceiling long before this. */
	if (len > UINT_MAX)
		return NULL;

	out = (char*) hub_malloc(capacity);
	if (!out)
		return NULL;

	memset(&stream, 0, sizeof(stream));
	if (BZ2_bzDecompressInit(&stream, 0, 0) != BZ_OK)
	{
		hub_free(out);
		return NULL;
	}

	stream.next_in = (char*) data;
	stream.avail_in = (unsigned int) len;

	for (;;)
	{
		stream.next_out = out + used;
		stream.avail_out = (unsigned int) (capacity - used);

		rc = BZ2_bzDecompress(&stream);
		used = capacity - stream.avail_out;

		if (rc == BZ_STREAM_END)
			break;

		if (rc != BZ_OK)
		{
			BZ2_bzDecompressEnd(&stream);
			hub_free(out);
			return NULL;
		}

		if (stream.avail_out == 0)
		{
			char* bigger;

			/*
			 * A compression bomb is a few kilobytes that expand without end,
			 * and this runs against bytes a stranger sent. The ceiling is what
			 * stops it; growing geometrically only decides how often we ask
			 * for more memory on the way there.
			 */
			if (capacity >= FS_FILELIST_MAX)
			{
				LOG_DEBUG("filelist: refusing a list larger than %d bytes", FS_FILELIST_MAX);
				BZ2_bzDecompressEnd(&stream);
				hub_free(out);
				return NULL;
			}

			capacity = (capacity > FS_FILELIST_MAX / 2) ? FS_FILELIST_MAX : capacity * 2;

			bigger = (char*) hub_realloc(out, capacity);
			if (!bigger)
			{
				BZ2_bzDecompressEnd(&stream);
				hub_free(out);
				return NULL;
			}
			out = bigger;
			continue;
		}

		if (stream.avail_in == 0 && stream.avail_out != 0)
		{
			/* The stream ended without saying so: truncated. */
			BZ2_bzDecompressEnd(&stream);
			hub_free(out);
			return NULL;
		}
	}

	BZ2_bzDecompressEnd(&stream);

	if (out_len)
		*out_len = used;

	return out;
}

/* -------------------------------------------------------------- XML */

/*
 * Not a general XML parser, and not trying to be one.
 *
 * A file list is a document with three element types and five attributes, and
 * anything else in it is of no interest. So this scans for the elements it
 * knows and steps over everything else -- comments, processing instructions,
 * namespaces, whatever a generator saw fit to add -- rather than modelling a
 * language. What it will not do is grow a feature that reads from anywhere but
 * the buffer it was given: no entity definitions, no external references, no
 * DTD. Those are how XML parsers become file-disclosure bugs, and a file list
 * has never needed any of them.
 */

struct fl_parser
{
	const char* data;
	size_t len;
	size_t pos;
	struct fs_filelist* list;
	struct fs_filelist_node* parent;    /** NULL at the top level. */
	struct fs_filelist_node* last;      /** Last node added to @c parent. */
	int depth;
};

static int fl_eof(struct fl_parser* p)
{
	return p->pos >= p->len;
}

static void fl_skip_space(struct fl_parser* p)
{
	while (!fl_eof(p) && is_white_space(p->data[p->pos]))
		p->pos++;
}

/** Decode the five named entities and numeric references, in place. */
static void fl_decode_entities(char* text)
{
	char* out = text;
	char* in = text;

	while (*in)
	{
		if (*in != '&')
		{
			*out++ = *in++;
			continue;
		}

		if (strncmp(in, "&amp;", 5) == 0)       { *out++ = '&';  in += 5; }
		else if (strncmp(in, "&lt;", 4) == 0)   { *out++ = '<';  in += 4; }
		else if (strncmp(in, "&gt;", 4) == 0)   { *out++ = '>';  in += 4; }
		else if (strncmp(in, "&quot;", 6) == 0) { *out++ = '"';  in += 6; }
		else if (strncmp(in, "&apos;", 6) == 0) { *out++ = '\''; in += 6; }
		else if (in[1] == '#')
		{
			unsigned long value = 0;
			char* end = NULL;
			int hex = (in[2] == 'x' || in[2] == 'X');

			errno = 0;
			value = strtoul(&in[hex ? 3 : 2], &end, hex ? 16 : 10);

			if (!end || *end != ';' || errno == ERANGE || value == 0 || value > 0x10FFFF)
			{
				*out++ = *in++;   /* Not a reference; an ampersand is just an ampersand. */
				continue;
			}

			/* Encoded as UTF-8, because that is what the rest of the mount is.
			   A surrogate or an overlong form is not written at all. */
			if (value < 0x80)
			{
				*out++ = (char) value;
			}
			else if (value < 0x800)
			{
				*out++ = (char) (0xC0 | (value >> 6));
				*out++ = (char) (0x80 | (value & 0x3F));
			}
			else if (value >= 0xD800 && value <= 0xDFFF)
			{
				/* Not a character. */
			}
			else if (value < 0x10000)
			{
				*out++ = (char) (0xE0 | (value >> 12));
				*out++ = (char) (0x80 | ((value >> 6) & 0x3F));
				*out++ = (char) (0x80 | (value & 0x3F));
			}
			else
			{
				*out++ = (char) (0xF0 | (value >> 18));
				*out++ = (char) (0x80 | ((value >> 12) & 0x3F));
				*out++ = (char) (0x80 | ((value >> 6) & 0x3F));
				*out++ = (char) (0x80 | (value & 0x3F));
			}

			in = end + 1;
		}
		else
		{
			*out++ = *in++;
		}
	}

	*out = '\0';
}

/** One attribute: name="value". @return 1 if one was read. */
static int fl_read_attribute(struct fl_parser* p, char* name, size_t name_size,
                             char* value, size_t value_size)
{
	size_t n = 0;
	char quote;

	fl_skip_space(p);

	while (!fl_eof(p) && (isalnum((unsigned char) p->data[p->pos]) ||
	                      p->data[p->pos] == '_' || p->data[p->pos] == '-' ||
	                      p->data[p->pos] == ':'))
	{
		if (n + 1 < name_size)
			name[n++] = p->data[p->pos];
		p->pos++;
	}

	name[n < name_size ? n : name_size - 1] = '\0';

	if (!n)
		return 0;

	fl_skip_space(p);
	if (fl_eof(p) || p->data[p->pos] != '=')
		return 0;
	p->pos++;

	fl_skip_space(p);
	if (fl_eof(p) || (p->data[p->pos] != '"' && p->data[p->pos] != '\''))
		return 0;

	quote = p->data[p->pos++];

	n = 0;
	while (!fl_eof(p) && p->data[p->pos] != quote)
	{
		if (n + 1 >= value_size)
			return 0;   /* An oversized attribute is a refusal, not a truncation. */

		value[n++] = p->data[p->pos++];
	}

	if (fl_eof(p))
		return 0;

	p->pos++;   /* the closing quote */
	value[n] = '\0';
	fl_decode_entities(value);
	return 1;
}

static struct fs_filelist_node* fl_new_node(struct fl_parser* p, const char* raw_name, int is_dir)
{
	struct fs_filelist_node* node;
	char safe[FS_FILELIST_NAME_MAX + 1];

	if (p->list->count >= FS_FILELIST_MAX_NODES)
		return NULL;

	if (!fs_filelist_safe_name(raw_name, safe, sizeof(safe)))
		return NULL;

	node = (struct fs_filelist_node*) hub_malloc_zero(sizeof(struct fs_filelist_node));
	if (!node)
		return NULL;

	node->name = hub_strdup(safe);
	if (!node->name)
	{
		hub_free(node);
		return NULL;
	}

	node->is_dir = is_dir;
	node->parent = p->parent;

	/* Appended in document order, so a listing comes out the way the peer
	   wrote it rather than reversed. */
	if (p->last)
		p->last->next = node;
	else if (p->parent)
		p->parent->children = node;
	else
		p->list->root = node;

	p->last = node;
	p->list->count++;
	return node;
}

static void fl_free_nodes(struct fs_filelist_node* node)
{
	while (node)
	{
		struct fs_filelist_node* next = node->next;

		fl_free_nodes(node->children);
		hub_free(node->name);
		hub_free(node);
		node = next;
	}
}

/** Skip to the end of the current tag. @return 1 if it was self-closing. */
static int fl_skip_tag(struct fl_parser* p)
{
	int self_closing = 0;

	while (!fl_eof(p) && p->data[p->pos] != '>')
	{
		if (p->data[p->pos] == '/')
			self_closing = 1;
		p->pos++;
	}

	if (!fl_eof(p))
		p->pos++;

	return self_closing;
}

/** Read the tag name at the current position into @p out. */
static void fl_read_tag_name(struct fl_parser* p, char* out, size_t size)
{
	size_t n = 0;

	while (!fl_eof(p) && (isalnum((unsigned char) p->data[p->pos]) ||
	                      p->data[p->pos] == '_' || p->data[p->pos] == '-' ||
	                      p->data[p->pos] == ':'))
	{
		if (n + 1 < size)
			out[n++] = p->data[p->pos];
		p->pos++;
	}

	out[n] = '\0';
}

static int fl_parse_file(struct fl_parser* p)
{
	char name[512];
	char value[512];
	char file_name[FS_FILELIST_NAME_MAX * 4 + 1];
	char tth[MAX_CID_LEN + 1];
	uint64_t size = 0;
	int have_name = 0;

	file_name[0] = '\0';
	tth[0] = '\0';

	for (;;)
	{
		fl_skip_space(p);

		if (fl_eof(p))
			return 0;

		if (p->data[p->pos] == '/' || p->data[p->pos] == '>')
			break;

		if (!fl_read_attribute(p, name, sizeof(name), value, sizeof(value)))
			return 0;

		if (strcmp(name, "Name") == 0)
		{
			snprintf(file_name, sizeof(file_name), "%s", value);
			have_name = 1;
		}
		else if (strcmp(name, "Size") == 0)
		{
			char* end = NULL;
			errno = 0;
			size = strtoull(value, &end, 10);
			if (!end || *end != '\0' || errno == ERANGE)
				size = 0;
		}
		else if (strcmp(name, "TTH") == 0)
		{
			if (strlen(value) == MAX_CID_LEN)
			{
				size_t i;
				int ok = 1;

				for (i = 0; i < MAX_CID_LEN; i++)
					if (!is_valid_base32_char(value[i]))
						ok = 0;

				if (ok)
					memcpy(tth, value, MAX_CID_LEN + 1);
			}
		}
	}

	fl_skip_tag(p);

	/*
	 * A file with no name cannot be listed and a file with no hash cannot be
	 * fetched, so neither is kept. Skipping it is not an error: a list may
	 * hold anything, and one unusable entry is no reason to lose the rest.
	 */
	if (have_name && *tth)
	{
		struct fs_filelist_node* node = fl_new_node(p, file_name, 0);
		if (node)
		{
			node->size = size;
			memcpy(node->tth, tth, sizeof(node->tth));
		}
	}

	return 1;
}

static int fl_parse_directory_open(struct fl_parser* p, struct fs_filelist_node** out,
                                   int* self_closing)
{
	char name[512];
	char value[512];
	char dir_name[FS_FILELIST_NAME_MAX * 4 + 1];
	int have_name = 0;

	dir_name[0] = '\0';
	*out = NULL;

	for (;;)
	{
		fl_skip_space(p);

		if (fl_eof(p))
			return 0;

		if (p->data[p->pos] == '/' || p->data[p->pos] == '>')
			break;

		if (!fl_read_attribute(p, name, sizeof(name), value, sizeof(value)))
			return 0;

		if (strcmp(name, "Name") == 0)
		{
			snprintf(dir_name, sizeof(dir_name), "%s", value);
			have_name = 1;
		}
	}

	*self_closing = fl_skip_tag(p);

	if (have_name)
		*out = fl_new_node(p, dir_name, 1);

	return 1;
}

struct fs_filelist* fs_filelist_parse(const char* data, size_t len)
{
	struct fl_parser p;
	struct fs_filelist* list;

	/* Where the walk came from, so a </Directory> can go back up without
	   recursion: a list is attacker-supplied and its nesting must not decide
	   how much stack this uses. */
	struct fs_filelist_node* stack[FS_FILELIST_MAX_DEPTH];
	struct fs_filelist_node* last_stack[FS_FILELIST_MAX_DEPTH];

	if (!data || !len || len > FS_FILELIST_MAX)
		return NULL;

	list = (struct fs_filelist*) hub_malloc_zero(sizeof(struct fs_filelist));
	if (!list)
		return NULL;

	memset(&p, 0, sizeof(p));
	p.data = data;
	p.len = len;
	p.list = list;

	while (!fl_eof(&p))
	{
		char tag[64];

		/* Anything that is not a tag is text between tags, which a file list
		   has no use for. */
		if (p.data[p.pos] != '<')
		{
			p.pos++;
			continue;
		}

		p.pos++;

		if (fl_eof(&p))
			break;

		/* <?xml ... ?>, <!-- ... -->, <!DOCTYPE ...>: stepped over, never
		   interpreted. A DOCTYPE in particular is where an XML parser would
		   start reading things it was not given. */
		if (p.data[p.pos] == '?' || p.data[p.pos] == '!')
		{
			fl_skip_tag(&p);
			continue;
		}

		if (p.data[p.pos] == '/')
		{
			p.pos++;
			fl_read_tag_name(&p, tag, sizeof(tag));
			fl_skip_tag(&p);

			if (strcmp(tag, "Directory") == 0 && p.depth > 0)
			{
				p.depth--;
				p.parent = stack[p.depth];
				p.last = last_stack[p.depth];
			}
			continue;
		}

		fl_read_tag_name(&p, tag, sizeof(tag));

		if (strcmp(tag, "File") == 0)
		{
			if (!fl_parse_file(&p))
				break;
		}
		else if (strcmp(tag, "Directory") == 0)
		{
			struct fs_filelist_node* node = NULL;
			int self_closing = 0;

			if (!fl_parse_directory_open(&p, &node, &self_closing))
				break;

			if (self_closing || !node)
				continue;   /* An empty directory, or one we could not name. */

			if (p.depth >= FS_FILELIST_MAX_DEPTH)
			{
				LOG_DEBUG("filelist: refusing a list nested deeper than %d", FS_FILELIST_MAX_DEPTH);
				fl_free_nodes(list->root);
				hub_free(list);
				return NULL;
			}

			stack[p.depth] = p.parent;
			last_stack[p.depth] = p.last;
			p.depth++;

			p.parent = node;
			p.last = NULL;
		}
		else
		{
			fl_skip_tag(&p);
		}
	}

	return list;
}

struct fs_filelist* fs_filelist_load(const void* bz2, size_t len)
{
	struct fs_filelist* list;
	size_t plain_len = 0;
	char* plain = fs_filelist_decompress(bz2, len, &plain_len);

	if (!plain)
		return NULL;

	list = fs_filelist_parse(plain, plain_len);
	hub_free(plain);
	return list;
}

void fs_filelist_destroy(struct fs_filelist* list)
{
	if (!list)
		return;

	fl_free_nodes(list->root);
	hub_free(list);
}

struct fs_filelist_node* fs_filelist_root(struct fs_filelist* list)
{
	return list ? list->root : NULL;
}

size_t fs_filelist_count(struct fs_filelist* list)
{
	return list ? list->count : 0;
}

struct fs_filelist_node* fs_filelist_lookup(struct fs_filelist* list, const char* path)
{
	struct fs_filelist_node* node;
	const char* pos;

	if (!list || !path)
		return NULL;

	node = list->root;
	pos = path;

	while (*pos && node)
	{
		const char* end = strchr(pos, '/');
		size_t len = end ? (size_t) (end - pos) : strlen(pos);
		struct fs_filelist_node* found = NULL;

		if (!len)
			return NULL;   /* An empty component is not a path. */

		for (; node; node = node->next)
		{
			if (strlen(node->name) == len && memcmp(node->name, pos, len) == 0)
			{
				found = node;
				break;
			}
		}

		if (!found)
			return NULL;

		if (!end || !end[1])
			return found;

		if (!found->is_dir)
			return NULL;   /* Something below a file: there is nothing there. */

		node = found->children;
		pos = end + 1;
	}

	return NULL;
}
