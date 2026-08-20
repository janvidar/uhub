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

#include "system.h"

#include "adc/adcconst.h"
#include "adc/message.h"
#include "seeder/embed.h"
#include "seeder/post.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"

/*
 * The parameters this reader knows, in the order BBS0 requires a composer to
 * emit them. Canonical form is checked against this table rather than against a
 * hand-written sequence of comparisons, so adding a field later cannot get the
 * ordering rule out of step with the parser.
 *
 * SG and KY are deliberately absent. They are reserved for a future extension
 * adding cryptographic authorship, and a BBS0 reader must ignore them -- which
 * here means treating them as the unrecognised parameters they are, so a
 * document carrying one is read and not rejected.
 */
static const char* const post_fields[] = {
	ADC_INF_FLAG_CLIENT_ID,  /* ID */
	ADC_BBS_FLAG_PARENT,     /* PA */
	ADC_BBS_FLAG_SUBJECT,    /* SJ */
	ADC_BBS_FLAG_COMPOSED,   /* DA */
	ADC_MSG_FLAG_RICH_TEXT   /* RT */
};

#define POST_NUM_FIELDS (sizeof(post_fields) / sizeof(post_fields[0]))

/* Position of a name in post_fields, or POST_NUM_FIELDS when unrecognised. */
static size_t post_field_index(const char* name)
{
	size_t i;

	for (i = 0; i < POST_NUM_FIELDS; i++)
	{
		if (name[0] == post_fields[i][0] && name[1] == post_fields[i][1])
			return i;
	}
	return POST_NUM_FIELDS;
}

static int post_all_base32(const char* str, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
	{
		if (!is_valid_base32_char(str[i]))
			return 0;
	}
	return len > 0;
}

/* An unsigned decimal, with no sign, no space and no overflow. */
static int post_parse_uint(const char* str, uint64_t* out)
{
	uint64_t value = 0;
	size_t i;

	if (!str || !*str)
		return 0;

	for (i = 0; str[i]; i++)
	{
		if (str[i] < '0' || str[i] > '9')
			return 0;
		if (value > (UINT64_MAX - (uint64_t) (str[i] - '0')) / 10)
			return 0;
		value = value * 10 + (uint64_t) (str[i] - '0');
	}

	*out = value;
	return 1;
}

static int post_fail(enum seed_post_error* error, enum seed_post_error code)
{
	if (error)
		*error = code;
	return 0;
}

/*
 * Walk the raw header and check it is in canonical form.
 *
 * This runs on the escaped text rather than on the parsed message, because
 * every rule here is about the text: a repeated parameter, an empty value and a
 * doubled space all survive parsing intact and are only visible before it.
 *
 * @param header the header, without its terminating LF.
 * @param len its length.
 */
static int post_header_is_canonical(const char* header, size_t len)
{
	size_t pos = 4; /* past the FOURCC */
	size_t highest = 0;
	int seen_unknown = 0;
	unsigned int seen_mask = 0;

	while (pos < len)
	{
		size_t name_at;
		size_t value_at;
		size_t index;

		/* Exactly one space between the FOURCC and each parameter, and between
		   parameters. A doubled space would parse as an empty argument. */
		if (header[pos] != ' ')
			return 0;
		pos++;
		if (pos >= len || header[pos] == ' ')
			return 0;

		/* A named parameter is a two character name and a value. */
		name_at = pos;
		if (len - name_at < 3)
			return 0;
		value_at = name_at + 2;
		if (header[value_at] == ' ')
			return 0; /* present but empty */

		index = post_field_index(header + name_at);
		if (index == POST_NUM_FIELDS)
		{
			/* Unrecognised: legal, ignored, and required to come last. */
			seen_unknown = 1;
		}
		else
		{
			if (seen_unknown)
				return 0; /* a known parameter after an unknown one */
			if (seen_mask & (1u << index))
				return 0; /* repeated */
			if (index < highest)
				return 0; /* out of order */

			seen_mask |= 1u << index;
			highest = index;
		}

		/* Advance to the next space, which starts the next parameter. A
		   backslash escape never introduces one: the escaped forms are \s, \n
		   and \\, and adc_msg_parse() has already refused any other. */
		while (pos < len && header[pos] != ' ')
			pos++;
	}

	return 1;
}

int seed_post_parse(const void* data, size_t len, struct seed_post* out, enum seed_post_error* error)
{
	const char* bytes = (const char*) data;
	const char* lf;
	size_t header_len;
	size_t scan;
	struct adc_message* msg;
	struct seed_post post;
	char* arg;

	if (error)
		*error = SEED_POST_OK;

	if (!bytes || len == 0)
		return post_fail(error, SEED_POST_ERR_NO_HEADER);

	/*
	 * Find the header terminator, refusing to look further than BBS0 allows.
	 * memchr is bounded and the body may contain NUL, so the search is over
	 * bytes and never over a string.
	 */
	scan = len < SEED_POST_HEADER_MAX ? len : SEED_POST_HEADER_MAX;
	lf = (const char*) memchr(bytes, '\n', scan);
	if (!lf)
		return post_fail(error, SEED_POST_ERR_NO_HEADER);

	header_len = (size_t) (lf - bytes);

	if (header_len < 4)
		return post_fail(error, SEED_POST_ERR_FOURCC);

	if (memcmp(bytes, "IBB0", 4) != 0)
		return post_fail(error, SEED_POST_ERR_FOURCC);

	/*
	 * A CR before the terminating LF is not part of the grammar. It is checked
	 * before parsing because a document with CRLF line endings is a different
	 * document that happens to look like this one, and repairing it would
	 * change the hash.
	 */
	if (header_len > 0 && bytes[header_len - 1] == '\r')
		return post_fail(error, SEED_POST_ERR_SYNTAX);

	/*
	 * Read the header with the parser the rest of the tree uses. That is the
	 * whole reason BBS0 made it a real ADC message: escape validation, the
	 * printable-UTF-8 rule and named argument extraction all come for free, and
	 * an unknown escape is refused here rather than in a private copy of the
	 * same logic. The LF is included, which is what adc_msg_parse() expects.
	 */
	msg = adc_msg_parse(bytes, header_len + 1);
	if (!msg)
		return post_fail(error, SEED_POST_ERR_SYNTAX);

	if (msg->cmd != ADC_CMD_IBB0)
	{
		adc_msg_free(msg);
		return post_fail(error, SEED_POST_ERR_FOURCC);
	}

	if (!post_header_is_canonical(bytes, header_len))
	{
		adc_msg_free(msg);
		return post_fail(error, SEED_POST_ERR_CANONICAL);
	}

	memset(&post, 0, sizeof(post));
	post.body_offset = header_len + 1;
	post.body_length = len - post.body_offset;

	/* ID: required, base32, and no longer than a CID. Its length follows the
	   session hash, so it is not compared against 39. */
	arg = adc_msg_get_named_argument(msg, ADC_INF_FLAG_CLIENT_ID);
	if (!arg)
	{
		adc_msg_free(msg);
		return post_fail(error, SEED_POST_ERR_MISSING);
	}
	if (strlen(arg) > MAX_CID_LEN || !post_all_base32(arg, strlen(arg)))
	{
		hub_free(arg);
		adc_msg_free(msg);
		return post_fail(error, SEED_POST_ERR_FIELD);
	}
	strcpy(post.author_cid, arg);
	hub_free(arg);

	/* PA: a TTH, and exactly one, when the post is a reply. */
	arg = adc_msg_get_named_argument(msg, ADC_BBS_FLAG_PARENT);
	if (arg)
	{
		if (strlen(arg) != SEED_TTH_STR_LEN || !post_all_base32(arg, SEED_TTH_STR_LEN))
		{
			hub_free(arg);
			adc_msg_free(msg);
			return post_fail(error, SEED_POST_ERR_FIELD);
		}
		strcpy(post.parent, arg);
		hub_free(arg);
	}

	/*
	 * SJ: required in a post that starts a thread.
	 *
	 * The only field here that has to be unescaped: it is free text, so "\\s"
	 * and "\\n" in it are a space and a newline and not those two characters.
	 * The others need no unescaping because an escape in any of them makes the
	 * value invalid anyway -- ID and PA are base32, DA and RT are decimal, and
	 * a backslash is in neither alphabet.
	 *
	 * A newline is then refused rather than trimmed: the composer was told not
	 * to emit one, and trimming would produce a different subject under a hash
	 * that no longer matched.
	 */
	arg = adc_msg_get_named_argument(msg, ADC_BBS_FLAG_SUBJECT);
	if (arg)
	{
		char* subject = adc_msg_unescape(arg);

		hub_free(arg);
		if (!subject)
		{
			adc_msg_free(msg);
			return post_fail(error, SEED_POST_ERR_SYNTAX);
		}

		if (strchr(subject, '\n'))
		{
			hub_free(subject);
			adc_msg_free(msg);
			return post_fail(error, SEED_POST_ERR_CANONICAL);
		}
		if (strlen(subject) >= sizeof(post.subject))
		{
			hub_free(subject);
			adc_msg_free(msg);
			return post_fail(error, SEED_POST_ERR_FIELD);
		}
		strcpy(post.subject, subject);
		hub_free(subject);
	}
	else if (!*post.parent)
	{
		adc_msg_free(msg);
		return post_fail(error, SEED_POST_ERR_MISSING);
	}

	/* DA: the author's claim about when this was written. Nothing verifies it,
	   and it is never used to order anything. */
	arg = adc_msg_get_named_argument(msg, ADC_BBS_FLAG_COMPOSED);
	if (arg)
	{
		if (!post_parse_uint(arg, &post.composed))
		{
			hub_free(arg);
			adc_msg_free(msg);
			return post_fail(error, SEED_POST_ERR_FIELD);
		}
		hub_free(arg);
	}

	/*
	 * RT: 1 means the body is RTF0 rich text. Other values are reserved, and a
	 * reader that does not recognise one treats the body as plain text -- so an
	 * unknown value is not an error, it just means no attachments are looked
	 * for. A non-numeric value is malformed and is refused.
	 */
	arg = adc_msg_get_named_argument(msg, ADC_MSG_FLAG_RICH_TEXT);
	if (arg)
	{
		uint64_t value = 0;

		if (!post_parse_uint(arg, &value))
		{
			hub_free(arg);
			adc_msg_free(msg);
			return post_fail(error, SEED_POST_ERR_FIELD);
		}
		post.rich_text = (value == 1) ? 1 : 0;
		hub_free(arg);
	}

	adc_msg_free(msg);

	if (out)
		*out = post;

	return 1;
}

const char* seed_post_error_string(enum seed_post_error error)
{
	switch (error)
	{
		case SEED_POST_OK:            return "ok";
		case SEED_POST_ERR_NO_HEADER: return "no header terminator within the first 8192 bytes";
		case SEED_POST_ERR_FOURCC:    return "does not begin with IBB0";
		case SEED_POST_ERR_SYNTAX:    return "header is not a well formed ADC message";
		case SEED_POST_ERR_CANONICAL: return "header is not in canonical form";
		case SEED_POST_ERR_MISSING:   return "a required field is missing";
		case SEED_POST_ERR_FIELD:     return "a field is malformed";
	}
	return "unknown";
}

size_t seed_post_attachments(const void* data, size_t len, const struct seed_post* post,
	struct seed_embed* out, size_t max)
{
	const char* bytes = (const char*) data;
	struct seed_embed found[SEED_POST_MAX_ATTACHMENTS];
	char* text;
	const char* nul;
	size_t body_len;
	size_t count;
	size_t kept = 0;
	size_t i;

	if (!bytes || !post || !out || max == 0)
		return 0;

	/* A plain text body displays literally, so a magnet URI in one is text the
	   author typed and not a reference to act on. */
	if (!post->rich_text)
		return 0;

	if (post->body_offset >= len)
		return 0;

	body_len = len - post->body_offset;
	if (body_len > SEED_POST_SCAN_MAX)
		body_len = SEED_POST_SCAN_MAX;

	/* The scanner takes a NUL terminated string and a document need not be
	   text, so the scan stops at the first NUL rather than reading past it. */
	nul = (const char*) memchr(bytes + post->body_offset, '\0', body_len);
	if (nul)
		body_len = (size_t) (nul - (bytes + post->body_offset));

	if (body_len == 0)
		return 0;

	text = hub_malloc(body_len + 1);
	if (!text)
		return 0;

	memcpy(text, bytes + post->body_offset, body_len);
	text[body_len] = '\0';

	count = seed_scan_message(text, found, SEED_POST_MAX_ATTACHMENTS);
	hub_free(text);

	/* One attachment referred to twice is one file to fetch. */
	for (i = 0; i < count && kept < max; i++)
	{
		size_t j;
		int duplicate = 0;

		for (j = 0; j < kept; j++)
		{
			if (strcmp(out[j].tth, found[i].tth) == 0)
			{
				duplicate = 1;
				break;
			}
		}

		if (!duplicate)
			out[kept++] = found[i];
	}

	return kept;
}
