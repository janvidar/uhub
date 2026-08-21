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

#include "fuse/render.h"
#include "adc/adcconst.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "util/memory.h"

/*
 * A rendered file is one INF argument, a timestamp, a number or the raw INF
 * line, so MAX_ADC_CMD_LEN bounds all of it: the raw line is the largest of
 * them and cannot be longer than the command that carried it. Unescaping only
 * ever shortens. The margin covers the newline and the labels.
 */
#define RENDER_MAX (MAX_ADC_CMD_LEN + 64)

struct render_buf
{
	char data[RENDER_MAX];
	size_t len;
	int overflow;
};

static void put_mem(struct render_buf* out, const char* data, size_t len)
{
	if (out->overflow)
		return;

	if (len > sizeof(out->data) - out->len)
	{
		out->overflow = 1;
		return;
	}

	memcpy(&out->data[out->len], data, len);
	out->len += len;
}

static void put_str(struct render_buf* out, const char* str)
{
	if (str)
		put_mem(out, str, strlen(str));
}

/** One value, and the newline that makes it a line. */
static void put_line(struct render_buf* out, const char* str)
{
	if (!str)
		return;

	put_str(out, str);
	put_mem(out, "\n", 1);
}

static void put_size(struct render_buf* out, size_t value)
{
	char num[32];
	int len = snprintf(num, sizeof(num), "%llu\n", (unsigned long long) value);

	if (len > 0)
		put_mem(out, num, (size_t) len);
}

static void put_sid(struct render_buf* out, sid_t sid)
{
	put_line(out, sid_to_string(sid));
}

/**
 * One INF argument, unescaped.
 *
 * An absent argument is an empty file, or "0" when the field is numeric --
 * SS, SF, SL and CT are all omitted rather than sent as zero by most clients,
 * and a reader that has to tell those two spellings apart learns nothing from
 * having been given the chance.
 */
static void put_inf_field(struct render_buf* out, struct adc_message* inf,
                          const struct fs_field* field)
{
	char* escaped;
	char* value;

	escaped = inf ? adc_msg_get_named_argument(inf, field->inf) : NULL;
	if (!escaped)
	{
		if (field->flags & FS_FIELD_NUMERIC)
			put_mem(out, "0\n", 2);
		return;
	}

	value = adc_msg_unescape(escaped);
	hub_free(escaped);

	if (!value)
	{
		out->overflow = 1;  /* OOM: fail the read rather than truncate it */
		return;
	}

	put_line(out, value);
	hub_free(value);
}

/** The address the hub observed, which is the only one it relays. */
static void put_address(struct render_buf* out, struct adc_message* inf)
{
	static const char* const flags[] = { ADC_INF_FLAG_IPV4_ADDR, ADC_INF_FLAG_IPV6_ADDR };
	size_t n;

	if (!inf)
		return;

	/* A user reached over both families has both, and both are true, so both
	   are listed -- one per line, in the order v4 then v6. */
	for (n = 0; n < 2; n++)
	{
		char* value = adc_msg_get_named_argument(inf, flags[n]);
		if (!value)
			continue;

		put_line(out, value);
		hub_free(value);
	}
}

size_t fs_render_timestamp(time_t when, char* buf, size_t size)
{
	struct tm tm;

	if (!buf || !size)
		return 0;

	if (!gmtime_r(&when, &tm))
		return 0;

	return strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static void put_timestamp(struct render_buf* out, time_t when)
{
	char stamp[32];

	if (fs_render_timestamp(when, stamp, sizeof(stamp)))
		put_line(out, stamp);
}

static void render_hub(struct render_buf* out, const struct fs_render_ctx* ctx,
                       const struct fs_field* field)
{
	if (strcmp(field->name, "state") == 0)
		put_line(out, ctx->hub_state);
	else if (strcmp(field->name, "name") == 0)
		put_line(out, ctx->hub_name);
	else if (strcmp(field->name, "description") == 0)
		put_line(out, ctx->hub_description);
	else if (strcmp(field->name, "version") == 0)
		put_line(out, ctx->hub_version);
	else if (strcmp(field->name, "address") == 0)
		put_line(out, ctx->hub_address);
	else if (strcmp(field->name, "support") == 0)
		put_line(out, ctx->hub_support);
	else if (strcmp(field->name, "users") == 0)
		put_size(out, ctx->hub_users);
	else if (strcmp(field->name, "sid") == 0)
		put_sid(out, ctx->my_sid);
	else if (strcmp(field->name, "tls") == 0)
	{
		/* Not "yes": which version and which cipher is the part an operator
		   checking a hub actually wants, and "no" is unambiguous without them. */
		if (!ctx->tls_version)
			put_line(out, "no");
		else
		{
			put_str(out, ctx->tls_version);
			if (ctx->tls_cipher)
			{
				put_mem(out, " ", 1);
				put_str(out, ctx->tls_cipher);
			}
			put_mem(out, "\n", 1);
		}
	}
}

static void render_me(struct render_buf* out, const struct fs_render_ctx* ctx,
                      const struct fs_field* field)
{
	if (strcmp(field->name, "nick") == 0)
		put_line(out, ctx->my_nick);
	else if (strcmp(field->name, "cid") == 0)
		put_line(out, ctx->my_cid);
	else if (strcmp(field->name, "sid") == 0)
		put_sid(out, ctx->my_sid);
	else if (strcmp(field->name, "support") == 0)
		put_line(out, ctx->my_support);
}

static void render_user(struct render_buf* out, const struct fs_render_ctx* ctx,
                        const struct fs_field* field)
{
	if (field->flags & FS_FIELD_RAW_INF)
	{
		/* Verbatim, escapes and all: this is the line the hub sent, and it is
		   here for the reader who wants the fields this mount does not model.
		   An ADC message carries its own terminating newline. */
		if (ctx->inf)
			put_mem(out, ctx->inf->cache, ctx->inf->length);
		return;
	}

	if (field->inf)
	{
		put_inf_field(out, ctx->inf, field);
		return;
	}

	if (strcmp(field->name, "ip") == 0)
		put_address(out, ctx->inf);
	else if (strcmp(field->name, "sid") == 0)
		put_sid(out, ctx->sid);
	else if (strcmp(field->name, "connected") == 0)
		put_timestamp(out, ctx->since);
}

ssize_t fs_render(const struct fs_node* node, const struct fs_render_ctx* ctx,
                  char* buf, size_t size)
{
	struct render_buf out;

	if (!node || !ctx || !node->field)
		return -1;

	out.len = 0;
	out.overflow = 0;

	switch (node->type)
	{
		case FS_NODE_HUB_FILE:
			render_hub(&out, ctx, node->field);
			break;

		case FS_NODE_ME_FILE:
			render_me(&out, ctx, node->field);
			break;

		case FS_NODE_USER_FILE:
			render_user(&out, ctx, node->field);
			break;

		default:
			return -1;
	}

	if (out.overflow)
		return -1;

	if (out.len <= size && buf)
		memcpy(buf, out.data, out.len);

	return (ssize_t) out.len;
}
