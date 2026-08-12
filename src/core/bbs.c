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

#include <stdlib.h>
#include <string.h>

#include "adc/adcconst.h"
#include "adc/message.h"
#include "core/bbs.h"
#include "core/bbs_index.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/route.h"
#include "core/user.h"
#include "network/backend.h"
#include "util/config_token.h"
#include "util/credentials.h"
#include "util/list.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"

/* Default post size limit, matching the example in the BBS0 draft. Generous for
   text, small enough that a full board fits in a replay burst. */
#define BBS_DEFAULT_MAX_SIZE 262144

/* The permission keywords accepted in the boards file, in PE bit order. */
static const char* const bbs_perm_keyword[bbs_perm_count] = {
	"subscribe", "post", "reply", "withdraw_own", "withdraw_any"
};

/* Credential required per permission on a board that says nothing about it.
   The shape of an ordinary discussion board: everyone reads and replies,
   registered users start threads and take their own posts back, operators
   moderate. */
static const int bbs_perm_default[bbs_perm_count] = {
	auth_cred_guest,   /* subscribe    */
	auth_cred_user,    /* post         */
	auth_cred_guest,   /* reply        */
	auth_cred_user,    /* withdraw_own */
	auth_cred_operator /* withdraw_any */
};

int bbs_board_name_is_valid(const char* name)
{
	size_t n;

	if (!name || !*name)
		return 0;

	for (n = 0; name[n]; n++)
	{
		char c = name[n];
		if (n >= BBS_MAX_BOARD_NAME)
			return 0;
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
			continue;
		if (c == '.' || c == '-' || c == '_')
			continue;
		return 0;
	}
	return 1;
}

int bbs_board_permissions(const struct bbs_board* board, enum auth_credentials credentials)
{
	int mask = 0;
	int i;

	if (!board)
		return 0;

	for (i = 0; i < bbs_perm_count; i++)
	{
		if (board->cred[i] == BBS_CRED_NEVER)
			continue;

		/* Same "required <= held" comparison that gates the hub's !commands
		   (see command_is_available in commands.c). */
		if ((enum auth_credentials) board->cred[i] <= credentials)
			mask |= (1 << i);
	}

	/* A session that may not subscribe is never told the board exists, so it
	   holds nothing on it. Collapsing that here means one bbs_board_permissions()
	   == 0 test answers "is this board usable by this session at all", rather
	   than every call site having to remember to check bit 1 first. */
	if (!(mask & ADC_BBS_PERM_SUBSCRIBE))
		return 0;

	return mask;
}

void bbs_board_free(struct bbs_board* board)
{
	if (!board)
		return;
	hub_free(board->title);
	hub_free(board->description);
	hub_free(board);
}

static void bbs_board_free_handle(void* ptr)
{
	bbs_board_free((struct bbs_board*) ptr);
}

/**
 * Split a "key=value" token in place at its first '='.
 *
 * cfg_settings_split() cannot be used here: it re-tokenises the string it is
 * given, by which point the quotes are gone, so a value containing a space
 * ("General discussion") loses everything after the first word.
 *
 * @return 1 on success, 0 if the token has no '=' or an empty key.
 */
static int bbs_split_setting(char* token, char** key, char** value)
{
	char* pos = strchr(token, '=');
	if (!pos)
		return 0;

	*pos = '\0';
	*key = strip_white_space(token);
	*value = pos + 1;
	return **key != '\0';
}

/* Parse a credential keyword. "none" is rejected by auth_string_to_cred's
   normal meaning here: on the wire it is the lowest credential, but in a boards
   file the operator writing it means "nobody", so it maps to BBS_CRED_NEVER. */
static int bbs_parse_credential(const char* value, int* out)
{
	enum auth_credentials cred;

	if (!strcasecmp(value, "none") || !strcasecmp(value, "never"))
	{
		*out = BBS_CRED_NEVER;
		return 1;
	}

	if (!auth_string_to_cred(value, &cred))
		return 0;

	*out = (int) cred;
	return 1;
}

static int bbs_parse_setting(struct bbs_board* board, char* token)
{
	char* key;
	char* value;
	int i;
	int number;

	if (!bbs_split_setting(token, &key, &value))
	{
		LOG_ERROR("Boards file: expected key=value, got '%s'", token);
		return 0;
	}

	for (i = 0; i < bbs_perm_count; i++)
	{
		if (strcmp(key, bbs_perm_keyword[i]) != 0)
			continue;

		if (!bbs_parse_credential(value, &board->cred[i]))
		{
			LOG_ERROR("Boards file: '%s' is not a credential", value);
			return 0;
		}
		return 1;
	}

	if (!strcmp(key, "title"))
	{
		hub_free(board->title);
		board->title = hub_strdup(value);
		return board->title != NULL;
	}

	if (!strcmp(key, "description"))
	{
		hub_free(board->description);
		board->description = hub_strdup(value);
		return board->description != NULL;
	}

	if (!strcmp(key, "max_size"))
	{
		if (!is_number(value, &number) || number <= 0)
		{
			LOG_ERROR("Boards file: max_size must be a positive number, got '%s'", value);
			return 0;
		}
		board->max_size = (size_t) number;
		return 1;
	}

	if (!strcmp(key, "replay_days"))
	{
		if (!is_number(value, &number) || number < 0)
		{
			LOG_ERROR("Boards file: replay_days must be zero or more, got '%s'", value);
			return 0;
		}
		board->replay_days = number;
		return 1;
	}

	LOG_ERROR("Boards file: unknown board setting '%s'", key);
	return 0;
}

struct bbs_board* bbs_board_parse(const char* line, int* error)
{
	struct bbs_board* board = NULL;
	struct cfg_tokens* tokens;
	char* token;
	int i;

	*error = 0;

	tokens = cfg_tokenize(line);
	if (!tokens)
		goto out_of_memory;

	/* cfg_tokenize strips comments and blank space for us. */
	if (cfg_token_count(tokens) == 0)
	{
		cfg_tokens_free(tokens);
		return NULL;
	}

	token = cfg_token_get_first(tokens);
	if (strcmp(token, "board") != 0)
	{
		LOG_ERROR("Boards file: expected 'board', got '%s'", token);
		goto invalid;
	}

	token = cfg_token_get_next(tokens);
	if (!token || !bbs_board_name_is_valid(token))
	{
		LOG_ERROR("Boards file: '%s' is not a valid board name (1-%d characters of A-Z a-z 0-9 . - _)",
		          token ? token : "", BBS_MAX_BOARD_NAME);
		goto invalid;
	}

	board = (struct bbs_board*) hub_malloc_zero(sizeof(struct bbs_board));
	if (!board)
		goto out_of_memory;

	strncpy(board->name, token, BBS_MAX_BOARD_NAME);
	board->max_size = BBS_DEFAULT_MAX_SIZE;
	board->replay_days = 0;
	for (i = 0; i < bbs_perm_count; i++)
		board->cred[i] = bbs_perm_default[i];

	for (token = cfg_token_get_next(tokens); token; token = cfg_token_get_next(tokens))
	{
		if (!bbs_parse_setting(board, token))
			goto invalid;
	}

	cfg_tokens_free(tokens);
	return board;

invalid:
	cfg_tokens_free(tokens);
	bbs_board_free(board);
	*error = 1;
	return NULL;

out_of_memory:
	LOG_ERROR("bbs_board_parse: out of memory");
	cfg_tokens_free(tokens);
	bbs_board_free(board);
	*error = 1;
	return NULL;
}

static int bbs_parse_file_line(char* line, int line_count, void* ptr_data)
{
	struct bbs_handle* handle = (struct bbs_handle*) ptr_data;
	struct bbs_board* board;
	int error = 0;

	board = bbs_board_parse(line, &error);
	if (error)
	{
		LOG_ERROR("Unable to parse boards file line %d: '%s'", line_count, line);
		return -1;
	}

	if (!board)
		return 0; /* blank or comment */

	if (bbs_board_find(handle, board->name))
	{
		LOG_ERROR("Boards file line %d: board '%s' is defined twice", line_count, board->name);
		bbs_board_free(board);
		return -1;
	}

	list_append(handle->boards, board);
	LOG_DEBUG("bbs: board '%s' (max_size=%zu, replay_days=%d)",
	          board->name, board->max_size, board->replay_days);
	return 0;
}

struct bbs_board* bbs_board_find(struct bbs_handle* handle, const char* name)
{
	struct bbs_board* board;

	if (!handle || !name)
		return NULL;

	/* Board names are case-sensitive. */
	LIST_FOREACH(struct bbs_board*, board, handle->boards,
	{
		if (strcmp(board->name, name) == 0)
			return board;
	});
	return NULL;
}

int bbs_initialize(struct hub_config* config, struct bbs_handle** out)
{
	struct bbs_handle* handle;

	*out = NULL;

	if (!config || !config->bbs_enable)
		return 0;

	if (!*config->file_bbs_boards)
	{
		LOG_ERROR("bbs_enable is set but file_bbs_boards is empty: there are no boards to serve.");
		return -1;
	}

	if (!*config->file_bbs_index)
	{
		LOG_ERROR("bbs_enable is set but file_bbs_index is empty: there is nowhere to keep the index.");
		return -1;
	}

	handle = (struct bbs_handle*) hub_malloc_zero(sizeof(struct bbs_handle));
	if (!handle)
	{
		LOG_FATAL("bbs_initialize: out of memory");
		return -1;
	}

	handle->boards = list_create();
	if (!handle->boards)
	{
		LOG_FATAL("bbs_initialize: out of memory");
		hub_free(handle);
		return -1;
	}

	/* Reads the whole file in one go, capped at MAX_RECV_BUF -- the same limit
	   file_acl has lived with. A boards file is a handful of lines. */
	if (file_read_lines(config->file_bbs_boards, handle, &bbs_parse_file_line) < 0)
	{
		bbs_shutdown(handle);
		return -1;
	}

	if (list_size(handle->boards) == 0)
	{
		LOG_ERROR("No boards defined in %s.", config->file_bbs_boards);
		bbs_shutdown(handle);
		return -1;
	}

	handle->index = bbs_index_open(config->file_bbs_index);
	if (!handle->index)
	{
		bbs_shutdown(handle);
		return -1;
	}

	LOG_INFO("Bulletin boards enabled: %zu board(s) from %s, index in %s.",
	         list_size(handle->boards), config->file_bbs_boards, config->file_bbs_index);

	*out = handle;
	return 0;
}

void bbs_shutdown(struct bbs_handle* handle)
{
	if (!handle)
		return;

	bbs_index_close(handle->index);
	list_clear(handle->boards, &bbs_board_free_handle);
	list_destroy(handle->boards);
	hub_free(handle);
}

int bbs_is_enabled(struct hub_info* hub)
{
	return hub && hub->bbs && hub->bbs->index;
}

void bbs_send_board_descriptor(struct hub_info* hub, struct hub_user* user,
                               const struct bbs_board* board)
{
	struct adc_message* cmd;
	time_t now;
	time_t newest = 0;
	size_t count = 0;
	int permissions;

	if (!bbs_is_enabled(hub) || !user || !board)
		return;

	permissions = bbs_board_permissions(board, user->credentials);
	if (!permissions)
		return;

	if (bbs_index_stats(hub->bbs->index, board->name, &newest, NULL, &count) < 0)
		return;

	cmd = adc_msg_construct(ADC_CMD_IBBD, 128);
	if (!cmd)
		return;

	now = net_get_time();

	/* Field order follows the BBS0 draft. BD is protocol text and needs no
	   escaping; the title and description are user text and do. */
	adc_msg_add_named_argument(cmd, ADC_BBS_FLAG_BOARD, board->name);
	if (board->title)
		adc_msg_add_named_argument_string(cmd, ADC_INF_FLAG_NICK, board->title);
	if (board->description)
		adc_msg_add_named_argument_string(cmd, ADC_INF_FLAG_DESCRIPTION, board->description);
	adc_msg_add_named_argument_int(cmd, ADC_BBS_FLAG_PERMISSIONS, permissions);
	adc_msg_add_named_argument_uint64(cmd, ADC_BBS_FLAG_MAX_SIZE, (uint64_t) board->max_size);
	adc_msg_add_named_argument_uint64(cmd, ADC_MSG_FLAG_TIMESTAMP, (uint64_t) newest);
	adc_msg_add_named_argument_uint64(cmd, ADC_BBS_FLAG_OLDEST,
	                                  (uint64_t) bbs_board_oldest_replay(hub->bbs, board, now));
	adc_msg_add_named_argument_uint64(cmd, ADC_BBS_FLAG_NUM_POSTS, (uint64_t) count);

	route_to_user(hub, user, cmd);
	adc_msg_free(cmd);
}

void bbs_send_board_list(struct hub_info* hub, struct hub_user* user)
{
	struct bbs_board* board;

	if (!bbs_is_enabled(hub) || !user)
		return;

	/* The hub's announcement in SUP is authoritative for the connection, and a
	   client that never offered BBS0 has no use for a board descriptor. */
	if (!user_flag_get(user, feature_bbs))
		return;

	LIST_FOREACH(struct bbs_board*, board, hub->bbs->boards,
	{
		bbs_send_board_descriptor(hub, user, board);
	});
}

time_t bbs_board_oldest_replay(struct bbs_handle* handle, const struct bbs_board* board, time_t now)
{
	time_t oldest = 0;
	time_t cutoff = 0;

	if (!handle || !board)
		return 0;

	if (bbs_index_stats(handle->index, board->name, NULL, &oldest, NULL) < 0)
		return 0;

	if (board->replay_days > 0)
	{
		cutoff = now - ((time_t) board->replay_days * 86400);
		if (cutoff < 0)
			cutoff = 0;
	}

	/* Whichever is the later bound wins: a hub that expires old entries says so
	   through OT, and a hub that has simply not been running long enough should
	   not claim a backlog it never had. */
	return (cutoff > oldest) ? cutoff : oldest;
}
