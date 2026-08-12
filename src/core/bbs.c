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
#include "core/ioqueue.h"
#include "core/netevent.h"
#include "core/route.h"
#include "core/user.h"
#include "core/usermanager.h"
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

/**
 * Refuse a command.
 *
 * BBS0 defines no success status, so a status message always means something
 * went wrong -- and always at severity 1, since none of these is a reason to
 * disconnect a client. hub_send_status() is no use here: it is welded to the
 * configurable message strings and builds an IQUI alongside.
 *
 * Every refusal names the command it refuses in "FC", and one further flag
 * where the code defines one, so that a client can match a refusal to what it
 * refused without a token: the hash or the board is the identifier.
 */
static void bbs_send_error(struct hub_info* hub, struct hub_user* user, int code,
                           const char* fourcc, const char* text,
                           const char* key, const char* value)
{
	struct adc_message* cmd;
	char status[4];
	char* escaped;

	if (!user)
		return;

	cmd = adc_msg_construct(ADC_CMD_ISTA, 128);
	if (!cmd)
		return;

	/* status_level_error is severity 1: recoverable, never a disconnect. */
	snprintf(status, sizeof(status), "%d%02d", (int) status_level_error, code);
	adc_msg_add_argument(cmd, status);
	escaped = adc_msg_escape(text);
	adc_msg_add_argument(cmd, escaped ? escaped : "");
	hub_free(escaped);
	adc_msg_add_named_argument(cmd, ADC_STA_FLAG_FOURCC, fourcc);
	if (key && value)
		adc_msg_add_named_argument_string(cmd, key, value);

	route_to_user(hub, user, cmd);
	adc_msg_free(cmd);
}

/* Send one index entry, or a tombstone. A withdrawn post carries only its hash,
   its board, the new timestamp and RM1: the subject and author of a withdrawn
   post are usually the reason it was withdrawn. */
void bbs_send_entry(struct hub_info* hub, struct hub_user* user,
                    const char* board, const struct bbs_entry* entry)
{
	struct adc_message* cmd;

	if (!user || !entry)
		return;

	cmd = adc_msg_construct(ADC_CMD_IBBL, 256);
	if (!cmd)
		return;

	adc_msg_add_named_argument(cmd, ADC_SCH_FLAG_TTH, entry->tth);

	if (entry->removed)
	{
		adc_msg_add_named_argument(cmd, ADC_BBS_FLAG_BOARD, board);
		adc_msg_add_named_argument_uint64(cmd, ADC_MSG_FLAG_TIMESTAMP, (uint64_t) entry->ts);
		adc_msg_add_named_argument(cmd, ADC_BBS_FLAG_REMOVED, "1");
	}
	else
	{
		adc_msg_add_named_argument_uint64(cmd, ADC_RES_FLAG_FILE_SIZE, entry->size);
		adc_msg_add_named_argument(cmd, ADC_BBS_FLAG_BOARD, board);
		adc_msg_add_named_argument(cmd, ADC_INF_FLAG_CLIENT_ID, entry->cid);
		if (*entry->nick)
			adc_msg_add_named_argument_string(cmd, ADC_INF_FLAG_NICK, entry->nick);
		if (*entry->parent)
			adc_msg_add_named_argument(cmd, ADC_BBS_FLAG_PARENT, entry->parent);
		adc_msg_add_named_argument(cmd, ADC_BBS_FLAG_THREAD, entry->thread);
		if (*entry->subject)
			adc_msg_add_named_argument_string(cmd, ADC_BBS_FLAG_SUBJECT, entry->subject);
		adc_msg_add_named_argument_uint64(cmd, ADC_MSG_FLAG_TIMESTAMP, (uint64_t) entry->ts);
	}

	route_to_user(hub, user, cmd);
	adc_msg_free(cmd);
}

struct bbs_subscription* bbs_user_subscription(struct hub_user* user, const struct bbs_board* board)
{
	struct bbs_subscription* sub;

	if (!user || !user->bbs_subs || !board)
		return NULL;

	LIST_FOREACH(struct bbs_subscription*, sub, user->bbs_subs,
	{
		if (sub->board == board)
			return sub;
	});
	return NULL;
}

void bbs_user_unsubscribe_all(struct hub_user* user)
{
	if (!user || !user->bbs_subs)
		return;

	list_clear(user->bbs_subs, &hub_free_handle);
	list_destroy(user->bbs_subs);
	user->bbs_subs = NULL;
}

static void bbs_user_unsubscribe(struct hub_user* user, const struct bbs_board* board)
{
	struct bbs_subscription* sub = bbs_user_subscription(user, board);
	if (!sub)
		return;

	list_remove(user->bbs_subs, sub);
	hub_free(sub);
}

void bbs_cancel_subscriptions(struct hub_info* hub, const struct bbs_board* board)
{
	struct hub_user* user;

	if (!hub || !hub->users || !board)
		return;

	LIST_FOREACH(struct hub_user*, user, hub->users->list,
	{
		bbs_user_unsubscribe(user, board);
	});
}

/* The replay burst reuses the send-queue bypass that the user list at login
   uses: a subscription from the start of a board is one large, bounded batch,
   and bbs_max_posts_per_board is what bounds it. */
struct bbs_replay_state
{
	struct hub_info* hub;
	struct hub_user* user;
	const char* board;
	time_t highest;
};

static void bbs_replay_entry(const struct bbs_entry* entry, void* ptr)
{
	struct bbs_replay_state* state = (struct bbs_replay_state*) ptr;

	/* A disconnect mid-replay (a send queue that overflowed) clears the
	   connection; stop writing to a user that is on its way out. */
	if (!state->user->connection)
		return;

	bbs_send_entry(state->hub, state->user, state->board, entry);
	if (entry->ts > state->highest)
		state->highest = entry->ts;
}

static void bbs_replay(struct hub_info* hub, struct hub_user* user,
                       struct bbs_board* board, struct bbs_subscription* sub, time_t from)
{
	struct bbs_replay_state state;
	int was_bypassing = user_flag_get(user, flag_user_list);

	state.hub = hub;
	state.user = user;
	state.board = board->name;
	state.highest = from;

	user_flag_set(user, flag_user_list);
	bbs_index_replay(hub->bbs->index, board->name, from, &bbs_replay_entry, &state);
	if (!was_bypassing)
		user_flag_unset(user, flag_user_list);

	sub->cursor = state.highest;

	/* A small replay rides the ordinary deferred write, which coalesces it with
	   whatever else the iteration queues. A large one is drained here instead:
	   left sitting in the queue it would exceed max_send_buffer, and the next
	   message routed to this user would trip the hard limit and disconnect them
	   mid-catch-up. This is what on_login_success() does with the user list, and
	   for the same reason. */
	if (user->connection && ioq_send_get_bytes(user->send_queue) > get_max_send_queue_soft(hub))
	{
		if (handle_net_write(user))
			hub_disconnect_user(hub, user, quit_send_queue);
	}
}

int bbs_handle_subscribe(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
	struct bbs_board* board;
	struct bbs_subscription* sub;
	char* board_name;
	char* arg_ts;
	char* arg_tr;
	char* arg_rm;
	time_t from = 0;
	time_t oldest;
	int ret = -1;

	if (!bbs_is_enabled(hub))
		return -1;

	board_name = adc_msg_get_named_argument(cmd, ADC_BBS_FLAG_BOARD);
	arg_ts = adc_msg_get_named_argument(cmd, ADC_MSG_FLAG_TIMESTAMP);
	arg_tr = adc_msg_get_named_argument(cmd, ADC_SCH_FLAG_TTH);
	arg_rm = adc_msg_get_named_argument(cmd, ADC_BBS_FLAG_REMOVED);

	if (!board_name || !*board_name)
	{
		bbs_send_error(hub, user, ADC_STATUS_INF_FIELD_BAD, "BBL",
		               "Missing board name", ADC_STA_FLAG_MISSING_FIELD, ADC_BBS_FLAG_BOARD);
		goto done;
	}

	board = bbs_board_find(hub->bbs, board_name);

	/* A board the session may not subscribe to is answered exactly as one that
	   does not exist, so that refusing does not disclose it. */
	if (!board || !(bbs_board_permissions(board, user->credentials) & ADC_BBS_PERM_SUBSCRIBE))
	{
		bbs_send_error(hub, user, ADC_STATUS_BBS_NO_BOARD, "BBL",
		               "No such board", ADC_BBS_FLAG_BOARD, board_name);
		goto done;
	}

	/* Cancelling: the client is done with the board. */
	if (arg_rm && *arg_rm == '1')
	{
		bbs_user_unsubscribe(user, board);
		ret = 0;
		goto done;
	}

	if (arg_tr && arg_ts)
	{
		bbs_send_error(hub, user, ADC_STATUS_PROTOCOL_GENERIC, "BBL",
		               "TR and TS must not both be given", NULL, NULL);
		goto done;
	}

	/* A request carrying TR is a question, not a subscription: answer with the
	   one entry and leave the session's subscriptions alone. */
	if (arg_tr)
	{
		struct bbs_entry entry;

		if (!bbs_tth_is_valid(arg_tr))
		{
			bbs_send_error(hub, user, ADC_STATUS_INF_FIELD_BAD, "BBL",
			               "Invalid hash", ADC_STA_FLAG_BAD_FIELD, ADC_SCH_FLAG_TTH);
			goto done;
		}

		if (bbs_index_lookup(hub->bbs->index, board->name, arg_tr, &entry) != bbs_index_ok)
		{
			bbs_send_error(hub, user, ADC_STATUS_BBS_NO_ENTRY, "BBL",
			               "No such post", ADC_SCH_FLAG_TTH, arg_tr);
			goto done;
		}

		bbs_send_entry(hub, user, board->name, &entry);
		ret = 0;
		goto done;
	}

	if (arg_ts)
		from = (time_t) strtoll(arg_ts, NULL, 10);
	if (from < 0)
		from = 0;

	/* A hub may refuse to replay from before its OT, and must treat a request
	   for anything earlier as a request from OT. */
	oldest = bbs_board_oldest_replay(hub->bbs, board, net_get_time());
	if (from < oldest)
		from = oldest;

	sub = bbs_user_subscription(user, board);
	if (!sub)
	{
		if (!user->bbs_subs)
			user->bbs_subs = list_create();
		if (!user->bbs_subs)
			goto done;

		if (list_size(user->bbs_subs) >= (size_t) hub->config->bbs_max_subscriptions)
		{
			bbs_send_error(hub, user, ADC_STATUS_BBS_GENERIC, "BBL",
			               "Too many subscriptions", ADC_BBS_FLAG_BOARD, board_name);
			goto done;
		}

		sub = (struct bbs_subscription*) hub_malloc_zero(sizeof(struct bbs_subscription));
		if (!sub)
			goto done;
		sub->board = board;
		list_append(user->bbs_subs, sub);
	}

	/* A second HBBL for a board already subscribed replaces the first rather
	   than adding to it, and replays from the newly requested timestamp. */
	bbs_replay(hub, user, board, sub, from);
	ret = 0;

done:
	hub_free(board_name);
	hub_free(arg_ts);
	hub_free(arg_tr);
	hub_free(arg_rm);
	return ret;
}

/**
 * Deliver an accepted entry to everyone who should see it.
 *
 * There is no success status in BBS0: the entry *is* the acknowledgement. The
 * submitting session therefore receives it even where it holds no subscription
 * on the board, so that acceptance is signalled the same way in every case.
 */
static void bbs_broadcast_entry(struct hub_info* hub, struct hub_user* author,
                                struct bbs_board* board, const struct bbs_entry* entry)
{
	struct hub_user* user;
	int author_served = 0;

	LIST_FOREACH(struct hub_user*, user, hub->users->list,
	{
		if (!bbs_user_subscription(user, board))
			continue;
		bbs_send_entry(hub, user, board->name, entry);
		if (user == author)
			author_served = 1;
	});

	if (author && !author_served)
		bbs_send_entry(hub, author, board->name, entry);
}

/* Withdraw a post: HBBP with RM1. */
static int bbs_handle_withdraw(struct hub_info* hub, struct hub_user* user,
                               struct bbs_board* board, const char* tth, int permissions)
{
	struct bbs_entry entry;
	struct bbs_entry tombstone;

	if (bbs_index_lookup(hub->bbs->index, board->name, tth, &entry) != bbs_index_ok)
	{
		bbs_send_error(hub, user, ADC_STATUS_BBS_NO_ENTRY, "BBP",
		               "No such post", ADC_SCH_FLAG_TTH, tth);
		return -1;
	}

	/* Permission 16 withdraws anything; permission 8 withdraws one's own, which
	   is decided on the CID the hub accepted the post from -- never on the nick,
	   which is unique on no hub and at no time. */
	if (!(permissions & ADC_BBS_PERM_WITHDRAW_ANY) &&
	    !((permissions & ADC_BBS_PERM_WITHDRAW_OWN) && strcmp(entry.cid, user->id.cid) == 0))
	{
		bbs_send_error(hub, user, ADC_STATUS_ACCESS_DENIED, "BBP",
		               "Not permitted to withdraw this post", ADC_SCH_FLAG_TTH, tth);
		return -1;
	}

	if (bbs_index_withdraw(hub->bbs->index, board->name, tth, net_get_time(), &tombstone) != bbs_index_ok)
	{
		bbs_send_error(hub, user, ADC_STATUS_BBS_GENERIC, "BBP",
		               "Unable to withdraw the post", ADC_SCH_FLAG_TTH, tth);
		return -1;
	}

	LOG_DEBUG("bbs: '%s' withdrew %s from board '%s'", user->id.nick, tth, board->name);
	bbs_broadcast_entry(hub, user, board, &tombstone);
	return 0;
}

int bbs_handle_post(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
	struct bbs_board* board;
	struct bbs_entry entry;
	char* board_name;
	char* arg_tr = NULL;
	char* arg_si = NULL;
	char* arg_pa = NULL;
	char* arg_sj = NULL;
	char* arg_rm = NULL;
	char* subject = NULL;
	int permissions;
	int size = 0;
	int needed;
	int ret = -1;

	if (!bbs_is_enabled(hub))
		return -1;

	board_name = adc_msg_get_named_argument(cmd, ADC_BBS_FLAG_BOARD);
	arg_tr = adc_msg_get_named_argument(cmd, ADC_SCH_FLAG_TTH);
	arg_si = adc_msg_get_named_argument(cmd, ADC_RES_FLAG_FILE_SIZE);
	arg_pa = adc_msg_get_named_argument(cmd, ADC_BBS_FLAG_PARENT);
	arg_sj = adc_msg_get_named_argument(cmd, ADC_BBS_FLAG_SUBJECT);
	arg_rm = adc_msg_get_named_argument(cmd, ADC_BBS_FLAG_REMOVED);

	/* ID, NI, TH and TS are the hub's to say. A client must not send them and
	   the hub discards them if it does, rather than refusing the command --
	   the same treatment PD gets in an INF. Simply never reading them is that. */

	if (!board_name || !*board_name)
	{
		bbs_send_error(hub, user, ADC_STATUS_INF_FIELD_BAD, "BBP",
		               "Missing board name", ADC_STA_FLAG_MISSING_FIELD, ADC_BBS_FLAG_BOARD);
		goto done;
	}

	if (!arg_tr || !bbs_tth_is_valid(arg_tr))
	{
		bbs_send_error(hub, user, ADC_STATUS_INF_FIELD_BAD, "BBP",
		               arg_tr ? "Invalid hash" : "Missing hash",
		               arg_tr ? ADC_STA_FLAG_BAD_FIELD : ADC_STA_FLAG_MISSING_FIELD,
		               ADC_SCH_FLAG_TTH);
		goto done;
	}

	board = bbs_board_find(hub->bbs, board_name);
	permissions = bbs_board_permissions(board, user->credentials);
	if (!board || !permissions)
	{
		bbs_send_error(hub, user, ADC_STATUS_BBS_NO_BOARD, "BBP",
		               "No such board", ADC_BBS_FLAG_BOARD, board_name);
		goto done;
	}

	if (arg_rm && *arg_rm == '1')
	{
		ret = bbs_handle_withdraw(hub, user, board, arg_tr, permissions);
		goto done;
	}

	if (!arg_si || !is_number(arg_si, &size) || size < 0)
	{
		bbs_send_error(hub, user, ADC_STATUS_INF_FIELD_BAD, "BBP",
		               arg_si ? "Invalid size" : "Missing size",
		               arg_si ? ADC_STA_FLAG_BAD_FIELD : ADC_STA_FLAG_MISSING_FIELD,
		               ADC_RES_FLAG_FILE_SIZE);
		goto done;
	}

	if (arg_pa && !bbs_tth_is_valid(arg_pa))
	{
		bbs_send_error(hub, user, ADC_STATUS_INF_FIELD_BAD, "BBP",
		               "Invalid parent hash", ADC_STA_FLAG_BAD_FIELD, ADC_BBS_FLAG_PARENT);
		goto done;
	}

	/* Separating the two is deliberate: a board where anyone may reply but only
	   operators may start a thread is the natural form of an announcements
	   board. */
	needed = arg_pa ? ADC_BBS_PERM_REPLY : ADC_BBS_PERM_POST;
	if (!(permissions & needed))
	{
		bbs_send_error(hub, user, ADC_STATUS_ACCESS_DENIED, "BBP",
		               arg_pa ? "Not permitted to reply on this board"
		                      : "Not permitted to start a thread on this board",
		               ADC_SCH_FLAG_TTH, arg_tr);
		goto done;
	}

	/* The declared size is the author's claim and nothing verifies it, but the
	   hub must enforce MS against it at submission all the same. */
	if ((size_t) size > board->max_size)
	{
		char limit[32];
		snprintf(limit, sizeof(limit), "%zu", board->max_size);
		bbs_send_error(hub, user, ADC_STATUS_BBS_TOO_LARGE, "BBP",
		               "Post exceeds the size limit for this board", ADC_BBS_FLAG_MAX_SIZE, limit);
		goto done;
	}

	/* The hub is the only place where posting can be refused. */
	if (hub->config->bbs_post_interval > 0 && !auth_cred_is_unrestricted(user->credentials))
	{
		time_t wait = user->bbs_last_post + hub->config->bbs_post_interval - net_get_time();
		if (user->bbs_last_post && wait > 0)
		{
			char seconds[32];
			snprintf(seconds, sizeof(seconds), "%d", (int) wait);
			bbs_send_error(hub, user, ADC_STATUS_BBS_RATE_LIMIT, "BBP",
			               "Posting too fast", ADC_QUI_FLAG_TIME_LEFT, seconds);
			goto done;
		}
	}

	memset(&entry, 0, sizeof(entry));
	memcpy(entry.tth, arg_tr, sizeof(entry.tth));
	if (arg_pa)
		memcpy(entry.parent, arg_pa, sizeof(entry.parent));
	entry.size = (uint64_t) size;

	/* The hub records the CID of the session it accepted the post from, and the
	   nick that session held at the time. Both are the hub's own testimony and
	   neither can be checked against anything. */
	memcpy(entry.cid, user->id.cid, sizeof(entry.cid));
	memcpy(entry.nick, user->id.nick, sizeof(entry.nick));

	if (arg_sj)
	{
		subject = adc_msg_unescape(arg_sj);
		if (!subject || strlen(subject) > BBS_MAX_SUBJECT || strchr(subject, '\n'))
		{
			bbs_send_error(hub, user, ADC_STATUS_INF_FIELD_BAD, "BBP",
			               "Invalid subject", ADC_STA_FLAG_BAD_FIELD, ADC_BBS_FLAG_SUBJECT);
			goto done;
		}
		memcpy(entry.subject, subject, strlen(subject));
	}

	switch (bbs_index_append(hub->bbs->index, board->name, &entry, net_get_time(),
	                         (size_t) hub->config->bbs_max_posts_per_board))
	{
		case bbs_index_ok:
			break;

		case bbs_index_duplicate:
			bbs_send_error(hub, user, ADC_STATUS_BBS_GENERIC, "BBP",
			               "Already posted on this board", ADC_SCH_FLAG_TTH, arg_tr);
			goto done;

		case bbs_index_no_parent:
			bbs_send_error(hub, user, ADC_STATUS_BBS_GENERIC, "BBP",
			               "No such post to reply to", ADC_BBS_FLAG_PARENT, arg_pa);
			goto done;

		default:
			bbs_send_error(hub, user, ADC_STATUS_BBS_GENERIC, "BBP",
			               "Unable to index the post", ADC_SCH_FLAG_TTH, arg_tr);
			goto done;
	}

	user->bbs_last_post = net_get_time();
	LOG_DEBUG("bbs: '%s' posted %s to board '%s'", user->id.nick, entry.tth, board->name);

	bbs_broadcast_entry(hub, user, board, &entry);
	ret = 0;

done:
	hub_free(board_name);
	hub_free(arg_tr);
	hub_free(arg_si);
	hub_free(arg_pa);
	hub_free(arg_sj);
	hub_free(arg_rm);
	hub_free(subject);
	return ret;
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
