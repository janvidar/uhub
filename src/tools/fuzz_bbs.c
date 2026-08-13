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

/*
 * libFuzzer target for the BBS0 bulletin board commands.
 *
 * Feeds fuzzer bytes through adc_msg_parse() into bbs_handle_subscribe() and
 * bbs_handle_post(), which read attacker-controlled board names, hashes, sizes
 * and subjects and put them into an index and onto the wire. Both run against a
 * logged-in but not otherwise trusted session, so the input here is exactly
 * what a remote user can send.
 *
 * The index is in-memory and the user has a send queue but no socket, so a run
 * touches neither disk nor network. The board set is fixed: it is the shape of
 * the commands that is being fuzzed, not the configuration, which an operator
 * writes.
 *
 * Build with:  cmake -B build-fuzz -DFUZZING=ON .  (clang)
 * Run with:    ./build-fuzz/fuzz_bbs -dict=autotest/fuzz/adc.dict autotest/fuzz/corpus/bbs
 */

#include "system.h"
#include "adc/message.h"
#include "core/bbs.h"
#include "core/bbs_index.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/ioqueue.h"
#include "core/user.h"
#include "core/usermanager.h"
#include "network/connection.h"
#include "network/network.h"
#include "util/list.h"
#include "util/log.h"
#include "util/memory.h"

#include <stdint.h>
#include <stddef.h>

static struct hub_info* g_hub = NULL;

static void add_board(const char* line)
{
	int error = 0;
	struct bbs_board* board = bbs_board_parse(line, &error);
	if (board)
		list_append(g_hub->bbs->boards, board);
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
	(void) argc;
	(void) argv;
	hub_set_log_verbosity(0);
	net_initialize();

	g_hub = hub_malloc_zero(sizeof(struct hub_info));
	g_hub->users = uman_init(0, 1);
	g_hub->config = hub_malloc_zero(sizeof(struct hub_config));
	config_defaults(g_hub->config);
	g_hub->write_queue = list_create();

	g_hub->bbs = hub_malloc_zero(sizeof(struct bbs_handle));
	g_hub->bbs->boards = list_create();

	/* One board a guest may do everything on and one it may only read, so both
	   the permitted and the refused paths are reachable. */
	add_board("board general post=guest withdraw_own=guest withdraw_any=guest");
	add_board("board locked post=none reply=none");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	struct hub_user* u;
	struct net_connection* con;
	struct adc_message* cmd;
	char* line;

	/* A logged-in session with a send queue but no socket: everything the hub
	   sends back is queued and dropped when the user is freed. A fresh user per
	   input keeps the run deterministic. */
	u = (struct hub_user*) hub_malloc_zero(sizeof(struct hub_user));
	con = (struct net_connection*) hub_malloc_zero(sizeof(struct net_connection));
	if (!u || !con)
	{
		hub_free(con);
		hub_free(u);
		return 0;
	}

	/* A fresh index per input, not one shared by the whole run: an index that
	   accumulated every post ever fuzzed would make a crash depend on the order
	   the corpus happened to be scheduled in, so the artifact libFuzzer writes
	   out would not reproduce it. It also keeps replay bounded. */
	g_hub->bbs->index = bbs_index_open(":memory:");
	if (!g_hub->bbs->index)
	{
		hub_free(con);
		hub_free(u);
		return 0;
	}

	u->hub = g_hub;
	u->connection = con;
	u->send_queue = ioq_send_create();
	u->id.sid = 1;
	u->state = state_normal;
	u->credentials = auth_cred_guest;
	memcpy(u->id.cid, "IPJJWEPPPLCA3PF2ZCRRYO4F2ZX2EV2JMW2KC3I", 39);
	memcpy(u->id.nick, "fuzz", 4);
	user_flag_set(u, feature_bbs);

	line = hub_malloc(size + 1);
	if (!line || !u->send_queue)
	{
		ioq_send_destroy(u->send_queue);
		bbs_index_close(g_hub->bbs->index);
		g_hub->bbs->index = NULL;
		hub_free(line);
		hub_free(con);
		hub_free(u);
		return 0;
	}
	memcpy(line, data, size);
	line[size] = '\0';

	cmd = adc_msg_parse(line, size);
	if (cmd)
	{
		switch (cmd->cmd)
		{
			case ADC_CMD_HBBL:
				bbs_handle_subscribe(g_hub, u, cmd);
				break;

			case ADC_CMD_HBBP:
				bbs_handle_post(g_hub, u, cmd);
				break;

			default:
				break;
		}
		adc_msg_free(cmd);
	}

	bbs_user_unsubscribe_all(u);
	if (user_flag_get(u, flag_dirty))
		list_remove(g_hub->write_queue, u);
	ioq_send_destroy(u->send_queue);
	bbs_index_close(g_hub->bbs->index);
	g_hub->bbs->index = NULL;
	hub_free(line);
	hub_free(con);
	hub_free(u);
	return 0;
}
