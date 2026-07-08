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
 * libFuzzer harness for the INF login-validation pipeline.
 *
 * hub_handle_info_login() runs the connect-time checks against an INF from a
 * not-yet-trusted client: parse/verify, then check_cid -> check_nick ->
 * check_network -> check_user_agent -> check_acl -> check_logged_in (see
 * inf.c::hub_perform_login_checks). These do bounded copies of
 * attacker-controlled CID/PID/nick/user-agent fields and are exactly the
 * surface with a history of out-of-bounds bugs. fuzz_message stops at the ADC
 * parse; this target continues into the login checks that run on the parsed
 * message.
 *
 * The checks are pure validation -- they return a status code and never touch a
 * socket -- so a connection-less user (the minimal state used by
 * autotest/test_inf.tcc) is sufficient, and a fresh one per input keeps the run
 * deterministic. adc_msg_parse_verify() requires the message's source SID to
 * match the user's, so seeds/dictionary carry SID "AAAB" (= sid 1) to let the
 * fuzzer reach the checks rather than getting rejected at the parse.
 *
 * Build with:  cmake -B build-fuzz -DFUZZING=ON .  (clang)
 * Run with:    ./build-fuzz/fuzz_login -dict=autotest/fuzz/login.dict autotest/fuzz/corpus/login
 */

#include "system.h"
#include "adc/message.h"
#include "network/network.h"
#include "core/auth.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/user.h"
#include "core/usermanager.h"
#include "util/log.h"
#include "util/memory.h"

#include <stdint.h>
#include <stddef.h>

/* Internal to inf.c (the login checks); not exposed in a public header. */
extern int hub_handle_info_login(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd);

static struct hub_info* g_hub = NULL;

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
	(void) argc;
	(void) argv;
	hub_set_log_verbosity(0);
	net_initialize();

	g_hub = hub_malloc_zero(sizeof(struct hub_info));
	g_hub->users = uman_init(0, 1);
	g_hub->acl = hub_malloc_zero(sizeof(struct acl_handle));
	g_hub->config = hub_malloc_zero(sizeof(struct hub_config));
	config_defaults(g_hub->config);
	acl_initialize(g_hub->config, g_hub->acl);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	struct hub_user* u;
	struct adc_message* cmd;
	char* line;

	/* Minimal connecting user: SID 1 ("AAAB") so parse/verify accepts a B-type
	   message, and one upload slot so the slot-limit check has a sane value.
	   No connection -- the login checks never write to a socket. */
	u = (struct hub_user*) hub_malloc_zero(sizeof(struct hub_user));
	if (!u)
		return 0;
	u->hub = g_hub;
	u->id.sid = 1;
	u->limits.upload_slots = 1;

	line = hub_malloc(size + 1);
	if (!line)
	{
		hub_free(u);
		return 0;
	}
	memcpy(line, data, size);
	line[size] = '\0';

	cmd = adc_msg_parse_verify(u, line, size);
	if (cmd)
	{
		hub_handle_info_login(g_hub, u, cmd);
		adc_msg_free(cmd);
	}

	/* hub_handle_info_login() may attach the INF to the user via
	   user_set_info(); release it before freeing the user. */
	user_set_info(u, 0);
	hub_free(line);
	hub_free(u);
	return 0;
}
