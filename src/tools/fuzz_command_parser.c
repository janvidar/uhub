/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2014, Jan Vidar Krey
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
 * libFuzzer harness for the !command parser.
 *
 * command_parse() interprets the text following a '!' / '+' chat command
 * from a logged-in user. It tokenizes the message and, per the matched
 * command's argument spec, parses each token as a user / CID / IP address /
 * IP range / credential / number / greedy string. The IP-address and
 * IP-range branches feed attacker-controlled tokens straight into the
 * ipcalc string parsers (ip_convert_to_binary / ip_convert_address_to_range),
 * so this target also exercises that surface for free.
 *
 * A command_base + hub_info + hub_user are built once in
 * LLVMFuzzerInitialize() and reused across inputs (the parser does not
 * mutate them). Commands covering every argument-code branch are registered
 * so the fuzzer can reach each parse path.
 *
 * Build with:  cmake -B build-fuzz -DFUZZING=ON -DSSL_SUPPORT=OFF .  (clang)
 * Run with:    ./build-fuzz/fuzz_command_parser autotest/fuzz/corpus/command_parser
 */

#include "uhub.h"

#include <stdint.h>
#include <stddef.h>

static struct hub_info* g_hub = NULL;
static struct command_base* g_cbase = NULL;
static struct hub_user g_user;

static int fuzz_command_handler(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	/* command_parse() never invokes handlers; this is only here so the
	 * registered commands have a non-NULL handler. */
	(void) cbase;
	(void) user;
	(void) cmd;
	return 0;
}

static struct command_handle* make_handler(const char* prefix, const char* args, enum auth_credentials cred)
{
	struct command_handle* c = hub_malloc_zero(sizeof(struct command_handle));
	if (!c)
		return NULL;
	c->prefix = prefix;
	c->length = strlen(prefix);
	c->args = args;
	c->cred = cred;
	c->handler = fuzz_command_handler;
	c->description = "fuzz target";
	c->origin = "fuzz";
	c->ptr = c;
	return c;
}

static void register_handler(const char* prefix, const char* args)
{
	struct command_handle* c = make_handler(prefix, args, auth_cred_guest);
	if (c)
		command_add(g_cbase, c, NULL);
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
	(void) argc;
	(void) argv;
	hub_set_log_verbosity(0);

	g_hub = hub_malloc_zero(sizeof(struct hub_info));
	g_cbase = command_initialize(g_hub);
	g_hub->commands = g_cbase;
	g_hub->users = uman_init();

	memset(&g_user, 0, sizeof(g_user));
	g_user.id.sid = 1;
	strncpy(g_user.id.nick, "fuzzer", MAX_NICK_LEN);
	g_user.id.nick[MAX_NICK_LEN] = '\0';
	strncpy(g_user.id.cid, "3AGHMAASJA2RFNM22AA6753V7B7DYEPNTIWHBAY", MAX_CID_LEN);
	g_user.id.cid[MAX_CID_LEN] = '\0';
	/* Admin so access checks never short-circuit before argument parsing. */
	g_user.credentials = auth_cred_admin;

	/* One command per argument-code branch in command_extract_arguments(). */
	register_handler("fuzz_none", "");        /* no arguments            */
	register_handler("fuzz_num",  "N?N?N");   /* integers, some optional */
	register_handler("fuzz_user", "u");       /* nick lookup             */
	register_handler("fuzz_cid",  "i");       /* CID lookup              */
	register_handler("fuzz_addr", "a");       /* IP address (ipcalc)     */
	register_handler("fuzz_range","r");       /* IP range (ipcalc)       */
	register_handler("fuzz_cmd",  "?c");      /* command name lookup     */
	register_handler("fuzz_cred", "C");       /* credentials             */
	register_handler("fuzz_str",  "nmp");     /* plain strings           */
	register_handler("fuzz_greedy","+m");     /* greedy trailing string  */

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	struct hub_command* cmd;
	char* message = hub_malloc(size + 1);
	if (!message)
		return 0;
	memcpy(message, data, size);
	message[size] = '\0';

	cmd = command_parse(g_cbase, g_hub, &g_user, message);
	if (cmd)
	{
		/* command_free() walks the parsed argument list and releases each
		 * entry by type, so the full parse -> arg-extraction -> teardown
		 * lifecycle is exercised. The typed hub_command_arg_next() accessor
		 * is deliberately not called here: it asserts the caller already
		 * knows each argument's type (it is for command handlers, not a
		 * parser surface). */
		command_free(cmd);
	}

	hub_free(message);
	return 0;
}
