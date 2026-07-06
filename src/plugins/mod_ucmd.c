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
#include "util/memory.h"
#include "plugin_api/handle.h"

/* ADC UCMD context bitfield (the "CT" field of an ICMD). */
#define UCMD_CT_HUB     1   /* hub / main-chat menu  */
#define UCMD_CT_USER    2   /* userlist / chat menu  */
#define UCMD_CT_SEARCH  4   /* search-results menu   */
#define UCMD_CT_FILE    8   /* filelist / transfer   */

/*
 * Every registered hub command is published as a UCMD context-menu entry. For
 * each command, the client transmits, when the entry is chosen, the line built
 * in emit_command(): a BMSG from the user's own SID whose message argument is
 * "+<prefix>" followed by one placeholder per required argument. uhub
 * intercepts a main-chat (BMSG) line starting with '+' or '!' as a command
 * (see hub.c).
 *
 * The line passed to send_user_command() is the literal protocol line BEFORE
 * the core escapes it into the TT field, so it must carry its own
 * argument-internal escaping:
 *   - the spaces separating BMSG / SID / the message argument are real ADC
 *     separators and stay as plain spaces;
 *   - a space *inside* the message argument is "\s" (written "\\s" here);
 *   - the trailing "\n" terminates the line the client sends.
 *
 * Client-side substitutions (filled in by the client before sending):
 *   %[mySID]           -> the clicking user's own SID
 *   %[userNI]          -> the targeted user's nick   (CT_USER entries)
 *   %[userCID]         -> the targeted user's CID    (CT_USER entries)
 *   %[line:Prompt]     -> prompt the user for a line of free text
 */

static void emit_command(struct plugin_handle* plugin, const struct plugin_command_info* cmd, void* ptr)
{
	struct plugin_user* user = (struct plugin_user*) ptr;
	char name[256];
	char line[512];
	int context = UCMD_CT_HUB | UCMD_CT_USER;
	size_t len;
	size_t i;

	/* Group every command under a top-level "uhub" submenu, using the
	 * human-readable description (falling back to the prefix) as the leaf. */
	snprintf(name, sizeof(name), "uhub/%s", (cmd->description && *cmd->description) ? cmd->description : cmd->prefix);

	len = (size_t) snprintf(line, sizeof(line), "BMSG %%[mySID] +%s", cmd->prefix);
	if (len >= sizeof(line))
		return;

	for (i = 0; cmd->args && cmd->args[i]; i++)
	{
		const char* placeholder;
		char code = cmd->args[i];

		if (code == '?')
			break;      /* optional argument: leave it and any following out */
		if (code == '+')
			continue;   /* greedy modifier: applies to the next (string) code */

		switch (code)
		{
			case 'u': /* fall through */
			case 'n': placeholder = "%[userNI]";  context = UCMD_CT_USER; break;
			case 'i': placeholder = "%[userCID]"; context = UCMD_CT_USER; break;
			case 'm': placeholder = "%[line:Message]";       break;
			case 'N': placeholder = "%[line:Number]";        break;
			case 'a': /* fall through */
			case 'A': placeholder = "%[line:Address]";       break;
			case 'r': placeholder = "%[line:Address range]"; break;
			case 'p': placeholder = "%[line:Password]";      break;
			case 'C': placeholder = "%[line:Credentials]";   break;
			case 'c': placeholder = "%[line:Command]";       break;
			default:  placeholder = "%[line:Argument]";      break;
		}

		len += (size_t) snprintf(line + len, sizeof(line) - len, "\\s%s", placeholder);
		if (len >= sizeof(line))
			return;
	}

	/* Terminate the line the client will transmit. */
	if (len + 2 > sizeof(line))
		return;
	line[len++] = '\n';
	line[len] = '\0';

	plugin->hub.send_user_command(plugin, user, name, context, line);
}

static void on_user_login(struct plugin_handle* plugin, struct plugin_user* user)
{
	/* Enumerate every command available at this user's credential level and
	 * publish each as a UCMD entry. Clients that did not advertise UCM0 ignore
	 * the unknown ICMD messages, so sending unconditionally is safe. The
	 * plugin API does not expose per-user feature flags, so no gate on
	 * feature_ucmd is applied. */
	plugin->hub.command_foreach(plugin, user->credentials, emit_command, user);
}

int plugin_register(struct plugin_handle* plugin, const char* config)
{
	(void) config;
	PLUGIN_INITIALIZE(plugin, "UCMD plugin", "0.2",
		"Publishes registered hub commands as ADC user-command (UCMD) context menus.");
	plugin->funcs.on_user_login = on_user_login;
	return 0;
}

int plugin_unregister(struct plugin_handle* plugin)
{
	(void) plugin;
	/* The ICMD entries live in each client; there is nothing hub-side to free.
	 * To clear a client's menu you would re-send each entry with an "RM" field. */
	return 0;
}
