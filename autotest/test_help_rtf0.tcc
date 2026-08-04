#include "util/cbuffer.h"
#include "util/memory.h"
#include "core/commands.h"
#include "core/hub.h"
#include "core/user.h"

/*
 * RTF0: the !help output sent to a client that negotiated RTF0 is markdown --
 * a table for the listing, a code span for the syntax. See command_help_rich().
 */

static struct hub_info* help_hub = NULL;
static struct command_base* help_cbase = NULL;
static struct hub_user help_user;
static struct command_handle* help_handle = NULL;

EXO_TEST(help_rtf0_setup, {
	help_hub = hub_malloc_zero(sizeof(struct hub_info));
	help_cbase = command_initialize(help_hub);
	help_hub->commands = help_cbase;

	memset(&help_user, 0, sizeof(help_user));
	help_user.id.sid = 1;
	help_user.credentials = auth_cred_guest;
	return help_hub && help_cbase;
});

static int help_dummy_handler(struct command_base* cbase, struct hub_user* user, struct hub_command* cmd)
{
	(void) cbase; (void) user; (void) cmd;
	return 0;
}

/* A command whose description carries markdown metacharacters. */
EXO_TEST(help_rtf0_add_handler, {
	help_handle = hub_malloc_zero(sizeof(struct command_handle));
	help_handle->prefix = "autotest";
	help_handle->length = strlen(help_handle->prefix);
	help_handle->args = "?m";
	help_handle->cred = auth_cred_guest;
	help_handle->handler = help_dummy_handler;
	help_handle->description = "a|b *c* _d_ `e` [f] <g> ~h~ i\\j";
	help_handle->origin = "exotic test";
	return command_add(help_cbase, help_handle, NULL);
});

static struct cbuffer* help_render(struct command_handle* command)
{
	struct cbuffer* buf = cbuf_create(512);
	command_help_rich(help_cbase, &help_user, buf, command);
	return buf;
}

static int help_contains(struct command_handle* command, const char* needle)
{
	struct cbuffer* buf = help_render(command);
	int found = strstr(cbuf_get(buf), needle) != NULL;
	cbuf_destroy(buf);
	return found;
}

/* The listing is a markdown table with a header and a delimiter row. */
EXO_TEST(help_rtf0_table_header, { return help_contains(NULL, "| Command | Description |\n| --- | --- |\n"); });
EXO_TEST(help_rtf0_table_intro, { return help_contains(NULL, "**Available commands**\n\n|"); });

/* Commands are code spans, one row each. */
EXO_TEST(help_rtf0_row_help, { return help_contains(NULL, "| `!help` | Show this help message. |\n"); });
EXO_TEST(help_rtf0_row_uptime, { return help_contains(NULL, "| `!uptime` | Display hub uptime info. |\n"); });

/* Commands above the user's credentials are still omitted. */
EXO_TEST(help_rtf0_no_privileged_rows, { return !help_contains(NULL, "`!shutdown`"); });

/* Descriptions are markdown escaped, so they cannot break out of a cell. */
EXO_TEST(help_rtf0_escape_description, {
	return help_contains(NULL, "| `!autotest` | a\\|b \\*c\\* \\_d\\_ \\`e\\` \\[f\\] \\<g\\> \\~h\\~ i\\\\j |\n");
});

/* The listing points at the per-command help. */
EXO_TEST(help_rtf0_footer, { return help_contains(NULL, "\nUse `!help <command>` for the syntax of a single command."); });

/* A single command renders as a usage line plus the description. */
EXO_TEST(help_rtf0_single_usage, {
	return help_contains(help_handle, "**Usage:** `!autotest [<message>]`\n\na\\|b ");
});

/* ... and stays hidden when it is out of reach. */
EXO_TEST(help_rtf0_single_denied, {
	help_handle->cred = auth_cred_admin;
	return help_contains(help_handle, "This command is not available to you.");
});

EXO_TEST(help_rtf0_cleanup, {
	command_del(help_cbase, help_handle);
	hub_free(help_handle);
	command_shutdown(help_cbase);
	hub_free(help_hub);
	return 1;
});
