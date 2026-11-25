#include "system.h"
#include "plugin_api/handle.h"

/*
 * Unit tests for mod_no_guest_downloads: a guest may not start a transfer in
 * either direction. The users are opaque to the plugin, so two placeholder
 * objects stand in for them and a fake credential lookup tells them apart.
 */

extern int mod_no_guest_downloads_register(struct plugin_handle* plugin, const char* config);
extern int mod_no_guest_downloads_unregister(struct plugin_handle* plugin);

static char ngd_guest_obj, ngd_reg_obj;
#define NGD_GUEST ((struct plugin_user*) &ngd_guest_obj)
#define NGD_REG   ((struct plugin_user*) &ngd_reg_obj)

static enum auth_credentials ngd_credentials(struct plugin_handle* plugin, struct plugin_user* user)
{
	(void) plugin;
	return user == NGD_REG ? auth_cred_user : auth_cred_guest;
}

static int ngd_register(struct plugin_handle* plugin)
{
	memset(plugin, 0, sizeof(*plugin));
	if (mod_no_guest_downloads_register(plugin, "") != 0)
		return 0;
	plugin->hub.get_user_credentials = ngd_credentials;
	return 1;
}

EXO_TEST(ngd_connect_guest_denied, {
	struct plugin_handle p;
	return ngd_register(&p) && p.funcs.on_p2p_connect(&p, NGD_GUEST, NGD_REG) == st_deny;
});

EXO_TEST(ngd_connect_registered_allowed, {
	struct plugin_handle p;
	return ngd_register(&p) && p.funcs.on_p2p_connect(&p, NGD_REG, NGD_GUEST) == st_default;
});

/* #137: a passive guest asking an active registered user to connect back. */
EXO_TEST(ngd_revconnect_guest_denied, {
	struct plugin_handle p;
	return ngd_register(&p) && p.funcs.on_p2p_revconnect
		&& p.funcs.on_p2p_revconnect(&p, NGD_GUEST, NGD_REG) == st_deny;
});

EXO_TEST(ngd_revconnect_registered_allowed, {
	struct plugin_handle p;
	return ngd_register(&p) && p.funcs.on_p2p_revconnect
		&& p.funcs.on_p2p_revconnect(&p, NGD_REG, NGD_GUEST) == st_default;
});
