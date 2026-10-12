/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
 *
 * Pulls mod_guest_passwd into autotest-bin so test_mod_guest_passwd.tcc can
 * drive it directly. Renamed for the same reason as mod_chat_history_shim.c:
 * every plugin exports plugin_register() / plugin_unregister().
 */
#define plugin_register   mod_guest_passwd_register
#define plugin_unregister mod_guest_passwd_unregister
#include "plugins/mod_guest_passwd.c"
