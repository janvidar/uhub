/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
 *
 * Pulls mod_joins into autotest-bin so test_mod_joins.tcc can
 * drive it directly. Renamed for the same reason as mod_chat_history_shim.c:
 * every plugin exports plugin_register() / plugin_unregister().
 */
#define plugin_register   mod_joins_register
#define plugin_unregister mod_joins_unregister
#include "plugins/mod_joins.c"
