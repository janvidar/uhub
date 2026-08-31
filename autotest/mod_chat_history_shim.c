/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
 *
 * Pulls mod_chat_history into autotest-bin so test_mod_chat_history.tcc can
 * drive it directly, the same way mod_auth_sqlite.c is compiled in.
 *
 * Every plugin exports plugin_register() / plugin_unregister(), so two of them
 * in one binary collide. Renaming this one's here keeps the plugin source
 * itself free of test scaffolding, and leaves the real mod_chat_history.so --
 * which must export the canonical names -- untouched.
 */
#define plugin_register   mod_chat_history_register
#define plugin_unregister mod_chat_history_unregister
#include "plugins/mod_chat_history.c"
