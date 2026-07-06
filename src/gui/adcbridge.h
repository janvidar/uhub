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
 * adcbridge -- a thin, C++-safe C wrapper around the uhub ADC client.
 *
 * The client library (tools/adcclient.h) is a fine seam for another C
 * program, but its header transitively pulls in uhub's C headers, some of
 * which do not compile cleanly under a C++ compiler (e.g. the strndup /
 * memmem fallback declarations clash with glibc's noexcept variants). This
 * header therefore exposes only plain C types so a C++ (Qt) frontend can
 * include it directly; every uhub header stays confined to adcbridge.c.
 *
 * The bridge also owns the reactor: adcbridge_create() spins up a worker
 * thread that runs uhub's single-threaded event loop. All adcbridge_*
 * entry points are thread-safe -- they marshal the request onto that thread
 * via uhub's own wakeup pipe. Callbacks fire ON the reactor thread, so a
 * frontend must re-marshal them to its own UI thread (the Qt frontend does
 * this with queued signals).
 */

#ifndef HAVE_UHUB_ADCBRIDGE_H
#define HAVE_UHUB_ADCBRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct adcbridge adcbridge;

/* Coarse connection/login lifecycle reported through on_state. */
enum adcbridge_state
{
	ADCBRIDGE_CONNECTING    = 1,
	ADCBRIDGE_CONNECTED     = 2,
	ADCBRIDGE_SSL_HANDSHAKE = 3,
	ADCBRIDGE_LOGGING_IN    = 4,
	ADCBRIDGE_LOGGED_IN     = 5,
	ADCBRIDGE_DISCONNECTED  = 6,
};

enum adcbridge_chat_flags
{
	ADCBRIDGE_CHAT_ACTION  = 1,
	ADCBRIDGE_CHAT_PRIVATE = 2,
};

struct adcbridge_user
{
	uint32_t    sid;
	const char* nick;
	const char* description;
	const char* address;
	const char* version;
	int         is_op;
	int         is_bot;
	uint64_t    shared_size;
};

/* All callbacks are invoked on the reactor thread. String arguments are
   owned by the bridge and valid only for the duration of the call. */
struct adcbridge_callbacks
{
	void* user; /* opaque, echoed back as the first argument of each cb */

	void (*on_state)(void* user, int state);
	void (*on_login_error)(void* user, int code, const char* message);
	void (*on_ssl_ok)(void* user, const char* version, const char* cipher);
	void (*on_hub_info)(void* user, const char* name, const char* version, const char* description);
	void (*on_status)(void* user, int code, const char* message);
	void (*on_chat)(void* user, uint32_t from_sid, const char* from_nick, const char* text, int flags);
	void (*on_user_join)(void* user, const struct adcbridge_user* u);
	void (*on_user_update)(void* user, const struct adcbridge_user* u);
	void (*on_user_quit)(void* user, uint32_t sid, const char* nick);
	void (*on_log)(void* user, const char* line);
};

adcbridge* adcbridge_create(const struct adcbridge_callbacks* callbacks);
void       adcbridge_destroy(adcbridge* b);

/* Thread-safe intent. Text arguments are plain (the bridge escapes them). */
void adcbridge_connect(adcbridge* b, const char* address, const char* nick, const char* password);
void adcbridge_disconnect(adcbridge* b);
void adcbridge_say(adcbridge* b, const char* text);
void adcbridge_say_me(adcbridge* b, const char* text);
void adcbridge_pm(adcbridge* b, uint32_t sid, const char* text);
void adcbridge_search(adcbridge* b, const char* terms);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_UHUB_ADCBRIDGE_H */
