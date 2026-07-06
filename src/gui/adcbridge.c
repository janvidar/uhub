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

#include "gui/adcbridge.h"

#include "tools/adcclient.h"
#include "network/network.h"
#include "network/backend.h"
#include "network/notify.h"

#include <pthread.h>

enum cmd_type
{
	CMD_CONNECT,
	CMD_DISCONNECT,
	CMD_SAY,
	CMD_SAY_ME,
	CMD_PM,
	CMD_SEARCH,
	CMD_QUIT,
};

struct cmd
{
	enum cmd_type type;
	char* s1;
	char* s2;
	char* s3;
	uint32_t sid;
	struct cmd* next;
};

struct adcbridge
{
	struct adcbridge_callbacks cb;
	struct ADC_client* client;
	struct uhub_notify_handle* notify;
	pthread_t thread;
	pthread_mutex_t lock;   /* guards the command queue and ready flag */
	pthread_cond_t ready_cond;
	int ready;              /* set once the reactor thread has its notify pipe */
	struct cmd* head;       /* FIFO: dequeue at head    */
	struct cmd* tail;
	int running;            /* reactor-thread-only after start */
	int started;
};

/* ------------------------------------------------------------------ *
 *  Command queue (GUI thread enqueues; reactor thread drains)
 * ------------------------------------------------------------------ */

static char* dup_str(const char* s)
{
	if (!s)
		return NULL;
	size_t n = strlen(s);
	char* c = (char*) hub_malloc(n + 1);
	memcpy(c, s, n + 1);
	return c;
}

static void cmd_free(struct cmd* c)
{
	hub_free(c->s1);
	hub_free(c->s2);
	hub_free(c->s3);
	hub_free(c);
}

static void bridge_post(adcbridge* b, struct cmd* c)
{
	c->next = NULL;
	pthread_mutex_lock(&b->lock);
	if (b->tail)
		b->tail->next = c;
	else
		b->head = c;
	b->tail = c;
	pthread_mutex_unlock(&b->lock);

	/* Wake the reactor thread out of its poll() so it drains the queue. */
	net_notify_signal(b->notify, 'c');
}

static struct cmd* bridge_take(adcbridge* b)
{
	struct cmd* c;
	pthread_mutex_lock(&b->lock);
	c = b->head;
	if (c)
	{
		b->head = c->next;
		if (!b->head)
			b->tail = NULL;
	}
	pthread_mutex_unlock(&b->lock);
	return c;
}

/* ------------------------------------------------------------------ *
 *  ADC client -> bridge callbacks (reactor thread)
 * ------------------------------------------------------------------ */

static const char* nick_for(struct ADC_client* client, sid_t sid)
{
	if (sid == 0)
		return NULL; /* hub */
	if (sid == ADC_client_get_sid(client))
		return ADC_client_get_nick(client);
	{
		const struct ADC_user* u = ADC_client_get_user(client, sid);
		return u ? u->name : NULL;
	}
}

static void fill_user(struct adcbridge_user* out, const struct ADC_user* u)
{
	memset(out, 0, sizeof(*out));
	out->sid         = u->sid;
	out->nick        = u->name;
	out->description = u->description;
	out->address     = u->address[0] ? u->address : u->address6;
	out->version     = u->version;
	out->is_op       = (u->type & adc_user_operator) != 0;
	out->is_bot      = (u->type & adc_user_bot) != 0;
	out->shared_size = u->shared_size;
}

static int bridge_adc_cb(struct ADC_client* client, enum ADC_client_event_type type, struct ADC_client_callback_data* data)
{
	adcbridge* b = (adcbridge*) ADC_client_get_ptr(client);
	const struct adcbridge_callbacks* cb = &b->cb;

	switch (type)
	{
		case ADC_CLIENT_CONNECTING:
			if (cb->on_state) cb->on_state(cb->user, ADCBRIDGE_CONNECTING);
			break;
		case ADC_CLIENT_CONNECTED:
			if (cb->on_state) cb->on_state(cb->user, ADCBRIDGE_CONNECTED);
			break;
		case ADC_CLIENT_SSL_HANDSHAKE:
			if (cb->on_state) cb->on_state(cb->user, ADCBRIDGE_SSL_HANDSHAKE);
			break;
		case ADC_CLIENT_SSL_OK:
			if (cb->on_ssl_ok && data && data->tls_info)
				cb->on_ssl_ok(cb->user, data->tls_info->version, data->tls_info->cipher);
			break;
		case ADC_CLIENT_LOGGING_IN:
			if (cb->on_state) cb->on_state(cb->user, ADCBRIDGE_LOGGING_IN);
			break;
		case ADC_CLIENT_LOGGED_IN:
			if (cb->on_state) cb->on_state(cb->user, ADCBRIDGE_LOGGED_IN);
			break;
		case ADC_CLIENT_DISCONNECTED:
			if (cb->on_state) cb->on_state(cb->user, ADCBRIDGE_DISCONNECTED);
			break;

		case ADC_CLIENT_LOGIN_ERROR:
			if (cb->on_login_error)
				cb->on_login_error(cb->user,
					data && data->status ? data->status->code : 0,
					data && data->status ? data->status->message : NULL);
			break;

		case ADC_CLIENT_PROTOCOL_STATUS:
			if (cb->on_status && data && data->status)
				cb->on_status(cb->user, data->status->code, data->status->message);
			break;

		case ADC_CLIENT_HUB_INFO:
			if (cb->on_hub_info && data && data->hubinfo)
				cb->on_hub_info(cb->user, data->hubinfo->name, data->hubinfo->version, data->hubinfo->description);
			break;

		case ADC_CLIENT_MESSAGE:
			if (cb->on_chat && data && data->chat)
				cb->on_chat(cb->user, data->chat->from_sid, nick_for(client, data->chat->from_sid),
					data->chat->message, data->chat->flags);
			break;

		case ADC_CLIENT_USER_JOIN:
			if (cb->on_user_join && data && data->user)
			{
				struct adcbridge_user u;
				fill_user(&u, data->user);
				cb->on_user_join(cb->user, &u);
			}
			break;

		case ADC_CLIENT_USER_UPDATE:
			if (cb->on_user_update && data && data->user)
			{
				struct adcbridge_user u;
				fill_user(&u, data->user);
				cb->on_user_update(cb->user, &u);
			}
			break;

		case ADC_CLIENT_USER_QUIT:
			if (cb->on_user_quit && data && data->quit)
				cb->on_user_quit(cb->user, data->quit->sid, nick_for(client, data->quit->sid));
			break;

		default:
			break;
	}
	return 0;
}

static void bridge_log_cb(struct ADC_client* client, int level, const char* msg)
{
	adcbridge* b = (adcbridge*) ADC_client_get_ptr(client);
	(void) level;
	if (b->cb.on_log)
		b->cb.on_log(b->cb.user, msg);
}

/* ------------------------------------------------------------------ *
 *  Command execution (reactor thread)
 * ------------------------------------------------------------------ */

static void exec_cmd(adcbridge* b, struct cmd* c)
{
	switch (c->type)
	{
		case CMD_CONNECT:
			if (b->client)
			{
				ADC_client_destroy(b->client);
				b->client = NULL;
			}
			b->client = ADC_client_create(c->s2 ? c->s2 : "uhub-qt", "uhub-qt", b);
			ADC_client_set_callback(b->client, bridge_adc_cb);
			ADC_client_set_log_callback(b->client, bridge_log_cb);
			if (c->s3 && *c->s3)
				ADC_client_set_password(b->client, c->s3);
			ADC_client_connect(b->client, c->s1);
			break;

		case CMD_DISCONNECT:
			if (b->client)
				ADC_client_disconnect(b->client);
			break;

		case CMD_SAY:
			if (b->client) ADC_client_say(b->client, c->s1);
			break;

		case CMD_SAY_ME:
			if (b->client) ADC_client_say_me(b->client, c->s1);
			break;

		case CMD_PM:
			if (b->client) ADC_client_pm(b->client, c->sid, c->s1);
			break;

		case CMD_SEARCH:
			if (b->client) ADC_client_search(b->client, c->s1);
			break;

		case CMD_QUIT:
			b->running = 0;
			break;
	}
}

static void notify_cb(struct uhub_notify_handle* handle, void* ptr)
{
	adcbridge* b = (adcbridge*) ptr;
	struct cmd* c;
	(void) handle;
	while ((c = bridge_take(b)) != NULL)
	{
		exec_cmd(b, c);
		cmd_free(c);
	}
}

/* ------------------------------------------------------------------ *
 *  Reactor thread
 * ------------------------------------------------------------------ */

static void* reactor_main(void* arg)
{
	adcbridge* b = (adcbridge*) arg;

	net_initialize();
	b->notify = net_notify_create(notify_cb, b);
	b->running = 1;

	/* Publish readiness: only now is net_notify_signal() safe to call, so
	   adcbridge_create() blocks until this point before returning and letting
	   the caller post commands. */
	pthread_mutex_lock(&b->lock);
	b->ready = 1;
	pthread_cond_signal(&b->ready_cond);
	pthread_mutex_unlock(&b->lock);

	while (b->running && net_backend_process())
	{
		/* net_backend_process() blocks in poll(); the notify pipe wakes it
		   whenever a command is posted, and the command callbacks run inline
		   before this returns. */
	}

	if (b->client)
	{
		ADC_client_destroy(b->client);
		b->client = NULL;
	}
	net_notify_destroy(b->notify);
	b->notify = NULL;
	net_destroy();
	return NULL;
}

/* ------------------------------------------------------------------ *
 *  Public API
 * ------------------------------------------------------------------ */

adcbridge* adcbridge_create(const struct adcbridge_callbacks* callbacks)
{
	adcbridge* b = (adcbridge*) hub_malloc_zero(sizeof(adcbridge));
	b->cb = *callbacks;
	pthread_mutex_init(&b->lock, NULL);
	pthread_cond_init(&b->ready_cond, NULL);

	if (pthread_create(&b->thread, NULL, reactor_main, b) != 0)
	{
		pthread_cond_destroy(&b->ready_cond);
		pthread_mutex_destroy(&b->lock);
		hub_free(b);
		return NULL;
	}
	b->started = 1;

	/* Wait until the reactor thread has created its notify pipe, so every
	   later adcbridge_* call has a valid handle to signal. */
	pthread_mutex_lock(&b->lock);
	while (!b->ready)
		pthread_cond_wait(&b->ready_cond, &b->lock);
	pthread_mutex_unlock(&b->lock);

	return b;
}

void adcbridge_destroy(adcbridge* b)
{
	struct cmd* c;
	if (!b)
		return;

	if (b->started)
	{
		struct cmd* q = (struct cmd*) hub_malloc_zero(sizeof(struct cmd));
		q->type = CMD_QUIT;
		bridge_post(b, q);
		pthread_join(b->thread, NULL);
	}

	/* Free any commands still queued (posted after QUIT, never executed). */
	while ((c = bridge_take(b)) != NULL)
		cmd_free(c);

	pthread_cond_destroy(&b->ready_cond);
	pthread_mutex_destroy(&b->lock);
	hub_free(b);
}

static void post_simple(adcbridge* b, enum cmd_type type, const char* s1)
{
	struct cmd* c = (struct cmd*) hub_malloc_zero(sizeof(struct cmd));
	c->type = type;
	c->s1 = dup_str(s1);
	bridge_post(b, c);
}

void adcbridge_connect(adcbridge* b, const char* address, const char* nick, const char* password)
{
	struct cmd* c = (struct cmd*) hub_malloc_zero(sizeof(struct cmd));
	c->type = CMD_CONNECT;
	c->s1 = dup_str(address);
	c->s2 = dup_str(nick);
	c->s3 = dup_str(password);
	bridge_post(b, c);
}

void adcbridge_disconnect(adcbridge* b)
{
	struct cmd* c = (struct cmd*) hub_malloc_zero(sizeof(struct cmd));
	c->type = CMD_DISCONNECT;
	bridge_post(b, c);
}

void adcbridge_say(adcbridge* b, const char* text)      { post_simple(b, CMD_SAY, text); }
void adcbridge_say_me(adcbridge* b, const char* text)   { post_simple(b, CMD_SAY_ME, text); }
void adcbridge_search(adcbridge* b, const char* terms)  { post_simple(b, CMD_SEARCH, terms); }

void adcbridge_pm(adcbridge* b, uint32_t sid, const char* text)
{
	struct cmd* c = (struct cmd*) hub_malloc_zero(sizeof(struct cmd));
	c->type = CMD_PM;
	c->sid = sid;
	c->s1 = dup_str(text);
	bridge_post(b, c);
}
