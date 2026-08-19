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

#include "util/log.h"
#include "util/memory.h"
#include "adc/message.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/ioqueue.h"
#include "core/link.h"
#include "core/netevent.h"
#include "core/route.h"
#include "core/usermanager.h"

/*
 * RTF0: the RT flag is only meaningful to clients that negotiated RTF0, so a
 * rich text message is relayed in two variants -- the original to RTF0 clients,
 * and an RT-stripped copy to everyone else. Returns NULL when no stripped copy
 * is needed, which is the common case: only MSG commands can carry the flag, so
 * ordinary traffic never pays for a copy (and an unknown "RT" in some other
 * command is left alone). NULL is also returned when the copy fails, in which
 * case every client simply sees the original.
 */
struct adc_message* route_rtf0_strip(struct adc_message* msg)
{
	struct adc_message* plain;

	if (msg->cmd != ADC_CMD_BMSG && msg->cmd != ADC_CMD_DMSG &&
	    msg->cmd != ADC_CMD_EMSG && msg->cmd != ADC_CMD_FMSG)
		return NULL;

	if (!adc_msg_has_named_argument(msg, ADC_MSG_FLAG_RICH_TEXT))
		return NULL;

	plain = adc_msg_copy(msg);
	if (plain)
		adc_msg_remove_named_argument(plain, ADC_MSG_FLAG_RICH_TEXT);
	return plain;
}

/**
 * Pick the message every recipient starts from: normally the original, but the
 * stripped copy when rich text is disabled hub-wide, so that no client -- and
 * no linked hub -- is handed the RT flag.
 * @param plain the RT-stripped copy, or NULL if the message is not rich text.
 */
struct adc_message* route_rtf0_baseline(struct hub_info* hub, struct adc_message* msg, struct adc_message* plain)
{
	if (plain && !hub->config->chat_rich_text)
		return plain;
	return msg;
}

/**
 * Pick the variant of a message a given user is allowed to see.
 * @param plain the RT-stripped copy, or NULL if the message is not rich text.
 */
struct adc_message* route_rtf0_variant(struct hub_user* user, struct adc_message* rich, struct adc_message* plain)
{
	if (plain && !user_flag_get(user, feature_rtf0))
		return plain;
	return rich;
}

/*
 * ADCS compatibility (adcs_translate).
 *
 * The encrypted client-to-client extension is announced in the INF "SU" field
 * as either ADCS (ADC-EXT) or ADC0 (the draft, and what the DC++ family sends),
 * and the connect requests name the matching protocol version, ADCS/1.0 or
 * ADCS/0.10. A fourcc in SU is matched whole and a protocol version compared as
 * a string, so a client that knows only one of the two reads the other as an
 * extension it does not have and a protocol it cannot speak: it refuses the
 * transfer, or arranges a plaintext one.
 *
 * Clients that understand both spellings need none of this, and the hub
 * rewriting the protocol field of a peer connection is not something to do by
 * default -- it is the one field in a CTM the hub gets to touch on the way past,
 * and clients treat "the hub relayed this" as a reason to distrust a weaker
 * protocol than they asked for. Translating between the two TLS spellings is
 * not a downgrade, but it is still the hub deciding, so it is opt-in.
 *
 * The rewrite is stateless and symmetric: every relayed connect request, and
 * every status message refusing one, is put into the spelling its single
 * recipient announced. An RCM asking for ADCS/1.0 reaches an ADC0 client as
 * ADCS/0.10, its CTM comes back as ADCS/0.10 and reaches the asker as
 * ADCS/1.0, and the STA that refuses either arrives in the reader's own words.
 */

/** Which spelling this user recognises, or NULL if it does not matter. */
static const char* adcs_spelling_for(struct hub_user* user)
{
	int spec = user_flag_get(user, feature_adcs) != 0;
	int draft = user_flag_get(user, feature_adc0) != 0;

	/* Both: it reads either, and the sender's own choice is left alone.
	   Neither: it announced no encryption at all, and there is nothing to
	   translate to -- inventing a spelling for it would be guessing. */
	if (spec == draft)
		return NULL;

	return spec ? ADC_PROTO_TLS : ADC_PROTO_TLS_DRAFT;
}

static int adcs_is_tls_protocol(const char* protocol)
{
	return strcmp(protocol, ADC_PROTO_TLS) == 0 || strcmp(protocol, ADC_PROTO_TLS_DRAFT) == 0;
}

struct adc_message* route_adcs_translate(struct hub_info* hub, struct hub_user* target, struct adc_message* msg)
{
	const char* want;
	char* have;
	struct adc_message* copy;
	int named;
	int rewrite;

	if (!hub->config->adcs_translate)
		return NULL;

	switch (msg->cmd)
	{
		/* The protocol is the first argument of a connect request. */
		case ADC_CMD_DCTM:
		case ADC_CMD_DRCM:
		case ADC_CMD_DNAT:
		case ADC_CMD_DRNT:
			named = 0;
			break;

		/* A status message refusing one echoes it back in "PR". */
		case ADC_CMD_DSTA:
			named = 1;
			break;

		default:
			return NULL;
	}

	want = adcs_spelling_for(target);
	if (!want)
		return NULL;

	have = named ? adc_msg_get_named_argument(msg, ADC_STA_FLAG_PROTOCOL)
	             : adc_msg_get_argument(msg, 0);
	if (!have)
		return NULL;

	/* Only the other TLS spelling is rewritten. Plain ADC/1.0 is left as it
	   is -- translating it would be offering encryption on the sender's behalf
	   -- and so is anything else, which is not ours to name. */
	rewrite = adcs_is_tls_protocol(have) && strcmp(have, want) != 0;
	hub_free(have);

	if (!rewrite)
		return NULL;

	copy = adc_msg_copy(msg);
	if (!copy)
		return NULL; /* OOM: the original goes out, in the sender's spelling */

	if ((named ? adc_msg_replace_named_argument(copy, ADC_STA_FLAG_PROTOCOL, want)
	           : adc_msg_replace_argument(copy, 0, want)) == -1)
	{
		adc_msg_free(copy);
		return NULL;
	}

	return copy;
}


static int route_to_all_ex(struct hub_info* hub, struct adc_message* rich, struct adc_message* plain);
static int route_to_subscribers_ex(struct hub_info* hub, struct adc_message* rich, struct adc_message* plain);

int route_message(struct hub_info* hub, struct hub_user* u, struct adc_message* msg)
{
	struct hub_user* target = NULL;
	struct adc_message* plain = route_rtf0_strip(msg);
	struct adc_message* rich = route_rtf0_baseline(hub, msg, plain);

	switch (msg->cache[0])
	{
		case 'B': /* Broadcast to all logged in clients */
			route_to_all_ex(hub, rich, plain);
			link_relay_broadcast(hub, rich); /* + linked hubs (chat/search only) */
			break;

		case 'D':
			target = uman_get_user_by_sid(hub->users, msg->target);
			if (target)
			{
				struct adc_message* variant = route_rtf0_variant(target, rich, plain);
				struct adc_message* translated = route_adcs_translate(hub, target, variant);

				route_to_user(hub, target, translated ? translated : variant);

				/* The recipient took its own reference in ioq_send_add(). */
				adc_msg_free(translated);
			}
			break;

		case 'E':
			target = uman_get_user_by_sid(hub->users, msg->target);
			if (target)
			{
				route_to_user(hub, target, route_rtf0_variant(target, rich, plain));
				route_to_user(hub, u, route_rtf0_variant(u, rich, plain));
			}
			break;

		case 'F':
			route_to_subscribers_ex(hub, rich, plain);
			link_relay_broadcast(hub, rich); /* + linked hubs (feature-cast chat/search) */
			break;

		default:
			/* Ignore the message */
			break;
	}

	/* Each recipient took its own reference in ioq_send_add(). */
	adc_msg_free(plain);
	return 0;
}

size_t get_max_send_queue(struct hub_info* hub)
{
	/*
	 * Hard send-queue limit (exceeding it disconnects the user). A user that
	 * drains slowly accumulates messages generated by every other active user
	 * -- chat, search results, INF updates -- so the legitimate ceiling grows
	 * with the number of connected users. Allow up to one max_recv_buffer per
	 * connected user, but never drop below the configured max_send_buffer floor
	 * (which also keeps the hard limit above the fixed soft limit).
	 */
	return MAX((size_t) hub->config->max_send_buffer,
	           (size_t) hub->config->max_recv_buffer * hub_get_user_count(hub));
}

size_t get_max_send_queue_soft(struct hub_info* hub)
{
	return hub->config->max_send_buffer_soft;
}

/*
 * @return 1 if send queue is OK.
 *         -1 if the hard send queue limit is overflowed (caller disconnects the user)
 *         0 if the soft send queue limit is overflowed (message still queued, user choked)
 */
static int check_send_queue(struct hub_info* hub, struct hub_user* user, struct adc_message* msg)
{
	if (user_flag_get(user, flag_user_list))
		return 1;

	if ((user->send_queue->size + msg->length) > get_max_send_queue(hub))
	{
		user_flag_set(user, flag_choke);
		LOG_WARN("send queue overflowed, disconnecting user.");
		return -1;
	}

	if (user->send_queue->size > get_max_send_queue_soft(hub))
	{
		user_flag_set(user, flag_choke);
		LOG_WARN("send queue soft overflowed.");
		return 0;
	}

	user_flag_unset(user, flag_choke);
	return 1;
}

int route_to_user(struct hub_info* hub, struct hub_user* user, struct adc_message* msg)
{
	/* Remote user (federation): no local socket. Forward only directed (D/E)
	   messages over the owning link; the peer delivers to its local target.
	   Broadcasts/presence reaching a remote user here are not relayed per-user
	   -- presence goes via the B3 delta path, and broadcast chat/search relay
	   is a separate per-link follow-up -- which avoids duplicate fan-out. */
	if (user_is_remote(user))
	{
		char type = msg->cache ? msg->cache[0] : 0;
		if (type == 'D' || type == 'E')
			link_forward_message(user->origin_link, msg);
		return 1;
	}

	if (!user->connection)
		return 0;

	uhub_assert(msg->cache && *msg->cache);

	if (check_send_queue(hub, user, msg) < 0)
	{
		/* Hard send-queue overflow: the client is not keeping up. */
		hub_disconnect_user(hub, user, quit_send_queue);
		return 1;
	}

	ioq_send_add(user->send_queue, msg);

	/* Defer the write to the end of the event-loop iteration (route_flush_dirty)
	   so that several messages queued in the same tick -- e.g. a broadcast, or
	   the per-message fan-out of a busy hub -- coalesce into a single
	   writev()/SSL_write() instead of one syscall each. Pipelined handshake
	   messages are flushed explicitly by route_flush_pipeline(). */
	if (!user_flag_get(user, flag_pipeline) && !user_flag_get(user, flag_dirty))
	{
		user_flag_set(user, flag_dirty);
		list_append(hub->write_queue, user);
	}
	return 1;
}

/*
 * Flush all connections with messages queued this iteration. Called once per
 * event-loop pass, at the very end -- after both net_backend_process() and
 * event_queue_process() -- so that deferred writes produced while handling
 * events (e.g. the user-list dump and presence sent on login) go out in the
 * same iteration rather than waiting for the next reactor wakeup. A user
 * destroyed during event processing is removed from the queue by
 * route_clear_dirty(), so every remaining entry is a live struct (its
 * connection may already be closed, which is skipped below).
 */
void route_flush_dirty(struct hub_info* hub)
{
	struct hub_user* user;

	if (list_size(hub->write_queue) == 0)
		return;

	LIST_FOREACH(struct hub_user*, user, hub->write_queue,
	{
		user_flag_unset(user, flag_dirty);
		if (user->connection && !user_is_disconnecting(user))
		{
			int ret = handle_net_write(user);
			if (ret)
				hub_disconnect_user(hub, user, ret);
		}
	});

	list_clear(hub->write_queue, NULL);
}

/*
 * Drop a user from the deferred-write queue. Called when a user is about to be
 * destroyed so route_flush_dirty() never dereferences a freed struct.
 */
void route_clear_dirty(struct hub_info* hub, struct hub_user* user)
{
	if (user_flag_get(user, flag_dirty))
	{
		user_flag_unset(user, flag_dirty);
		list_remove(hub->write_queue, user);
	}
}

int route_flush_pipeline(struct hub_info* hub, struct hub_user* u)
{
	(void) hub;
	if (ioq_send_is_empty(u->send_queue))
		return 0;

	handle_net_write(u);
	user_flag_unset(u, flag_pipeline);
	return 1;
}


static int route_to_all_ex(struct hub_info* hub, struct adc_message* rich, struct adc_message* plain) /* iterate users */
{
	struct hub_user* user;
	hub->metrics.broadcasts++;
	LIST_FOREACH(struct hub_user*, user, hub->users->list,
	{
		route_to_user(hub, user, route_rtf0_variant(user, rich, plain));
	});

	return 0;
}

int route_to_all(struct hub_info* hub, struct adc_message* command) /* iterate users */
{
	return route_to_all_ex(hub, command, NULL);
}

static int route_to_subscribers_ex(struct hub_info* hub, struct adc_message* command, struct adc_message* plain) /* iterate users */
{
	int do_send;
	char* tmp;

	struct hub_user* user;
	hub->metrics.feature_casts++;
	LIST_FOREACH(struct hub_user*, user, hub->users->list,
	{
		if (user->feature_cast)
		{
			do_send = 1;

			LIST_FOREACH(char*, tmp, command->feature_cast_include,
			{
				if (!user_have_feature_cast_support(user, tmp))
				{
					do_send = 0;
					break;
				}
			});

			if (!do_send)
				continue;

			LIST_FOREACH(char*, tmp, command->feature_cast_exclude,
			{
				if (user_have_feature_cast_support(user, tmp))
				{
					do_send = 0;
					break;
				}
			});

			if (do_send)
				route_to_user(hub, user, route_rtf0_variant(user, command, plain));
		}
	});

	return 0;
}

int route_to_subscribers(struct hub_info* hub, struct adc_message* command) /* iterate users */
{
	return route_to_subscribers_ex(hub, command, NULL);
}

int route_info_message(struct hub_info* hub, struct hub_user* u)
{
	if (!user_is_nat_override(u))
	{
		return route_to_all(hub, u->info);
	}
	else
	{
		struct adc_message* cmd = adc_msg_copy(u->info);
		const char* address = user_get_address(u);
		struct hub_user* user = 0;

		adc_msg_remove_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR);
		adc_msg_add_named_argument(cmd, ADC_INF_FLAG_IPV4_ADDR, address);

		LIST_FOREACH(struct hub_user*, user, hub->users->list,
		{
			if (user_is_nat_override(user))
				route_to_user(hub, user, cmd);
			else
				route_to_user(hub, user, u->info);
		});
		adc_msg_free(cmd);
	}
	return 0;
}
