#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "system.h"
#include "util/memory.h"
#include "util/list.h"
#include "network/connection.h"
#include "network/ipcalc.h"
#include "network/network.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "core/auth.h"
#include "core/config.h"
#include "core/eventid.h"
#include "core/eventqueue.h"
#include "core/hub.h"
#include "core/netevent.h"
#include "core/route.h"
#include "core/user.h"
#include "core/usermanager.h"
#include "testutil_net.h"

/*
 * net_event(), the per-user socket callback, against a real user on a
 * socketpair. The test plays the client on the far end and calls net_event()
 * directly with the event mask a reactor wakeup would carry.
 */

static struct hub_info* ne_hub = 0;

/* The parts of hub_event_dispatcher() that unlink and free users. */
static void ne_dispatch(void* data, struct event_data* ev)
{
	struct hub_info* hub = (struct hub_info*) data;
	struct hub_user* user = (struct hub_user*) ev->ptr;
	if (ev->id == UHUB_EVENT_USER_QUIT)
	{
		uman_remove(hub->users, user);
		hub_schedule_destroy_user(hub, user);
	}
	else if (ev->id == UHUB_EVENT_USER_DESTROY)
	{
		route_clear_dirty(hub, user);
		user_destroy(user);
	}
}

EXO_SETUP({
	if (!test_net_acquire())
		return 0;
	ne_hub = (struct hub_info*) hub_malloc_zero(sizeof(struct hub_info));
	if (!ne_hub)
		return 0;
	ne_hub->users = uman_init(0, 1);
	ne_hub->acl = (struct acl_handle*) hub_malloc_zero(sizeof(struct acl_handle));
	ne_hub->config = (struct hub_config*) hub_malloc_zero(sizeof(struct hub_config));
	ne_hub->write_queue = list_create();
	if (!ne_hub->users || !ne_hub->acl || !ne_hub->config || !ne_hub->write_queue)
		return 0;
	config_defaults(ne_hub->config);
	acl_initialize(ne_hub->config, ne_hub->acl);
	ne_hub->status = hub_status_running;
	return event_queue_initialize(&ne_hub->queue, ne_dispatch, ne_hub) != -1;
});

EXO_TEARDOWN({
	if (ne_hub)
	{
		if (ne_hub->queue)
		{
			event_queue_process(ne_hub->queue);
			event_queue_shutdown(ne_hub->queue);
		}
		uman_shutdown(ne_hub->users);
		list_destroy(ne_hub->write_queue);
		acl_shutdown(ne_hub->acl);
		free_config(ne_hub->config);
		hub_free(ne_hub->acl);
		hub_free(ne_hub->config);
		hub_free(ne_hub);
		ne_hub = 0;
	}
	test_net_release();
	return 1;
});

/* A freshly accepted user, still negotiating SUP; *peer is the client end. */
static struct hub_user* ne_user(int* peer)
{
	int sv[2];
	struct net_connection* con;
	struct ip_addr_encap addr;
	struct hub_user* user;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return NULL;
	net_set_nonblocking(sv[0], 1);
	con = net_con_create();
	if (!con)
	{
		close(sv[0]);
		close(sv[1]);
		return NULL;
	}
	net_con_initialize(con, sv[0], NULL, NULL, 0);
	memset(&addr, 0, sizeof(addr));
	addr.af = AF_INET;
	user = user_create(ne_hub, con, &addr);
	if (!user)
	{
		net_con_close(con);
		close(sv[1]);
		return NULL;
	}
	*peer = sv[1];
	return user;
}

/* A handler can disconnect the sender and still succeed -- here a SUP naming no
   hash the hub knows; a flood plugin's kick is another. If that was the last
   line read and the same wakeup reported the socket writable too, the write
   side must be left alone: it used to dereference the connection the
   disconnect had just dropped. */
EXO_TEST(netevent_disconnect_on_read_skips_write, {
	const char* sup = "HSUP ADBASE\n";
	struct hub_user* user;
	int peer = -1;
	int ok;

	user = ne_user(&peer);
	if (!user)
		return 0;
	ok = write(peer, sup, strlen(sup)) == (ssize_t) strlen(sup);
	if (ok)
	{
		net_event(user->connection, NET_EVENT_READ | NET_EVENT_WRITE, user);
		ok = user->connection == NULL && user_is_disconnecting(user);
	}
	else
	{
		hub_disconnect_user(ne_hub, user, quit_disconnected);
	}
	event_queue_process(ne_hub->queue); /* frees the user */
	close(peer);
	return ok;
});

/* Writing for a user whose connection is already gone is a no-op. */
EXO_TEST(netevent_write_without_connection, {
	struct hub_user* user;
	int peer = -1;
	int ok;

	user = ne_user(&peer);
	if (!user)
		return 0;
	hub_disconnect_user(ne_hub, user, quit_disconnected);
	ok = user->connection == NULL && handle_net_write(user) == 0;
	event_queue_process(ne_hub->queue);
	close(peer);
	return ok;
});

/* Everything the hub has written to the client end so far. */
static size_t ne_read(int peer, char* buf, size_t size)
{
	size_t len = 0;
	ssize_t n;
	fcntl(peer, F_SETFL, fcntl(peer, F_GETFL) | O_NONBLOCK);
	while (len < size - 1 && (n = read(peer, buf + len, size - 1 - len)) > 0)
		len += (size_t) n;
	buf[len] = 0;
	return len;
}

/* A node that leases its SID window has none until the lease arrives, and a
   full window has none to give either. The login is refused rather than handed
   SID 0 -- AAAA, the hub's own, which every such user would share. */
EXO_TEST(netevent_no_free_sid_refuses_login, {
	const char* sup = "HSUP ADBASE ADTIGR\n";
	struct hub_user_manager* users = ne_hub->users;
	struct hub_user* user;
	char out[1024];
	int peer = -1;
	int ok;

	ne_hub->users = uman_init(-1, 2); /* pending dynamic lease: empty window */
	ne_hub->command_support = adc_msg_create("ISUP ADBASE ADTIGR\n");
	user = ne_hub->users ? ne_user(&peer) : NULL;
	ok = user != NULL;
	if (ok)
		ok = write(peer, sup, strlen(sup)) == (ssize_t) strlen(sup);
	if (ok)
	{
		net_event(user->connection, NET_EVENT_READ, user);
		ne_read(peer, out, sizeof(out));
		ok = user_is_disconnecting(user) && user->id.sid == 0
			&& strstr(out, "ISUP ") && strstr(out, "ISTA ") && !strstr(out, "ISID");
	}
	else if (user)
	{
		hub_disconnect_user(ne_hub, user, quit_disconnected);
	}
	event_queue_process(ne_hub->queue);
	if (peer != -1)
		close(peer);
	adc_msg_free(ne_hub->command_support);
	ne_hub->command_support = NULL;
	uman_shutdown(ne_hub->users);
	ne_hub->users = users;
	return ok;
});

/* Log a user in, have it leave while the hub is in `status`, and check that
   the quit event -- what unlinks it and tells the others, linked hubs and
   plugins -- is what removes it, rather than an unannounced drop on the spot.
   That drop also restarted, or ran a reentrant walk off, any walk of the user
   list the departure happened in. */
static int ne_quit_announced(enum hub_state status)
{
	struct hub_user* user;
	int peer = -1;
	int ok;

	user = ne_user(&peer);
	if (!user)
		return 0;
	strcpy(user->id.nick, "leaver");
	strcpy(user->id.cid, "GNSSMURMD7K466NGZIHU65TP3S3UZSQ6MN5B2RI");
	user_set_state(user, state_normal);
	ok = uman_add(ne_hub->users, user) == 0;

	ne_hub->status = status;
	hub_disconnect_user(ne_hub, user, quit_disconnected);
	/* Still listed: the quit event is what unlinks and announces it. */
	ok = ok && uman_get_user_by_nick(ne_hub->users, "leaver") == user
		&& event_queue_size(ne_hub->queue) == 1;
	event_queue_process(ne_hub->queue); /* QUIT */
	ok = ok && uman_get_user_by_nick(ne_hub->users, "leaver") == NULL;
	event_queue_process(ne_hub->queue); /* DESTROY */
	ne_hub->status = hub_status_running;
	close(peer);
	return ok;
}

/* A disabled hub (hub_enabled = no) keeps the users it has; one leaving used
   to vanish from every other client's view without a quit. */
EXO_TEST(netevent_disabled_hub_announces_quit, { return ne_quit_announced(hub_status_disabled); });

/* So does a reloading one: users stay connected across a reload. */
EXO_TEST(netevent_reloading_hub_announces_quit, { return ne_quit_announced(hub_status_restart); });
