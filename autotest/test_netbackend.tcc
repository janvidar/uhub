#include "network/network.h"
#include "network/connection.h"
#include "network/backend.h"

/*
 * Regression tests for the network backend event-registration state machine.
 *
 * These exercise the per-cycle "last write wins" semantics that the epoll
 * backend has always had and that the kqueue backend used to get wrong: a
 * second net_con_update() issued before the next poll must replace the desired
 * read/write mask, not be silently coalesced away (kqueue's add_change() used
 * to drop it). The bug manifested as either stalled output (a WRITE enable that
 * never reached the kernel) or a busy-spin (a WRITE disable that was lost).
 *
 * The suite is written to be hang-free: every net_backend_process() call is
 * made with at least one event already satisfiable (a readable byte and/or a
 * writable socket), so a misbehaving backend fails an assertion rather than
 * blocking on the poll.
 */

struct nb_probe
{
	int events;	/* OR of every NET_EVENT_* delivered to this connection */
	int reads;	/* number of read events (drained to keep level-trigger sane) */
};

static int nb_sv[2];
static struct net_connection* nb_con = 0;
static struct nb_probe nb_state;

static void nb_reset(struct nb_probe* p)
{
	p->events = 0;
	p->reads = 0;
}

static void nb_callback(struct net_connection* con, int events, void* ptr)
{
	struct nb_probe* p = (struct nb_probe*) ptr;
	p->events |= events;
	if (events & NET_EVENT_READ)
	{
		char buf[64];
		net_con_recv(con, buf, sizeof(buf)); /* drain so READ does not re-fire forever */
		p->reads++;
	}
}

EXO_TEST(netbackend_init, {
	return net_initialize() == 0;
});

/* A backend was actually selected and named. */
EXO_TEST(netbackend_named, {
	struct timeout_queue* tq = net_backend_get_timeout_queue();
	return tq != 0;
});

/* Basic sanity: a readable socket delivers a READ event. */
EXO_TEST(netbackend_read_fires, {
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, nb_sv) != 0)
		return 0;
	nb_reset(&nb_state);
	nb_con = net_con_create();
	net_con_initialize(nb_con, nb_sv[0], nb_callback, &nb_state, NET_EVENT_READ);

	if (write(nb_sv[1], "x", 1) != 1)
		return 0;

	net_backend_process();
	return (nb_state.events & NET_EVENT_READ) && nb_state.reads >= 1;
});

EXO_TEST(netbackend_read_cleanup, {
	net_con_close(nb_con);
	net_backend_process();	/* flushes the delayed-free queue */
	close(nb_sv[1]);
	nb_con = 0;
	return 1;
});

/*
 * Regression: enable WRITE via a second update issued in the same cycle as the
 * initial READ registration. The kqueue add_change() coalescing bug dropped
 * this update, so WRITE was registered DISABLED and never fired. We also write
 * a byte so READ is always ready and the poll cannot block: a buggy backend
 * therefore reports READ-only and fails this test instead of hanging.
 */
EXO_TEST(netbackend_update_adds_write, {
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, nb_sv) != 0)
		return 0;
	nb_reset(&nb_state);
	nb_con = net_con_create();
	net_con_initialize(nb_con, nb_sv[0], nb_callback, &nb_state, NET_EVENT_READ);

	/* Second registration change in the same cycle - must take effect. */
	net_con_update(nb_con, NET_EVENT_READ | NET_EVENT_WRITE);

	if (write(nb_sv[1], "y", 1) != 1)
		return 0;

	net_backend_process();
	return (nb_state.events & NET_EVENT_READ) && (nb_state.events & NET_EVENT_WRITE);
});

EXO_TEST(netbackend_update_adds_write_cleanup, {
	net_con_close(nb_con);
	net_backend_process();
	close(nb_sv[1]);
	nb_con = 0;
	return 1;
});

/*
 * Regression (other direction): a connection registered for WRITE is updated
 * to READ-only in the same cycle. The buggy backend kept the initial
 * WRITE-enabled registration and dropped the update - leaving WRITE enabled on
 * an idle connection, which is the busy-spin (EVFILT_WRITE fires every poll).
 * The initial mask (WRITE) deliberately differs from the desired final mask
 * (READ) so a "first write wins" backend produces the wrong answer: it reports
 * WRITE and no READ, failing this test rather than hanging (the socket is
 * always writable).
 */
EXO_TEST(netbackend_update_disables_write, {
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, nb_sv) != 0)
		return 0;
	nb_reset(&nb_state);
	nb_con = net_con_create();
	net_con_initialize(nb_con, nb_sv[0], nb_callback, &nb_state, NET_EVENT_WRITE);

	/* Supersede the WRITE registration with READ-only before the first poll. */
	net_con_update(nb_con, NET_EVENT_READ);

	if (write(nb_sv[1], "z", 1) != 1)
		return 0;

	net_backend_process();
	return (nb_state.events & NET_EVENT_READ) && !(nb_state.events & NET_EVENT_WRITE);
});

EXO_TEST(netbackend_update_disables_write_cleanup, {
	net_con_close(nb_con);
	net_backend_process();
	close(nb_sv[1]);
	nb_con = 0;
	return 1;
});

EXO_TEST(netbackend_shutdown, {
	return net_destroy() == 0;
});
