#include "network/network.h"
#include "network/connection.h"
#include "network/backend.h"
#include "testutil_net.h"

/*
 * Regression tests for the network backend event-registration state machine.
 *
 * These exercise the per-cycle "last write wins" semantics that the epoll
 * backend has always had and that the kqueue backend used to get wrong: when
 * more than one net_con_update() is issued before the next poll, only the final
 * desired read/write mask must take effect. kqueue's add_change() used to keep
 * the first change of a cycle and silently drop the rest, which showed up as
 * either stalled output (a WRITE enable that never reached the kernel) or a
 * busy-spin (a WRITE disable that was lost).
 *
 * Design notes:
 *  - A single connection is kept registered for the whole file (EXO_SETUP). We
 *    never close and re-open between cases: that would defer a backend
 *    deregistration and let the next socketpair() reuse the fd, which is a
 *    different (and on some backends fd-reuse-sensitive) scenario from what
 *    these tests target. Instead each case starts with nb_baseline(), which
 *    puts the connection back to READ-only with nothing pending, so no case
 *    depends on what the one before it left behind.
 *  - Every net_backend_process() is reached with at least one event already
 *    satisfiable (a readable byte and/or a writable socket). net_backend_process
 *    polls with the timeout queue's idle timeout (up to ~120s) when nothing is
 *    ready, so a test that armed the wrong events would block; instead a broken
 *    backend delivers the wrong readiness and fails an assertion.
 */

struct nb_probe
{
	int events;	/* OR of every NET_EVENT_* delivered to the connection */
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

/*
 * Register the persistent connection for READ and flush that registration, so
 * every case starts from a clean (no pending change) cycle.
 */
EXO_SETUP({
	if (!test_net_acquire())
		return 0;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, nb_sv) != 0)
		return 0;
	nb_con = net_con_create();
	net_con_initialize(nb_con, nb_sv[0], nb_callback, &nb_state, NET_EVENT_READ);
	if (write(nb_sv[1], "s", 1) != 1)
		return 0;
	net_backend_process();
	return 1;
});

/* net_con_close() synchronously deregisters the fd; the struct free is
   deferred and flushed by net_destroy() at shutdown. No poll here: with
   nothing readable it would block on the idle timeout. */
EXO_TEARDOWN({
	if (nb_con)
		net_con_close(nb_con);
	close(nb_sv[1]);
	nb_con = 0;
	test_net_release();
	return 1;
});

/* Back to READ only, with that change applied and nothing left to read. A byte
   is written so the poll has something ready and returns at once. */
static int nb_baseline(void)
{
	net_con_update(nb_con, NET_EVENT_READ);
	if (write(nb_sv[1], "r", 1) != 1)
		return 0;
	nb_reset(&nb_state);
	net_backend_process();
	return (nb_state.events & NET_EVENT_READ) != 0;
}

/* A backend was actually selected (its timeout queue exists). */
EXO_TEST(netbackend_named, {
	return net_backend_get_timeout_queue() != 0;
});

/* The basic case: a readable socket delivers a READ event. */
EXO_TEST(netbackend_read_fires, {
	if (!nb_baseline())
		return 0;

	nb_reset(&nb_state);
	if (write(nb_sv[1], "x", 1) != 1)
		return 0;

	net_backend_process();
	return (nb_state.events & NET_EVENT_READ) && nb_state.reads >= 1;
});

/*
 * Regression: two updates in one cycle where the LAST one enables WRITE. The
 * coalescing bug kept the first (READ-only) change and dropped the enable, so
 * WRITE never fired. A byte is written so READ is always ready and the poll
 * cannot block: a buggy backend reports READ-only and fails here instead.
 */
EXO_TEST(netbackend_update_adds_write, {
	if (!nb_baseline())
		return 0;
	nb_reset(&nb_state);
	net_con_update(nb_con, NET_EVENT_READ);				/* superseded */
	net_con_update(nb_con, NET_EVENT_READ | NET_EVENT_WRITE);	/* wins */

	if (write(nb_sv[1], "y", 1) != 1)
		return 0;

	net_backend_process();
	return (nb_state.events & NET_EVENT_READ) && (nb_state.events & NET_EVENT_WRITE);
});

/*
 * Regression (other direction): two updates in one cycle where the LAST one
 * disables WRITE, leaving READ only. The coalescing bug kept the first
 * (WRITE-enabled) change and dropped the disable - leaving WRITE armed on an
 * idle connection, the busy-spin. WRITE is enabled and applied first, so a
 * "first write wins" backend reports WRITE and no READ and fails here rather
 * than hanging (the socket is always writable).
 */
EXO_TEST(netbackend_update_disables_write, {
	if (!nb_baseline())
		return 0;
	net_con_update(nb_con, NET_EVENT_READ | NET_EVENT_WRITE);
	nb_reset(&nb_state);
	net_backend_process();	/* applies it: the socket is writable */
	if (!(nb_state.events & NET_EVENT_WRITE))
		return 0;

	nb_reset(&nb_state);
	net_con_update(nb_con, NET_EVENT_WRITE);			/* superseded */
	net_con_update(nb_con, NET_EVENT_READ);				/* wins: read only */

	if (write(nb_sv[1], "z", 1) != 1)
		return 0;

	net_backend_process();
	return (nb_state.events & NET_EVENT_READ) && !(nb_state.events & NET_EVENT_WRITE);
});

/*
 * Exercise the close / backend-deregister path (con_del, and on kqueue the
 * deferred change_list DEL processed by create_change_list) that the cases
 * above deliberately avoid. Register a second connection, flush its add, close
 * it, then pump once more so the backend actually processes the queued
 * deregistration. nb_con is kept readable so the poll returns promptly instead
 * of blocking on the idle timeout. This covers the previously-untested del path
 * that the kqueue create_change_list bounds fix hardens.
 */
EXO_TEST(netbackend_close_deregister, {
	int sv2[2];
	int i;
	struct net_connection* c2;
	if (!nb_baseline())
		return 0;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) != 0)
		return 0;
	c2 = net_con_create();
	net_con_initialize(c2, sv2[0], nb_callback, &nb_state, NET_EVENT_READ);

	/* Flush c2's registration; keep nb_con readable so the poll returns. */
	nb_reset(&nb_state);
	if (write(nb_sv[1], "a", 1) != 1)
		return 0;
	net_backend_process();

	/* Close c2: deregisters the fd now, queues the backend DEL for next poll. */
	net_con_close(c2);
	close(sv2[1]);

	/* Pump so create_change_list (kqueue) processes c2's DEL entry; a bad
	   deregister index would fault here under ASan. The DEL is flushed on the
	   first poll after close; keep nb_con readable and pump until it delivers,
	   recovering from the single-cycle kevent perturbation the DEL can cause. */
	nb_reset(&nb_state);
	if (write(nb_sv[1], "b", 1) != 1)
		return 0;
	for (i = 0; i < 100 && nb_state.reads == 0; i++)
		net_backend_process();

	/* Backend survived the deregister and still delivers to the live connection. */
	return nb_state.reads >= 1;
});
