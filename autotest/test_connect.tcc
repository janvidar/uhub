#include "network/network.h"
#include "network/connection.h"
#include "network/backend.h"

/*
 * Tests for the outbound-connect / happy-eyeballs failover path in
 * connection.c (net_con_connect -> net_connect_process -> failover ->
 * terminal report).
 *
 * The path is asynchronous: the hostname is resolved on a DNS worker thread
 * and each address is attempted via a non-blocking connect that completes on a
 * later event-loop iteration. The tests therefore call net_con_connect() and
 * then pump net_backend_process() until the terminal callback fires. The poll
 * inside net_backend_process() blocks only until the DNS notify pipe or a
 * socket event wakes it, so the loop does not busy-spin; loopback connects to a
 * closed port refuse immediately and to an open port complete immediately, so
 * the cases finish in a handful of iterations rather than hitting the connect
 * timeout.
 *
 * The key behaviour under test, matching the failover contract: the terminal
 * callback is invoked exactly once, with net_connect_status_ok (and a live
 * connection) when any address connects, or with the recorded failure status
 * and a NULL connection only once every address has been exhausted.
 */

struct ct_probe
{
	int calls;			/* number of times the connect callback fired */
	enum net_connect_status status;	/* status of the last callback */
	struct net_connection* con;	/* connection handed back on success */
};

static struct ct_probe ct_state;

static void ct_reset(void)
{
	ct_state.calls = 0;
	ct_state.status = net_connect_status_ok;
	ct_state.con = 0;
}

static void ct_callback(struct net_connect_handle* handle, enum net_connect_status status, struct net_connection* con, void* ptr)
{
	struct ct_probe* p = (struct ct_probe*) ptr;
	(void) handle;
	p->calls++;
	p->status = status;
	p->con = con;
}

/*
 * Pump the event loop until the connect callback has fired (or a generous
 * iteration cap is hit, so a regression that never reports completion fails the
 * assertion instead of hanging the suite forever).
 */
static void ct_pump_until_done(void)
{
	int i;
	for (i = 0; i < 10000 && ct_state.calls == 0; i++)
		net_backend_process();
}

/*
 * Bind a loopback TCP socket to an ephemeral port. When do_listen is set the
 * socket is listening (an open port); otherwise it is returned bound but not
 * listening. The chosen port is written to *out_port. Returns the socket fd, or
 * -1 on failure.
 */
static int ct_make_socket(int do_listen, uint16_t* out_port)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0; /* ephemeral */

	if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0
		|| getsockname(sd, (struct sockaddr*) &addr, &len) != 0
		|| (do_listen && listen(sd, 4) != 0))
	{
		close(sd);
		return -1;
	}

	*out_port = ntohs(addr.sin_port);
	return sd;
}

EXO_TEST(connect_init, {
	return net_initialize() == 0;
});

/*
 * Every address fails: connect to a loopback port that is bound but not
 * listening, so the kernel refuses immediately. The machinery must exhaust the
 * (single) address and invoke the callback exactly once with
 * net_connect_status_refused and no connection.
 */
EXO_TEST(connect_refused_reports_once, {
	uint16_t port = 0;
	struct net_connect_handle* h;
	int closed = 0;
	/* A bound-but-not-listening socket gives a stable "connection refused"
	   target that no other process can start listening on mid-test. */
	int sd = ct_make_socket(0, &port);
	if (sd == -1)
		return 0;

	ct_reset();
	h = net_con_connect("127.0.0.1", port, ct_callback, &ct_state);
	if (!h)
	{
		close(sd);
		return 0;
	}

	ct_pump_until_done();
	close(sd);
	closed = 1;
	(void) closed;

	return ct_state.calls == 1
		&& ct_state.status == net_connect_status_refused
		&& ct_state.con == 0;
});

/*
 * Happy path: an address connects. The terminal failure path (and any
 * "unreachable"-style reporting) must be skipped entirely - the callback fires
 * exactly once with net_connect_status_ok and a live connection.
 */
EXO_TEST(connect_success_reports_ok, {
	uint16_t port = 0;
	struct net_connect_handle* h;
	int ok;
	int sd = ct_make_socket(1, &port);
	if (sd == -1)
		return 0;

	ct_reset();
	h = net_con_connect("127.0.0.1", port, ct_callback, &ct_state);
	if (!h)
	{
		close(sd);
		return 0;
	}

	ct_pump_until_done();

	ok = (ct_state.calls == 1
		&& ct_state.status == net_connect_status_ok
		&& ct_state.con != 0);

	if (ct_state.con)
		net_con_close(ct_state.con); /* freed when the loop next runs / at net_destroy */
	close(sd);
	return ok;
});

/*
 * Failover across multiple resolved addresses: "localhost" typically resolves
 * to both ::1 and 127.0.0.1, so connecting to a closed port exercises the
 * job-list walk and the IPv6->IPv4 family failover before the terminal report.
 * Host resolution is environment-dependent, so this asserts the contract that
 * survives any address mix: a single callback, a failure status, no connection.
 */
EXO_TEST(connect_failover_localhost, {
	uint16_t port = 0;
	struct net_connect_handle* h;
	/* Reuse a bound-but-not-listening port so every resolved address refuses. */
	int sd = ct_make_socket(0, &port);
	if (sd == -1)
		return 0;

	ct_reset();
	h = net_con_connect("localhost", port, ct_callback, &ct_state);
	if (!h)
	{
		close(sd);
		return 0;
	}

	ct_pump_until_done();
	close(sd);

	return ct_state.calls == 1
		&& ct_state.status != net_connect_status_ok
		&& ct_state.con == 0;
});

EXO_TEST(connect_shutdown, {
	return net_destroy() == 0;
});
