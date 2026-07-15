#include "network/network.h"
#include "network/connection.h"
#include "network/backend.h"
#include "network/dnsresolver.h"

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
 * Every address fails: connect to a loopback port with no listener, so the
 * kernel refuses immediately. The machinery must exhaust the (single) address
 * and invoke the callback exactly once with net_connect_status_refused and no
 * connection.
 */
EXO_TEST(connect_refused_reports_once, {
	uint16_t port = 0;
	struct net_connect_handle* h;
	/* Bind an ephemeral loopback port, then release it: connecting to a port
	   with no socket gets a RST -> ECONNREFUSED on both Linux and macOS. (A
	   bound-but-not-listening socket is NOT portable here -- macOS leaves the
	   SYN unanswered and the connect times out instead of refusing.) Grabbing
	   the port first makes it very unlikely another process holds that exact
	   ephemeral port in the microseconds before we connect. */
	int sd = ct_make_socket(0, &port);
	if (sd == -1)
		return 0;
	close(sd);

	ct_reset();
	h = net_con_connect("127.0.0.1", port, ct_callback, &ct_state);
	if (!h)
		return 0;

	ct_pump_until_done();

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

/*
 * Regression: a DNS callback that takes ownership of the result (returns 0)
 * and frees it synchronously must not lead net_dns_process to touch the freed
 * result/job afterwards. This mirrors net_con_connect_dns_callback, which frees
 * handle->result (via net_connect_destroy) on its synchronous-completion paths
 * -- "no usable addresses" and "every connect failed synchronously" -- and then
 * returns 0. Previously net_dns_process would still run
 * "result->job = NULL; free_job(job);", a use-after-free write plus a double
 * free of the job -- heap corruption that showed up as an intermittent,
 * platform-dependent crash. Deterministic here: a numeric-literal host resolves
 * offline, and the callback frees the delivered result and returns 0.
 * Under ASan this aborts before the fix and passes after it.
 */
static int dns_owner_fired = 0;
static int dns_owner_free_callback(struct net_dns_job* job, const struct net_dns_result* result)
{
	(void) job;
	dns_owner_fired = 1;
	if (result)
		net_dns_result_free(result);   /* take ownership and free it now */
	return 0;                          /* 0 == "caller owns the result" */
}

EXO_TEST(connect_dns_owner_frees_sync, {
	int i;
	struct net_dns_job* job;
	dns_owner_fired = 0;
	/* A numeric literal resolves offline (getaddrinfo, no DNS query). */
	job = net_dns_gethostbyname("127.0.0.1", AF_UNSPEC, dns_owner_free_callback, 0);
	if (!job)
		return 0;
	for (i = 0; i < 10000 && !dns_owner_fired; i++)
		net_backend_process();
	return dns_owner_fired == 1;
});

/*
 * Concurrency stress for the DNS worker pool. The rest of the suite only ever
 * has one lookup in flight at a time; here many are queued before the loop is
 * pumped, so up to pool-size worker threads race on the shared queue/results
 * list, the mutex/condvars, and the notify-pipe handoff back to the event
 * thread. Numeric-literal hosts resolve offline (getaddrinfo, no DNS traffic),
 * keeping it fast and deterministic. Run under ASan (and TSan, once wired) this
 * exercises the threaded paths that a single serial lookup never reaches.
 */
static int dns_stress_count = 0;
static int dns_stress_cb(struct net_dns_job* job, const struct net_dns_result* result)
{
	(void) job; (void) result;   /* delivered on the event thread; single-threaded here */
	dns_stress_count++;
	return 1;                    /* decline ownership: net_dns_process frees the result */
}

EXO_TEST(connect_dns_pool_concurrent, {
	int i;
	int pumps;
	const int N = 64;
	dns_stress_count = 0;
	/* Queue every lookup first so the workers have a backlog to contend over. */
	for (i = 0; i < N; i++)
	{
		const char* host = (i & 1) ? "127.0.0.1" : "::1";
		if (!net_dns_gethostbyname(host, AF_UNSPEC, dns_stress_cb, 0))
			return 0;
	}
	for (pumps = 0; pumps < 100000 && dns_stress_count < N; pumps++)
		net_backend_process();
	return dns_stress_count == N;
});

/*
 * Cancel a job in each pre-delivery state. Cancelling before any pump means the
 * targets are QUEUED, RUNNING, or DONE-but-undelivered -- every branch of
 * net_dns_job_cancel -- and a cancelled job must never invoke its callback.
 */
EXO_TEST(connect_dns_cancel_races, {
	int i;
	const int N = 16;
	struct net_dns_job* jobs[16];
	dns_stress_count = 0;
	for (i = 0; i < N; i++)
	{
		jobs[i] = net_dns_gethostbyname("127.0.0.1", AF_UNSPEC, dns_stress_cb, 0);
		if (!jobs[i])
			return 0;
	}
	/* Cancel the even-indexed jobs (no pump yet, so none have delivered). */
	for (i = 0; i < N; i += 2)
		net_dns_job_cancel(jobs[i]);

	/* Let the races settle deterministically: on return every job is terminal
	   -- the odd half has parked results awaiting delivery, the cancelled even
	   half has been discarded. Waiting on the pool (rather than pumping the
	   reactor a fixed number of times) avoids blocking on the idle poll, which
	   waits up to TIMEOUT_QUEUE_MAX seconds when there is nothing to deliver. */
	net_dns_wait_idle();

	/* Deliver the parked results directly, bypassing the event loop. A
	   cancelled job that wrongly delivered would have parked a result too and
	   would surface here, pushing the tally past N/2. */
	net_dns_process();

	return dns_stress_count == N / 2;
});

EXO_TEST(connect_shutdown, {
	return net_destroy() == 0;
});
