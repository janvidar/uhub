#include "system.h"
#include "util/memory.h"
#include "network/network.h"
#include "network/connection.h"

static struct net_connection* cd_con = 0;
static int cd_listen = -1;
static int cd_local = -1;
static int cd_peer = -1;

static int cd_connect(void)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int client;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	cd_listen = net_socket_create(AF_INET, SOCK_STREAM, 0);
	if (cd_listen == -1)
		return 0;
	if (net_bind(cd_listen, (struct sockaddr*) &addr, sizeof(addr)) == -1)
		return 0;
	if (net_listen(cd_listen, 1) == -1)
		return 0;
	if (getsockname(cd_listen, (struct sockaddr*) &addr, &len) == -1)
		return 0;

	client = net_socket_create(AF_INET, SOCK_STREAM, 0);
	if (client == -1)
		return 0;
	if (net_connect(client, (struct sockaddr*) &addr, sizeof(addr)) == -1)
		return 0;

	cd_peer = net_accept(cd_listen, NULL);
	if (cd_peer == -1)
		return 0;

	cd_local = client;
	net_set_nonblocking(cd_local, 1);
	cd_con->sd = cd_local;
	cd_con->flags = 0;
	return 1;
}

static void cd_disconnect(void)
{
	if (cd_peer != -1)   net_close(cd_peer);
	if (cd_local != -1)  net_close(cd_local);
	if (cd_listen != -1) net_close(cd_listen);
	cd_peer = cd_local = cd_listen = -1;
}

EXO_TEST(condead_setup, {
	net_initialize();
	cd_con = (struct net_connection*) hub_malloc_zero(sizeof(struct net_connection));
	if (!cd_con)
		return 0;
	cd_con->sd = -1;
	return 1;
});

EXO_TEST(condead_closed_socket_is_dead, {
	cd_con->sd = -1;
	return net_con_is_dead(cd_con) == 1;
});

EXO_TEST(condead_cleanup_flag_is_dead, {
	if (!cd_connect())
		return 0;
	cd_con->flags = NET_CLEANUP;
	if (net_con_is_dead(cd_con) != 1)
		return 0;
	cd_con->flags = 0;
	return 1;
});

EXO_TEST(condead_established_is_alive, {
	if (net_con_is_dead(cd_con) != 0)
		return 0;
	return net_con_is_dead(cd_con) == 0;
});

EXO_TEST(condead_pending_data_is_alive, {
	char buf[4];
	if (send(cd_peer, "x", 1, 0) != 1)
		return 0;
	if (net_con_is_dead(cd_con) != 0)
		return 0;
	if (recv(cd_local, buf, sizeof(buf), 0) != 1)
		return 0;
	return buf[0] == 'x';
});

EXO_TEST(condead_peer_fin_is_dead, {
	net_close(cd_peer);
	cd_peer = -1;
	return net_con_is_dead(cd_con) == 1;
});

EXO_TEST(condead_peer_reset_is_dead, {
	struct linger opt;
	cd_disconnect();
	if (!cd_connect())
		return 0;

	opt.l_onoff = 1;
	opt.l_linger = 0;
	if (setsockopt(cd_peer, SOL_SOCKET, SO_LINGER, &opt, sizeof(opt)) == -1)
		return 0;
	net_close(cd_peer);
	cd_peer = -1;

	usleep(50000);
	return net_con_is_dead(cd_con) == 1;
});

EXO_TEST(condead_teardown, {
	cd_disconnect();
	hub_free(cd_con);
	cd_con = 0;
	return 1;
});
