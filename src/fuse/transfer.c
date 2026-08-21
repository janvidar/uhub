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

#include "fuse/transfer.h"
#include "fuse/bridge.h"
#include "fuse/config.h"
#include "fuse/filelist.h"
#include "fuse/roster.h"
#include "fuse/session.h"
#include "fuse/stream.h"
#include "network/backend.h"
#include "network/connection.h"
#include "network/ipcalc.h"
#include "network/network.h"
#include "network/tls.h"
#include "seeder/cache.h"
#include "seeder/cc.h"
#include "seeder/grant.h"
#include "util/log.h"
#include "util/memory.h"

/** Backlog for the transfer port, as uhub-seeder uses. */
#define FS_LISTEN_BACKLOG 128

/**
 * Room for the cache directory. Matches SEED_DIR_MAX, which cache.c enforces
 * and does not export; a longer path is refused there, so there is nothing to
 * gain by carrying one here.
 */
#define FS_CACHE_DIR_MAX 256

/** Wants outstanding at once. A mount is a person reading files, not a crawler. */
#define FS_MAX_WANTS 32

/** Seconds between re-asking about a hash nobody has answered for. */
#define FS_RETRY_INTERVAL 15

/** Peers whose file list is held at once. */
#define FS_MAX_FILELISTS 8

/** Large files open for reading at once. */
#define FS_MAX_STREAMS 16

/** Seconds a file list is considered current. A share changes slowly. */
#define FS_FILELIST_TTL 300

/** The file every DC client publishes its share in. */
#define FS_FILELIST_NAME "files.xml.bz2"

enum fs_want_state
{
	FS_WANT_FREE = 0,
	FS_WANT_SEARCHING,   /** A BSCH is out; waiting for somebody to answer. */
	FS_WANT_ASKED,       /** A CTM is out; waiting for the peer to dial in. */
};

/**
 * One hash somebody is waiting for.
 *
 * Several readers may want the same file, so the waiters are a list: one
 * download answers all of them. The tasks are the FUSE threads' own stack
 * memory, chained through the `next` a parked task lends its parker.
 */
struct fs_want
{
	enum fs_want_state state;
	char tth[SEED_TTH_STR_LEN + 1];
	struct fs_task* waiters;
	time_t deadline;
	time_t next_attempt;
	sid_t asked;         /** Who the outstanding CTM went to. */
	uint64_t size;       /** As announced in the search result; 0 if unknown. */

	/** Whom to ask before asking everybody, and whether we have. */
	char from_cid[MAX_CID_LEN + 1];
	int asked_source;
};

/** A file list being fetched from one peer. */
struct fs_filelist_want
{
	int used;
	char cid[MAX_CID_LEN + 1];
	struct fs_task* waiters;
	time_t deadline;
};

/** A file list we hold, parsed. */
struct fs_peer_files
{
	char cid[MAX_CID_LEN + 1];
	struct fs_filelist* list;
	time_t fetched;
};

struct fs_transfer
{
	struct fs_session* session;

	struct seed_cache* cache;
	struct seed_grants* grants;
	struct seed_cc_policy policy;
	struct ssl_context_handle* tls_ctx;

	struct net_connection* listener;
	int listen_af;
	uint16_t port;
	char support[64];

	/* The policy keeps pointers into these, so they live as long as it does. */
	char own_cid[MAX_CID_LEN + 1];
	char tls_version[8];
	char* tls_ciphersuite;
	char* tls_ciphersuites;

	struct fs_stream* streams[FS_MAX_STREAMS];
	uint64_t max_cached;

	struct fs_want wants[FS_MAX_WANTS];
	struct fs_filelist_want list_wants[FS_MAX_FILELISTS];
	struct fs_peer_files files[FS_MAX_FILELISTS];
	int timeout;
};

/* ------------------------------------------------------------- the wants */

static struct fs_want* want_find(struct fs_transfer* t, const char* tth)
{
	size_t n;

	for (n = 0; n < FS_MAX_WANTS; n++)
		if (t->wants[n].state != FS_WANT_FREE && strcmp(t->wants[n].tth, tth) == 0)
			return &t->wants[n];

	return NULL;
}

static struct fs_want* want_alloc(struct fs_transfer* t)
{
	size_t n;

	for (n = 0; n < FS_MAX_WANTS; n++)
		if (t->wants[n].state == FS_WANT_FREE)
			return &t->wants[n];

	return NULL;
}

/** Answer everybody waiting for this hash, and let the slot go. */
static void want_finish(struct fs_transfer* t, struct fs_want* want, int result)
{
	struct fs_task* task = want->waiters;

	want->waiters = NULL;
	want->state = FS_WANT_FREE;

	while (task)
	{
		/* Read `next` before completing: the task is the waiter's stack and is
		   gone the moment it is woken. */
		struct fs_task* next = task->next;

		task->next = NULL;
		fs_bridge_complete(t->session->bridge, task, result);
		task = next;
	}
}

/**
 * Ask one peer for a hash directly.
 *
 * @return 1 if the request went out.
 */
static int want_ask_peer(struct fs_transfer* t, struct fs_want* want, const char* cid, time_t now)
{
	struct fs_roster_user* user = fs_roster_by_cid(t->session->roster, cid);
	struct fs_peer peer;
	char token[SEED_TOKEN_MAX + 1];
	const char* protocol;

	if (!user || !fs_session_peer_by_sid(t->session, user->sid, &peer))
		return 0;

	if (!seed_cc_request_token(&t->policy, peer.cid, want->tth, want->size, NULL, token))
		return 0;

	protocol = seed_cc_protocol_for_peer(&t->policy, peer.support, NULL);

	if (!fs_session_send_ctm(t->session, peer.sid, protocol, t->port, token))
	{
		seed_grant_release(t->grants, token);
		return 0;
	}

	want->state = FS_WANT_ASKED;
	want->asked = peer.sid;
	want->next_attempt = now + FS_RETRY_INTERVAL;
	LOG_INFO("fuse: asked %s for TTH=%s (%s)", peer.cid, want->tth, protocol);
	return 1;
}

/**
 * Ask the hub who has this hash.
 *
 * The token is the hash itself. A search result carries it back, which is what
 * lets an answer be matched to the question without keeping a table of tokens
 * -- and a hash is already unique among the things we are asking about.
 */
static void want_search(struct fs_transfer* t, struct fs_want* want, time_t now)
{
	want->state = FS_WANT_SEARCHING;
	want->next_attempt = now + FS_RETRY_INTERVAL;
	want->asked = 0;

	if (!fs_session_send_search_tth(t->session, want->tth, want->tth))
		LOG_DEBUG("fuse: unable to search for TTH=%s", want->tth);
}

/* ------------------------------------------------------------ file lists */

static struct fs_peer_files* files_find(struct fs_transfer* t, const char* cid)
{
	size_t n;

	for (n = 0; n < FS_MAX_FILELISTS; n++)
		if (t->files[n].list && strcmp(t->files[n].cid, cid) == 0)
			return &t->files[n];

	return NULL;
}

/** A free slot, or the least recently fetched one, whose list is dropped. */
static struct fs_peer_files* files_slot(struct fs_transfer* t)
{
	struct fs_peer_files* oldest = &t->files[0];
	size_t n;

	for (n = 0; n < FS_MAX_FILELISTS; n++)
	{
		if (!t->files[n].list)
			return &t->files[n];

		if (t->files[n].fetched < oldest->fetched)
			oldest = &t->files[n];
	}

	fs_filelist_destroy(oldest->list);
	memset(oldest, 0, sizeof(*oldest));
	return oldest;
}

static struct fs_filelist_want* list_want_find(struct fs_transfer* t, const char* cid)
{
	size_t n;

	for (n = 0; n < FS_MAX_FILELISTS; n++)
		if (t->list_wants[n].used && strcmp(t->list_wants[n].cid, cid) == 0)
			return &t->list_wants[n];

	return NULL;
}

static void list_want_finish(struct fs_transfer* t, struct fs_filelist_want* want, int result)
{
	struct fs_task* task = want->waiters;

	want->waiters = NULL;
	want->used = 0;

	while (task)
	{
		struct fs_task* next = task->next;

		task->next = NULL;
		fs_bridge_complete(t->session->bridge, task, result);
		task = next;
	}
}

/**
 * Turn a downloaded file list into a tree.
 *
 * The compressed document is read back out of the cache and then removed from
 * it: it is not content anybody will ask us for by hash, and a share list can
 * be large enough to be worth not keeping twice.
 */
static int files_adopt(struct fs_transfer* t, const char* cid, const char* tth, uint64_t size)
{
	struct fs_peer_files* slot;
	struct fs_filelist* list;
	char* buf;
	ssize_t got;
	int fd;

	if (!size || size > FS_FILELIST_MAX)
	{
		seed_cache_remove(t->cache, tth, "file list, unusable");
		return 0;
	}

	fd = fs_transfer_open_file(t, tth, NULL);
	if (fd < 0)
		return 0;

	buf = (char*) hub_malloc((size_t) size);
	if (!buf)
	{
		fs_transfer_close_file(t, tth, fd);
		return 0;
	}

	got = seed_cache_read(t->cache, fd, size, 0, buf, (size_t) size);
	fs_transfer_close_file(t, tth, fd);

	if (got != (ssize_t) size)
	{
		hub_free(buf);
		seed_cache_remove(t->cache, tth, "file list, short read");
		return 0;
	}

	list = fs_filelist_load(buf, (size_t) size);
	hub_free(buf);
	seed_cache_remove(t->cache, tth, "file list, parsed");

	if (!list)
	{
		LOG_DEBUG("fuse: %s sent a file list that does not parse", cid);
		return 0;
	}

	slot = files_slot(t);

	/* A CID is exactly MAX_CID_LEN characters wherever it comes from, and the
	   caller only ever passes one; anything else is not a peer we could have
	   asked. */
	if (strlen(cid) != MAX_CID_LEN)
	{
		fs_filelist_destroy(list);
		return 0;
	}

	memcpy(slot->cid, cid, MAX_CID_LEN + 1);
	slot->list = list;
	slot->fetched = time(NULL);

	LOG_INFO("fuse: file list from %s holds %zu entries", cid, fs_filelist_count(list));
	return 1;
}

/* ------------------------------------------------------------- streaming */

/** Whichever stream is waiting on @p token. */
static struct fs_stream* stream_by_token(struct fs_transfer* t, const char* token)
{
	size_t n;

	if (!token || !*token)
		return NULL;

	for (n = 0; n < FS_MAX_STREAMS; n++)
		if (t->streams[n] && strcmp(fs_stream_token(t->streams[n]), token) == 0)
			return t->streams[n];

	return NULL;
}

static int transfer_on_body(void* ptr, const char* token, uint64_t offset,
                            const void* data, size_t len)
{
	struct fs_transfer* t = (struct fs_transfer*) ptr;
	struct fs_stream* stream = stream_by_token(t, token);

	/* Nobody is waiting for this any more -- the reader seeked away, or closed
	   the file. Answering 0 ends the transfer rather than paying for the rest
	   of a range that will be thrown away. */
	if (!stream)
		return 0;

	return fs_stream_on_body(stream, offset, data, len);
}

static void transfer_on_body_done(void* ptr, const char* token, int ok)
{
	struct fs_transfer* t = (struct fs_transfer*) ptr;
	struct fs_stream* stream = stream_by_token(t, token);

	if (stream)
		fs_stream_on_done(stream, ok);
}

uint64_t fs_transfer_max_cached_size(struct fs_transfer* t)
{
	return t ? t->max_cached : 0;
}

struct fs_stream* fs_transfer_stream_open(struct fs_transfer* t, const char* tth,
                                          const char* cid, uint64_t size)
{
	struct fs_stream* stream;
	size_t n;

	if (!t)
		return NULL;

	for (n = 0; n < FS_MAX_STREAMS; n++)
		if (!t->streams[n])
			break;

	if (n == FS_MAX_STREAMS)
		return NULL;

	stream = fs_stream_open(t, tth, cid, size);
	if (!stream)
		return NULL;

	t->streams[n] = stream;
	return stream;
}

void fs_transfer_stream_close(struct fs_transfer* t, struct fs_stream* stream)
{
	size_t n;

	if (!t || !stream)
		return;

	for (n = 0; n < FS_MAX_STREAMS; n++)
	{
		if (t->streams[n] == stream)
		{
			t->streams[n] = NULL;
			break;
		}
	}

	fs_stream_close(stream);
}

void fs_transfer_complete_task(struct fs_transfer* t, struct fs_task* task, int result)
{
	fs_bridge_complete(t->session->bridge, task, result);
}

int fs_transfer_request_range(struct fs_transfer* t, const char* cid, const char* tth,
                              uint64_t start, uint64_t len, char out_token[SEED_TOKEN_MAX + 1])
{
	struct fs_roster_user* user;
	struct fs_peer peer;
	const char* protocol;
	char token[SEED_TOKEN_MAX + 1];

	if (!t)
		return -ENODEV;

	user = fs_roster_by_cid(t->session->roster, cid);
	if (!user || !fs_session_peer_by_sid(t->session, user->sid, &peer))
		return -ENOENT;

	if (!seed_grant_make_token(token))
		return -EAGAIN;

	if (!seed_grant_issue_range(t->grants, token, cid, tth, start, len, time(NULL)))
		return -EAGAIN;

	protocol = seed_cc_protocol_for_peer(&t->policy, peer.support, NULL);

	if (!fs_session_send_ctm(t->session, peer.sid, protocol, t->port, token))
	{
		seed_grant_release(t->grants, token);
		return -EHOSTUNREACH;
	}

	memcpy(out_token, token, sizeof(token));
	LOG_DEBUG("fuse: asked %s for %llu bytes of TTH=%s at %llu", cid,
		(unsigned long long) len, tth, (unsigned long long) start);
	return 0;
}

/* --------------------------------------------------------- the cache side */

static void transfer_on_download(void* ptr, const char* tth, enum seed_error err,
                                 const struct seed_entry* entry)
{
	struct fs_transfer* t = (struct fs_transfer*) ptr;
	struct fs_want* want = want_find(t, tth);

	/*
	 * A file list has no hash to be recognised by -- that is why it was asked
	 * for by name -- so it is attributed by who sent it. A hash that is on the
	 * want queue is content and takes precedence; anything else from a peer we
	 * have a list outstanding with is that list.
	 */
	if (!want && err == SEED_OK && entry && *entry->origin_cid)
	{
		struct fs_filelist_want* list_want = list_want_find(t, entry->origin_cid);

		if (list_want)
		{
			/*
			 * entry->tth, not the tth argument: that one is the hash the
			 * request named, and a request made by name named none. What the
			 * list turned out to hash to is only known now, and is the only
			 * way to find it in the cache.
			 */
			int ok = files_adopt(t, entry->origin_cid, entry->tth, entry->size);
			list_want_finish(t, list_want, ok ? 0 : -EIO);
			return;
		}
	}

	if (!want)
		return;

	if (err == SEED_OK)
	{
		LOG_INFO("fuse: TTH=%s is now cached", tth);
		want_finish(t, want, 0);
		return;
	}

	/* The bytes arrived and were not what was asked for, or would not fit.
	   Another peer offering the same hash would produce the same file, so
	   there is nothing to retry. */
	LOG_WARN("fuse: download of TTH=%s failed (%s)", tth, seed_error_string(err));
	want_finish(t, want, -EIO);
}

/* ------------------------------------------------------------ the listener */

static void transfer_on_accept(struct net_connection* con, int events, void* arg)
{
	struct fs_transfer* t = (struct fs_transfer*) arg;
	int server_fd = net_con_get_sd(con);

	(void) events;

	for (;;)
	{
		struct ip_addr_encap addr;
		struct net_connection* client;
		int fd = net_accept(server_fd, &addr);

		if (fd == -1)
		{
			if (net_error() != EWOULDBLOCK)
				LOG_ERROR("fuse: accept error: %d %s", net_error(), strerror(net_error()));
			break;
		}

		/* Drain the backlog even while refusing, so the kernel accept queue
		   empties and the listener stops re-firing. */
		if (net_backend_get_num_connections() >= net_backend_get_max_connections() ||
		    (size_t) fd >= net_backend_get_max_connections())
		{
			LOG_WARN("fuse: connection limit reached, rejecting connection.");
			net_close(fd);
			continue;
		}

		client = net_con_create();
		if (!client)
		{
			net_close(fd);
			break;
		}

		/* seed_cc_accept() reinitializes this with its own handler; the
		   placeholder here just gets the descriptor into the backend. */
		net_con_initialize(client, fd, transfer_on_accept, t, NET_EVENT_READ);

		if (!seed_cc_accept(&t->policy, client, &addr))
		{
			LOG_WARN("fuse: unable to accept a connection from %s", ip_convert_to_string(&addr));
			net_con_close(client);
		}
	}
}

static struct net_connection* transfer_listen(struct fs_transfer* t, const struct fs_config* cfg)
{
	struct net_connection* server;
	struct sockaddr_storage addr;
	socklen_t sockaddr_size;
	int sd;

	if (ip_convert_address(cfg->transfer_bind_addr, cfg->transfer_port,
	                       (struct sockaddr*) &addr, &sockaddr_size) == -1)
	{
		LOG_FATAL("fuse: unable to resolve the bind address \"%s\".", cfg->transfer_bind_addr);
		return NULL;
	}

	sd = net_socket_create(addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (sd == -1)
		return NULL;

	if (net_set_reuseaddress(sd, 1) == -1 || net_set_nonblocking(sd, 1) == -1)
	{
		net_close(sd);
		return NULL;
	}

	if (net_bind(sd, (struct sockaddr*) &addr, sockaddr_size) == -1)
	{
		LOG_FATAL("fuse: unable to bind to %s port %d: %s", cfg->transfer_bind_addr,
			cfg->transfer_port, net_error_string(net_error()));
		net_close(sd);
		return NULL;
	}

	if (net_listen(sd, FS_LISTEN_BACKLOG) == -1)
	{
		LOG_FATAL("fuse: unable to listen on %s port %d.", cfg->transfer_bind_addr, cfg->transfer_port);
		net_close(sd);
		return NULL;
	}

	server = net_con_create();
	if (!server)
	{
		net_close(sd);
		return NULL;
	}

	net_con_initialize(server, sd, transfer_on_accept, t, NET_EVENT_READ);
	t->listen_af = addr.ss_family;
	return server;
}

/* ------------------------------------------------------------------- TLS */

static int transfer_setup_tls(struct fs_transfer* t, const struct fs_config* cfg)
{
	const char* cert = cfg->tls_certificate;
	const char* key = cfg->tls_private_key;

	if (!cert || !*cert || !key || !*key)
	{
		/* Not fatal, but worth saying: most clients refuse a plain transfer. */
		LOG_WARN("fuse: no tls_certificate configured; transfers are offered as plain "
			"ADC/1.0, which many clients will not accept.");
		return 1;
	}

	t->tls_ctx = net_ssl_context_create(cfg->tls_version, cfg->tls_ciphersuite, cfg->tls_ciphersuites);
	if (!t->tls_ctx)
	{
		LOG_FATAL("fuse: unable to create a TLS context.");
		return 0;
	}

	if (!ssl_load_certificate(t->tls_ctx, cert) ||
	    !ssl_load_private_key(t->tls_ctx, key) ||
	    !ssl_check_private_key(t->tls_ctx))
	{
		LOG_FATAL("fuse: unable to load the TLS certificate \"%s\" and key \"%s\".", cert, key);
		return 0;
	}

	LOG_INFO("fuse: transfers offered over ADCS, using certificate: %s", cert);
	return 1;
}

/* ------------------------------------------------------------------ setup */

struct fs_transfer* fs_transfer_create(struct fs_session* session, const struct fs_config* config)
{
	struct fs_transfer* t;
	struct seed_cache_config cache_cfg;
	char cache_dir[FS_CACHE_DIR_MAX];

	t = (struct fs_transfer*) hub_malloc_zero(sizeof(struct fs_transfer));
	if (!t)
		return NULL;

	t->session = session;
	t->timeout = config->download_timeout;
	t->port = (uint16_t) config->transfer_port;

	snprintf(t->own_cid, sizeof(t->own_cid), "%s", fs_session_own_cid(session));
	snprintf(t->tls_version, sizeof(t->tls_version), "%s", config->tls_version ? config->tls_version : "1.2");
	t->tls_ciphersuite = hub_strdup(config->tls_ciphersuite ? config->tls_ciphersuite : "");
	t->tls_ciphersuites = hub_strdup(config->tls_ciphersuites ? config->tls_ciphersuites : "");

	if (config->cache_dir && *config->cache_dir)
		snprintf(cache_dir, sizeof(cache_dir), "%s", config->cache_dir);
	else if (!fs_config_default_cache_dir(cache_dir, sizeof(cache_dir)))
	{
		LOG_FATAL("fuse: no cache_dir configured and neither XDG_CACHE_HOME nor HOME is set.");
		fs_transfer_destroy(t);
		return NULL;
	}

	memset(&cache_cfg, 0, sizeof(cache_cfg));
	cache_cfg.dir = cache_dir;
	cache_cfg.max_bytes = (uint64_t) config->cache_size * 1024 * 1024;
	cache_cfg.max_file_size = (uint64_t) config->max_file_size * 1024 * 1024;
	cache_cfg.max_entries = (size_t) config->max_entries;
	cache_cfg.entry_ttl = 0;                /* Evict by size, not by age. */
	cache_cfg.max_concurrent_ingest = 4;
	/* Any type: a filesystem serves whatever file the hash names, and a mount
	   has no curated set of media types the way a seed cache does. */
	cache_cfg.allowed_types = "*";

	t->cache = seed_cache_open(&cache_cfg);
	if (!t->cache)
	{
		LOG_FATAL("fuse: unable to open the cache in %s.", cache_dir);
		fs_transfer_destroy(t);
		return NULL;
	}

	t->grants = seed_grants_create();
	if (!t->grants || !transfer_setup_tls(t, config))
	{
		fs_transfer_destroy(t);
		return NULL;
	}

	t->policy.cache = t->cache;
	t->policy.grants = t->grants;
	t->policy.cid = t->own_cid;
	t->policy.max_concurrent_upload = 8;
	t->policy.ingest_interval = 0;     /* We asked for these files ourselves. */
	t->policy.ingest_per_user = 0;
	t->policy.ingest_quota_kb = 0;
	t->policy.tls_version = t->tls_version;
	t->policy.tls_ciphersuite = t->tls_ciphersuite;
	t->policy.tls_ciphersuites = t->tls_ciphersuites;
	t->policy.ssl_ctx = t->tls_ctx;
	t->policy.on_download = transfer_on_download;
	t->policy.on_download_ptr = t;
	t->policy.on_body = transfer_on_body;
	t->policy.on_body_done = transfer_on_body_done;
	t->policy.on_body_ptr = t;

	t->max_cached = cache_cfg.max_file_size;

	t->listener = transfer_listen(t, config);
	if (!t->listener)
	{
		fs_transfer_destroy(t);
		return NULL;
	}

	/* Claim only what is true: the family actually bound, and ADCS only with a
	   certificate behind it. */
	snprintf(t->support, sizeof(t->support), "%s%s",
		(t->listen_af == AF_INET6) ? "TCP4,TCP6" : "TCP4",
		t->tls_ctx ? ",ADCS,ADC0" : "");

	LOG_INFO("fuse: transfers on port %d, cache in %s", config->transfer_port, cache_dir);
	return t;
}

void fs_transfer_destroy(struct fs_transfer* t)
{
	size_t n;

	if (!t)
		return;

	fs_transfer_abort_all(t, -ENOTCONN);

	if (t->listener)
		net_con_close(t->listener);

	if (t->grants)
		seed_grants_destroy(t->grants);

	for (n = 0; n < FS_MAX_STREAMS; n++)
		fs_stream_close(t->streams[n]);

	for (n = 0; n < FS_MAX_FILELISTS; n++)
		fs_filelist_destroy(t->files[n].list);

	if (t->cache)
		seed_cache_close(t->cache);

	if (t->tls_ctx)
		net_ssl_context_destroy(t->tls_ctx);

	hub_free(t->tls_ciphersuite);
	hub_free(t->tls_ciphersuites);
	hub_free(t);
}

const char* fs_transfer_support(struct fs_transfer* t)
{
	return t ? t->support : "";
}

/* ------------------------------------------------------------- the reading */

int fs_transfer_peek(struct fs_transfer* t, const char* tth, uint64_t* out_size)
{
	struct seed_entry entry;

	if (!t || !seed_cache_peek(t->cache, tth, &entry))
		return 0;

	if (out_size)
		*out_size = entry.size;

	return 1;
}

int fs_transfer_want_from(struct fs_transfer* t, const char* tth, const char* cid,
                          struct fs_task* task)
{
	struct fs_want* want;
	time_t now = time(NULL);

	if (!t)
		return -ENODEV;

	if (fs_transfer_peek(t, tth, NULL))
		return 0;

	if (seed_cache_is_blocked(t->cache, tth))
		return -EACCES;

	want = want_find(t, tth);
	if (!want)
	{
		want = want_alloc(t);
		if (!want)
			return -EAGAIN;

		memset(want, 0, sizeof(*want));
		snprintf(want->tth, sizeof(want->tth), "%s", tth);
		want->deadline = now + t->timeout;

		if (cid && *cid)
			snprintf(want->from_cid, sizeof(want->from_cid), "%s", cid);

		/* Whoever is known to have it, before everybody who might. */
		if (*want->from_cid)
		{
			want->asked_source = 1;

			if (!want_ask_peer(t, want, want->from_cid, now))
				want_search(t, want, now);
		}
		else
		{
			want_search(t, want, now);
		}
	}

	/* Everyone waiting for this hash is answered by the one download. */
	task->next = want->waiters;
	want->waiters = task;
	return FS_TASK_PARKED;
}

void fs_transfer_abandon(struct fs_transfer* t, struct fs_task* task)
{
	size_t n;

	if (!t || !task)
		return;

	for (n = 0; n < FS_MAX_STREAMS; n++)
		fs_stream_abandon(t->streams[n], task);

	for (n = 0; n < FS_MAX_FILELISTS; n++)
	{
		struct fs_filelist_want* want = &t->list_wants[n];
		struct fs_task** link = &want->waiters;

		if (!want->used)
			continue;

		while (*link)
		{
			if (*link != task)
			{
				link = &(*link)->next;
				continue;
			}

			*link = task->next;
			task->next = NULL;
			return;
		}
	}

	for (n = 0; n < FS_MAX_WANTS; n++)
	{
		struct fs_want* want = &t->wants[n];
		struct fs_task** link = &want->waiters;

		if (want->state == FS_WANT_FREE)
			continue;

		while (*link)
		{
			if (*link != task)
			{
				link = &(*link)->next;
				continue;
			}

			*link = task->next;
			task->next = NULL;

			/*
			 * The fetch itself is left alone even with nobody waiting for it.
			 * A transfer that is already under way costs nothing to finish and
			 * the file lands in the cache, where the next reader -- very
			 * likely the one who just pressed ^C, trying again -- finds it
			 * without asking the hub twice.
			 */
			return;
		}
	}
}

struct fs_filelist* fs_transfer_filelist(struct fs_transfer* t, const char* cid)
{
	struct fs_peer_files* files;

	if (!t || !cid)
		return NULL;

	files = files_find(t, cid);
	return files ? files->list : NULL;
}

int fs_transfer_want_filelist(struct fs_transfer* t, const char* cid, struct fs_task* task)
{
	struct fs_filelist_want* want;
	struct fs_peer_files* files;
	struct fs_peer peer;
	char token[SEED_TOKEN_MAX + 1];
	const char* protocol;
	time_t now;
	size_t n;

	if (!t || !cid)
		return -ENODEV;

	now = time(NULL);

	files = files_find(t, cid);
	if (files && (now - files->fetched) < FS_FILELIST_TTL)
		return 0;

	want = list_want_find(t, cid);
	if (want)
	{
		task->next = want->waiters;
		want->waiters = task;
		return FS_TASK_PARKED;
	}

	/* Only somebody who is here can be asked. */
	{
		struct fs_roster_user* user = fs_roster_by_cid(t->session->roster, cid);

		if (!user || !fs_session_peer_by_sid(t->session, user->sid, &peer))
			return -ENOENT;
	}

	for (n = 0; n < FS_MAX_FILELISTS; n++)
		if (!t->list_wants[n].used)
			break;

	if (n == FS_MAX_FILELISTS)
		return -EAGAIN;

	if (!seed_grant_make_token(token))
		return -EAGAIN;

	if (!seed_grant_issue_filelist(t->grants, token, cid, FS_FILELIST_NAME, now))
		return -EAGAIN;

	protocol = seed_cc_protocol_for_peer(&t->policy, peer.support, NULL);

	if (!fs_session_send_ctm(t->session, peer.sid, protocol, t->port, token))
	{
		seed_grant_release(t->grants, token);
		return -EHOSTUNREACH;
	}

	want = &t->list_wants[n];
	memset(want, 0, sizeof(*want));
	want->used = 1;
	snprintf(want->cid, sizeof(want->cid), "%s", cid);
	want->deadline = now + t->timeout;

	task->next = want->waiters;
	want->waiters = task;

	LOG_INFO("fuse: asked %s for its file list (%s)", cid, protocol);
	return FS_TASK_PARKED;
}

int fs_transfer_want(struct fs_transfer* t, const char* tth, struct fs_task* task)
{
	return fs_transfer_want_from(t, tth, NULL, task);
}

int fs_transfer_open_file(struct fs_transfer* t, const char* tth, uint64_t* out_size)
{
	struct seed_entry entry;
	int fd;

	if (!t)
		return -ENODEV;

	if (!seed_cache_lookup(t->cache, tth, &entry))
		return -ENOENT;

	/* Pin first: an eviction between the lookup and the open would leave a
	   descriptor on a file that is no longer there. */
	if (!seed_cache_pin(t->cache, tth))
		return -ENOENT;

	fd = seed_cache_open_file(t->cache, tth);
	if (fd < 0)
	{
		seed_cache_unpin(t->cache, tth);
		return -EIO;
	}

	if (out_size)
		*out_size = entry.size;

	return fd;
}

void fs_transfer_close_file(struct fs_transfer* t, const char* tth, int fd)
{
	if (!t)
		return;

	if (fd >= 0)
		close(fd);

	seed_cache_unpin(t->cache, tth);
}

ssize_t fs_transfer_read(struct fs_transfer* t, int fd, uint64_t size, uint64_t offset,
                         void* buf, size_t len)
{
	return seed_cache_read(t ? t->cache : NULL, fd, size, offset, buf, len);
}

/* ------------------------------------------------------------ hub events */

void fs_transfer_on_search_result(struct fs_transfer* t, sid_t from, const char* tth, uint64_t size)
{
	struct fs_want* want;
	struct fs_peer peer;
	char token[SEED_TOKEN_MAX + 1];
	const char* protocol;

	if (!t)
		return;

	want = want_find(t, tth);
	if (!want || want->state != FS_WANT_SEARCHING)
		return;   /* Not asked for, or already being fetched from somebody. */

	if (!fs_session_peer_by_sid(t->session, from, &peer))
		return;

	want->size = size;

	if (!seed_cc_request_token(&t->policy, peer.cid, tth, size, NULL, token))
	{
		LOG_DEBUG("fuse: no grant for TTH=%s from %s", tth, peer.cid);
		return;
	}

	protocol = seed_cc_protocol_for_peer(&t->policy, peer.support, NULL);

	if (!fs_session_send_ctm(t->session, from, protocol, t->port, token))
	{
		seed_grant_release(t->grants, token);
		return;
	}

	want->state = FS_WANT_ASKED;
	want->asked = from;
	want->next_attempt = time(NULL) + FS_RETRY_INTERVAL;
	LOG_INFO("fuse: asked %s for TTH=%s (%s)", peer.cid, tth, protocol);
}

void fs_transfer_on_connect_req(struct fs_transfer* t, sid_t from, const char* protocol,
                                uint16_t port, const char* token)
{
	struct fs_peer peer;
	struct seed_cc_peer target;

	if (!t || !fs_session_peer_by_sid(t->session, from, &peer))
		return;

	memset(&target, 0, sizeof(target));
	target.cid = peer.cid;
	target.addr = &peer.addr;

	if (!seed_cc_may_dial(&t->policy, &target))
		return;

	seed_cc_connect_to_peer(&t->policy, &target, protocol, port, token);
}

void fs_transfer_tick(struct fs_transfer* t)
{
	time_t now;
	size_t n;

	if (!t)
		return;

	now = time(NULL);
	seed_grant_sweep(t->grants, now);
	seed_cache_sweep(t->cache, now);

	for (n = 0; n < FS_MAX_WANTS; n++)
	{
		struct fs_want* want = &t->wants[n];

		if (want->state == FS_WANT_FREE)
			continue;

		/*
		 * A peer that never dials in produces no failure of its own -- there
		 * is no event for "the connection I asked for never happened" -- so
		 * the deadline is the only thing that ends this. Without it a cat on a
		 * hash nobody has would block for ever.
		 */
		if (now >= want->deadline)
		{
			LOG_INFO("fuse: gave up on TTH=%s", want->tth);
			want_finish(t, want, want->state == FS_WANT_SEARCHING ? -ENOENT : -ETIMEDOUT);
			continue;
		}

		if (now >= want->next_attempt)
			want_search(t, want, now);
	}

	for (n = 0; n < FS_MAX_FILELISTS; n++)
	{
		struct fs_filelist_want* want = &t->list_wants[n];

		/* One peer, one request, one deadline: there is nobody else to ask. */
		if (want->used && now >= want->deadline)
		{
			LOG_INFO("fuse: %s never sent its file list", want->cid);
			list_want_finish(t, want, -ETIMEDOUT);
		}
	}

	for (n = 0; n < FS_MAX_STREAMS; n++)
		if (fs_stream_expired(t->streams[n], now, t->timeout))
			fs_stream_abort(t->streams[n], -ETIMEDOUT);
}

void fs_transfer_abort_all(struct fs_transfer* t, int error)
{
	size_t n;

	if (!t)
		return;

	for (n = 0; n < FS_MAX_WANTS; n++)
		if (t->wants[n].state != FS_WANT_FREE)
			want_finish(t, &t->wants[n], error);

	for (n = 0; n < FS_MAX_FILELISTS; n++)
		if (t->list_wants[n].used)
			list_want_finish(t, &t->list_wants[n], error);

	for (n = 0; n < FS_MAX_STREAMS; n++)
		fs_stream_abort(t->streams[n], error);
}
