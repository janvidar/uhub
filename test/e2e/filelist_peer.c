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
 * filelist_peer: a user on a hub with a share, for testing against.
 *
 * A test double for the part of a DC client that uhub-fuse's users/<cid>/files
 * talks to, and which nothing else in this tree does: uhub-seeder serves
 * content by hash and has no share to list, so it cannot stand in for a peer
 * being browsed.
 *
 * It logs into a hub as an ordinary client, waits to be asked to connect
 * (CTM), dials back, and answers whatever is asked for out of a directory on
 * disk -- the file list itself, and any file in it by TTH.
 *
 *   filelist_peer <hub-url> <nick> <share-dir>
 *
 * The share is one flat directory; every file in it is published at the top
 * level of the list. That is enough to exercise a browse, and a fixture that
 * modelled a tree would only be modelling this one's own output.
 *
 * Deliberately simple: the client connection is handled with blocking reads
 * and writes inside the event callback, which would be wrong in a daemon and
 * is exactly right in a fixture that serves one peer at a time and must fail
 * visibly rather than subtly.
 */

#include "system.h"
#include "adc/adcconst.h"
#include "adc/message.h"
#include "adc/sid.h"
#include "network/network.h"
#include "network/backend.h"
#include "network/ipcalc.h"
#include "tools/adcclient.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "util/tth.h"

#include <bzlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_SHARED 64
#define LINE_MAX_LEN 1024

struct shared_file
{
	char name[256];
	char path[1024];
	char tth[MAX_CID_LEN + 1];
	uint64_t size;
};

static struct shared_file g_files[MAX_SHARED];
static size_t g_file_count = 0;
static char* g_list_bz2 = NULL;
static size_t g_list_len = 0;
static char g_own_cid[MAX_CID_LEN + 1];
static int g_running = 1;

/* -- the share ------------------------------------------------------------- */

static int hash_file(const char* path, char* tth, uint64_t* size)
{
	struct tth_context ctx;
	uint8_t root[TTH_SIZE];
	char buf[64 * 1024];
	FILE* file = fopen(path, "rb");
	size_t got;

	if (!file)
		return 0;

	*size = 0;
	tth_init(&ctx);

	while ((got = fread(buf, 1, sizeof(buf), file)) > 0)
	{
		tth_update(&ctx, buf, got);
		*size += got;
	}

	fclose(file);
	tth_finalize(&ctx, root);
	tth_to_string(root, tth);
	return 1;
}

static int scan_share(const char* dir)
{
	struct dirent* entry;
	DIR* handle = opendir(dir);

	if (!handle)
	{
		fprintf(stderr, "filelist_peer: cannot open %s: %s\n", dir, strerror(errno));
		return 0;
	}

	while ((entry = readdir(handle)) != NULL && g_file_count < MAX_SHARED)
	{
		struct shared_file* file = &g_files[g_file_count];
		struct stat st;

		if (entry->d_name[0] == '.')
			continue;

		snprintf(file->path, sizeof(file->path), "%s/%s", dir, entry->d_name);

		if (stat(file->path, &st) != 0 || !S_ISREG(st.st_mode))
			continue;

		snprintf(file->name, sizeof(file->name), "%s", entry->d_name);

		if (!hash_file(file->path, file->tth, &file->size))
			continue;

		printf("filelist_peer: sharing %s (%llu bytes) TTH=%s\n",
			file->name, (unsigned long long) file->size, file->tth);
		g_file_count++;
	}

	closedir(handle);
	return 1;
}

/** Build the file list document and compress it, once. */
static int build_list(void)
{
	char* xml;
	size_t cap = 64 * 1024 + g_file_count * 512;
	size_t n = 0;
	unsigned int packed_len;
	size_t i;

	xml = (char*) hub_malloc(cap);
	if (!xml)
		return 0;

	n += snprintf(&xml[n], cap - n,
		"<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\r\n"
		"<FileListing Version=\"1\" CID=\"%s\" Base=\"/\" Generator=\"filelist_peer\">\r\n",
		g_own_cid);

	/* One directory, so that a browse has something to descend into, plus the
	   files at the top level. */
	n += snprintf(&xml[n], cap - n, "<Directory Name=\"Shared\">\r\n");

	for (i = 0; i < g_file_count; i++)
		n += snprintf(&xml[n], cap - n,
			"<File Name=\"%s\" Size=\"%llu\" TTH=\"%s\"/>\r\n",
			g_files[i].name, (unsigned long long) g_files[i].size, g_files[i].tth);

	n += snprintf(&xml[n], cap - n, "</Directory>\r\n</FileListing>\r\n");

	packed_len = (unsigned int) (n * 2 + 1024);
	g_list_bz2 = (char*) hub_malloc(packed_len);

	if (!g_list_bz2 ||
	    BZ2_bzBuffToBuffCompress(g_list_bz2, &packed_len, xml, (unsigned int) n, 9, 0, 30) != BZ_OK)
	{
		hub_free(xml);
		return 0;
	}

	g_list_len = packed_len;
	hub_free(xml);

	printf("filelist_peer: file list is %zu bytes compressed\n", g_list_len);
	return 1;
}

/* -- the client connection ------------------------------------------------- */

static int read_line(int sd, char* buf, size_t size)
{
	size_t n = 0;

	while (n + 1 < size)
	{
		char c;
		ssize_t got = recv(sd, &c, 1, 0);

		if (got <= 0)
			return 0;

		if (c == '\n')
		{
			buf[n] = '\0';
			return 1;
		}

		buf[n++] = c;
	}

	return 0;
}

static int send_all(int sd, const void* data, size_t len)
{
	const char* p = (const char*) data;

	while (len)
	{
		ssize_t sent = send(sd, p, len, 0);

		if (sent <= 0)
			return 0;

		p += sent;
		len -= (size_t) sent;
	}

	return 1;
}

static int send_line(int sd, const char* line)
{
	printf("filelist_peer: --> %s", line);
	return send_all(sd, line, strlen(line));
}

/**
 * Answer one CGET.
 *
 * @param start  the first byte asked for.
 * @param bytes  how many, or -1 for "to the end of the file".
 * @return 1 if something was sent.
 */
static int serve_get(int sd, const char* ident, uint64_t start, int64_t bytes)
{
	char line[LINE_MAX_LEN];
	size_t i;

	if (strcmp(ident, "files.xml.bz2") == 0)
	{
		snprintf(line, sizeof(line), "CSND file files.xml.bz2 0 %zu\n", g_list_len);
		return send_line(sd, line) && send_all(sd, g_list_bz2, g_list_len);
	}

	if (strncmp(ident, "TTH/", 4) != 0)
	{
		send_line(sd, "CSTA 151 File\\snot\\savailable\n");
		return 1;
	}

	for (i = 0; i < g_file_count; i++)
	{
		FILE* file;
		char buf[64 * 1024];
		uint64_t remaining;

		if (strcmp(&ident[4], g_files[i].tth) != 0)
			continue;

		/* A range has to be inside the file, and "to the end" means what is
		   left from where it starts -- the same rule the seeder applies. */
		if (start > g_files[i].size)
		{
			send_line(sd, "CSTA 152 File\\spart\\snot\\savailable\n");
			return 1;
		}

		remaining = (bytes < 0) ? (g_files[i].size - start) : (uint64_t) bytes;

		if (remaining > g_files[i].size - start)
		{
			send_line(sd, "CSTA 152 File\\spart\\snot\\savailable\n");
			return 1;
		}

		snprintf(line, sizeof(line), "CSND file TTH/%s %llu %llu\n",
			g_files[i].tth, (unsigned long long) start, (unsigned long long) remaining);

		if (!send_line(sd, line))
			return 0;

		file = fopen(g_files[i].path, "rb");
		if (!file)
			return 0;

		if (fseek(file, (long) start, SEEK_SET) != 0)
		{
			fclose(file);
			return 0;
		}

		while (remaining)
		{
			size_t want = (remaining < sizeof(buf)) ? (size_t) remaining : sizeof(buf);
			size_t got = fread(buf, 1, want, file);

			if (!got || !send_all(sd, buf, got))
			{
				fclose(file);
				return 0;
			}

			remaining -= got;
		}

		fclose(file);
		return 1;
	}

	send_line(sd, "CSTA 151 File\\snot\\savailable\n");
	return 1;
}

/**
 * Dial a peer that asked us to, and serve it.
 *
 * We are the side that dialled, so we speak first and our CINF carries the
 * token -- the same convention seeder/cc.c follows, and the one clients expect.
 */
static void serve_peer(const char* address, uint16_t port, const char* token)
{
	struct sockaddr_in addr;
	char line[LINE_MAX_LEN];
	int sd;

	printf("filelist_peer: dialling %s:%u with token %s\n", address, (unsigned) port, token);

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0)
		return;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (inet_pton(AF_INET, address, &addr.sin_addr) != 1 ||
	    connect(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0)
	{
		printf("filelist_peer: cannot connect to %s:%u\n", address, (unsigned) port);
		close(sd);
		return;
	}

	if (!send_line(sd, "CSUP ADBASE ADTIGR\n"))
	{
		close(sd);
		return;
	}

	/* Their CSUP, then their CINF, then the CGET we are here for. */
	for (;;)
	{
		if (!read_line(sd, line, sizeof(line)))
			break;

		printf("filelist_peer: <-- %s\n", line);

		if (strncmp(line, "CSUP", 4) == 0)
		{
			continue;
		}
		else if (strncmp(line, "CINF", 4) == 0)
		{
			char inf[LINE_MAX_LEN];
			snprintf(inf, sizeof(inf), "CINF ID%s TO%s\n", g_own_cid, token);
			if (!send_line(sd, inf))
				break;
		}
		else if (strncmp(line, "CGET file ", 10) == 0)
		{
			char ident[512];
			const char* pos = &line[10];
			const char* end = strchr(pos, ' ');
			size_t len = end ? (size_t) (end - pos) : strlen(pos);
			uint64_t start = 0;
			int64_t bytes = -1;

			if (len >= sizeof(ident))
				break;

			memcpy(ident, pos, len);
			ident[len] = '\0';

			/* "<start> <bytes>" follow the identifier. */
			if (end && sscanf(end + 1, "%" SCNu64 " %" SCNd64, &start, &bytes) != 2)
			{
				start = 0;
				bytes = -1;
			}

			if (!serve_get(sd, ident, start, bytes))
				break;
		}
		else if (strncmp(line, "CSTA", 4) == 0)
		{
			break;
		}
	}

	close(sd);
	printf("filelist_peer: connection finished\n");
}

/* -- the hub connection ---------------------------------------------------- */

static int handle(struct ADC_client* client, enum ADC_client_callback_type type,
                  struct ADC_client_callback_data* data)
{
	(void) client;

	switch (type)
	{
		case ADC_CLIENT_LOGGED_IN:
			printf("filelist_peer: logged in as CID %s\n", ADC_client_get_cid(client));
			snprintf(g_own_cid, sizeof(g_own_cid), "%s", ADC_client_get_cid(client));
			fflush(stdout);
			break;

		case ADC_CLIENT_CONNECT_REQ:
			if (data && data->message)
			{
				char* protocol = adc_msg_get_argument(data->message, 0);
				char* port = adc_msg_get_argument(data->message, 1);
				char* token = adc_msg_get_argument(data->message, 2);

				/* Only plain ADC: a fixture that also did TLS would be
				   testing OpenSSL rather than the filesystem. */
				if (protocol && port && token && strncmp(protocol, "ADC/", 4) == 0)
					serve_peer("127.0.0.1", (uint16_t) strtoul(port, NULL, 10), token);
				else if (protocol)
					printf("filelist_peer: refusing protocol %s\n", protocol);

				hub_free(protocol);
				hub_free(port);
				hub_free(token);
				fflush(stdout);
			}
			break;

		case ADC_CLIENT_DISCONNECTED:
			g_running = 0;
			break;

		default:
			break;
	}

	return 0;
}

int main(int argc, char** argv)
{
	struct ADC_client* client;

	if (argc < 4)
	{
		fprintf(stderr, "Usage: %s adc://host:port <nick> <share-dir>\n", argv[0]);
		return 1;
	}

	hub_set_log_verbosity(2);

	if (!scan_share(argv[3]))
		return 1;

	net_initialize();

	client = ADC_client_create(argv[2], "filelist peer", NULL);
	if (!client)
		return 1;

	ADC_client_set_callback(client, handle);

	/* TCP4 so the mount knows it can be dialled, which is what makes it send a
	   CTM rather than give up. */
	ADC_client_set_support(client, "TCP4");

	if (!ADC_client_connect(client, argv[1]))
	{
		fprintf(stderr, "filelist_peer: cannot connect to %s\n", argv[1]);
		return 1;
	}

	/* The list is built after login, since it names our own CID. */
	while (g_running && net_backend_process())
	{
		if (*g_own_cid && !g_list_bz2 && !build_list())
			break;
	}

	ADC_client_destroy(client);
	net_destroy();
	hub_free(g_list_bz2);
	return 0;
}
