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

#ifndef HAVE_UHUB_FUSE_CONFIG_H
#define HAVE_UHUB_FUSE_CONFIG_H

#include "system.h"

/**
 * Where a mount gets its settings.
 *
 * Everything here can also be given on the command line, and the command line
 * wins. The file exists for one reason above the others: a password passed as
 * --password=... is in the process's argv, which every user on the machine can
 * read out of ps. uhub-seeder keeps its bot password in a file installed 0600
 * for exactly that reason, and this is the same arrangement.
 *
 * The format is the hub's: "key = value", one per line, # to end of line for
 * comments, unknown keys refused rather than ignored.
 */

/** Largest configuration file that will be read, in bytes. */
#define FS_CONFIG_MAX_FILE (64 * 1024)

struct fs_config
{
	/* Hub connection */
	char* address;         /** hub = adc[s]://host:port[/?kp=...] */
	char* nick;            /** nick = NAME */
	char* password;        /** password = SECRET */

	/*
	 * Transfers. The mount has to be dialable to fetch anything from a passive
	 * peer -- two passive clients cannot connect to each other at all -- so it
	 * listens, exactly as uhub-seeder does, and says so in its INF.
	 */
	int   transfer_port;
	char* transfer_bind_addr;
	int   download_timeout;   /** Seconds before a fetch is given up on. */

	/* TLS on the transfer port. Both or neither; ADCS is advertised only when
	   there is a certificate to complete a handshake with. */
	char* tls_certificate;
	char* tls_private_key;
	char* tls_version;
	char* tls_ciphersuite;
	char* tls_ciphersuites;

	/* The content cache downloaded files land in. */
	char* cache_dir;          /** Empty means $XDG_CACHE_HOME/uhub-fuse. */
	int   cache_size;         /** MiB */
	int   max_file_size;      /** MiB */
	int   max_entries;
};

/**
 * Where the cache goes when cache_dir is empty: $XDG_CACHE_HOME/uhub-fuse, or
 * $HOME/.cache/uhub-fuse. A mount is usually run by a person rather than a
 * service, and /var/lib is not theirs to write to.
 *
 * @return 1 on success.
 */
extern int fs_config_default_cache_dir(char* buf, size_t size);

/** Zero it and apply the defaults. */
extern void fs_config_defaults(struct fs_config* cfg);

/** Release every string; leaves the struct zeroed and reusable. */
extern void fs_config_free(struct fs_config* cfg);

/**
 * Read @p file into @p cfg, over the defaults.
 *
 * A file that holds a password and is readable by anyone but its owner is
 * warned about, and read anyway: refusing would leave an operator with a
 * mounted filesystem and no way to say why, and the warning is the part that
 * gets the mode fixed.
 *
 * @return 1 on success. On failure @p cfg is left zeroed and the reason has
 *         been logged.
 */
extern int fs_config_read(const char* file, struct fs_config* cfg);

/**
 * Set one key, as if it had been read from a file.
 *
 * Used for the command line, so that both routes agree on what a value means.
 * @return 1 if the key is known and the value was stored.
 */
extern int fs_config_set(struct fs_config* cfg, const char* key, const char* value);

/**
 * Parse one "key = value" line into @p cfg. Exposed for the tests.
 *
 * @param line    modified in place.
 * @param line_no used in messages.
 * @return 1 if the line was blank, a comment, or a key that was stored.
 */
extern int fs_config_parse_line(char* line, int line_no, struct fs_config* cfg);

#endif /* HAVE_UHUB_FUSE_CONFIG_H */
