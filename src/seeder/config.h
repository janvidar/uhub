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
 * Configuration for the standalone uhub-seeder daemon (uhub-seeder.conf).
 *
 * This is deliberately NOT the hub's generated configuration. The hub's
 * src/core/config.c is produced from config.xml by config.py; the seeder has
 * roughly two dozen keys of its own and is a separate program, so it carries a
 * small hand-rolled parser instead of teaching the generator about a second
 * output. The validation behaviour is modelled on the hub's, though:
 * per-type apply_*() helpers, ranges on every integer, and a hard error on
 * anything that does not parse.
 *
 * File format: "key = value" per line, '#' starts a comment, blank lines are
 * ignored. Values may be quoted to protect leading/trailing whitespace or a
 * literal '#'; a quote inside a quoted value is written \". Unquoted runs of
 * whitespace inside a value collapse to a single space. Unknown keys are an
 * error, and so is a missing (or empty) required key.
 *
 * NOTE: there is deliberately no "advertised address" / "external address"
 * option here, and that omission is the entire point of splitting the seeder
 * out of the hub. The seeder logs in as an ordinary ADC client, so whatever I4
 * it puts in its own INF is overwritten by the hub with the address the hub
 * actually observed the connection coming from -- see check_network() in
 * src/core/inf.c. A seeder behind NAT is therefore fixed the same way any other
 * NATed client is: the hub operator lists its address in the hub's existing
 * nat_override setting. Adding a seed_advertise_addr key here would be a knob
 * the hub is guaranteed to ignore.
 */

#ifndef HAVE_UHUB_SEEDER_CONFIG_H
#define HAVE_UHUB_SEEDER_CONFIG_H

/**
 * Parsed uhub-seeder.conf.
 *
 * One field per configuration key, named exactly after the key (as the hub
 * does). Strings are always non-NULL after a successful read or after
 * seed_config_defaults() -- an unset string key is the empty string, never a
 * null pointer -- and are owned by the struct.
 */
struct seed_config
{
	/* Hub connection. */
	char* seed_hub_url;               /* required, e.g. "adcs://hub.example.org:1511/" */
	char* seed_nick;                  /* default "[seed]cache" */
	char* seed_password;              /* required; password of the bot account */
	char* seed_description;           /* default "seed cache" */

	/* Client connections: the seeder listens for transfers on its own port. */
	int   seed_client_port;           /* 1024..65535, default 1512 */
	char* seed_client_bind_addr;      /* default "any" */

	/*
	 * TLS on the transfer port. The seeder accepts ADCS and plain ADC on the
	 * same port and tells them apart from the first bytes, so this switches
	 * nothing on or off beyond whether ADCS can be answered at all: without a
	 * certificate the seeder can only offer ADC/1.0, and most clients refuse
	 * plain transfers. The key names mirror the hub's (src/core/config.xml).
	 */
	char* seed_tls_certificate;       /* PEM certificate/chain, default empty */
	char* seed_tls_private_key;       /* PEM private key, default empty */
	char* seed_tls_version;           /* minimum: "1.2" (default) or "1.3" */
	char* seed_tls_ciphersuite;       /* TLS 1.2 and earlier cipher list */
	char* seed_tls_ciphersuites;      /* TLS 1.3 cipher suites */

	/* Cache. Sizes are in MiB, mirroring the hub's convention that every
	   configurable number is a plain int. */
	char* seed_cache_dir;             /* default "/var/lib/uhub/seed" */
	int   seed_cache_size;            /* MiB, 1..1048576, default 256 */
	int   seed_max_file_size;         /* MiB, 1..1024, default 2 */
	int   seed_max_entries;           /* 1..1000000, default 4096 */
	int   seed_entry_ttl;             /* seconds, 0..315360000, default 2592000 */
	int   seed_max_concurrent_ingest; /* 1..64, default 4 */
	int   seed_max_concurrent_upload; /* 1..1024, default 16 */
	char* seed_allowed_types;         /* comma separated MIME types */

	/* Who may cause an ingest, and how fast. */
	char* seed_min_credentials;       /* guest|user|operator|super|admin, default "user" */
	int   seed_ingest_interval;       /* seconds, 1..86400, default 300 */
	int   seed_ingest_per_user;       /* 0..1000, default 5 (0 = unlimited) */
	int   seed_ingest_quota_kb;       /* 0..1048576, default 32768 (0 = unlimited) */

	/* URL mirroring. Off by default: it is an SSRF surface. */
	int   seed_url_mirror;            /* boolean, default 0 */
	char* seed_url_allow_ports;       /* default "80,443" */
	int   seed_url_max_redirects;     /* 0..5, default 2 */
	int   seed_url_timeout;           /* seconds, 1..120, default 30 */
	int   seed_url_allow_private;     /* boolean, default 0 */
	int   seed_url_verify_tls;        /* boolean, default 1 */
	char* seed_url_allow_hosts;       /* default empty */
	char* seed_url_deny_hosts;        /* default empty */

	/* Optional HTTP serving. Unauthenticated, hence opt-in. */
	int   seed_http_enable;           /* boolean, default 0 */
	int   seed_http_port;             /* 1024..65535, default 1513 */
};

/**
 * Read and validate a uhub-seeder.conf.
 *
 * Fills cfg with the defaults first, then applies the file on top. Any parse
 * error, out-of-range value, unknown key or missing required key is fatal and
 * is logged naming the key (and the line, where there is one). So is a key that
 * only makes sense together with another one: seed_tls_certificate and
 * seed_tls_private_key must be given as a pair, since either alone would leave
 * the transfer port silently serving in the clear.
 *
 * The previous contents of cfg are ignored; on failure cfg is left freed and
 * zeroed, so calling seed_config_free() on it afterwards is harmless.
 *
 * @return 1 on success, 0 on failure.
 */
int seed_config_read(const char* file, struct seed_config* cfg);

/**
 * Fill cfg with the compiled-in defaults. Required keys (seed_hub_url,
 * seed_password) have no default and are left empty. Any previous contents are
 * overwritten without being freed, so call seed_config_free() first if cfg was
 * already populated.
 */
void seed_config_defaults(struct seed_config* cfg);

/**
 * Release every string owned by cfg and null the pointers. Idempotent, and
 * safe on a zeroed struct.
 */
void seed_config_free(struct seed_config* cfg);

#endif /* HAVE_UHUB_SEEDER_CONFIG_H */
