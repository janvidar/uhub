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

#include "fuse/config.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"

#include <sys/stat.h>

enum fs_cfg_type
{
	FS_CFG_STR,
	FS_CFG_INT
};

/** One recognised key, and where its value goes. */
struct fs_cfg_key
{
	const char* name;
	enum fs_cfg_type type;
	size_t offset;        /** of the field inside struct fs_config */
	int secret;           /** Setting it makes the file worth protecting. */
	const char* def_str;  /** FS_CFG_STR default; NULL means "". */
	int def_int;          /** FS_CFG_INT default. */
	int min;              /** FS_CFG_INT inclusive range. */
	int max;
	const char* values;   /** FS_CFG_STR: comma separated allowed set, or NULL. */
};

#define STR_KEY(k, member, secret, def, vals) \
	{ k, FS_CFG_STR, offsetof(struct fs_config, member), secret, def, 0, 0, 0, vals }
#define INT_KEY(k, member, def, lo, hi) \
	{ k, FS_CFG_INT, offsetof(struct fs_config, member), 0, NULL, def, lo, hi, NULL }

/*
 * The TLS defaults are the hub's and the seeder's, so an operator who knows
 * uhub.conf does not have to learn a third set of cipher strings.
 */
static const struct fs_cfg_key fs_config_keys[] = {
	STR_KEY("hub",                address,            0, NULL,        NULL),
	STR_KEY("nick",               nick,               0, "uhub-fuse", NULL),
	STR_KEY("password",           password,           1, NULL,        NULL),

	INT_KEY("transfer_port",      transfer_port,      1514, 1024, 65535),
	STR_KEY("transfer_bind_addr", transfer_bind_addr, 0, "any",       NULL),
	INT_KEY("download_timeout",   download_timeout,   60,   1,    3600),

	STR_KEY("tls_certificate",    tls_certificate,    0, NULL,        NULL),
	STR_KEY("tls_private_key",    tls_private_key,    0, NULL,        NULL),
	STR_KEY("tls_version",        tls_version,        0, "1.2",       "1.2,1.3"),
	STR_KEY("tls_ciphersuite",    tls_ciphersuite,    0,
		"ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS", NULL),
	STR_KEY("tls_ciphersuites",   tls_ciphersuites,   0,
		"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256", NULL),

	STR_KEY("cache_dir",          cache_dir,          0, NULL,        NULL),
	INT_KEY("cache_size",         cache_size,         512,  1,    1048576),
	INT_KEY("max_file_size",      max_file_size,      1024, 1,    1048576),
	INT_KEY("max_entries",        max_entries,        4096, 1,    1000000),

	{ NULL, FS_CFG_STR, 0, 0, NULL, 0, 0, 0, NULL }
};

static const struct fs_cfg_key* fs_config_lookup(const char* key)
{
	size_t n;

	for (n = 0; fs_config_keys[n].name; n++)
		if (strcmp(fs_config_keys[n].name, key) == 0)
			return &fs_config_keys[n];

	return NULL;
}

static char** fs_str_field(struct fs_config* cfg, const struct fs_cfg_key* key)
{
	return (char**) (void*) (((char*) cfg) + key->offset);
}

static int* fs_int_field(struct fs_config* cfg, const struct fs_cfg_key* key)
{
	return (int*) (void*) (((char*) cfg) + key->offset);
}

int fs_config_default_cache_dir(char* buf, size_t size)
{
	const char* xdg = getenv("XDG_CACHE_HOME");
	const char* home = getenv("HOME");
	int len;

	if (xdg && *xdg)
		len = snprintf(buf, size, "%s/uhub-fuse", xdg);
	else if (home && *home)
		len = snprintf(buf, size, "%s/.cache/uhub-fuse", home);
	else
		return 0;

	return (len > 0 && (size_t) len < size);
}

void fs_config_defaults(struct fs_config* cfg)
{
	size_t n;

	memset(cfg, 0, sizeof(*cfg));

	for (n = 0; fs_config_keys[n].name; n++)
	{
		const struct fs_cfg_key* key = &fs_config_keys[n];

		if (key->type == FS_CFG_STR)
			*fs_str_field(cfg, key) = hub_strdup(key->def_str ? key->def_str : "");
		else
			*fs_int_field(cfg, key) = key->def_int;
	}
}

void fs_config_free(struct fs_config* cfg)
{
	size_t n;

	if (!cfg)
		return;

	for (n = 0; fs_config_keys[n].name; n++)
	{
		const struct fs_cfg_key* key = &fs_config_keys[n];
		char** member;

		if (key->type != FS_CFG_STR)
			continue;

		member = fs_str_field(cfg, key);

		/* A password does not need to outlive the login, and the process may
		   go on running for weeks after it. */
		if (key->secret && *member)
			memset(*member, 0, strlen(*member));

		hub_free(*member);
		*member = NULL;
	}
}

/**
 * Unlike the hub's apply_integer(), this rejects trailing garbage: "8080x" is a
 * typo, not the number 8080, and a configuration that means something other
 * than what it says is worse than one that refuses to load.
 */
static int apply_integer(const struct fs_cfg_key* key, const char* data, int* target)
{
	char* endptr = NULL;
	long val;

	errno = 0;
	val = strtol(data, &endptr, 10);

	if (endptr == data || !endptr || *endptr != '\0')
	{
		LOG_ERROR("Invalid numeric value for configuration key '%s': \"%s\"", key->name, data);
		return 0;
	}

	if (errno == ERANGE || val < (long) key->min || val > (long) key->max)
	{
		LOG_ERROR("Value out of range for configuration key '%s': \"%s\" (allowed: %d-%d)",
			key->name, data, key->min, key->max);
		return 0;
	}

	*target = (int) val;
	return 1;
}

/** Check a value against a comma separated set. An empty set permits anything. */
static int value_in_set(const struct fs_cfg_key* key, const char* data)
{
	const char* p = key->values;
	size_t len = strlen(data);

	if (!p || !*p)
		return 1;

	while (*p)
	{
		const char* end = strchr(p, ',');
		size_t n = end ? (size_t) (end - p) : strlen(p);

		if (n == len && strncmp(p, data, n) == 0)
			return 1;

		if (!end)
			break;
		p = end + 1;
	}

	LOG_ERROR("Invalid value for configuration key '%s': \"%s\" (must be one of: %s)",
		key->name, data, key->values);
	return 0;
}

int fs_config_set(struct fs_config* cfg, const char* key_name, const char* value)
{
	const struct fs_cfg_key* key = fs_config_lookup(key_name);
	char** member;
	char* copy;

	if (!cfg || !key || !value)
		return 0;

	if (key->type == FS_CFG_INT)
		return apply_integer(key, value, fs_int_field(cfg, key));

	if (!value_in_set(key, value))
		return 0;

	copy = hub_strdup(value);
	if (!copy)
		return 0;

	member = fs_str_field(cfg, key);
	hub_free(*member);
	*member = copy;
	return 1;
}

int fs_config_parse_line(char* line, int line_no, struct fs_config* cfg)
{
	const struct fs_cfg_key* key_def;
	char* pos;
	char* key;
	char* value;

	if (!line || !cfg)
		return 0;

	line = strip_white_space(line);

	if (!*line || line[0] == '#')
		return 1;

	if (!is_valid_utf8(line))
		LOG_WARN("Invalid utf-8 characters on line %d", line_no);

	pos = strchr(line, '=');
	if (!pos)
	{
		LOG_FATAL("Configuration parse error on line %d: expected 'key = value'", line_no);
		return 0;
	}

	pos[0] = '\0';
	key = strip_white_space(line);

	if (!*key)
	{
		LOG_FATAL("Configuration parse error on line %d: missing key", line_no);
		return 0;
	}

	key_def = fs_config_lookup(key);
	if (!key_def)
	{
		LOG_FATAL("Unknown configuration key '%s' on line %d", key, line_no);
		return 0;
	}

	/*
	 * The value runs to the end of the line, with the surrounding whitespace
	 * removed and nothing else interpreted -- no comment character, no quote
	 * processing. A password is the reason: '#' is an ordinary character in
	 * one, and a parser that treated it as the start of a comment would
	 * silently truncate the secret and then fail the login for no visible
	 * reason.
	 */
	value = strip_white_space(&pos[1]);

	if (!fs_config_set(cfg, key, value))
	{
		LOG_FATAL("Out of memory parsing configuration line %d", line_no);
		return 0;
	}

	return 1;
}

static char* fs_config_slurp(const char* file)
{
	FILE* fh;
	long size;
	size_t got;
	char* buf;

	fh = fopen(file, "rb");
	if (!fh)
	{
		LOG_FATAL("Unable to open configuration file %s: %s", file, strerror(errno));
		return NULL;
	}

	if (fseek(fh, 0, SEEK_END) != 0 || (size = ftell(fh)) < 0 || fseek(fh, 0, SEEK_SET) != 0)
	{
		LOG_FATAL("Unable to read configuration file %s: not a regular file?", file);
		fclose(fh);
		return NULL;
	}

	if (size > FS_CONFIG_MAX_FILE)
	{
		LOG_FATAL("Configuration file %s is too large (%ld bytes, max %d)", file, size, FS_CONFIG_MAX_FILE);
		fclose(fh);
		return NULL;
	}

	buf = (char*) hub_malloc((size_t) size + 1);
	if (!buf)
	{
		LOG_FATAL("Out of memory reading configuration file %s", file);
		fclose(fh);
		return NULL;
	}

	got = fread(buf, 1, (size_t) size, fh);
	if (ferror(fh))
	{
		LOG_FATAL("Unable to read configuration file %s: %s", file, strerror(errno));
		hub_free(buf);
		fclose(fh);
		return NULL;
	}
	fclose(fh);

	buf[got] = '\0';
	return buf;
}

/** Say so if a file holding a secret is readable by anyone but its owner. */
static void fs_config_check_mode(const char* file, const struct fs_config* cfg)
{
	struct stat st;

	if (!cfg->password || !*cfg->password)
		return;

	if (stat(file, &st) != 0)
		return;

	if (st.st_mode & (S_IRGRP | S_IROTH))
		LOG_WARN("%s holds a password and is readable by others; chmod 600 it", file);
}

int fs_config_read(const char* file, struct fs_config* cfg)
{
	char* buf;
	char* line;
	int line_no = 1;
	int ok = 1;

	if (!cfg)
		return 0;

	if (!file)
	{
		LOG_FATAL("No configuration file given.");
		return 0;
	}

	buf = fs_config_slurp(file);
	if (!buf)
	{
		fs_config_free(cfg);
		return 0;
	}

	/* Split on '\n'. A trailing '\r' from a CRLF file is whitespace to
	   strip_white_space(), so it needs no handling of its own. */
	line = buf;
	while (ok)
	{
		char* eol = strchr(line, '\n');
		if (eol)
			*eol = '\0';

		ok = fs_config_parse_line(line, line_no, cfg);

		if (!eol)
			break;

		line = eol + 1;
		line_no++;
	}

	/* The file may have held a password; do not leave it in freed memory. */
	memset(buf, 0, strlen(buf));
	hub_free(buf);

	if (!ok)
	{
		fs_config_free(cfg);
		return 0;
	}

	/*
	 * A certificate without its key, or the other way round, fails quietly:
	 * the transfer port would come up serving plain ADC while the operator
	 * believes it is serving ADCS. Refuse the file instead.
	 */
	if (!!(cfg->tls_certificate && *cfg->tls_certificate) !=
	    !!(cfg->tls_private_key && *cfg->tls_private_key))
	{
		LOG_FATAL("Configuration error in %s: tls_certificate and tls_private_key must be "
			"set together (only '%s' is set)", file,
			(cfg->tls_certificate && *cfg->tls_certificate) ? "tls_certificate" : "tls_private_key");
		fs_config_free(cfg);
		return 0;
	}

	fs_config_check_mode(file, cfg);
	return 1;
}
