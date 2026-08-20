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

#include "system.h"
#include <stddef.h>
#include <limits.h>
#include "util/config_token.h"
#include "util/log.h"
#include "util/memory.h"
#include "util/misc.h"
#include "seeder/config.h"

/* A configuration file this size is not a configuration file. Bounded so a
   pipe, a device node or a runaway file cannot be slurped into memory. */
#define SEED_CONFIG_MAX_FILE (1024 * 1024)

enum seed_cfg_type
{
	SEED_CFG_STR,
	SEED_CFG_INT,
	SEED_CFG_BOOL
};

struct seed_cfg_key
{
	const char* name;
	enum seed_cfg_type type;
	size_t offset;        /* offset of the field inside struct seed_config */
	int required;         /* must be present, and non-empty */
	const char* def_str;  /* SEED_CFG_STR default; NULL means "" */
	int def_int;          /* SEED_CFG_INT / SEED_CFG_BOOL default */
	int min;              /* SEED_CFG_INT inclusive range */
	int max;
	const char* values;   /* SEED_CFG_STR: comma separated allowed set, or NULL */
};

#define STR_KEY(k, req, def, vals) { #k, SEED_CFG_STR,  offsetof(struct seed_config, k), req, def,  0,   0, 0, vals }
#define INT_KEY(k, def, lo, hi)    { #k, SEED_CFG_INT,  offsetof(struct seed_config, k), 0,   NULL, def, lo, hi, NULL }
#define BOOL_KEY(k, def)           { #k, SEED_CFG_BOOL, offsetof(struct seed_config, k), 0,   NULL, def, 0, 1, NULL }

/*
 * The single source of truth for the configuration: the parser, the defaults
 * and the destructor all walk this table, so a key cannot be added to one and
 * forgotten in another.
 */
static const struct seed_cfg_key SEED_CONFIG_KEYS[] =
{
	/* Hub connection */
	STR_KEY(seed_hub_url,               1, NULL,                NULL),
	STR_KEY(seed_nick,                  0, "[seed]cache",       NULL),
	STR_KEY(seed_password,              1, NULL,                NULL),
	STR_KEY(seed_description,           0, "seed cache",        NULL),

	/* Client connections */
	INT_KEY(seed_client_port,           1512, 1024, 65535),
	STR_KEY(seed_client_bind_addr,      0, "any",               NULL),

	/* TLS on the transfer port. The defaults are the hub's, so an operator who
	   knows uhub.conf does not have to learn a second set of cipher strings. */
	STR_KEY(seed_tls_certificate,       0, NULL,                NULL),
	STR_KEY(seed_tls_private_key,       0, NULL,                NULL),
	STR_KEY(seed_tls_version,           0, "1.2",               "1.2,1.3"),
	STR_KEY(seed_tls_ciphersuite,       0, "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS", NULL),
	STR_KEY(seed_tls_ciphersuites,      0, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256", NULL),

	/* Cache */
	STR_KEY(seed_cache_dir,             0, "/var/lib/uhub/seed", NULL),
	INT_KEY(seed_cache_size,            256,  1, 1048576),
	INT_KEY(seed_max_file_size,         2,    1, 1024),
	INT_KEY(seed_max_entries,           4096, 1, 1000000),
	INT_KEY(seed_entry_ttl,             2592000, 0, 315360000),
	INT_KEY(seed_max_concurrent_ingest, 4,    1, 64),
	INT_KEY(seed_max_concurrent_upload, 16,   1, 1024),
	STR_KEY(seed_allowed_types,         0, "image/png,image/jpeg,image/gif,image/webp,application/x-adc-bbs-post", NULL),

	/* Ingest policy */
	STR_KEY(seed_min_credentials,       0, "user", "guest,user,operator,super,admin"),
	INT_KEY(seed_ingest_interval,       300,   1, 86400),
	INT_KEY(seed_ingest_per_user,       5,     0, 1000),
	INT_KEY(seed_ingest_quota_kb,       32768, 0, 1048576),

	/* URL mirroring */
	BOOL_KEY(seed_url_mirror,           0),
	STR_KEY(seed_url_allow_ports,       0, "80,443",            NULL),
	INT_KEY(seed_url_max_redirects,     2, 0, 5),
	INT_KEY(seed_url_timeout,           30, 1, 120),
	BOOL_KEY(seed_url_allow_private,    0),
	BOOL_KEY(seed_url_verify_tls,       1),
	STR_KEY(seed_url_allow_hosts,       0, NULL,                NULL),
	STR_KEY(seed_url_deny_hosts,        0, NULL,                NULL),

	/* Optional HTTP serving */
	BOOL_KEY(seed_http_enable,          0),
	INT_KEY(seed_http_port,             1513, 1024, 65535),

	/* BBS0 bulletin boards */
	BOOL_KEY(seed_bbs_enable,           1),
	STR_KEY(seed_bbs_boards,            0, NULL,                NULL),
	INT_KEY(seed_bbs_max_backlog,       5000, 0, 1000000),
	INT_KEY(seed_bbs_fetch_delay,       5,    0, 3600),
	BOOL_KEY(seed_bbs_attachments,      1),
	BOOL_KEY(seed_bbs_search_fallback,  1)
};

#define SEED_CONFIG_KEY_COUNT (sizeof(SEED_CONFIG_KEYS) / sizeof(SEED_CONFIG_KEYS[0]))

static char** seed_str_field(struct seed_config* cfg, const struct seed_cfg_key* key)
{
	return (char**) (void*) ((char*) cfg + key->offset);
}

static int* seed_int_field(struct seed_config* cfg, const struct seed_cfg_key* key)
{
	return (int*) (void*) ((char*) cfg + key->offset);
}

/* -------------------------------------------------------------------------
 * Value application. One helper per type, in the style of src/core/config.c.
 * ------------------------------------------------------------------------- */

static int apply_boolean(const char* key, const char* data, int* target)
{
	if (!string_to_boolean(data, target))
	{
		LOG_ERROR("Invalid boolean value for configuration key '%s': \"%s\"", key, data);
		return 0;
	}
	return 1;
}

/**
 * Check a value against a comma separated set of permitted values.
 * An empty or absent set permits anything.
 */
static int value_in_set(const char* key, const char* data, const char* set)
{
	const char* p = set;
	size_t len = strlen(data);

	if (!set || !*set)
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

	LOG_ERROR("Invalid value for configuration key '%s': \"%s\" (must be one of: %s)", key, data, set);
	return 0;
}

static int apply_string(const char* key, const char* data, char** target, const char* values)
{
	char* copy;

	if (!value_in_set(key, data, values))
		return 0;

	copy = hub_strdup(data);
	if (!copy)
	{
		LOG_ERROR("Out of memory setting configuration key '%s'", key);
		return 0;
	}

	hub_free(*target);
	*target = copy;
	return 1;
}

/**
 * Unlike the hub's apply_integer(), this rejects trailing garbage: "8080x" is a
 * typo, not the number 8080, and a config that means something other than what
 * it says is worse than one that refuses to load.
 */
static int apply_integer(const char* key, const char* data, int* target, int min, int max)
{
	char* endptr = NULL;
	long val;

	errno = 0;
	val = strtol(data, &endptr, 10);

	if (endptr == data || !endptr || *endptr != '\0')
	{
		LOG_ERROR("Invalid numeric value for configuration key '%s': \"%s\"", key, data);
		return 0;
	}

	if (errno == ERANGE || val < (long) INT_MIN || val > (long) INT_MAX)
	{
		LOG_ERROR("Value out of range for configuration key '%s': \"%s\"", key, data);
		return 0;
	}

	if (val < (long) min || val > (long) max)
	{
		LOG_ERROR("Value out of range for configuration key '%s': %ld (allowed: %d-%d)", key, val, min, max);
		return 0;
	}

	*target = (int) val;
	return 1;
}

/* -------------------------------------------------------------------------
 * Parsing
 * ------------------------------------------------------------------------- */

static const struct seed_cfg_key* seed_config_lookup(const char* key)
{
	size_t i;
	for (i = 0; i < SEED_CONFIG_KEY_COUNT; i++)
		if (strcmp(SEED_CONFIG_KEYS[i].name, key) == 0)
			return &SEED_CONFIG_KEYS[i];
	return NULL;
}

/**
 * Turn the right hand side of a "key = value" line into a value string.
 *
 * The heavy lifting is cfg_tokenize() from util/config_token.c: it strips an
 * unquoted trailing '#' comment, honours double quotes (so a value may contain
 * '#', leading or trailing spaces), understands \" and \\ escapes, and drops
 * the '\r' of a CRLF file. Whatever tokens come back are re-joined with single
 * spaces, so an unquoted multi-word value such as
 *
 *     seed_description = my seed cache
 *
 * still works, with runs of whitespace collapsed. A value that is entirely
 * absent yields the empty string.
 *
 * @return a newly allocated string, or NULL on allocation failure.
 */
static char* seed_config_value(const char* raw)
{
	struct cfg_tokens* tokens = cfg_tokenize(raw);
	size_t count;
	size_t i;
	size_t len = 0;
	char* value;
	char* out;

	if (!tokens)
		return NULL;

	count = cfg_token_count(tokens);
	for (i = 0; i < count; i++)
		len += strlen(cfg_token_get(tokens, i)) + 1; /* + separator or NUL */

	value = (char*) hub_malloc(len ? len : 1);
	if (!value)
	{
		cfg_tokens_free(tokens);
		return NULL;
	}

	out = value;
	for (i = 0; i < count; i++)
	{
		const char* tok = cfg_token_get(tokens, i);
		size_t n = strlen(tok);
		if (i)
			*out++ = ' ';
		memcpy(out, tok, n);
		out += n;
	}
	*out = '\0';

	cfg_tokens_free(tokens);
	return value;
}

/**
 * Apply a single line. The line buffer is modified in place.
 * @return 1 on success, 0 on error.
 */
static int seed_config_parse_line(char* line, int line_no, struct seed_config* cfg, unsigned char* seen)
{
	const struct seed_cfg_key* key_def;
	char* pos;
	char* key;
	char* value;
	int ok;

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

	key_def = seed_config_lookup(key);
	if (!key_def)
	{
		LOG_FATAL("Unknown configuration key '%s' on line %d", key, line_no);
		return 0;
	}

	value = seed_config_value(&pos[1]);
	if (!value)
	{
		LOG_FATAL("Out of memory parsing configuration line %d", line_no);
		return 0;
	}

	LOG_DUMP("seed_config_parse_line: '%s' => '%s'", key, value);

	switch (key_def->type)
	{
		case SEED_CFG_STR:
			ok = apply_string(key_def->name, value, seed_str_field(cfg, key_def), key_def->values);
			break;

		case SEED_CFG_INT:
			ok = apply_integer(key_def->name, value, seed_int_field(cfg, key_def), key_def->min, key_def->max);
			break;

		case SEED_CFG_BOOL:
			ok = apply_boolean(key_def->name, value, seed_int_field(cfg, key_def));
			break;

		default:
			ok = 0;
			break;
	}

	hub_free(value);

	if (!ok)
	{
		LOG_FATAL("Configuration error on line %d", line_no);
		return 0;
	}

	seen[key_def - SEED_CONFIG_KEYS] = 1;
	return 1;
}

/**
 * Read a whole configuration file into memory.
 *
 * Deliberately not file_read_lines(): that reads into a fixed MAX_RECV_BUF
 * stack buffer and silently truncates anything larger, which for a config file
 * means quietly ignoring settings. Here an oversized file is an error instead.
 *
 * @return a NUL terminated buffer the caller must hub_free(), or NULL.
 */
static char* seed_config_slurp(const char* file)
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

	if (size > SEED_CONFIG_MAX_FILE)
	{
		LOG_FATAL("Configuration file %s is too large (%ld bytes, max %d)", file, size, SEED_CONFIG_MAX_FILE);
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

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

void seed_config_defaults(struct seed_config* cfg)
{
	size_t i;

	memset(cfg, 0, sizeof(struct seed_config));

	for (i = 0; i < SEED_CONFIG_KEY_COUNT; i++)
	{
		const struct seed_cfg_key* key = &SEED_CONFIG_KEYS[i];

		if (key->type == SEED_CFG_STR)
			*seed_str_field(cfg, key) = hub_strdup(key->def_str ? key->def_str : "");
		else
			*seed_int_field(cfg, key) = key->def_int;
	}
}

void seed_config_free(struct seed_config* cfg)
{
	size_t i;

	if (!cfg)
		return;

	for (i = 0; i < SEED_CONFIG_KEY_COUNT; i++)
	{
		const struct seed_cfg_key* key = &SEED_CONFIG_KEYS[i];
		char** field;

		if (key->type != SEED_CFG_STR)
			continue;

		field = seed_str_field(cfg, key);
		hub_free(*field);
		*field = NULL;
	}
}

int seed_config_read(const char* file, struct seed_config* cfg)
{
	unsigned char seen[SEED_CONFIG_KEY_COUNT];
	char* buf;
	char* line;
	int line_no = 1;
	size_t i;
	int ok = 1;

	if (!cfg)
		return 0;

	seed_config_defaults(cfg);
	memset(seen, 0, sizeof(seen));

	if (!file)
	{
		LOG_FATAL("No configuration file given.");
		seed_config_free(cfg);
		memset(cfg, 0, sizeof(struct seed_config));
		return 0;
	}

	buf = seed_config_slurp(file);
	if (!buf)
	{
		seed_config_free(cfg);
		memset(cfg, 0, sizeof(struct seed_config));
		return 0;
	}

	/* Split on '\n'. A trailing '\r' (CRLF file) is whitespace as far as
	   strip_white_space() and cfg_tokenize() are concerned, so it needs no
	   special handling here. */
	line = buf;
	while (ok)
	{
		char* eol = strchr(line, '\n');
		if (eol)
			*eol = '\0';

		ok = seed_config_parse_line(line, line_no, cfg, seen);

		if (!eol)
			break;

		line = eol + 1;
		line_no++;
	}

	hub_free(buf);

	if (ok)
	{
		for (i = 0; i < SEED_CONFIG_KEY_COUNT; i++)
		{
			const struct seed_cfg_key* key = &SEED_CONFIG_KEYS[i];
			const char* val;

			if (!key->required || key->type != SEED_CFG_STR)
				continue;

			val = *seed_str_field(cfg, key);
			if (!seen[i] || !val || !*val)
			{
				LOG_FATAL("Required configuration key '%s' is missing in %s", key->name, file);
				ok = 0;
			}
		}
	}

	/*
	 * A certificate is useless without its key and vice versa, and the failure
	 * mode is a quiet one: the transfer port would come up serving plain ADC
	 * while the operator believes it is serving ADCS. Refuse the file instead.
	 */
	if (ok && (!!*cfg->seed_tls_certificate != !!*cfg->seed_tls_private_key))
	{
		LOG_FATAL("Configuration error in %s: seed_tls_certificate and seed_tls_private_key "
			"must be set together (only '%s' is set)", file,
			*cfg->seed_tls_certificate ? "seed_tls_certificate" : "seed_tls_private_key");
		ok = 0;
	}

	if (!ok)
	{
		seed_config_free(cfg);
		memset(cfg, 0, sizeof(struct seed_config));
		return 0;
	}

	return 1;
}
