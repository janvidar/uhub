#include "system.h"
#include "util/memory.h"
#include "core/config.h"
#include "core/regserver.h"
#include "testutil_net.h"

#include <ctype.h>

/*
 * Every <example> in src/core/config.xml must be a configuration the hub
 * accepts. The examples are what operators copy, and they end up in the
 * generated documentation; one the hub refuses is a hub that silently does
 * not do what it was configured to (#136 was an http:// reg_server_url).
 *
 * Each "key = value" line of an example is run through read_config() -- the
 * same parser and per-option checks as uhub.conf -- and options whose value is
 * refused later, at use rather than at parse, go through that check too.
 */

#define CE_XML UHUB_TEST_DIR "/../src/core/config.xml"
#define CE_TMP "test_config_examples.tmp"
#define CE_MAX_XML (1024 * 1024)

static char* ce_xml;

/* Read the whole of config.xml. */
static char* ce_load(void)
{
	FILE* f = fopen(CE_XML, "rb");
	char* buf;
	size_t len;

	if (!f)
		return NULL;
	buf = hub_malloc(CE_MAX_XML + 1);
	len = fread(buf, 1, CE_MAX_XML, f);
	fclose(f);
	if (len == 0 || len == CE_MAX_XML)
	{
		hub_free(buf);
		return NULL;
	}
	buf[len] = '\0';
	return buf;
}

/* Remove HTML tags (<p>, <br />) in place; the examples are documentation. */
static void ce_strip_tags(char* s)
{
	char* out = s;
	int in_tag = 0;

	for (; *s; s++)
	{
		if (*s == '<')
			in_tag = 1;
		else if (*s == '>' && in_tag)
			in_tag = 0;
		else if (!in_tag)
			*out++ = *s;
	}
	*out = '\0';
}

/* A line of the form "key = value" whose key is a word. */
static int ce_is_setting(const char* line)
{
	const char* p = line;

	while (*p == ' ' || *p == '\t')
		p++;
	if (!isalpha((unsigned char) *p))
		return 0;
	while (isalnum((unsigned char) *p) || *p == '_')
		p++;
	while (*p == ' ' || *p == '\t')
		p++;
	return *p == '=';
}

/* The value of the setting in @p line, unquoted, into @p out. */
static void ce_value(const char* line, char* out, size_t size)
{
	const char* v = strchr(line, '=') + 1;
	size_t len;

	while (*v == ' ' || *v == '\t')
		v++;
	len = strlen(v);
	while (len && (v[len - 1] == ' ' || v[len - 1] == '\t' || v[len - 1] == '\r'))
		len--;
	if (len >= 2 && v[0] == '"' && v[len - 1] == '"')
	{
		v++;
		len -= 2;
	}
	if (len >= size)
		len = size - 1;
	memcpy(out, v, len);
	out[len] = '\0';
}

/*
 * A backslash before anything but \\, # or " is dropped by the parser with only
 * a warning, so "c:\uhub\users.conf" would quietly become "c:uhubusers.conf".
 */
static int ce_bad_escape(const char* line)
{
	const char* p;

	for (p = line; *p; p++)
	{
		if (*p != '\\')
			continue;
		if (p[1] != '\\' && p[1] != '#' && p[1] != '"')
			return 1;
		p++;
	}
	return 0;
}

/* Parse one setting as uhub.conf would. */
static int ce_parses(const char* line)
{
	struct hub_config config;
	FILE* f;
	int ret;

	if (ce_bad_escape(line))
		return 0;
	f = fopen(CE_TMP, "w");
	if (!f)
		return 0;
	fprintf(f, "%s\n", line);
	fclose(f);
	ret = read_config(CE_TMP, &config, 0);
	free_config(&config);
	remove(CE_TMP);
	return ret == 0;
}

/* The checks made when an option is used rather than when it is parsed. */
static int ce_usable(const char* option, const char* value)
{
	if (strcmp(option, "reg_server_url") == 0)
	{
		struct regserver_url url;
		return regserver_check_url(value, &url) == 1;
	}
	return 1;
}

/*
 * Walk every option's example and check each setting in it.
 * @return the number of settings checked, or -1 after printing what failed.
 */
static int ce_check_all(void)
{
	const char* p = ce_xml;
	int checked = 0;
	int failed = 0;

	while ((p = strstr(p, "<option name=\"")) != NULL)
	{
		char option[64];
		const char* name = p + strlen("<option name=\"");
		const char* end_name = strchr(name, '"');
		const char* end_option = strstr(name, "</option>");
		const char* ex;
		const char* ex_end;
		char* text;
		char* line;
		char* save;

		if (!end_name || !end_option || (size_t) (end_name - name) >= sizeof(option))
			return -1;
		memcpy(option, name, (size_t) (end_name - name));
		option[end_name - name] = '\0';
		p = end_option;

		ex = strstr(name, "<example><![CDATA[");
		if (!ex || ex > end_option)
			continue;
		ex += strlen("<example><![CDATA[");
		ex_end = strstr(ex, "]]></example>");
		if (!ex_end || ex_end > end_option)
			return -1;

		text = hub_malloc((size_t) (ex_end - ex) + 1);
		memcpy(text, ex, (size_t) (ex_end - ex));
		text[ex_end - ex] = '\0';
		ce_strip_tags(text);

		for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save))
		{
			char value[1024];

			if (!ce_is_setting(line))
				continue;
			checked++;
			ce_value(line, value, sizeof(value));
			if (!ce_parses(line) || !ce_usable(option, value))
			{
				printf("config.xml: the example for %s is refused: %s\n", option, line);
				failed++;
			}
		}
		hub_free(text);
	}
	return failed ? -1 : checked;
}

EXO_SETUP({
	ce_xml = ce_load();
	return ce_xml != NULL && test_net_acquire();
});

EXO_TEARDOWN({
	hub_free(ce_xml);
	ce_xml = NULL;
	test_net_release();
	return 1;
});

/* Guards the walk itself: an XML layout it no longer understands must fail
   here, not quietly check nothing. */
EXO_TEST(config_examples_found, {
	return ce_check_all() >= 30;
});

EXO_TEST(config_examples_accepted, {
	return ce_check_all() >= 0;
});

/* The checker is not vacuous: the example #136 fixed would have failed it. */
EXO_TEST(config_examples_reject_plain_reg_server_url, {
	return ce_usable("reg_server_url", "http://adcreg.dchublist.org:8080/register") == 0
		&& ce_parses("max_users = lots") == 0
		&& ce_parses("file_acl = \"c:\\uhub\\users.conf\"") == 0
		&& ce_parses("file_acl = \"c:\\\\uhub\\\\users.conf\"") == 1;
});
