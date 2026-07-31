#include "util/memory.h"
#include "adc/message.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/route.h"
#include "core/user.h"

static struct hub_user rtf0_user;
static struct hub_info rtf0_hub;
static struct hub_config rtf0_config;

/* A hub with rich text either allowed (the default) or switched off. */
static struct hub_info* rtf0_make_hub(int rich_text_enabled)
{
	memset(&rtf0_hub, 0, sizeof(rtf0_hub));
	memset(&rtf0_config, 0, sizeof(rtf0_config));
	rtf0_config.chat_rich_text = rich_text_enabled;
	rtf0_hub.config = &rtf0_config;
	return &rtf0_hub;
}

/**
 * Parse a MSG line and ask the hub whether it should go to the command parser.
 * @return 1 if it is a command, 0 if it is ordinary chat, -1 on parse failure.
 */
static int rtf0_is_command_cfg(const char* line, int supports_rtf0, int rich_text_enabled)
{
	struct adc_message* msg;
	char* message;
	int ret;

	memset(&rtf0_user, 0, sizeof(rtf0_user));
	rtf0_user.id.sid = 1; /* "AAAB" */
	if (supports_rtf0)
		user_support_add(&rtf0_user, FOURCC('R', 'T', 'F', '0'));

	msg = adc_msg_parse_verify(&rtf0_user, line, strlen(line));
	if (!msg)
		return -1;

	message = adc_msg_get_argument(msg, 0);
	ret = message ? hub_chat_message_is_command(rtf0_make_hub(rich_text_enabled),
	                                            &rtf0_user, msg, message)
	              : -1;

	hub_free(message);
	adc_msg_free(msg);
	return ret;
}

static int rtf0_is_command(const char* line, int supports_rtf0)
{
	return rtf0_is_command_cfg(line, supports_rtf0, 1);
}

EXO_TEST(rtf0_support_flag, {
	memset(&rtf0_user, 0, sizeof(rtf0_user));
	user_support_add(&rtf0_user, FOURCC('R', 'T', 'F', '0'));
	return user_flag_get(&rtf0_user, feature_rtf0) != 0;
});

/* Ordinary chat is never a command. */
EXO_TEST(rtf0_plain_chat, { return rtf0_is_command("BMSG AAAB Hello\\sWorld!\n", 0) == 0; });
EXO_TEST(rtf0_plain_chat_rich, { return rtf0_is_command("BMSG AAAB Hello\\sWorld! RT1\n", 1) == 0; });

/* Commands are still commands, rich text or not. */
EXO_TEST(rtf0_command_bang, { return rtf0_is_command("BMSG AAAB !help\n", 0) == 1; });
EXO_TEST(rtf0_command_plus, { return rtf0_is_command("BMSG AAAB +help\n", 0) == 1; });
EXO_TEST(rtf0_command_bang_rich, { return rtf0_is_command("BMSG AAAB !help RT1\n", 1) == 1; });
EXO_TEST(rtf0_command_bare_bang, { return rtf0_is_command("BMSG AAAB ! RT1\n", 1) == 1; });

/* An image embed in a rich text message is chat, not a command. */
EXO_TEST(rtf0_embed, {
	return rtf0_is_command("BMSG AAAB ![a\\scat](http://example.org/cat.png) RT1\n", 1) == 0;
});
EXO_TEST(rtf0_embed_empty_description, {
	return rtf0_is_command("BMSG AAAB ![](http://example.org/cat.png) RT1\n", 1) == 0;
});
EXO_TEST(rtf0_embed_truncated, { return rtf0_is_command("BMSG AAAB ![ RT1\n", 1) == 0; });

/* ... but only when the message really is rich text ... */
EXO_TEST(rtf0_embed_without_rt_flag, {
	return rtf0_is_command("BMSG AAAB ![a\\scat](http://example.org/cat.png)\n", 1) == 1;
});
EXO_TEST(rtf0_embed_rt_disabled, {
	return rtf0_is_command("BMSG AAAB ![a\\scat](http://example.org/cat.png) RT0\n", 1) == 1;
});

/* ... and only from a client that negotiated RTF0. */
EXO_TEST(rtf0_embed_unsupported_client, {
	return rtf0_is_command("BMSG AAAB ![a\\scat](http://example.org/cat.png) RT1\n", 0) == 1;
});

/* A "!" command that merely resembles an embed is unaffected. */
EXO_TEST(rtf0_command_lookalike, {
	return rtf0_is_command("BMSG AAAB !ban\\s[user] RT1\n", 1) == 1;
});

/*
 * Relay: clients that did not negotiate RTF0 must not see the RT flag, so a
 * rich text message is relayed as an RT-stripped copy to them.
 */

/**
 * Strip a MSG line and compare the result against the expected wire form.
 * @param expected the stripped message, or NULL if no copy should be made.
 */
static int rtf0_strips_to(const char* line, const char* expected)
{
	struct adc_message* msg;
	struct adc_message* plain;
	int ok;

	memset(&rtf0_user, 0, sizeof(rtf0_user));
	rtf0_user.id.sid = 1; /* "AAAB" */

	msg = adc_msg_parse_verify(&rtf0_user, line, strlen(line));
	if (!msg)
		return 0;

	plain = route_rtf0_strip(msg);
	if (!expected)
		ok = (plain == NULL);
	else
		ok = plain && strcmp(plain->cache, expected) == 0;

	/* Stripping must never disturb the original. */
	if (ok && strcmp(msg->cache, line) != 0)
		ok = 0;

	adc_msg_free(plain);
	adc_msg_free(msg);
	return ok;
}

EXO_TEST(rtf0_strip_broadcast, {
	return rtf0_strips_to("BMSG AAAB ![a\\scat](http://example.org/cat.png) RT1\n",
	                      "BMSG AAAB ![a\\scat](http://example.org/cat.png)\n");
});
EXO_TEST(rtf0_strip_keeps_other_flags, {
	return rtf0_strips_to("BMSG AAAB Hello RT1 ME1\n", "BMSG AAAB Hello ME1\n");
});
EXO_TEST(rtf0_strip_private, {
	return rtf0_strips_to("DMSG AAAB AAAC Hello RT1\n", "DMSG AAAB AAAC Hello\n");
});
EXO_TEST(rtf0_strip_echo, {
	return rtf0_strips_to("EMSG AAAB AAAC Hello RT1\n", "EMSG AAAB AAAC Hello\n");
});
EXO_TEST(rtf0_strip_feature_cast, {
	return rtf0_strips_to("FMSG AAAB +TCP4 Hello RT1\n", "FMSG AAAB +TCP4 Hello\n");
});

/* No RT flag: no copy is made, so ordinary traffic pays nothing. */
EXO_TEST(rtf0_strip_skips_plain_chat, { return rtf0_strips_to("BMSG AAAB Hello\n", NULL); });

/* Only MSG commands can carry RT; an "RT" elsewhere is left alone. */
EXO_TEST(rtf0_strip_skips_non_msg, {
	return rtf0_strips_to("BINF AAAB NIfoo RT1\n", NULL);
});

/*
 * chat_rich_text=0: the hub does not advertise RTF0, ignores the RT flag when
 * deciding what is a command, and strips RT for everyone on relay.
 */
EXO_TEST(rtf0_disabled_embed_is_a_command, {
	return rtf0_is_command_cfg("BMSG AAAB ![a\\scat](http://example.org/cat.png) RT1\n", 1, 0) == 1;
});
EXO_TEST(rtf0_disabled_plain_chat_unaffected, {
	return rtf0_is_command_cfg("BMSG AAAB Hello\\sWorld!\n", 1, 0) == 0;
});
EXO_TEST(rtf0_disabled_command_unaffected, {
	return rtf0_is_command_cfg("BMSG AAAB !help\n", 1, 0) == 1;
});

/* The baseline every recipient starts from: the original while rich text is
   allowed, the stripped copy once it is disabled. */
EXO_TEST(rtf0_baseline_enabled, {
	struct adc_message* rich = adc_msg_create("BMSG AAAB Hello RT1\n");
	struct adc_message* plain = adc_msg_create("BMSG AAAB Hello\n");
	int ok = rich && plain
	         && route_rtf0_baseline(rtf0_make_hub(1), rich, plain) == rich
	         /* Not rich text at all: always the original. */
	         && route_rtf0_baseline(rtf0_make_hub(1), rich, NULL) == rich
	         && route_rtf0_baseline(rtf0_make_hub(0), rich, NULL) == rich;
	adc_msg_free(rich);
	adc_msg_free(plain);
	return ok;
});
EXO_TEST(rtf0_baseline_disabled, {
	struct adc_message* rich = adc_msg_create("BMSG AAAB Hello RT1\n");
	struct adc_message* plain = adc_msg_create("BMSG AAAB Hello\n");
	struct hub_user supports;
	struct adc_message* baseline;
	int ok;

	memset(&supports, 0, sizeof(supports));
	user_support_add(&supports, FOURCC('R', 'T', 'F', '0'));

	baseline = (rich && plain) ? route_rtf0_baseline(rtf0_make_hub(0), rich, plain) : NULL;
	/* Even a client that negotiated RTF0 ends up with the stripped copy. */
	ok = baseline == plain && route_rtf0_variant(&supports, baseline, plain) == plain;

	adc_msg_free(rich);
	adc_msg_free(plain);
	return ok;
});

/* Variant selection: the stripped copy goes only to non-RTF0 clients. */
EXO_TEST(rtf0_variant_selection, {
	struct adc_message* rich = adc_msg_create("BMSG AAAB Hello RT1\n");
	struct adc_message* plain = adc_msg_create("BMSG AAAB Hello\n");
	struct hub_user supports, plain_client;
	int ok;

	memset(&supports, 0, sizeof(supports));
	memset(&plain_client, 0, sizeof(plain_client));
	user_support_add(&supports, FOURCC('R', 'T', 'F', '0'));

	ok = rich && plain
	     && route_rtf0_variant(&supports, rich, plain) == rich
	     && route_rtf0_variant(&plain_client, rich, plain) == plain
	     /* No stripped copy (not rich text, or OOM): everyone gets the original. */
	     && route_rtf0_variant(&supports, rich, NULL) == rich
	     && route_rtf0_variant(&plain_client, rich, NULL) == rich;

	adc_msg_free(rich);
	adc_msg_free(plain);
	return ok;
});
