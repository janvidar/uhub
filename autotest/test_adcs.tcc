#include "util/memory.h"
#include "adc/message.h"
#include "core/config.h"
#include "core/hub.h"
#include "core/route.h"
#include "core/user.h"

/*
 * ADCS compatibility mode (adcs_translate).
 *
 * The encrypted client-to-client extension has two names -- ADCS as ADC-EXT
 * settled on it, ADC0 as its draft called it -- and two matching protocol
 * versions, ADCS/1.0 and ADCS/0.10. A client recognises the one it announced
 * and no other, so with the mode enabled the hub puts the protocol field of
 * every relayed connect request, and of the status message refusing one, into
 * the spelling its recipient announced.
 *
 * The decision itself is tested by driving route_adcs_translate() directly;
 * the relay section at the end of this file then routes real messages to a
 * real send queue, so the wiring is established as well as the rule.
 */

static struct hub_info adcs_hub;
static struct hub_config adcs_config;

static struct hub_info* adcs_make_hub(int translate_enabled)
{
	memset(&adcs_hub, 0, sizeof(adcs_hub));
	memset(&adcs_config, 0, sizeof(adcs_config));
	adcs_config.adcs_translate = translate_enabled;
	adcs_hub.config = &adcs_config;
	return &adcs_hub;
}

/* A recipient announcing the given spellings of the extension. */
static void adcs_make_user(struct hub_user* user, int spec, int draft)
{
	memset(user, 0, sizeof(*user));
	user->id.sid = 2; /* "AAAC" */
	if (spec)
		user_support_add(user, FOURCC('A', 'D', 'C', 'S'));
	if (draft)
		user_support_add(user, FOURCC('A', 'D', 'C', '0'));
}

/**
 * Relay one message to a recipient announcing the given spellings and compare
 * what it is handed against the expected wire form.
 *
 * @param expected the translated message, or NULL if the original should go out
 *                 untouched (which route_adcs_translate() signals by returning
 *                 no copy at all).
 */
static int adcs_translates_to(const char* line, int spec, int draft, const char* expected)
{
	struct hub_user sender;
	struct hub_user target;
	struct adc_message* msg;
	struct adc_message* out;
	int ok;

	memset(&sender, 0, sizeof(sender));
	sender.id.sid = 1; /* "AAAB" */
	adcs_make_user(&target, spec, draft);

	msg = adc_msg_parse_verify(&sender, line, strlen(line));
	if (!msg)
		return 0;

	out = route_adcs_translate(adcs_make_hub(1), &target, msg);

	if (!expected)
		ok = (out == NULL);
	else
		ok = out && strcmp(out->cache, expected) == 0;

	if (!ok)
		printf("translate mismatch: got '%s', expected '%s'\n",
		       out ? out->cache : "(no copy)", expected ? expected : "(no copy)");

	/* Translating must never disturb the message the sender sent. */
	if (ok && strcmp(msg->cache, line) != 0)
	{
		printf("original was modified: '%s'\n", msg->cache);
		ok = 0;
	}

	adc_msg_free(out);
	adc_msg_free(msg);
	return ok;
}

/* The support flags are tracked apart: ADC0 is not ADCS. */
EXO_TEST(adcs_support_flags_are_distinct, {
	struct hub_user spec, draft;
	adcs_make_user(&spec, 1, 0);
	adcs_make_user(&draft, 0, 1);
	return user_flag_get(&spec, feature_adcs) != 0
	    && user_flag_get(&spec, feature_adc0) == 0
	    && user_flag_get(&draft, feature_adc0) != 0
	    && user_flag_get(&draft, feature_adcs) == 0;
});

/*
 * A client that knows only the draft is told about the connection in the draft's
 * words -- which is the whole point: answered with ADCS/1.0 it reads a protocol
 * it has never heard of and refuses the transfer it was offered.
 */
EXO_TEST(adcs_ctm_to_a_draft_client, {
	return adcs_translates_to("DCTM AAAB AAAC ADCS/1.0 1412 job1\n", 0, 1,
	                          "DCTM AAAB AAAC ADCS/0.10 1412 job1\n");
});

/* And the other way round, which is the same rule read backwards. */
EXO_TEST(adcs_ctm_to_a_spec_client, {
	return adcs_translates_to("DCTM AAAB AAAC ADCS/0.10 1412 job1\n", 1, 0,
	                          "DCTM AAAB AAAC ADCS/1.0 1412 job1\n");
});

/* Every connect request carries the field, and all four are relayed. */
EXO_TEST(adcs_rcm_is_translated, {
	return adcs_translates_to("DRCM AAAB AAAC ADCS/1.0 job1\n", 0, 1,
	                          "DRCM AAAB AAAC ADCS/0.10 job1\n");
});
EXO_TEST(adcs_nat_is_translated, {
	return adcs_translates_to("DNAT AAAB AAAC ADCS/1.0 1412 job1\n", 0, 1,
	                          "DNAT AAAB AAAC ADCS/0.10 1412 job1\n");
});
EXO_TEST(adcs_rnt_is_translated, {
	return adcs_translates_to("DRNT AAAB AAAC ADCS/0.10 1412 job1\n", 1, 0,
	                          "DRNT AAAB AAAC ADCS/1.0 1412 job1\n");
});

/*
 * And the status message refusing one, where the protocol is the "PR" field
 * rather than the first argument: a client matches the refusal against the
 * request it made, so it has to arrive in the same words the request did.
 */
EXO_TEST(adcs_sta_pr_is_translated, {
	return adcs_translates_to("DSTA AAAB AAAC 141 Protocol\\sunsupported TOjob1 PRADCS/1.0\n", 0, 1,
	                          "DSTA AAAB AAAC 141 Protocol\\sunsupported TOjob1 PRADCS/0.10\n");
});

/* A client that reads both spellings needs no help, and gets what was sent. */
EXO_TEST(adcs_a_client_that_knows_both_is_left_alone, {
	return adcs_translates_to("DCTM AAAB AAAC ADCS/1.0 1412 job1\n", 1, 1, NULL)
	    && adcs_translates_to("DCTM AAAB AAAC ADCS/0.10 1412 job1\n", 1, 1, NULL);
});

/*
 * Nor is a client that announced no encryption at all translated for: there is
 * nothing to translate to, and picking a spelling for it would be guessing.
 */
EXO_TEST(adcs_a_client_that_announced_neither_is_left_alone, {
	return adcs_translates_to("DCTM AAAB AAAC ADCS/1.0 1412 job1\n", 0, 0, NULL);
});

/* Already in the recipient's words: no copy, no rewrite. */
EXO_TEST(adcs_matching_spelling_is_left_alone, {
	return adcs_translates_to("DCTM AAAB AAAC ADCS/1.0 1412 job1\n", 1, 0, NULL)
	    && adcs_translates_to("DCTM AAAB AAAC ADCS/0.10 1412 job1\n", 0, 1, NULL);
});

/*
 * Plain ADC is not touched. Rewriting it would be the hub offering encryption
 * on the sender's behalf, to an end that never asked for it and may have no
 * certificate to answer with.
 */
EXO_TEST(adcs_plain_adc_is_never_translated, {
	return adcs_translates_to("DCTM AAAB AAAC ADC/1.0 1412 job1\n", 0, 1, NULL)
	    && adcs_translates_to("DCTM AAAB AAAC ADC/1.0 1412 job1\n", 1, 0, NULL);
});

/* And neither is a protocol that is neither of ours, which is the boundary. */
EXO_TEST(adcs_an_unknown_protocol_is_never_translated, {
	return adcs_translates_to("DCTM AAAB AAAC ADCS/9.9 1412 job1\n", 0, 1, NULL)
	    && adcs_translates_to("DCTM AAAB AAAC ADCS 1412 job1\n", 0, 1, NULL);
});

/* Messages that carry no protocol field are not connect requests. */
EXO_TEST(adcs_other_commands_are_left_alone, {
	return adcs_translates_to("DMSG AAAB AAAC ADCS/1.0\n", 0, 1, NULL)
	    && adcs_translates_to("DRES AAAB AAAC FNfile TR4dl ADCS/1.0\n", 0, 1, NULL);
});

/* A refusal that names no protocol has nothing to rewrite. */
EXO_TEST(adcs_sta_without_pr_is_left_alone, {
	return adcs_translates_to("DSTA AAAB AAAC 141 Protocol\\sunsupported TOjob1\n", 0, 1, NULL);
});

/* Off by default: with the mode disabled nothing is rewritten for anyone. */
EXO_TEST(adcs_translation_is_opt_in, {
	struct hub_user sender, target;
	struct adc_message* msg;
	struct adc_message* out;
	const char* line = "DCTM AAAB AAAC ADCS/1.0 1412 job1\n";

	memset(&sender, 0, sizeof(sender));
	sender.id.sid = 1;
	adcs_make_user(&target, 0, 1);

	msg = adc_msg_parse_verify(&sender, line, strlen(line));
	if (!msg)
		return 0;

	out = route_adcs_translate(adcs_make_hub(0), &target, msg);
	adc_msg_free(msg);

	if (out)
	{
		adc_msg_free(out);
		return 0;
	}
	return 1;
});

/*
 * The underlying edit: a positional argument is replaced where it stands, and
 * the arguments around it survive a replacement of a different length in either
 * direction. adc_msg_replace_named_argument() cannot be used here because it
 * moves the field it rewrites to the end, and position is what identifies the
 * protocol field of a CTM.
 */
static int adcs_replaces_to(const char* line, int offset, const char* with, const char* expected)
{
	struct adc_message* msg = adc_msg_create(line);
	int ok;

	if (!msg)
		return 0;

	ok = (adc_msg_replace_argument(msg, offset, with) == 0)
	     && strcmp(msg->cache, expected) == 0;

	if (!ok)
		printf("replace mismatch: got '%s', expected '%s'\n", msg->cache, expected);

	adc_msg_free(msg);
	return ok;
}

EXO_TEST(adcs_replace_argument_longer, {
	return adcs_replaces_to("DCTM AAAB AAAC ADCS/1.0 1412 job1\n", 0, "ADCS/0.10",
	                        "DCTM AAAB AAAC ADCS/0.10 1412 job1\n");
});
EXO_TEST(adcs_replace_argument_shorter, {
	return adcs_replaces_to("DCTM AAAB AAAC ADCS/0.10 1412 job1\n", 0, "ADCS/1.0",
	                        "DCTM AAAB AAAC ADCS/1.0 1412 job1\n");
});
EXO_TEST(adcs_replace_argument_same_length, {
	return adcs_replaces_to("DCTM AAAB AAAC ADCS/1.0 1412 job1\n", 0, "ADCS/2.0",
	                        "DCTM AAAB AAAC ADCS/2.0 1412 job1\n");
});
EXO_TEST(adcs_replace_middle_argument, {
	return adcs_replaces_to("DCTM AAAB AAAC ADCS/1.0 1412 job1\n", 1, "65535",
	                        "DCTM AAAB AAAC ADCS/1.0 65535 job1\n");
});
EXO_TEST(adcs_replace_last_argument, {
	return adcs_replaces_to("DCTM AAAB AAAC ADCS/1.0 1412 job1\n", 2, "a\\slonger\\stoken",
	                        "DCTM AAAB AAAC ADCS/1.0 1412 a\\slonger\\stoken\n");
});
EXO_TEST(adcs_replace_the_only_argument, {
	return adcs_replaces_to("DRCM AAAB AAAC ADCS/1.0\n", 0, "ADCS/0.10",
	                        "DRCM AAAB AAAC ADCS/0.10\n");
});

/* An argument that is not there cannot be replaced, and nothing is disturbed. */
EXO_TEST(adcs_replace_missing_argument_fails, {
	struct adc_message* msg = adc_msg_create("DCTM AAAB AAAC ADCS/1.0 1412 job1\n");
	int ok;

	if (!msg)
		return 0;

	ok = (adc_msg_replace_argument(msg, 7, "nope") == -1)
	     && (adc_msg_replace_argument(msg, -1, "nope") == -1)
	     && strcmp(msg->cache, "DCTM AAAB AAAC ADCS/1.0 1412 job1\n") == 0;

	adc_msg_free(msg);
	return ok;
});

/*
 * And the same decision reached through route_message(), which is where it is
 * actually made: what matters to a client is the bytes that land in its send
 * queue, and only the relay path puts them there.
 */

#include "network/network.h"
#include "adc/sid.h"
#include "core/usermanager.h"
#include "testutil_user.h"
#include "testutil_net.h"

static struct hub_info* adcs_relay_hub = 0;
static struct hub_user* adcs_sender = 0;   /* AAAB: announces ADCS */
static struct hub_user* adcs_target = 0;   /* AAAC: announces ADC0 only */
static int adcs_relay_net = 0;             /* holds a test_net_acquire() count */

/** Relay one line from the sender and return what the target was handed. */
static const char* adcs_relayed(const char* line)
{
	struct adc_message* msg;

	tu_queue_clear(adcs_target);

	msg = adc_msg_parse_verify(adcs_sender, line, strlen(line));
	if (!msg)
		return NULL;

	route_message(adcs_relay_hub, adcs_sender, msg);
	adc_msg_free(msg);

	return tu_queue_line(adcs_target, 0);
}

static void adcs_relay_close(void);

/* The relay fixture: a hub with two users on it. Each test clears the target's
   queue before it relays, and a test that changes the hub's config puts it
   back, so one fixture serves the whole file. */
EXO_SETUP({
	if (!test_net_acquire())
		return 0;
	adcs_relay_net = 1;

	adcs_relay_hub = (struct hub_info*) hub_malloc_zero(sizeof(struct hub_info));
	if (!adcs_relay_hub)
		return 0;
	adcs_relay_hub->config = (struct hub_config*) hub_malloc_zero(sizeof(struct hub_config));
	if (!adcs_relay_hub->config)
		return 0;
	config_defaults(adcs_relay_hub->config);
	adcs_relay_hub->config->adcs_translate = 1;
	adcs_relay_hub->users = uman_init(0, 1);
	adcs_relay_hub->write_queue = list_create();

	adcs_sender = tu_user_create(adcs_relay_hub, 1, "sender",
		"AN7ZMSLIEBL53OPTM7WXGSTXUS3XOY6KQS5LBGX", auth_cred_user);
	adcs_target = tu_user_create(adcs_relay_hub, 2, "target",
		"BN7ZMSLIEBL53OPTM7WXGSTXUS3XOY6KQS5LBGX", auth_cred_user);
	if (!adcs_sender || !adcs_target)
		return 0;

	user_support_add(adcs_sender, FOURCC('A', 'D', 'C', 'S'));
	user_support_add(adcs_target, FOURCC('A', 'D', 'C', '0'));

	/* uman_add() fills the nick and CID maps; the SID map is normally filled
	   by the allocation these users skip, and routing a directed message looks
	   the recipient up by SID. */
	if (!sid_pool_insert(adcs_relay_hub->users->sids, adcs_sender->id.sid, adcs_sender)
		|| !sid_pool_insert(adcs_relay_hub->users->sids, adcs_target->id.sid, adcs_target))
		return 0;

	uman_add(adcs_relay_hub->users, adcs_sender);
	uman_add(adcs_relay_hub->users, adcs_target);

	return uman_get_user_by_sid(adcs_relay_hub->users, adcs_target->id.sid) == adcs_target
		&& adcs_relay_hub->write_queue != 0;
});

/* The connect request arrives in the recipient's spelling ... */
EXO_TEST(adcs_relay_translates_a_connect_request, {
	const char* got = adcs_relayed("DCTM AAAB AAAC ADCS/1.0 1412 job1\n");
	return got && strcmp(got, "DCTM AAAB AAAC ADCS/0.10 1412 job1\n") == 0;
});

/* ... and so does the refusal, so the two can be matched up by token. */
EXO_TEST(adcs_relay_translates_a_refusal, {
	const char* got = adcs_relayed("DSTA AAAB AAAC 141 Nope TOjob1 PRADCS/1.0\n");
	return got && strcmp(got, "DSTA AAAB AAAC 141 Nope TOjob1 PRADCS/0.10\n") == 0;
});

/* Ordinary traffic is relayed untouched, and pays for no copy. */
EXO_TEST(adcs_relay_leaves_other_messages_alone, {
	const char* got = adcs_relayed("DMSG AAAB AAAC Hello\n");
	return got && strcmp(got, "DMSG AAAB AAAC Hello\n") == 0;
});

/* With the mode off the recipient gets exactly what the sender sent. */
EXO_TEST(adcs_relay_is_opt_in, {
	const char* got;
	adcs_relay_hub->config->adcs_translate = 0;
	got = adcs_relayed("DCTM AAAB AAAC ADCS/1.0 1412 job1\n");
	adcs_relay_hub->config->adcs_translate = 1;
	return got && strcmp(got, "DCTM AAAB AAAC ADCS/1.0 1412 job1\n") == 0;
});

EXO_TEARDOWN({
	adcs_relay_close();
	return 1;
});

/* Undoes as much of the set-up as got done, so a set-up that failed halfway
   does not leave the network acquired or the hub allocated. */
static void adcs_relay_close(void)
{
	if (adcs_relay_hub && adcs_relay_hub->users)
	{
		struct hub_user* users[2] = { adcs_sender, adcs_target };
		size_t n;
		for (n = 0; n < 2; n++)
		{
			if (!users[n])
				continue;
			if (uman_get_user_by_sid(adcs_relay_hub->users, users[n]->id.sid) == users[n])
			{
				sid_free(adcs_relay_hub->users->sids, users[n]->id.sid);
				uman_remove(adcs_relay_hub->users, users[n]);
			}
			tu_user_destroy(users[n]);
		}
		uman_shutdown(adcs_relay_hub->users);
	}
	adcs_sender = adcs_target = 0;
	if (adcs_relay_hub)
	{
		if (adcs_relay_hub->write_queue)
			list_destroy(adcs_relay_hub->write_queue);
		if (adcs_relay_hub->config)
		{
			free_config(adcs_relay_hub->config);
			hub_free(adcs_relay_hub->config);
		}
		hub_free(adcs_relay_hub);
		adcs_relay_hub = 0;
	}
	if (adcs_relay_net)
		test_net_release();
	adcs_relay_net = 0;
}
