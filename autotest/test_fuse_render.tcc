#include "system.h"
#include "util/memory.h"
#include "adc/message.h"
#include "fuse/nodes.h"
#include "fuse/render.h"

#define CID_A "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

static struct adc_message* inf = NULL;
static struct adc_message* bare = NULL;
static struct fs_render_ctx ctx;
static char buf[8192];

/* Render <path> and compare the bytes with <expect>. */
static int render_is(const char* path, const char* expect)
{
	struct fs_node node;
	ssize_t len;

	if (!fs_node_resolve(path, &node))
		return 0;

	len = fs_render(&node, &ctx, buf, sizeof(buf));
	if (len < 0 || (size_t) len >= sizeof(buf))
		return 0;

	buf[len] = '\0';
	return strcmp(buf, expect) == 0;
}

/* The two INFs the user tests render from, parsed once. NIJan\sVidar exercises
   the unescaping: a nick may contain a space. */
EXO_SETUP({
	const char* line = "BINF AAAB ID" CID_A " NIJan\\sVidar DEon\\sholiday SS1024 SF7 SL3"
	                   " APuhub VE0.8.0 CT2 SUTCP4,ADCS I4192.0.2.10\n";
	const char* bare_line = "BINF AAAB ID" CID_A "\n";
	inf = adc_msg_parse(line, strlen(line));
	bare = adc_msg_parse(bare_line, strlen(bare_line));
	return inf != NULL && bare != NULL;
});

EXO_TEARDOWN({
	adc_msg_free(inf);
	adc_msg_free(bare);
	inf = NULL;
	bare = NULL;
	return 1;
});

/*
 * Every test sets the context it renders with, through one of these, so none
 * depends on what the test before it left in ctx.
 */

/* A user with a full INF. */
static void ctx_user(void)
{
	memset(&ctx, 0, sizeof(ctx));
	ctx.inf = inf;
	ctx.sid = 1;
	ctx.since = 1600000000;
	ctx.hub_name = "Test hub";
	ctx.hub_description = "a hub";
	ctx.hub_version = "uhub/0.8.0";
	ctx.hub_address = "adcs://localhost:1511";
	ctx.hub_support = "ADBASE ADTIGR";
	ctx.hub_users = 42;
	ctx.my_sid = 1;
	ctx.my_nick = "tester";
	ctx.my_cid = CID_A;
	ctx.my_support = "ADBASE";
}

EXO_TEST(fuse_render_nick_unescaped, { ctx_user(); return render_is("/users/" CID_A "/nick", "Jan Vidar\n"); });
EXO_TEST(fuse_render_description, { ctx_user(); return render_is("/users/" CID_A "/description", "on holiday\n"); });
EXO_TEST(fuse_render_share_size, { ctx_user(); return render_is("/users/" CID_A "/share_size", "1024\n"); });
EXO_TEST(fuse_render_shared_files, { ctx_user(); return render_is("/users/" CID_A "/shared_files", "7\n"); });
EXO_TEST(fuse_render_slots, { ctx_user(); return render_is("/users/" CID_A "/slots", "3\n"); });
EXO_TEST(fuse_render_user_agent, { ctx_user(); return render_is("/users/" CID_A "/user_agent", "uhub\n"); });
EXO_TEST(fuse_render_version, { ctx_user(); return render_is("/users/" CID_A "/version", "0.8.0\n"); });
EXO_TEST(fuse_render_client_type, { ctx_user(); return render_is("/users/" CID_A "/client_type", "2\n"); });
EXO_TEST(fuse_render_support, { ctx_user(); return render_is("/users/" CID_A "/support", "TCP4,ADCS\n"); });
EXO_TEST(fuse_render_ip, { ctx_user(); return render_is("/users/" CID_A "/ip", "192.0.2.10\n"); });
EXO_TEST(fuse_render_sid, { ctx_user(); return render_is("/users/" CID_A "/sid", "AAAB\n"); });
EXO_TEST(fuse_render_connected, { ctx_user(); return render_is("/users/" CID_A "/connected", "2020-09-13T12:26:40Z\n"); });

/* The raw line, escapes and all, so a reader can get at fields this mount
   does not model. */
EXO_TEST(fuse_render_inf_verbatim, {
	ctx_user();
	return render_is("/users/" CID_A "/inf",
		"BINF AAAB ID" CID_A " NIJan\\sVidar DEon\\sholiday SS1024 SF7 SL3"
		" APuhub VE0.8.0 CT2 SUTCP4,ADCS I4192.0.2.10\n");
});

/* A user whose INF carries nothing but its CID: an absent text field is an
   empty file; an absent number is zero. */
static void ctx_bare(void)
{
	memset(&ctx, 0, sizeof(ctx));
	ctx.inf = bare;
}

EXO_TEST(fuse_render_absent_text, { ctx_bare(); return render_is("/users/" CID_A "/description", ""); });
EXO_TEST(fuse_render_absent_numeric, { ctx_bare(); return render_is("/users/" CID_A "/share_size", "0\n"); });
EXO_TEST(fuse_render_absent_ip, { ctx_bare(); return render_is("/users/" CID_A "/ip", ""); });

EXO_TEST(fuse_render_no_inf, {
	memset(&ctx, 0, sizeof(ctx));
	return render_is("/users/" CID_A "/nick", "") && render_is("/users/" CID_A "/inf", "");
});

/* ------------------------------------------------------------------- hub/ */

/* The hub and this client, with no INF and no TLS. */
static void ctx_hub(void)
{
	memset(&ctx, 0, sizeof(ctx));
	ctx.hub_name = "Test hub";
	ctx.hub_description = "a hub";
	ctx.hub_version = "uhub/0.8.0";
	ctx.hub_address = "adcs://localhost:1511";
	ctx.hub_support = "ADBASE ADTIGR";
	ctx.hub_users = 42;
	ctx.my_sid = 1;
	ctx.my_nick = "tester";
	ctx.my_cid = CID_A;
	ctx.my_support = "ADBASE";
	ctx.my_ip4 = "192.0.2.20";
	ctx.my_ip6 = "";     /* this host has no route to the hub over IPv6 */
}

EXO_TEST(fuse_render_hub_state_absent, { ctx_hub(); return render_is("/hub/state", ""); });

EXO_TEST(fuse_render_hub_state, {
	ctx_hub();
	ctx.hub_state = "online";
	return render_is("/hub/state", "online\n");
});

EXO_TEST(fuse_render_hub_name, { ctx_hub(); return render_is("/hub/name", "Test hub\n"); });
EXO_TEST(fuse_render_hub_users, { ctx_hub(); return render_is("/hub/users", "42\n"); });
EXO_TEST(fuse_render_hub_address, { ctx_hub(); return render_is("/hub/address", "adcs://localhost:1511\n"); });
EXO_TEST(fuse_render_hub_sid, { ctx_hub(); return render_is("/hub/sid", "AAAB\n"); });
EXO_TEST(fuse_render_hub_tls_off, { ctx_hub(); return render_is("/hub/tls", "no\n"); });

EXO_TEST(fuse_render_hub_tls_on, {
	ctx_hub();
	ctx.tls_version = "TLSv1.3";
	ctx.tls_cipher = "TLS_AES_256_GCM_SHA384";
	return render_is("/hub/tls", "TLSv1.3 TLS_AES_256_GCM_SHA384\n");
});

EXO_TEST(fuse_render_me_nick, { ctx_hub(); return render_is("/me/nick", "tester\n"); });
EXO_TEST(fuse_render_me_cid, { ctx_hub(); return render_is("/me/cid", CID_A "\n"); });
EXO_TEST(fuse_render_me_ip4, { ctx_hub(); return render_is("/me/ip4", "192.0.2.20\n"); });

/* A family with no route to the hub renders as an empty file, not as a blank
   line: there is no address, and "" is how that is said. */
EXO_TEST(fuse_render_me_ip6_unknown, { ctx_hub(); return render_is("/me/ip6", ""); });

EXO_TEST(fuse_render_me_ip6, {
	ctx_hub();
	ctx.my_ip6 = "2001:db8::20";
	return render_is("/me/ip6", "2001:db8::20\n");
});

/* ------------------------------------------------------- buffer and errors */

EXO_TEST(fuse_render_measures, {
	ctx_hub();
	struct fs_node node;
	fs_node_resolve("/hub/name", &node);
	/* Nothing is written when it does not fit, but the length is still right. */
	return fs_render(&node, &ctx, NULL, 0) == 9;
});

EXO_TEST(fuse_render_short_buffer, {
	ctx_hub();
	struct fs_node node;
	char small[4];
	memset(small, 'x', sizeof(small));
	fs_node_resolve("/hub/name", &node);
	return fs_render(&node, &ctx, small, sizeof(small)) == 9 && small[0] == 'x';
});

EXO_TEST(fuse_render_directory_is_not_a_file, {
	ctx_hub();
	struct fs_node node;
	fs_node_resolve("/hub", &node);
	return fs_render(&node, &ctx, buf, sizeof(buf)) == -1;
});

EXO_TEST(fuse_render_null_node, { return fs_render(NULL, &ctx, buf, sizeof(buf)) == -1; });

EXO_TEST(fuse_render_timestamp_short_buffer, {
	char small[4];
	return fs_render_timestamp(0, small, sizeof(small)) == 0;
});
