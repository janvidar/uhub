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

EXO_TEST(fuse_render_setup, {
	/* NIJan\sVidar exercises the unescaping: a nick may contain a space. */
	const char* line = "BINF AAAB ID" CID_A " NIJan\\sVidar DEon\\sholiday SS1024 SF7 SL3"
	                   " APuhub VE0.8.0 CT2 SUTCP4,ADCS I4192.0.2.10\n";
	inf = adc_msg_parse(line, strlen(line));

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
	return inf != NULL;
});

EXO_TEST(fuse_render_nick_unescaped, { return render_is("/users/" CID_A "/nick", "Jan Vidar\n"); });
EXO_TEST(fuse_render_description, { return render_is("/users/" CID_A "/description", "on holiday\n"); });
EXO_TEST(fuse_render_share_size, { return render_is("/users/" CID_A "/share_size", "1024\n"); });
EXO_TEST(fuse_render_shared_files, { return render_is("/users/" CID_A "/shared_files", "7\n"); });
EXO_TEST(fuse_render_slots, { return render_is("/users/" CID_A "/slots", "3\n"); });
EXO_TEST(fuse_render_user_agent, { return render_is("/users/" CID_A "/user_agent", "uhub\n"); });
EXO_TEST(fuse_render_version, { return render_is("/users/" CID_A "/version", "0.8.0\n"); });
EXO_TEST(fuse_render_client_type, { return render_is("/users/" CID_A "/client_type", "2\n"); });
EXO_TEST(fuse_render_support, { return render_is("/users/" CID_A "/support", "TCP4,ADCS\n"); });
EXO_TEST(fuse_render_ip, { return render_is("/users/" CID_A "/ip", "192.0.2.10\n"); });
EXO_TEST(fuse_render_sid, { return render_is("/users/" CID_A "/sid", "AAAB\n"); });
EXO_TEST(fuse_render_connected, { return render_is("/users/" CID_A "/connected", "2020-09-13T12:26:40Z\n"); });

/* The raw line, escapes and all, so a reader can get at fields this mount
   does not model. */
EXO_TEST(fuse_render_inf_verbatim, {
	return render_is("/users/" CID_A "/inf",
		"BINF AAAB ID" CID_A " NIJan\\sVidar DEon\\sholiday SS1024 SF7 SL3"
		" APuhub VE0.8.0 CT2 SUTCP4,ADCS I4192.0.2.10\n");
});

/* An absent text field is an empty file; an absent number is zero. */
EXO_TEST(fuse_render_absent_setup, {
	const char* line = "BINF AAAB ID" CID_A "\n";
	bare = adc_msg_parse(line, strlen(line));

	memset(&ctx, 0, sizeof(ctx));
	ctx.inf = bare;
	return bare != NULL;
});

EXO_TEST(fuse_render_absent_text, { return render_is("/users/" CID_A "/description", ""); });
EXO_TEST(fuse_render_absent_numeric, { return render_is("/users/" CID_A "/share_size", "0\n"); });
EXO_TEST(fuse_render_absent_ip, { return render_is("/users/" CID_A "/ip", ""); });

EXO_TEST(fuse_render_no_inf, {
	memset(&ctx, 0, sizeof(ctx));
	return render_is("/users/" CID_A "/nick", "") && render_is("/users/" CID_A "/inf", "");
});

/* ------------------------------------------------------------------- hub/ */

EXO_TEST(fuse_render_hub_reset, {
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
	return 1;
});

EXO_TEST(fuse_render_hub_state_absent, { return render_is("/hub/state", ""); });

EXO_TEST(fuse_render_hub_state, {
	ctx.hub_state = "online";
	return render_is("/hub/state", "online\n");
});

EXO_TEST(fuse_render_hub_name, { return render_is("/hub/name", "Test hub\n"); });
EXO_TEST(fuse_render_hub_users, { return render_is("/hub/users", "42\n"); });
EXO_TEST(fuse_render_hub_address, { return render_is("/hub/address", "adcs://localhost:1511\n"); });
EXO_TEST(fuse_render_hub_sid, { return render_is("/hub/sid", "AAAB\n"); });
EXO_TEST(fuse_render_hub_tls_off, { return render_is("/hub/tls", "no\n"); });

EXO_TEST(fuse_render_hub_tls_on, {
	ctx.tls_version = "TLSv1.3";
	ctx.tls_cipher = "TLS_AES_256_GCM_SHA384";
	return render_is("/hub/tls", "TLSv1.3 TLS_AES_256_GCM_SHA384\n");
});

EXO_TEST(fuse_render_me_nick, { return render_is("/me/nick", "tester\n"); });
EXO_TEST(fuse_render_me_cid, { return render_is("/me/cid", CID_A "\n"); });

/* ------------------------------------------------------- buffer and errors */

EXO_TEST(fuse_render_measures, {
	struct fs_node node;
	fs_node_resolve("/hub/name", &node);
	/* Nothing is written when it does not fit, but the length is still right. */
	return fs_render(&node, &ctx, NULL, 0) == 9;
});

EXO_TEST(fuse_render_short_buffer, {
	struct fs_node node;
	char small[4];
	memset(small, 'x', sizeof(small));
	fs_node_resolve("/hub/name", &node);
	return fs_render(&node, &ctx, small, sizeof(small)) == 9 && small[0] == 'x';
});

EXO_TEST(fuse_render_directory_is_not_a_file, {
	struct fs_node node;
	fs_node_resolve("/hub", &node);
	return fs_render(&node, &ctx, buf, sizeof(buf)) == -1;
});

EXO_TEST(fuse_render_null_node, { return fs_render(NULL, &ctx, buf, sizeof(buf)) == -1; });

EXO_TEST(fuse_render_timestamp_short_buffer, {
	char small[4];
	return fs_render_timestamp(0, small, sizeof(small)) == 0;
});

EXO_TEST(fuse_render_teardown, {
	adc_msg_free(inf);
	adc_msg_free(bare);
	inf = NULL;
	bare = NULL;
	return 1;
});
