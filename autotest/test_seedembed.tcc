#include "system.h"
#include "seeder/embed.h"

/* Three distinct, well formed base32 tiger tree roots. */
#define SEED_TTH_A "5FR2HYQVGRDLKZ7BEBWMHFVXBHTIVJYQBFY4MOY"
#define SEED_TTH_B "QQ4KJ7NM2XHVBWTYW4CN3PZFV6UJVN2DBLQ5A5A"
#define SEED_TTH_C "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

/* The destination of an embed, up to but not including the TTH. Tests spell the
   closing ']' of the label themselves, since that is what decides inline_image. */
#define SEED_MAGNET "(magnet:?xt=urn:tree:tiger:"

static struct seed_embed seed_out[8];
static char seed_text[8192];

/**
 * Scan into the shared output array, poisoning it first so that a test can tell
 * a fully written entry from a stale one -- in particular, the string fields
 * have to be NUL terminated by the scanner itself.
 */
static size_t seed_scan(const char* text, size_t max)
{
	memset(seed_out, 0xAA, sizeof(seed_out));
	return seed_scan_message(text, seed_out, max);
}

/* Compare entry n against the expected values. Only valid for entries the
   scanner reported as written. */
static int seed_check(size_t n, const char* tth, uint64_t size, const char* name, const char* mime, int inline_image)
{
	struct seed_embed* e = &seed_out[n];
	return (strcmp(e->tth, tth) == 0 &&
		e->size == size &&
		strcmp(e->name, name) == 0 &&
		strcmp(e->mime, mime) == 0 &&
		e->inline_image == inline_image);
}

/* Build a message in the shared buffer. */
static const char* seed_fmt(const char* prefix, const char* tth, const char* suffix)
{
	snprintf(seed_text, sizeof(seed_text), "%s%s%s", prefix, tth, suffix);
	return seed_text;
}

/* The two examples from the RTF0 documentation. */

EXO_TEST(seed_inline_image, {
	const char* text = "![shot.png]" "(magnet:?xt=urn:tree:tiger:" SEED_TTH_A "&xl=48213&dn=shot.png&mt=image/png)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 48213, "shot.png", "image/png", 1);
});

EXO_TEST(seed_attachment, {
	const char* text = "[report.pdf]" "(magnet:?xt=urn:tree:tiger:" SEED_TTH_B "&xl=1048576&dn=report.pdf)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_B, 1048576, "report.pdf", "", 0);
});

EXO_TEST(seed_image_and_attachment, {
	const char* text =
		"see ![shot.png]" "(magnet:?xt=urn:tree:tiger:" SEED_TTH_A "&xl=48213&dn=shot.png&mt=image/png)"
		" and [report.pdf]" "(magnet:?xt=urn:tree:tiger:" SEED_TTH_B "&xl=1048576&dn=report.pdf) ok";
	return seed_scan(text, 8) == 2 &&
		seed_check(0, SEED_TTH_A, 48213, "shot.png", "image/png", 1) &&
		seed_check(1, SEED_TTH_B, 1048576, "report.pdf", "", 0);
});

/* Parameter order is not significant. */

EXO_TEST(seed_param_order_dn_first, {
	const char* text = "![a](magnet:?dn=shot.png&xl=48213&xt=urn:tree:tiger:" SEED_TTH_A "&mt=image/png)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 48213, "shot.png", "image/png", 1);
});

EXO_TEST(seed_param_order_xt_last, {
	const char* text = "[a](magnet:?mt=text/plain&dn=x.txt&xt=urn:tree:tiger:" SEED_TTH_C ")";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_C, 0, "x.txt", "text/plain", 0);
});

/* Optional parameters. */

EXO_TEST(seed_missing_xl, {
	const char* text = "![a]" SEED_MAGNET SEED_TTH_A "&dn=a.png&mt=image/png)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "a.png", "image/png", 1);
});

EXO_TEST(seed_missing_dn, {
	const char* text = "![a]" SEED_MAGNET SEED_TTH_A "&xl=17&mt=image/png)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 17, "", "image/png", 1);
});

EXO_TEST(seed_missing_mt, {
	const char* text = "![a]" SEED_MAGNET SEED_TTH_A "&xl=17&dn=a.png)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 17, "a.png", "", 1);
});

EXO_TEST(seed_xt_only, {
	const char* text = "[a]" SEED_MAGNET SEED_TTH_A ")";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "", "", 0);
});

EXO_TEST(seed_empty_dn_and_mt, {
	const char* text = "[a]" SEED_MAGNET SEED_TTH_A "&dn=&mt=)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "", "", 0);
});

/* The TTH must be exactly 39 characters from [A-Z2-7]. */

EXO_TEST(seed_tth_38_chars, {
	return seed_scan(seed_fmt("[a]" SEED_MAGNET, "5FR2HYQVGRDLKZ7BEBWMHFVXBHTIVJYQBFY4MO", "&xl=1)"), 8) == 0;
});

EXO_TEST(seed_tth_40_chars, {
	return seed_scan(seed_fmt("[a]" SEED_MAGNET, SEED_TTH_A "Y", "&xl=1)"), 8) == 0;
});

EXO_TEST(seed_tth_empty, { return seed_scan("[a]" SEED_MAGNET ")", 8) == 0; });

EXO_TEST(seed_tth_digit_0, {
	return seed_scan(seed_fmt("[a]" SEED_MAGNET, "0FR2HYQVGRDLKZ7BEBWMHFVXBHTIVJYQBFY4MOY", ")"), 8) == 0;
});

EXO_TEST(seed_tth_digit_1, {
	return seed_scan(seed_fmt("[a]" SEED_MAGNET, "5FR2HYQVGRDLKZ7BEBWMHFVXBHTIVJYQBFY4MO1", ")"), 8) == 0;
});

EXO_TEST(seed_tth_digit_8, {
	return seed_scan(seed_fmt("[a]" SEED_MAGNET, "5FR2HYQVGRDLKZ8BEBWMHFVXBHTIVJYQBFY4MOY", ")"), 8) == 0;
});

EXO_TEST(seed_tth_digit_9, {
	return seed_scan(seed_fmt("[a]" SEED_MAGNET, "5FR2HYQVGRDLKZ9BEBWMHFVXBHTIVJYQBFY4MOY", ")"), 8) == 0;
});

EXO_TEST(seed_tth_lowercase, {
	return seed_scan(seed_fmt("[a]" SEED_MAGNET, "5fr2hyqvgrdlkz7bebwmhfvxbhtivjyqbfy4moy", ")"), 8) == 0;
});

EXO_TEST(seed_tth_mixed_case, {
	return seed_scan(seed_fmt("[a]" SEED_MAGNET, "5FR2HYQVGRDLKZ7BEBWMHFVXBHTIVJYQBFY4MOy", ")"), 8) == 0;
});

EXO_TEST(seed_tth_padding_char, {
	return seed_scan(seed_fmt("[a]" SEED_MAGNET, "5FR2HYQVGRDLKZ7BEBWMHFVXBHTIVJYQBFY4MO=", ")"), 8) == 0;
});

EXO_TEST(seed_xt_wrong_urn, {
	const char* text = "[a](magnet:?xt=urn:bitprint:" SEED_TTH_A ")";
	return seed_scan(text, 8) == 0;
});

EXO_TEST(seed_xt_absent, { return seed_scan("[a](magnet:?xl=5&dn=a.txt)", 8) == 0; });

/* A malformed xt does not stop a well formed one elsewhere in the same url. */
EXO_TEST(seed_xt_bad_then_good, {
	const char* text = "[a](magnet:?xt=urn:tree:tiger:TOOSHORT&xt=urn:tree:tiger:" SEED_TTH_A ")";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "", "", 0);
});

/* xl parsing: a bad length is treated as absent, the embed survives. */

EXO_TEST(seed_xl_non_numeric, {
	const char* text = "[a]" SEED_MAGNET SEED_TTH_A "&xl=12x4&dn=a.txt)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "a.txt", "", 0);
});

EXO_TEST(seed_xl_empty, {
	const char* text = "[a]" SEED_MAGNET SEED_TTH_A "&xl=&dn=a.txt)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "a.txt", "", 0);
});

EXO_TEST(seed_xl_negative, {
	const char* text = "[a]" SEED_MAGNET SEED_TTH_A "&xl=-1)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "", "", 0);
});

EXO_TEST(seed_xl_overflow, {
	const char* text = "[a]" SEED_MAGNET SEED_TTH_A "&xl=18446744073709551616&dn=a.txt)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "a.txt", "", 0);
});

EXO_TEST(seed_xl_way_overflow, {
	const char* text = "[a]" SEED_MAGNET SEED_TTH_A "&xl=99999999999999999999999999999999999999)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "", "", 0);
});

EXO_TEST(seed_xl_uint64_max, {
	const char* text = "[a]" SEED_MAGNET SEED_TTH_A "&xl=18446744073709551615)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, UINT64_MAX, "", "", 0);
});

EXO_TEST(seed_xl_zero, {
	const char* text = "[a]" SEED_MAGNET SEED_TTH_A "&xl=0)";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "", "", 0);
});

/* Non-magnet embeds and plain text. */

EXO_TEST(seed_http_image, { return seed_scan("![alt](http://example.org/x.png)", 8) == 0; });
EXO_TEST(seed_http_link, { return seed_scan("[text](https://example.org/x.pdf)", 8) == 0; });
EXO_TEST(seed_magnet_without_bracket, {
	return seed_scan("magnet:?xt=urn:tree:tiger:" SEED_TTH_A, 8) == 0;
});
EXO_TEST(seed_plain_text, { return seed_scan("hello world, nothing to see here", 8) == 0; });
EXO_TEST(seed_empty_string, { return seed_scan("", 8) == 0; });
EXO_TEST(seed_null_text, { return seed_scan_message(NULL, seed_out, 8) == 0; });

/* Buffer limits. */

EXO_TEST(seed_dn_truncated, {
	char name[600];
	memset(name, 'x', sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	snprintf(seed_text, sizeof(seed_text), "![a]" SEED_MAGNET SEED_TTH_A "&dn=%s&mt=image/png)", name);
	return seed_scan(seed_text, 8) == 1 &&
		strlen(seed_out[0].name) == SEED_EMBED_MAX_NAME - 1 &&
		seed_out[0].name[0] == 'x' &&
		seed_out[0].name[SEED_EMBED_MAX_NAME - 1] == '\0' &&
		strcmp(seed_out[0].mime, "image/png") == 0 &&
		strcmp(seed_out[0].tth, SEED_TTH_A) == 0;
});

EXO_TEST(seed_mt_truncated, {
	char mime[300];
	memset(mime, 'm', sizeof(mime) - 1);
	mime[sizeof(mime) - 1] = '\0';
	snprintf(seed_text, sizeof(seed_text), "[a]" SEED_MAGNET SEED_TTH_A "&mt=%s)", mime);
	return seed_scan(seed_text, 8) == 1 &&
		strlen(seed_out[0].mime) == SEED_EMBED_MAX_MIME - 1 &&
		seed_out[0].mime[SEED_EMBED_MAX_MIME - 1] == '\0';
});

EXO_TEST(seed_dn_exactly_fits, {
	char name[SEED_EMBED_MAX_NAME];
	memset(name, 'y', sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	snprintf(seed_text, sizeof(seed_text), "[a]" SEED_MAGNET SEED_TTH_A "&dn=%s)", name);
	return seed_scan(seed_text, 8) == 1 && strcmp(seed_out[0].name, name) == 0;
});

/* max is respected. */

EXO_TEST(seed_max_respected, {
	const char* text =
		"[a]" SEED_MAGNET SEED_TTH_A ") "
		"[b]" SEED_MAGNET SEED_TTH_B ") "
		"[c]" SEED_MAGNET SEED_TTH_C ")";
	return seed_scan(text, 2) == 2 &&
		strcmp(seed_out[0].tth, SEED_TTH_A) == 0 &&
		strcmp(seed_out[1].tth, SEED_TTH_B) == 0;
});

EXO_TEST(seed_max_exact, {
	const char* text =
		"[a]" SEED_MAGNET SEED_TTH_A ") "
		"[b]" SEED_MAGNET SEED_TTH_B ") "
		"[c]" SEED_MAGNET SEED_TTH_C ")";
	return seed_scan(text, 3) == 3 && strcmp(seed_out[2].tth, SEED_TTH_C) == 0;
});

EXO_TEST(seed_max_one, { return seed_scan("[a]" SEED_MAGNET SEED_TTH_A ") [b]" SEED_MAGNET SEED_TTH_B ")", 1) == 1; });
EXO_TEST(seed_max_zero, { return seed_scan_message("[a]" SEED_MAGNET SEED_TTH_A ")", NULL, 0) == 0; });

/* Duplicates are reported once per occurrence. */
EXO_TEST(seed_duplicate_tth, {
	const char* text = "![a]" SEED_MAGNET SEED_TTH_A ") again [b]" SEED_MAGNET SEED_TTH_A ")";
	return seed_scan(text, 8) == 2 &&
		seed_check(0, SEED_TTH_A, 0, "", "", 1) &&
		seed_check(1, SEED_TTH_A, 0, "", "", 0);
});

/* Where the url ends, and where the label starts. */

EXO_TEST(seed_url_ends_at_space, {
	const char* text = "[a]" SEED_MAGNET SEED_TTH_A " &xl=48213";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "", "", 0);
});

EXO_TEST(seed_url_ends_at_paren, {
	const char* text = "[a]" SEED_MAGNET SEED_TTH_A ")&xl=48213 trailing text";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "", "", 0);
});

EXO_TEST(seed_url_unterminated, {
	const char* text = "[a]" SEED_MAGNET SEED_TTH_A "&dn=a.txt";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "a.txt", "", 0);
});

EXO_TEST(seed_empty_label_inline, {
	const char* text = "![]" SEED_MAGNET SEED_TTH_A ")";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "", "", 1);
});

EXO_TEST(seed_empty_label_link, {
	const char* text = "[]" SEED_MAGNET SEED_TTH_A ")";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "", "", 0);
});

EXO_TEST(seed_bang_only_when_adjacent, {
	const char* text = "! [a]" SEED_MAGNET SEED_TTH_A ")";
	return seed_scan(text, 8) == 1 && seed_out[0].inline_image == 0;
});

EXO_TEST(seed_bang_mid_message, {
	const char* text = "look here ![a]" SEED_MAGNET SEED_TTH_A ")";
	return seed_scan(text, 8) == 1 && seed_out[0].inline_image == 1;
});

/* Brackets inside the label are counted, not matched on sight. */
EXO_TEST(seed_nested_brackets_in_label, {
	const char* text = "![a[b]c]" SEED_MAGNET SEED_TTH_A ")";
	return seed_scan(text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "", "", 1);
});

/* "![a]b](...)" has no unmatched '[' before the anchor, so there is no embed --
   the same reading CommonMark gives it. */
EXO_TEST(seed_unmatched_label, {
	const char* text = "![a]b]" SEED_MAGNET SEED_TTH_A ")";
	return seed_scan(text, 8) == 0;
});

EXO_TEST(seed_no_opening_bracket, {
	const char* text = "]" SEED_MAGNET SEED_TTH_A ")";
	return seed_scan(text, 8) == 0;
});

EXO_TEST(seed_newline_before_label, {
	const char* text = "[a\n]" SEED_MAGNET SEED_TTH_A ")";
	return seed_scan(text, 8) == 0;
});

EXO_TEST(seed_label_on_previous_line, {
	const char* text = "[a\nb]" SEED_MAGNET SEED_TTH_A ")";
	return seed_scan(text, 8) == 0;
});

EXO_TEST(seed_second_line_embed, {
	const char* text = "line one\n![a]" SEED_MAGNET SEED_TTH_A ")";
	return seed_scan(text, 8) == 1 && seed_out[0].inline_image == 1;
});

/* Pathological input: none of these may read out of bounds or crash. */

EXO_TEST(seed_trunc_bracket_paren, { return seed_scan("](", 8) == 0; });
EXO_TEST(seed_trunc_magnet, { return seed_scan("](magnet:?", 8) == 0; });
EXO_TEST(seed_trunc_magnet_labelled, { return seed_scan("[a](magnet:?", 8) == 0; });
EXO_TEST(seed_trunc_xt, { return seed_scan("](magnet:?xt=urn:tree:tiger:", 8) == 0; });
EXO_TEST(seed_trunc_xt_labelled, { return seed_scan("[a](magnet:?xt=urn:tree:tiger:", 8) == 0; });
EXO_TEST(seed_trunc_magnet_prefix, { return seed_scan("](magnet:", 8) == 0; });
EXO_TEST(seed_lone_bang, { return seed_scan("!", 8) == 0; });
EXO_TEST(seed_lone_bracket_open, { return seed_scan("[", 8) == 0; });
EXO_TEST(seed_lone_bracket_close, { return seed_scan("]", 8) == 0; });
EXO_TEST(seed_bang_bracket, { return seed_scan("![", 8) == 0; });
EXO_TEST(seed_paren_at_end, { return seed_scan("![a](", 8) == 0; });
EXO_TEST(seed_ampersands_only, { return seed_scan("[a](magnet:?&&&&&&&&)", 8) == 0; });
EXO_TEST(seed_equals_only, { return seed_scan("[a](magnet:?=&=&=)", 8) == 0; });
EXO_TEST(seed_xt_prefix_only, { return seed_scan("[a](magnet:?xt=)", 8) == 0; });

EXO_TEST(seed_500_open_brackets, {
	memset(seed_text, '[', 500);
	seed_text[500] = '\0';
	return seed_scan(seed_text, 8) == 0;
});

EXO_TEST(seed_4096_open_brackets, {
	memset(seed_text, '[', 4096);
	seed_text[4096] = '\0';
	return seed_scan(seed_text, 8) == 0;
});

EXO_TEST(seed_4096_close_brackets, {
	memset(seed_text, ']', 4096);
	seed_text[4096] = '\0';
	return seed_scan(seed_text, 8) == 0;
});

EXO_TEST(seed_500_brackets_then_embed, {
	memset(seed_text, '[', 500);
	seed_text[500] = '\0';
	strncat(seed_text, "]" SEED_MAGNET SEED_TTH_A ")", sizeof(seed_text) - 501);
	return seed_scan(seed_text, 8) == 1 && seed_check(0, SEED_TTH_A, 0, "", "", 0);
});

EXO_TEST(seed_repeated_anchors, {
	size_t i;
	seed_text[0] = '\0';
	for (i = 0; i < 300; i++)
		strncat(seed_text, "](magnet:?", sizeof(seed_text) - strlen(seed_text) - 1);
	return seed_scan(seed_text, 8) == 0;
});

EXO_TEST(seed_control_bytes, {
	const char* text = "\x01\x02![\x7f\x1b]" SEED_MAGNET SEED_TTH_A "&dn=\x01\x02\x03)";
	return seed_scan(text, 8) == 1 &&
		strcmp(seed_out[0].tth, SEED_TTH_A) == 0 &&
		strcmp(seed_out[0].name, "\x01\x02\x03") == 0 &&
		seed_out[0].inline_image == 1;
});

EXO_TEST(seed_high_bytes_in_dn, {
	const char* text = "[a]" SEED_MAGNET SEED_TTH_A "&dn=\xc3\xa6\xc3\xb8\xc3\xa5)";
	return seed_scan(text, 8) == 1 && strcmp(seed_out[0].name, "\xc3\xa6\xc3\xb8\xc3\xa5") == 0;
});

EXO_TEST(seed_magnet_inside_label, {
	/* The url of the first embed swallows the rest of the line, so the well
	   formed magnet nested inside it is not reported separately. */
	const char* text = "[a](magnet:?xt=bogus]" SEED_MAGNET SEED_TTH_A ")";
	return seed_scan(text, 8) == 0;
});
