#include "system.h"
#include "seeder/post.h"

/* Well formed, distinct base32 roots. A CID has the same shape as a TTH. */
#define POST_CID  "IPJJWEPPPLCA3PF2ZCRRYO4F2ZX2EV2JMW2KC3I"
#define POST_TTH  "KX3TQ7ZVN5PLQGKD3NDBK6ZTZG5PYQXSNMFYVJH"
#define POST_TTH2 "5FR2HYQVGRDLKZ7BEBWMHFVXBHTIVJYQBFY4MOY"

static struct seed_post pd_post;
static enum seed_post_error pd_error;
static char pd_doc[16384];

/* Parse a NUL terminated document, poisoning the output first so a test can
   tell a written field from a stale one. */
static int pd_parse(const char* doc)
{
	memset(&pd_post, 0xAA, sizeof(pd_post));
	pd_error = SEED_POST_OK;
	return seed_post_parse(doc, strlen(doc), &pd_post, &pd_error);
}

/* Parse an explicit byte range, for documents carrying a NUL or no terminator. */
static int pd_parse_len(const char* doc, size_t len)
{
	memset(&pd_post, 0xAA, sizeof(pd_post));
	pd_error = SEED_POST_OK;
	return seed_post_parse(doc, len, &pd_post, &pd_error);
}

static const char* pd_fmt(const char* header, const char* body)
{
	snprintf(pd_doc, sizeof(pd_doc), "%s\n%s", header, body);
	return pd_doc;
}

/* ------------------------------------------------------------ the happy path */

/* The example from the BBS0 specification: a post that starts a thread. */
EXO_TEST(seedpost_thread_root, {
	const char* doc = pd_fmt("IBB0 ID" POST_CID " SJHub\\supgrade\\son\\sSaturday DA1786439000",
		"The hub goes down at 0200 UTC.\n");
	int ok = pd_parse(doc);
	if (ok)
		ok = strcmp(pd_post.author_cid, POST_CID) == 0;
	if (ok)
		ok = strcmp(pd_post.subject, "Hub upgrade on Saturday") == 0;
	if (ok)
		ok = pd_post.parent[0] == '\0' && pd_post.composed == 1786439000 && pd_post.rich_text == 0;
	return ok;
});

/* A reply names its parent, and may omit the subject. */
EXO_TEST(seedpost_reply, {
	const char* doc = pd_fmt("IBB0 ID" POST_CID " PA" POST_TTH, "Thanks for the notice.\n");
	int ok = pd_parse(doc);
	if (ok)
		ok = strcmp(pd_post.parent, POST_TTH) == 0 && pd_post.subject[0] == '\0';
	return ok;
});

/* The body begins one byte past the LF, and is every byte after it. */
EXO_TEST(seedpost_body_offset, {
	const char* header = "IBB0 ID" POST_CID " SJx";
	const char* doc = pd_fmt(header, "abc");
	int ok = pd_parse(doc);
	if (ok)
		ok = pd_post.body_offset == strlen(header) + 1 && pd_post.body_length == 3;
	return ok;
});

/* An empty body is a legal post: the body is *OCTET. */
EXO_TEST(seedpost_empty_body, {
	int ok = pd_parse("IBB0 ID" POST_CID " SJhi\n");
	if (ok)
		ok = pd_post.body_length == 0;
	return ok;
});

/* RT1 marks the body as rich text; any other value is reserved and read as
   plain text rather than rejected. */
EXO_TEST(seedpost_rich_text_flag, {
	int ok = pd_parse(pd_fmt("IBB0 ID" POST_CID " SJx RT1", "hi")) && pd_post.rich_text == 1;
	if (ok)
		ok = pd_parse(pd_fmt("IBB0 ID" POST_CID " SJx RT2", "hi")) && pd_post.rich_text == 0;
	return ok;
});

/* An unrecognised parameter is ignored, and must not be a reason to reject.
   SG and KY are reserved for a future extension and are exactly this case. */
EXO_TEST(seedpost_unknown_field_ignored, {
	return pd_parse(pd_fmt("IBB0 ID" POST_CID " SJx SGsomething", "hi"));
});

EXO_TEST(seedpost_reserved_ky_ignored, {
	return pd_parse(pd_fmt("IBB0 ID" POST_CID " SJx KYkeymaterial", "hi"));
});

/* ------------------------------------------------------------- the header bound */

/* No LF at all: the header has to be bounded before the file is read. */
EXO_TEST(seedpost_no_terminator, {
	return pd_parse("IBB0 ID" POST_CID " SJno newline here") == 0
		&& pd_error == SEED_POST_ERR_NO_HEADER;
});

/* An LF beyond the 8192 byte bound does not count as one. */
EXO_TEST(seedpost_header_too_long, {
	size_t i;
	pd_doc[0] = '\0';
	strcat(pd_doc, "IBB0 ID" POST_CID " SJ");
	for (i = strlen(pd_doc); i < SEED_POST_HEADER_MAX + 16; i++)
		pd_doc[i] = 'x';
	pd_doc[i] = '\n';
	pd_doc[i + 1] = '\0';
	return pd_parse(pd_doc) == 0 && pd_error == SEED_POST_ERR_NO_HEADER;
});

/*
 * An LF exactly at the bound is still a header. The padding goes into a
 * trailing unrecognised parameter rather than into the subject, which has a
 * bound of its own and would otherwise be what the test tripped over.
 */
EXO_TEST(seedpost_header_at_bound, {
	size_t used;
	snprintf(pd_doc, sizeof(pd_doc), "IBB0 ID" POST_CID " SJx ZZ");
	used = strlen(pd_doc);
	memset(pd_doc + used, 'x', SEED_POST_HEADER_MAX - 1 - used);
	pd_doc[SEED_POST_HEADER_MAX - 1] = '\n';
	pd_doc[SEED_POST_HEADER_MAX] = '\0';
	return pd_parse(pd_doc) == 1;
});

/* -------------------------------------------------------------- the FOURCC */

EXO_TEST(seedpost_wrong_fourcc, {
	return pd_parse("IBB1 ID" POST_CID "\n") == 0 && pd_error == SEED_POST_ERR_FOURCC;
});

EXO_TEST(seedpost_not_an_i_message, {
	return pd_parse("BBB0 ID" POST_CID "\n") == 0 && pd_error == SEED_POST_ERR_FOURCC;
});

EXO_TEST(seedpost_truncated_fourcc, {
	return pd_parse("IB\n") == 0 && pd_error == SEED_POST_ERR_FOURCC;
});

EXO_TEST(seedpost_empty_document, {
	return seed_post_parse("", 0, &pd_post, &pd_error) == 0
		&& pd_error == SEED_POST_ERR_NO_HEADER;
});

EXO_TEST(seedpost_null_document, {
	return seed_post_parse(NULL, 10, NULL, NULL) == 0;
});

/* ------------------------------------------------------------------- syntax */

/* An unknown escape is refused, as ADC requires of any message carrying one. */
EXO_TEST(seedpost_bad_escape, {
	return pd_parse("IBB0 ID" POST_CID " SJoops\\q\n") == 0
		&& pd_error == SEED_POST_ERR_SYNTAX;
});

/* A CR before the terminating LF is not part of the grammar. */
EXO_TEST(seedpost_cr_before_lf, {
	return pd_parse("IBB0 ID" POST_CID " SJx\r\n") == 0
		&& pd_error == SEED_POST_ERR_SYNTAX;
});

/*
 * A control byte in the header is not printable UTF-8. Tab, CR and LF are
 * deliberately not tested here: ADC's own parser accepts all three as
 * printable, so a document carrying one is refused for another reason or not
 * at all, and that is the message grammar's decision rather than this one's.
 */
EXO_TEST(seedpost_control_byte, {
	return pd_parse("IBB0 ID" POST_CID " SJa\x01b\n") == 0
		&& pd_error == SEED_POST_ERR_SYNTAX;
});

/* ----------------------------------------------------------- canonical form */

/* Two spaces between parameters would parse as an empty argument. */
EXO_TEST(seedpost_double_space, {
	return pd_parse("IBB0 ID" POST_CID "  SJx\n") == 0
		&& pd_error == SEED_POST_ERR_CANONICAL;
});

/* A parameter with no value at all. */
EXO_TEST(seedpost_empty_value, {
	return pd_parse("IBB0 ID" POST_CID " SJ\n") == 0
		&& pd_error == SEED_POST_ERR_CANONICAL;
});

/* No parameter twice, even with the same value. */
EXO_TEST(seedpost_repeated_field, {
	return pd_parse("IBB0 ID" POST_CID " ID" POST_CID " SJx\n") == 0
		&& pd_error == SEED_POST_ERR_CANONICAL;
});

EXO_TEST(seedpost_repeated_subject, {
	return pd_parse("IBB0 ID" POST_CID " SJa SJb\n") == 0
		&& pd_error == SEED_POST_ERR_CANONICAL;
});

/* Recognised parameters come in the order the specification lists them. */
EXO_TEST(seedpost_out_of_order, {
	return pd_parse("IBB0 SJx ID" POST_CID "\n") == 0
		&& pd_error == SEED_POST_ERR_CANONICAL;
});

EXO_TEST(seedpost_rt_before_da, {
	return pd_parse("IBB0 ID" POST_CID " SJx RT1 DA5\n") == 0
		&& pd_error == SEED_POST_ERR_CANONICAL;
});

/* The full field order is accepted. */
EXO_TEST(seedpost_full_order_ok, {
	return pd_parse("IBB0 ID" POST_CID " PA" POST_TTH " SJx DA5 RT1\n") == 1;
});

/* An unrecognised parameter must come after every recognised one. */
EXO_TEST(seedpost_unknown_before_known, {
	return pd_parse("IBB0 ID" POST_CID " ZZjunk SJx\n") == 0
		&& pd_error == SEED_POST_ERR_CANONICAL;
});

/* A trailing space is a parameter with no name. */
EXO_TEST(seedpost_trailing_space, {
	return pd_parse("IBB0 ID" POST_CID " \n") == 0
		&& pd_error == SEED_POST_ERR_CANONICAL;
});

/* A one character parameter is not a named parameter. */
EXO_TEST(seedpost_short_parameter, {
	return pd_parse("IBB0 ID" POST_CID " X\n") == 0
		&& pd_error == SEED_POST_ERR_CANONICAL;
});

/* A newline in the subject: the composer was told not to emit one. */
EXO_TEST(seedpost_newline_in_subject, {
	return pd_parse("IBB0 ID" POST_CID " SJa\\nb\n") == 0
		&& pd_error == SEED_POST_ERR_CANONICAL;
});

/* An escaped space in the subject is ordinary and must survive unescaped. */
EXO_TEST(seedpost_escaped_space_in_subject, {
	int ok = pd_parse("IBB0 ID" POST_CID " SJa\\sb\n");
	if (ok)
		ok = strcmp(pd_post.subject, "a b") == 0;
	return ok;
});

/* --------------------------------------------------------- required fields */

/* ID is required in every post. */
EXO_TEST(seedpost_missing_author, {
	return pd_parse("IBB0 SJx\n") == 0 && pd_error == SEED_POST_ERR_MISSING;
});

/* SJ is required in a post that starts a thread, and optional in a reply. */
EXO_TEST(seedpost_thread_root_needs_subject, {
	return pd_parse("IBB0 ID" POST_CID "\n") == 0 && pd_error == SEED_POST_ERR_MISSING;
});

/* --------------------------------------------------------- malformed fields */

EXO_TEST(seedpost_author_not_base32, {
	return pd_parse("IBB0 IDnot-base32 SJx\n") == 0 && pd_error == SEED_POST_ERR_FIELD;
});

EXO_TEST(seedpost_author_too_long, {
	return pd_parse("IBB0 ID" POST_CID "AAAA SJx\n") == 0 && pd_error == SEED_POST_ERR_FIELD;
});

/*
 * A CID is base32 but is not fixed at 39 characters -- its length follows the
 * session hash -- so a shorter one is accepted where a TTH would not be.
 */
EXO_TEST(seedpost_short_author_accepted, {
	return pd_parse("IBB0 IDAAAA SJx\n") == 1;
});

/* A parent is a TTH, and a TTH is exactly 39 base32 characters. */
EXO_TEST(seedpost_parent_wrong_length, {
	return pd_parse("IBB0 ID" POST_CID " PAAAAA\n") == 0 && pd_error == SEED_POST_ERR_FIELD;
});

EXO_TEST(seedpost_parent_not_base32, {
	return pd_parse("IBB0 ID" POST_CID " PA1111111111111111111111111111111111111\n") == 0
		&& pd_error == SEED_POST_ERR_FIELD;
});

EXO_TEST(seedpost_composed_not_a_number, {
	return pd_parse("IBB0 ID" POST_CID " SJx DAtomorrow\n") == 0
		&& pd_error == SEED_POST_ERR_FIELD;
});

EXO_TEST(seedpost_rich_text_not_a_number, {
	return pd_parse("IBB0 ID" POST_CID " SJx RTyes\n") == 0
		&& pd_error == SEED_POST_ERR_FIELD;
});

/* An oversized subject is refused rather than truncated: a truncated subject
   is a different subject. */
EXO_TEST(seedpost_subject_too_long, {
	size_t i;
	snprintf(pd_doc, sizeof(pd_doc), "IBB0 ID" POST_CID " SJ");
	i = strlen(pd_doc);
	memset(pd_doc + i, 'x', SEED_POST_SUBJECT_MAX + 8);
	pd_doc[i + SEED_POST_SUBJECT_MAX + 8] = '\n';
	pd_doc[i + SEED_POST_SUBJECT_MAX + 9] = '\0';
	return pd_parse(pd_doc) == 0 && pd_error == SEED_POST_ERR_FIELD;
});

/* ---------------------------------------------------------------- attachments */

#define POST_MAGNET(tth, extra) "(magnet:?xt=urn:tree:tiger:" tth extra ")"

static struct seed_embed pd_att[SEED_POST_MAX_ATTACHMENTS];

static size_t pd_attachments(const char* doc)
{
	memset(pd_att, 0xAA, sizeof(pd_att));
	return seed_post_attachments(doc, strlen(doc), &pd_post, pd_att, SEED_POST_MAX_ATTACHMENTS);
}

/* An RT1 body carries attachments as ordinary RTF0 magnet embeds. */
EXO_TEST(seedpost_attachment_found, {
	const char* doc = pd_fmt("IBB0 ID" POST_CID " SJx RT1",
		"See ![plan.png]" POST_MAGNET(POST_TTH, "&xl=48213&dn=plan.png") " for details.");
	int ok = pd_parse(doc) && pd_post.rich_text == 1;
	if (ok)
		ok = pd_attachments(doc) == 1;
	if (ok)
		ok = strcmp(pd_att[0].tth, POST_TTH) == 0 && pd_att[0].size == 48213;
	return ok;
});

/* A plain text body displays literally, so a magnet in one is text the author
   typed and not a reference to act on. */
EXO_TEST(seedpost_no_attachments_without_rt1, {
	const char* doc = pd_fmt("IBB0 ID" POST_CID " SJx",
		"See ![plan.png]" POST_MAGNET(POST_TTH, "&xl=1") ".");
	int ok = pd_parse(doc) && pd_post.rich_text == 0;
	if (ok)
		ok = pd_attachments(doc) == 0;
	return ok;
});

/* A plain link, not just an inline image, is an attachment too. */
EXO_TEST(seedpost_attachment_plain_link, {
	const char* doc = pd_fmt("IBB0 ID" POST_CID " SJx RT1",
		"the [report.pdf]" POST_MAGNET(POST_TTH, "&dn=report.pdf"));
	int ok = pd_parse(doc);
	if (ok)
		ok = pd_attachments(doc) == 1 && pd_att[0].inline_image == 0;
	return ok;
});

EXO_TEST(seedpost_two_attachments, {
	const char* doc = pd_fmt("IBB0 ID" POST_CID " SJx RT1",
		"a ![x]" POST_MAGNET(POST_TTH, "") " b ![y]" POST_MAGNET(POST_TTH2, ""));
	int ok = pd_parse(doc);
	if (ok)
		ok = pd_attachments(doc) == 2;
	if (ok)
		ok = strcmp(pd_att[0].tth, POST_TTH) == 0 && strcmp(pd_att[1].tth, POST_TTH2) == 0;
	return ok;
});

/* One attachment referred to twice is one file to fetch. */
EXO_TEST(seedpost_duplicate_attachment_collapsed, {
	const char* doc = pd_fmt("IBB0 ID" POST_CID " SJx RT1",
		"a ![x]" POST_MAGNET(POST_TTH, "") " again ![x]" POST_MAGNET(POST_TTH, ""));
	int ok = pd_parse(doc);
	if (ok)
		ok = pd_attachments(doc) == 1;
	return ok;
});

EXO_TEST(seedpost_no_attachment_in_empty_body, {
	const char* doc = "IBB0 ID" POST_CID " SJx RT1\n";
	int ok = pd_parse(doc);
	if (ok)
		ok = pd_attachments(doc) == 0;
	return ok;
});

/*
 * A document need not be text. The scan stops at an embedded NUL rather than
 * reading past it, so a magnet after one is not found -- which is the safe
 * direction to be wrong in.
 */
EXO_TEST(seedpost_scan_stops_at_nul, {
	const char* header = "IBB0 ID" POST_CID " SJx RT1";
	const char* tail = "![x]" POST_MAGNET(POST_TTH, "");
	size_t hlen = strlen(header);
	size_t len;

	memcpy(pd_doc, header, hlen);
	pd_doc[hlen] = '\n';
	pd_doc[hlen + 1] = 'a';
	pd_doc[hlen + 2] = '\0';
	memcpy(pd_doc + hlen + 3, tail, strlen(tail));
	len = hlen + 3 + strlen(tail);

	if (!pd_parse_len(pd_doc, len))
		return 0;
	memset(pd_att, 0xAA, sizeof(pd_att));
	return seed_post_attachments(pd_doc, len, &pd_post, pd_att, SEED_POST_MAX_ATTACHMENTS) == 0;
});

/* Asking for no attachments writes nothing and reports nothing. */
EXO_TEST(seedpost_attachments_zero_max, {
	const char* doc = pd_fmt("IBB0 ID" POST_CID " SJx RT1", "![x]" POST_MAGNET(POST_TTH, ""));
	int ok = pd_parse(doc);
	if (ok)
		ok = seed_post_attachments(doc, strlen(doc), &pd_post, pd_att, 0) == 0;
	return ok;
});

EXO_TEST(seedpost_attachments_null_args, {
	return seed_post_attachments(NULL, 0, &pd_post, pd_att, SEED_POST_MAX_ATTACHMENTS) == 0;
});

/* An error string exists for every code, and none of them is NULL. */
EXO_TEST(seedpost_error_strings, {
	int i;
	for (i = SEED_POST_OK; i <= SEED_POST_ERR_FIELD; i++)
	{
		const char* s = seed_post_error_string((enum seed_post_error) i);
		if (!s || !*s)
			return 0;
	}
	return 1;
});
