#include "system.h"
#include "seeder/sniff.h"

/* Pass a string literal as a (buffer, length) pair without its NUL. */
#define SNIFF_LIT(s) ((const uint8_t*) (s)), (sizeof(s) - 1)

/* Pass a uint8_t array fixture as a (buffer, length) pair. */
#define SNIFF_BUF(a) (a), (sizeof(a))

static int sniff_is(const uint8_t* buf, size_t len, const char* expect)
{
	const char* got = seed_sniff_media_type(buf, len);
	return got != NULL && strcmp(got, expect) == 0;
}

static int sniff_not(const uint8_t* buf, size_t len, const char* unexpected)
{
	const char* got = seed_sniff_media_type(buf, len);
	return got != NULL && strcmp(got, unexpected) != 0;
}

/**
 * The security invariant: whatever the input, the sniffer never reports an
 * image type for it, and in particular never anything SVG or XML flavoured.
 * The only acceptable answers are the two types absent from the default
 * allowlist.
 */
static int sniff_inert(const uint8_t* buf, size_t len)
{
	const char* got = seed_sniff_media_type(buf, len);
	if (!got)
		return 0;
	if (strncmp(got, "image/", 6) == 0)
		return 0;
	if (strstr(got, "svg") != NULL || strstr(got, "xml") != NULL)
		return 0;
	return strcmp(got, "text/plain") == 0 || strcmp(got, "application/octet-stream") == 0;
}

/* Binary fixtures. These carry NUL bytes, so they cannot be string literals. */

static const uint8_t sniff_png[] = {
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
	0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R',
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01
};

static const uint8_t sniff_png_trunc[] = { 0x89, 0x50, 0x4e, 0x47 };

static const uint8_t sniff_jpeg[] = {
	0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01
};

static const uint8_t sniff_jpeg_trunc[] = { 0xff, 0xd8 };

static const uint8_t sniff_bmp[] = {
	'B', 'M', 0x36, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00
};

static const uint8_t sniff_avif[] = {
	0x00, 0x00, 0x00, 0x20, 'f', 't', 'y', 'p', 'a', 'v', 'i', 'f',
	0x00, 0x00, 0x00, 0x00, 'a', 'v', 'i', 'f', 'm', 'i', 'f', '1'
};

static const uint8_t sniff_avis[] = {
	0x00, 0x00, 0x00, 0x20, 'f', 't', 'y', 'p', 'a', 'v', 'i', 's',
	0x00, 0x00, 0x00, 0x00, 'a', 'v', 'i', 's', 'm', 's', 'f', '1'
};

static const uint8_t sniff_heic[] = {
	0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p', 'h', 'e', 'i', 'c',
	0x00, 0x00, 0x00, 0x00, 'm', 'i', 'f', '1', 'h', 'e', 'i', 'c'
};

static const uint8_t sniff_heix[] = {
	0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p', 'h', 'e', 'i', 'x',
	0x00, 0x00, 0x00, 0x00, 'm', 'i', 'f', '1', 'h', 'e', 'i', 'x'
};

static const uint8_t sniff_hevc[] = {
	0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p', 'h', 'e', 'v', 'c',
	0x00, 0x00, 0x00, 0x00, 'm', 'i', 'f', '1', 'h', 'e', 'v', 'c'
};

static const uint8_t sniff_mif1[] = {
	0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p', 'm', 'i', 'f', '1',
	0x00, 0x00, 0x00, 0x00, 'm', 'i', 'f', '1', 'h', 'e', 'i', 'c'
};

/* "ftyp" at 4, but a brand the sniffer must not claim. */
static const uint8_t sniff_ftyp_mp42[] = {
	0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p', 'm', 'p', '4', '2',
	0x00, 0x00, 0x00, 0x00, 'm', 'p', '4', '2', 'i', 's', 'o', 'm'
};

static const uint8_t sniff_ftyp_trunc[] = {
	0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p', 'a', 'v'
};

static const uint8_t sniff_zip[] = {
	'P', 'K', 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00
};

static const uint8_t sniff_zeroes[SEED_SNIFF_BYTES] = { 0 };

static const uint8_t sniff_invalid_utf8[] = {
	'h', 'e', 'l', 'l', 'o', ' ', 0xff, 0xfe, ' ', 'w', 'o', 'r', 'l', 'd'
};

/* One positive case per magic number. */

EXO_TEST(seedsniff_png, { return sniff_is(SNIFF_BUF(sniff_png), "image/png"); });
EXO_TEST(seedsniff_jpeg, { return sniff_is(SNIFF_BUF(sniff_jpeg), "image/jpeg"); });
EXO_TEST(seedsniff_gif87a, { return sniff_is(SNIFF_LIT("GIF87a" "\x01\x00\x01\x00"), "image/gif"); });
EXO_TEST(seedsniff_gif89a, { return sniff_is(SNIFF_LIT("GIF89a" "\x01\x00\x01\x00"), "image/gif"); });
EXO_TEST(seedsniff_webp, { return sniff_is(SNIFF_LIT("RIFF" "\x24\x10\x00\x00" "WEBPVP8 "), "image/webp"); });
EXO_TEST(seedsniff_bmp, { return sniff_is(SNIFF_BUF(sniff_bmp), "image/bmp"); });
EXO_TEST(seedsniff_avif, { return sniff_is(SNIFF_BUF(sniff_avif), "image/avif"); });
EXO_TEST(seedsniff_avis, { return sniff_is(SNIFF_BUF(sniff_avis), "image/avif"); });
EXO_TEST(seedsniff_heic, { return sniff_is(SNIFF_BUF(sniff_heic), "image/heic"); });
EXO_TEST(seedsniff_heix, { return sniff_is(SNIFF_BUF(sniff_heix), "image/heic"); });
EXO_TEST(seedsniff_hevc, { return sniff_is(SNIFF_BUF(sniff_hevc), "image/heic"); });
EXO_TEST(seedsniff_mif1, { return sniff_is(SNIFF_BUF(sniff_mif1), "image/heic"); });
EXO_TEST(seedsniff_pdf, { return sniff_is(SNIFF_LIT("%PDF-1.7\n1 0 obj\n"), "application/pdf"); });
EXO_TEST(seedsniff_text, { return sniff_is(SNIFF_LIT("hello world, just some text\n"), "text/plain"); });

/* Truncated magic numbers: a short buffer must never be matched against a
   longer magic, and must not be misreported. */

EXO_TEST(seedsniff_png_truncated_not_png, { return sniff_not(SNIFF_BUF(sniff_png_trunc), "image/png"); });
EXO_TEST(seedsniff_png_truncated_is_octet, { return sniff_is(SNIFF_BUF(sniff_png_trunc), "application/octet-stream"); });
EXO_TEST(seedsniff_jpeg_two_bytes_not_jpeg, { return sniff_not(SNIFF_BUF(sniff_jpeg_trunc), "image/jpeg"); });
EXO_TEST(seedsniff_jpeg_two_bytes_is_octet, { return sniff_is(SNIFF_BUF(sniff_jpeg_trunc), "application/octet-stream"); });
EXO_TEST(seedsniff_gif_truncated, { return sniff_not(SNIFF_LIT("GIF8"), "image/gif"); });
EXO_TEST(seedsniff_bmp_one_byte, { return sniff_not(SNIFF_LIT("B"), "image/bmp"); });
EXO_TEST(seedsniff_pdf_truncated, { return sniff_not(SNIFF_LIT("%PDF"), "application/pdf"); });
EXO_TEST(seedsniff_ftyp_truncated_brand, { return sniff_not(SNIFF_BUF(sniff_ftyp_trunc), "image/avif"); });
EXO_TEST(seedsniff_ftyp_truncated_not_heic, { return sniff_not(SNIFF_BUF(sniff_ftyp_trunc), "image/heic"); });
EXO_TEST(seedsniff_ftyp_unknown_brand, { return sniff_inert(SNIFF_BUF(sniff_ftyp_mp42)); });

/* RIFF containers that are not WebP. */

EXO_TEST(seedsniff_riff_wave_not_webp, { return sniff_not(SNIFF_LIT("RIFF" "\x24\x10\x00\x00" "WAVEfmt "), "image/webp"); });
EXO_TEST(seedsniff_riff_avi_not_webp, { return sniff_not(SNIFF_LIT("RIFF" "\x24\x10\x00\x00" "AVI LIST"), "image/webp"); });
EXO_TEST(seedsniff_riff_only, { return sniff_not(SNIFF_LIT("RIFF"), "image/webp"); });
EXO_TEST(seedsniff_riff_short_of_offset_8, { return sniff_not(SNIFF_LIT("RIFF" "\x24\x10\x00\x00" "WEB"), "image/webp"); });
EXO_TEST(seedsniff_webp_at_offset_8_only, { return sniff_not(SNIFF_LIT("XIFF" "\x24\x10\x00\x00" "WEBPVP8 "), "image/webp"); });

/*
 * SVG must never be detected. An SVG document has to come back as text/plain
 * or application/octet-stream -- neither is on the default allowlist -- so
 * that the hub refuses to cache and re-serve it. See the notice in seeder/sniff.c.
 */

EXO_TEST(seedsniff_svg_is_never_an_image, {
	return sniff_inert(SNIFF_LIT("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"8\" height=\"8\"></svg>"));
});

EXO_TEST(seedsniff_svg_with_xml_declaration, {
	return sniff_inert(SNIFF_LIT("<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"/>"));
});

EXO_TEST(seedsniff_svg_with_script, {
	return sniff_inert(SNIFF_LIT("<svg onload=\"alert(1)\" xmlns=\"http://www.w3.org/2000/svg\"><script/></svg>"));
});

EXO_TEST(seedsniff_svg_doctype, {
	return sniff_inert(SNIFF_LIT("<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\"><svg></svg>"));
});

EXO_TEST(seedsniff_svg_leading_whitespace, {
	return sniff_inert(SNIFF_LIT("   \n\t<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"));
});

EXO_TEST(seedsniff_html, { return sniff_inert(SNIFF_LIT("<!DOCTYPE html><html><body><script>x</script></body></html>")); });

/* Other blobs that must fall through to application/octet-stream. */

EXO_TEST(seedsniff_zip, { return sniff_is(SNIFF_BUF(sniff_zip), "application/octet-stream"); });
EXO_TEST(seedsniff_64_zero_bytes, { return sniff_is(SNIFF_BUF(sniff_zeroes), "application/octet-stream"); });
EXO_TEST(seedsniff_64_zero_bytes_length, { return sizeof(sniff_zeroes) == SEED_SNIFF_BYTES; });
EXO_TEST(seedsniff_invalid_utf8, { return sniff_is(SNIFF_BUF(sniff_invalid_utf8), "application/octet-stream"); });
EXO_TEST(seedsniff_single_nul_byte, { return sniff_is(SNIFF_LIT("\x00"), "application/octet-stream"); });

/* Empty input, and a NULL buffer. Neither may crash. */

EXO_TEST(seedsniff_empty_buffer, { return sniff_is(sniff_png, 0, "application/octet-stream"); });
EXO_TEST(seedsniff_null_buffer, { return sniff_is(NULL, 0, "application/octet-stream"); });

/* Only the leading bytes matter, and the buffer is never assumed to be NUL
   terminated: one byte fewer means the magic no longer fits. */

EXO_TEST(seedsniff_png_exactly_8_bytes, { return sniff_is(sniff_png, 8, "image/png"); });
EXO_TEST(seedsniff_png_7_bytes, { return sniff_not(sniff_png, 7, "image/png"); });
EXO_TEST(seedsniff_jpeg_exactly_3_bytes, { return sniff_is(sniff_jpeg, 3, "image/jpeg"); });
EXO_TEST(seedsniff_text_prefix_only, {
	/* A printable prefix followed by binary beyond SEED_SNIFF_BYTES is still
	   text as far as the sniffer is concerned -- it only sees the prefix. */
	uint8_t buf[SEED_SNIFF_BYTES + 16];
	memset(buf, 'a', sizeof(buf));
	memset(buf + SEED_SNIFF_BYTES, 0x00, 16);
	return sniff_is(buf, sizeof(buf), "text/plain");
});
EXO_TEST(seedsniff_binary_inside_prefix, {
	uint8_t buf[SEED_SNIFF_BYTES];
	memset(buf, 'a', sizeof(buf));
	buf[SEED_SNIFF_BYTES - 1] = 0x00;
	return sniff_is(buf, sizeof(buf), "application/octet-stream");
});

/* seed_sniff_type_allowed */

#define SEEDSNIFF_DEFAULT_TYPES "image/png,image/jpeg,image/gif,image/webp"

EXO_TEST(seedsniff_allowed_exact, { return seed_sniff_type_allowed("image/png", "image/png") == 1; });
EXO_TEST(seedsniff_allowed_first, { return seed_sniff_type_allowed("image/png", SEEDSNIFF_DEFAULT_TYPES) == 1; });
EXO_TEST(seedsniff_allowed_middle, { return seed_sniff_type_allowed("image/gif", SEEDSNIFF_DEFAULT_TYPES) == 1; });
EXO_TEST(seedsniff_allowed_last, { return seed_sniff_type_allowed("image/webp", SEEDSNIFF_DEFAULT_TYPES) == 1; });
EXO_TEST(seedsniff_allowed_no_match, { return seed_sniff_type_allowed("application/pdf", SEEDSNIFF_DEFAULT_TYPES) == 0; });
EXO_TEST(seedsniff_allowed_empty_list, { return seed_sniff_type_allowed("image/png", "") == 0; });
EXO_TEST(seedsniff_allowed_null_list, { return seed_sniff_type_allowed("image/png", NULL) == 0; });
EXO_TEST(seedsniff_allowed_null_type, { return seed_sniff_type_allowed(NULL, SEEDSNIFF_DEFAULT_TYPES) == 0; });
EXO_TEST(seedsniff_allowed_empty_type, { return seed_sniff_type_allowed("", SEEDSNIFF_DEFAULT_TYPES) == 0; });
EXO_TEST(seedsniff_allowed_empty_type_empty_list, { return seed_sniff_type_allowed("", "") == 0; });

EXO_TEST(seedsniff_allowed_spaces, { return seed_sniff_type_allowed("image/gif", "image/png, image/gif") == 1; });
EXO_TEST(seedsniff_allowed_spaces_first, { return seed_sniff_type_allowed("image/png", "image/png, image/gif") == 1; });
EXO_TEST(seedsniff_allowed_spaces_around, { return seed_sniff_type_allowed("image/gif", "  image/png ,  image/gif  ") == 1; });
EXO_TEST(seedsniff_allowed_tabs, { return seed_sniff_type_allowed("image/gif", "image/png,\timage/gif\t") == 1; });
EXO_TEST(seedsniff_allowed_spaces_only, { return seed_sniff_type_allowed("image/png", "   ") == 0; });

/* Prefixes and suffixes must never match. */

EXO_TEST(seedsniff_allowed_prefix_of_item, { return seed_sniff_type_allowed("image/pn", "image/png") == 0; });
EXO_TEST(seedsniff_allowed_prefix_of_item_in_list, { return seed_sniff_type_allowed("image/pn", SEEDSNIFF_DEFAULT_TYPES) == 0; });
EXO_TEST(seedsniff_allowed_item_is_prefix_of_type, { return seed_sniff_type_allowed("image/png", "image/pngx") == 0; });
EXO_TEST(seedsniff_allowed_item_extends_type, { return seed_sniff_type_allowed("image/png", "image/pngx,image/pngy") == 0; });
EXO_TEST(seedsniff_allowed_substring, { return seed_sniff_type_allowed("age/pn", "image/png") == 0; });
EXO_TEST(seedsniff_allowed_case_sensitive, { return seed_sniff_type_allowed("IMAGE/PNG", SEEDSNIFF_DEFAULT_TYPES) == 0; });

/* Neither of the two types an SVG can be detected as is on the default
   allowlist, which is what makes such a blob refusable at ingest. */

EXO_TEST(seedsniff_text_not_allowed_by_default, { return seed_sniff_type_allowed("text/plain", SEEDSNIFF_DEFAULT_TYPES) == 0; });
EXO_TEST(seedsniff_octet_not_allowed_by_default, { return seed_sniff_type_allowed("application/octet-stream", SEEDSNIFF_DEFAULT_TYPES) == 0; });
EXO_TEST(seedsniff_svg_not_allowed_by_default, { return seed_sniff_type_allowed("image/svg+xml", SEEDSNIFF_DEFAULT_TYPES) == 0; });

EXO_TEST(seedsniff_svg_refused_end_to_end, {
	const char* svg = "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";
	const char* type = seed_sniff_media_type((const uint8_t*) svg, strlen(svg));
	return seed_sniff_type_allowed(type, SEEDSNIFF_DEFAULT_TYPES) == 0;
});

EXO_TEST(seedsniff_png_accepted_end_to_end, {
	const char* type = seed_sniff_media_type(sniff_png, sizeof(sniff_png));
	return seed_sniff_type_allowed(type, SEEDSNIFF_DEFAULT_TYPES) == 1;
});
