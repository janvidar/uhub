#include "system.h"
#include "util/misc.h"
#include "util/tiger.h"
#include "util/tth.h"

/*
 * The well known TTH of an empty file, as every DC client reports it. Unlike
 * the structural tests below this pins the actual THEX conventions -- the 0x00
 * leaf prefix and the single-leaf-for-empty-input rule -- against the outside
 * world rather than against our own idea of them.
 */
#define TTH_EMPTY_BASE32 "LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ"

#define TTH_REF_MAX_LEAVES 64

static uint8_t tth_buf[TTH_REF_MAX_LEAVES * TTH_BLOCK_SIZE];

/* Deterministic filler, so a failure is always reproducible. */
static void tth_fill(uint8_t* buf, size_t len, uint32_t seed)
{
	size_t i;
	uint32_t x = seed ? seed : 1;
	for (i = 0; i < len; i++)
	{
		x = (x * 1103515245u) + 12345u;
		buf[i] = (uint8_t) (x >> 16);
	}
}

/* Reference leaf hash, written independently of tth.c. */
static void tth_ref_leaf(const uint8_t* data, size_t len, uint8_t out[TTH_SIZE])
{
	uint64_t buf[(TTH_BLOCK_SIZE / 8) + 1];
	uint64_t res[3];
	uint8_t* raw = (uint8_t*) buf;

	raw[0] = 0x00;
	if (len)
		memcpy(raw + 1, data, len);
	tiger(buf, (uint64_t) (len + 1), res);
	memcpy(out, res, TTH_SIZE);
}

/* Reference internal node hash. */
static void tth_ref_node(const uint8_t* left, const uint8_t* right, uint8_t out[TTH_SIZE])
{
	uint64_t buf[7];
	uint64_t res[3];
	uint8_t tmp[TTH_SIZE];
	uint8_t* raw = (uint8_t*) buf;

	raw[0] = 0x01;
	memcpy(raw + 1, left, TTH_SIZE);
	memcpy(raw + 1 + TTH_SIZE, right, TTH_SIZE);
	tiger(buf, (uint64_t) (1 + (2 * TTH_SIZE)), res);
	memcpy(tmp, res, TTH_SIZE);
	memcpy(out, tmp, TTH_SIZE);
}

/*
 * A deliberately naive, non-streaming reference: hash every leaf into an array,
 * then collapse level by level, promoting an odd trailing node unchanged. It
 * shares no code with the incremental stack in tth.c, so agreement between the
 * two is meaningful evidence that the stack folds in the right order.
 */
static void tth_ref(const uint8_t* data, size_t len, uint8_t out[TTH_SIZE])
{
	static uint8_t nodes[TTH_REF_MAX_LEAVES][TTH_SIZE];
	size_t n = 0;

	if (len == 0)
	{
		tth_ref_leaf(NULL, 0, nodes[0]);
		n = 1;
	}
	else
	{
		size_t off = 0;
		while (off < len)
		{
			size_t take = ((len - off) < TTH_BLOCK_SIZE) ? (len - off) : TTH_BLOCK_SIZE;
			tth_ref_leaf(data + off, take, nodes[n++]);
			off += take;
		}
	}

	while (n > 1)
	{
		size_t i = 0;
		size_t w = 0;
		for (i = 0; (i + 1) < n; i += 2)
			tth_ref_node(nodes[i], nodes[i + 1], nodes[w++]);
		if (i < n)
		{
			memcpy(nodes[w], nodes[i], TTH_SIZE);
			w++;
		}
		n = w;
	}

	memcpy(out, nodes[0], TTH_SIZE);
}

/* Hash `len` bytes of the shared buffer in fixed size chunks. */
static void tth_chunked(const uint8_t* data, size_t len, size_t chunk, uint8_t out[TTH_SIZE])
{
	struct tth_context ctx;
	size_t off = 0;

	tth_init(&ctx);
	while (off < len)
	{
		size_t take = ((len - off) < chunk) ? (len - off) : chunk;
		tth_update(&ctx, data + off, take);
		off += take;
	}
	tth_finalize(&ctx, out);
}

static int tth_matches_reference(size_t len)
{
	uint8_t got[TTH_SIZE];
	uint8_t expected[TTH_SIZE];

	tth_fill(tth_buf, len, (uint32_t) (len + 1));
	tth(tth_buf, len, got);
	tth_ref(tth_buf, len, expected);
	return memcmp(got, expected, TTH_SIZE) == 0;
}

EXO_TEST(tth_empty_is_tiger_of_prefix, {
	/*
	 * Self checking: an empty input is one leaf, and that leaf is the tiger
	 * digest of the lone 0x00 prefix byte. Needs no external constant.
	 */
	uint64_t prefix = 0;
	uint64_t res[3];
	uint8_t root[TTH_SIZE];

	tiger(&prefix, 1, res);
	tth("", 0, root);
	return memcmp(root, res, TTH_SIZE) == 0;
});

EXO_TEST(tth_empty_base32, {
	uint8_t root[TTH_SIZE];
	char str[TTH_BASE32_LEN + 1];

	tth("", 0, root);
	tth_to_string(root, str);
	return strcmp(str, TTH_EMPTY_BASE32) == 0;
});

EXO_TEST(tth_single_leaf_matches_reference, {
	return tth_matches_reference(1);
});

EXO_TEST(tth_three_leaves_promotes_odd_node, {
	/*
	 * The test that catches a wrong odd node rule. With three leaves the only
	 * correct shape is I(I(L0,L1), L2); hashing L2 with itself, or combining
	 * left to right, both produce a self consistent but wrong root.
	 */
	uint8_t l0[TTH_SIZE], l1[TTH_SIZE], l2[TTH_SIZE];
	uint8_t inner[TTH_SIZE], expected[TTH_SIZE], got[TTH_SIZE];
	size_t len = (2 * TTH_BLOCK_SIZE) + 7;

	tth_fill(tth_buf, len, 3);
	tth_ref_leaf(tth_buf, TTH_BLOCK_SIZE, l0);
	tth_ref_leaf(tth_buf + TTH_BLOCK_SIZE, TTH_BLOCK_SIZE, l1);
	tth_ref_leaf(tth_buf + (2 * TTH_BLOCK_SIZE), 7, l2);
	tth_ref_node(l0, l1, inner);
	tth_ref_node(inner, l2, expected);

	tth(tth_buf, len, got);
	return memcmp(got, expected, TTH_SIZE) == 0;
});

EXO_TEST(tth_five_leaves_matches_reference, {
	return tth_matches_reference((4 * TTH_BLOCK_SIZE) + 1);
});

EXO_TEST(tth_block_boundaries, {
	static const size_t sizes[] = { 1, 1023, 1024, 1025, 2047, 2048, 2049, 3072, 4095, 4096, 4097 };
	size_t i;
	for (i = 0; i < (sizeof(sizes) / sizeof(sizes[0])); i++)
		if (!tth_matches_reference(sizes[i]))
			return 0;
	return 1;
});

EXO_TEST(tth_many_sizes_match_reference, {
	size_t len;
	/* Sweep every leaf count from 1 to 16, plus offsets around each boundary. */
	for (len = 1; len <= (16 * TTH_BLOCK_SIZE); len += 337)
		if (!tth_matches_reference(len))
			return 0;
	return 1;
});

EXO_TEST(tth_chunking_is_invariant, {
	static const size_t chunks[] = { 1, 7, 63, 64, 1023, 1024, 1025, 4096, 65536 };
	size_t len = (9 * TTH_BLOCK_SIZE) + 511;
	uint8_t expected[TTH_SIZE];
	uint8_t got[TTH_SIZE];
	size_t i;

	tth_fill(tth_buf, len, 9);
	tth(tth_buf, len, expected);

	for (i = 0; i < (sizeof(chunks) / sizeof(chunks[0])); i++)
	{
		tth_chunked(tth_buf, len, chunks[i], got);
		if (memcmp(got, expected, TTH_SIZE) != 0)
			return 0;
	}
	return 1;
});

EXO_TEST(tth_exact_multiple_has_no_empty_leaf, {
	/* 2048 bytes must be two leaves, not two plus an empty third. */
	uint8_t l0[TTH_SIZE], l1[TTH_SIZE], expected[TTH_SIZE], got[TTH_SIZE];
	size_t len = 2 * TTH_BLOCK_SIZE;

	tth_fill(tth_buf, len, 11);
	tth_ref_leaf(tth_buf, TTH_BLOCK_SIZE, l0);
	tth_ref_leaf(tth_buf + TTH_BLOCK_SIZE, TTH_BLOCK_SIZE, l1);
	tth_ref_node(l0, l1, expected);

	tth(tth_buf, len, got);
	return memcmp(got, expected, TTH_SIZE) == 0;
});

EXO_TEST(tth_reinit_resets_state, {
	struct tth_context ctx;
	uint8_t first[TTH_SIZE];
	uint8_t second[TTH_SIZE];

	tth_init(&ctx);
	tth_update(&ctx, "hello world", 11);
	tth_finalize(&ctx, first);

	tth_init(&ctx);
	tth_update(&ctx, "hello world", 11);
	tth_finalize(&ctx, second);

	return memcmp(first, second, TTH_SIZE) == 0;
});

EXO_TEST(tth_string_roundtrip, {
	uint8_t root[TTH_SIZE];
	uint8_t back[TTH_SIZE];
	char str[TTH_BASE32_LEN + 1];

	tth_fill(tth_buf, 5000, 42);
	tth(tth_buf, 5000, root);
	tth_to_string(root, str);

	if (strlen(str) != TTH_BASE32_LEN)
		return 0;
	if (!tth_from_string(str, back))
		return 0;
	return memcmp(root, back, TTH_SIZE) == 0;
});

EXO_TEST(tth_from_string_rejects_bad_input, {
	uint8_t root[TTH_SIZE];

	if (tth_from_string("", root)) return 0;
	if (tth_from_string(NULL, root)) return 0;
	/* 38 characters -- one short. */
	if (tth_from_string("LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLN", root)) return 0;
	/* 40 characters -- one too many. */
	if (tth_from_string("LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQQ", root)) return 0;
	/* Digits outside the base32 alphabet. */
	if (tth_from_string("0WPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ", root)) return 0;
	if (tth_from_string("1WPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ", root)) return 0;
	if (tth_from_string("8WPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ", root)) return 0;
	if (tth_from_string("9WPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ", root)) return 0;
	/* Lower case is not accepted. */
	if (tth_from_string("lwpnacqdbzryxw3vhjvcj64qbzngHOHHHZWCLNQ", root)) return 0;
	/* Punctuation, including a path separator. */
	if (tth_from_string("../NACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ", root)) return 0;

	return tth_from_string(TTH_EMPTY_BASE32, root);
});
