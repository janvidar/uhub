#include <uhub.h>

#define DEBUG_HASH

static char* byte_to_hex(char* dest, uint8_t c)
{
	static const char* hexchars = "0123456789abcdef";
	*dest = hexchars[c / 16]; dest++;
	*dest = hexchars[c % 16]; dest++;
	return dest;
}


static int test_tiger_hex(char* input, char* expected) {
	char buf[TIGERSIZE*2+1];
	uint64_t tiger_res[3];
	int i = 0;
#ifdef DEBUG_HASH
	int res = 0;
#endif
	char* ptr = buf;
	buf[TIGERSIZE*2] = 0;
	
	tiger((uint64_t*) input, strlen(input), (uint64_t*) tiger_res);
	for (i = 0; i < TIGERSIZE; i++)
		ptr = byte_to_hex(ptr, (char) (((uint8_t*) tiger_res)[i]) );

#ifdef DEBUG_HASH
	res = strcasecmp(buf, expected) == 0 ? 1 : 0;

	if (!res)
	{
		printf("Expected: '%s', Got: '%s'\n", expected, buf);
	}
	return res;
#else
	return strcasecmp(buf, expected) == 0;
#endif
}


EXO_TEST(hash_tiger_1, {
	return test_tiger_hex("", "3293AC630C13F0245F92BBB1766E16167A4E58492DDE73F3");
});

EXO_TEST(hash_tiger_2, {
	return test_tiger_hex("a", "77BEFBEF2E7EF8AB2EC8F93BF587A7FC613E247F5F247809");
});

EXO_TEST(hash_tiger_3, {
	return test_tiger_hex("abc", "2AAB1484E8C158F2BFB8C5FF41B57A525129131C957B5F93");
});

EXO_TEST(hash_tiger_4, {
	return test_tiger_hex("message digest", "D981F8CB78201A950DCF3048751E441C517FCA1AA55A29F6");
});

EXO_TEST(hash_tiger_5, {
	return test_tiger_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "0F7BF9A19B9C58F2B7610DF7E84F0AC3A71C631E7B53F78E");
});

EXO_TEST(hash_tiger_6, {
	return test_tiger_hex("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "8DCEA680A17583EE502BA38A3C368651890FFBCCDC49A8CC");
});

EXO_TEST(hash_tiger_7, {
	return test_tiger_hex("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "1C14795529FD9F207A958F84C52F11E887FA0CABDFD91BFD");
});

