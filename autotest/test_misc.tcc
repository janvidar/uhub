#include <uhub.h>

EXO_TEST(is_num_0,  { return is_num('0'); });
EXO_TEST(is_num_1,  { return is_num('1'); });
EXO_TEST(is_num_2,  { return is_num('2'); });
EXO_TEST(is_num_3,  { return is_num('3'); });
EXO_TEST(is_num_4,  { return is_num('4'); });
EXO_TEST(is_num_5,  { return is_num('5'); });
EXO_TEST(is_num_6,  { return is_num('6'); });
EXO_TEST(is_num_7,  { return is_num('7'); });
EXO_TEST(is_num_8,  { return is_num('8'); });
EXO_TEST(is_num_9,  { return is_num('9'); });
EXO_TEST(is_num_10, { return !is_num('/'); });
EXO_TEST(is_num_11, { return !is_num(':'); });

EXO_TEST(is_space_1, { return is_space(' '); });
EXO_TEST(is_space_2, { return !is_space('\t'); });
EXO_TEST(is_white_space_1, { return is_white_space(' '); });
EXO_TEST(is_white_space_2, { return is_white_space('\t'); });
EXO_TEST(is_white_space_3, { return !is_white_space('A'); });
EXO_TEST(is_white_space_4, { return !is_white_space('!'); });

EXO_TEST(itoa_1, { return strcmp(uhub_itoa(0), "0") == 0; });
EXO_TEST(itoa_2, { return strcmp(uhub_itoa(1), "1") == 0; });
EXO_TEST(itoa_3, { return strcmp(uhub_itoa(-1), "-1") == 0; });
EXO_TEST(itoa_4, { return strcmp(uhub_itoa(255), "255") == 0; });
EXO_TEST(itoa_5, { return strcmp(uhub_itoa(-3), "-3") == 0; });
EXO_TEST(itoa_6, { return strcmp(uhub_itoa(-2147483647), "-2147483647") == 0; });
EXO_TEST(itoa_7, { return strcmp(uhub_itoa(2147483647), "2147483647") == 0; });
EXO_TEST(itoa_8, { return strcmp(uhub_itoa(-65536), "-65536") == 0; });

EXO_TEST(base32_valid_1,  { return is_valid_base32_char('A'); });
EXO_TEST(base32_valid_2,  { return is_valid_base32_char('B'); });
EXO_TEST(base32_valid_3,  { return is_valid_base32_char('C'); });
EXO_TEST(base32_valid_4,  { return is_valid_base32_char('D'); });
EXO_TEST(base32_valid_5,  { return is_valid_base32_char('E'); });
EXO_TEST(base32_valid_6,  { return is_valid_base32_char('F'); });
EXO_TEST(base32_valid_7,  { return is_valid_base32_char('G'); });
EXO_TEST(base32_valid_8,  { return is_valid_base32_char('H'); });
EXO_TEST(base32_valid_9,  { return is_valid_base32_char('I'); });
EXO_TEST(base32_valid_10, { return is_valid_base32_char('J'); });
EXO_TEST(base32_valid_11, { return is_valid_base32_char('K'); });
EXO_TEST(base32_valid_12, { return is_valid_base32_char('L'); });
EXO_TEST(base32_valid_13, { return is_valid_base32_char('M'); });
EXO_TEST(base32_valid_14, { return is_valid_base32_char('N'); });
EXO_TEST(base32_valid_15, { return is_valid_base32_char('O'); });
EXO_TEST(base32_valid_16, { return is_valid_base32_char('P'); });
EXO_TEST(base32_valid_17, { return is_valid_base32_char('Q'); });
EXO_TEST(base32_valid_18, { return is_valid_base32_char('R'); });
EXO_TEST(base32_valid_19, { return is_valid_base32_char('S'); });
EXO_TEST(base32_valid_20, { return is_valid_base32_char('T'); });
EXO_TEST(base32_valid_21, { return is_valid_base32_char('U'); });
EXO_TEST(base32_valid_22, { return is_valid_base32_char('V'); });
EXO_TEST(base32_valid_23, { return is_valid_base32_char('W'); });
EXO_TEST(base32_valid_24, { return is_valid_base32_char('X'); });
EXO_TEST(base32_valid_25, { return is_valid_base32_char('Y'); });
EXO_TEST(base32_valid_26, { return is_valid_base32_char('Z'); });
EXO_TEST(base32_valid_27, { return is_valid_base32_char('2'); });
EXO_TEST(base32_valid_28, { return is_valid_base32_char('3'); });
EXO_TEST(base32_valid_29, { return is_valid_base32_char('4'); });
EXO_TEST(base32_valid_30, { return is_valid_base32_char('5'); });
EXO_TEST(base32_valid_31, { return is_valid_base32_char('6'); });
EXO_TEST(base32_valid_32, { return is_valid_base32_char('7'); });

EXO_TEST(base32_invalid_1,  { return !is_valid_base32_char('a'); });
EXO_TEST(base32_invalid_2,  { return !is_valid_base32_char('b'); });
EXO_TEST(base32_invalid_3,  { return !is_valid_base32_char('c'); });
EXO_TEST(base32_invalid_4,  { return !is_valid_base32_char('d'); });
EXO_TEST(base32_invalid_5,  { return !is_valid_base32_char('e'); });
EXO_TEST(base32_invalid_6,  { return !is_valid_base32_char('f'); });
EXO_TEST(base32_invalid_7,  { return !is_valid_base32_char('g'); });
EXO_TEST(base32_invalid_8,  { return !is_valid_base32_char('h'); });
EXO_TEST(base32_invalid_9,  { return !is_valid_base32_char('i'); });
EXO_TEST(base32_invalid_10, { return !is_valid_base32_char('j'); });
EXO_TEST(base32_invalid_11, { return !is_valid_base32_char('k'); });
EXO_TEST(base32_invalid_12, { return !is_valid_base32_char('l'); });
EXO_TEST(base32_invalid_13, { return !is_valid_base32_char('m'); });
EXO_TEST(base32_invalid_14, { return !is_valid_base32_char('n'); });
EXO_TEST(base32_invalid_15, { return !is_valid_base32_char('o'); });
EXO_TEST(base32_invalid_16, { return !is_valid_base32_char('p'); });
EXO_TEST(base32_invalid_17, { return !is_valid_base32_char('q'); });
EXO_TEST(base32_invalid_18, { return !is_valid_base32_char('r'); });
EXO_TEST(base32_invalid_19, { return !is_valid_base32_char('s'); });
EXO_TEST(base32_invalid_20, { return !is_valid_base32_char('t'); });
EXO_TEST(base32_invalid_21, { return !is_valid_base32_char('u'); });
EXO_TEST(base32_invalid_22, { return !is_valid_base32_char('v'); });
EXO_TEST(base32_invalid_23, { return !is_valid_base32_char('w'); });
EXO_TEST(base32_invalid_24, { return !is_valid_base32_char('x'); });
EXO_TEST(base32_invalid_25, { return !is_valid_base32_char('y'); });
EXO_TEST(base32_invalid_26, { return !is_valid_base32_char('z'); });
EXO_TEST(base32_invalid_27, { return !is_valid_base32_char('0'); });
EXO_TEST(base32_invalid_28, { return !is_valid_base32_char('1'); });
EXO_TEST(base32_invalid_29, { return !is_valid_base32_char('8'); });
EXO_TEST(base32_invalid_30, { return !is_valid_base32_char('9'); });
EXO_TEST(base32_invalid_31, { return !is_valid_base32_char('@'); });

EXO_TEST(utf8_valid_1, { return is_valid_utf8("abcdefghijklmnopqrstuvwxyz"); });
EXO_TEST(utf8_valid_2, { return is_valid_utf8("ABCDEFGHIJKLMNOPQRSTUVWXYZ"); });
EXO_TEST(utf8_valid_3, { return is_valid_utf8("0123456789"); });

static const char test_utf_seq_1[] = { 0x65, 0x00 }; // valid
static const char test_utf_seq_2[] = { 0xD8, 0x00 }; // invalid
static const char test_utf_seq_3[] = { 0x24, 0x00 }; // valid
static const char test_utf_seq_4[] = { 0xC2, 0x24, 0x00}; // invalid
static const char test_utf_seq_5[] = { 0xC2, 0xA2, 0x00}; // valid
static const char test_utf_seq_6[] = { 0xE2, 0x82, 0xAC, 0x00}; // valid
static const char test_utf_seq_7[] = { 0xC2, 0x32, 0x00}; // invalid
static const char test_utf_seq_8[] = { 0xE2, 0x82, 0x32, 0x00}; // invalid
static const char test_utf_seq_9[] = { 0xE2, 0x32, 0x82, 0x00}; // invalid
static const char test_utf_seq_10[] = { 0xF0, 0x9F, 0x98, 0x81, 0x00}; // valid

EXO_TEST(utf8_valid_4, { return is_valid_utf8(test_utf_seq_1); });
EXO_TEST(utf8_valid_5, { return !is_valid_utf8(test_utf_seq_2); });
EXO_TEST(utf8_valid_6, { return is_valid_utf8(test_utf_seq_3); });
EXO_TEST(utf8_valid_7, { return !is_valid_utf8(test_utf_seq_4); });
EXO_TEST(utf8_valid_8, { return is_valid_utf8(test_utf_seq_5); });
EXO_TEST(utf8_valid_9, { return is_valid_utf8(test_utf_seq_6); });
EXO_TEST(utf8_valid_10, { return !is_valid_utf8(test_utf_seq_7); });
EXO_TEST(utf8_valid_11, { return !is_valid_utf8(test_utf_seq_8); });
EXO_TEST(utf8_valid_12, { return !is_valid_utf8(test_utf_seq_9); });
EXO_TEST(utf8_valid_13, { return is_valid_utf8(test_utf_seq_10); });

// Limits of utf-8
static const char test_utf_seq_11[] = { 0x7F, 0x00 }; // valid last 7-bit character
static const char test_utf_seq_12[] = { 0x80, 0x00 }; // invalid truncated string
static const char test_utf_seq_13[] = { 0xBF, 0x00 }; // invalid truncated string
static const char test_utf_seq_14[] = { 0xC0, 0x80, 0x00 }; // invalid out of 2 bytes range
static const char test_utf_seq_15[] = { 0xC1, 0x7F, 0x00 }; // invalid out of 2 bytes range
static const char test_utf_seq_16[] = { 0xC2, 0x00 }; // invalid truncated string
static const char test_utf_seq_17[] = { 0xC2, 0x80, 0x00 }; // valid
static const char test_utf_seq_18[] = { 0xDF, 0xBF, 0x00 }; // valid
static const char test_utf_seq_19[] = { 0xE0, 0x80, 0x80, 0x00 }; // invalid out of 3 bytes range
static const char test_utf_seq_20[] = { 0xE0, 0x9F, 0xBF, 0x00 }; // invalid out of 3 bytes range
static const char test_utf_seq_21[] = { 0xE0, 0x00 }; // invalid truncated string
static const char test_utf_seq_22[] = { 0xE0, 0xA0, 0x00 }; // invalid truncated string
static const char test_utf_seq_23[] = { 0xE0, 0xA0, 0x80, 0x00 }; // valid
static const char test_utf_seq_24[] = { 0xEC, 0x9F, 0xBF, 0x00 }; // valid
static const char test_utf_seq_25[] = { 0xED, 0xA0, 0x80, 0x00 }; // invalid surrogate
static const char test_utf_seq_26[] = { 0xED, 0xBF, 0xBF, 0x00 }; // invalid surrogate
static const char test_utf_seq_27[] = { 0xEF, 0x80, 0x80, 0x00 }; // valid
static const char test_utf_seq_28[] = { 0xEF, 0xBF, 0xBF, 0x00 }; // valid
static const char test_utf_seq_29[] = { 0xF0, 0x80, 0x80, 0x80, 0x00 }; // invalid out of 4 bytes range
static const char test_utf_seq_30[] = { 0xF0, 0x8F, 0xBF, 0xBF, 0x00 }; // invalid out of 4 bytes range
static const char test_utf_seq_31[] = { 0xF0, 0x00 }; // invalid truncated string
static const char test_utf_seq_32[] = { 0xF0, 0x90, 0x00 }; // invalid truncated string
static const char test_utf_seq_33[] = { 0xF0, 0x90, 0x80, 0x00 }; // invalid truncated string
static const char test_utf_seq_34[] = { 0xF0, 0x90, 0x80, 0x80, 0x00 }; // valid
static const char test_utf_seq_35[] = { 0xF4, 0x8F, 0xBF, 0xBF, 0x00 }; // valid
static const char test_utf_seq_36[] = { 0xF4, 0x90, 0x80, 0x80, 0x00 }; // invalid out of 4 bytes range
static const char test_utf_seq_37[] = { 0xFF, 0xBF, 0xBF, 0xBF, 0x00 }; // invalid out of 4 bytes range

EXO_TEST(utf8_valid_14, { return is_valid_utf8(test_utf_seq_11); });
EXO_TEST(utf8_valid_15, { return !is_valid_utf8(test_utf_seq_12); });
EXO_TEST(utf8_valid_16, { return !is_valid_utf8(test_utf_seq_13); });
EXO_TEST(utf8_valid_17, { return !is_valid_utf8(test_utf_seq_14); });
EXO_TEST(utf8_valid_18, { return !is_valid_utf8(test_utf_seq_15); });
EXO_TEST(utf8_valid_19, { return !is_valid_utf8(test_utf_seq_16); });
EXO_TEST(utf8_valid_20, { return is_valid_utf8(test_utf_seq_17); });
EXO_TEST(utf8_valid_21, { return is_valid_utf8(test_utf_seq_18); });
EXO_TEST(utf8_valid_22, { return !is_valid_utf8(test_utf_seq_19); });
EXO_TEST(utf8_valid_23, { return !is_valid_utf8(test_utf_seq_20); });
EXO_TEST(utf8_valid_24, { return !is_valid_utf8(test_utf_seq_21); });
EXO_TEST(utf8_valid_25, { return !is_valid_utf8(test_utf_seq_22); });
EXO_TEST(utf8_valid_26, { return is_valid_utf8(test_utf_seq_23); });
EXO_TEST(utf8_valid_27, { return is_valid_utf8(test_utf_seq_24); });
EXO_TEST(utf8_valid_28, { return !is_valid_utf8(test_utf_seq_25); });
EXO_TEST(utf8_valid_29, { return !is_valid_utf8(test_utf_seq_26); });
EXO_TEST(utf8_valid_30, { return is_valid_utf8(test_utf_seq_27); });
EXO_TEST(utf8_valid_31, { return is_valid_utf8(test_utf_seq_28); });
EXO_TEST(utf8_valid_32, { return !is_valid_utf8(test_utf_seq_29); });
EXO_TEST(utf8_valid_33, { return !is_valid_utf8(test_utf_seq_30); });
EXO_TEST(utf8_valid_34, { return !is_valid_utf8(test_utf_seq_31); });
EXO_TEST(utf8_valid_35, { return !is_valid_utf8(test_utf_seq_32); });
EXO_TEST(utf8_valid_36, { return !is_valid_utf8(test_utf_seq_33); });
EXO_TEST(utf8_valid_37, { return is_valid_utf8(test_utf_seq_34); });
EXO_TEST(utf8_valid_38, { return is_valid_utf8(test_utf_seq_35); });
EXO_TEST(utf8_valid_39, { return !is_valid_utf8(test_utf_seq_36); });
EXO_TEST(utf8_valid_40, { return !is_valid_utf8(test_utf_seq_37); });
