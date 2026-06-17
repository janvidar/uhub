#include <check.h>
#include <stdlib.h>
#include <string.h>

/* Define MAX_NICK_LEN as typically used in IRC-like protocols */
#define MAX_NICK_LEN 32

/* Simulated user structure matching typical IRC implementations */
struct user_id {
    char nick[MAX_NICK_LEN];
};

struct user_info {
    struct user_id id;
};

/* Function that validates nickname length before copy - this is what SHOULD happen */
static int safe_set_nickname(struct user_info *user, const char *nick)
{
    size_t nick_len = strlen(nick);
    
    /* Security invariant: nickname must fit within buffer bounds */
    if (nick_len >= MAX_NICK_LEN) {
        return -1; /* Reject oversized nickname */
    }
    
    memcpy(user->id.nick, nick, nick_len);
    user->id.nick[nick_len] = '\0';
    return 0;
}

START_TEST(test_nickname_buffer_overflow_prevention)
{
    /* Invariant: Nicknames exceeding buffer size must be rejected to prevent heap overflow */
    const char *payloads[] = {
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", /* 100 chars - exploit case */
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", /* 34 chars - boundary case (MAX_NICK_LEN + 2) */
        "validnick", /* Valid input */
    };
    int expected_results[] = { -1, -1, 0 }; /* Oversized must fail, valid must succeed */
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        struct user_info user;
        memset(&user, 0, sizeof(user));
        
        int result = safe_set_nickname(&user, payloads[i]);
        
        /* Security property: oversized nicknames must be rejected */
        ck_assert_msg(result == expected_results[i],
            "Payload %d: expected %d, got %d (len=%zu)",
            i, expected_results[i], result, strlen(payloads[i]));
        
        /* If accepted, verify no buffer overflow occurred */
        if (result == 0) {
            ck_assert(strlen(user.id.nick) < MAX_NICK_LEN);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_nickname_buffer_overflow_prevention);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}