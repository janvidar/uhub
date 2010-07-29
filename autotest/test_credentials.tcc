#include <uhub.h>

EXO_TEST(cred_to_string_1, { return !strcmp(auth_cred_to_string(auth_cred_none),     "none");     });
EXO_TEST(cred_to_string_2, { return !strcmp(auth_cred_to_string(auth_cred_bot),      "bot");      });
EXO_TEST(cred_to_string_3, { return !strcmp(auth_cred_to_string(auth_cred_guest),    "guest");    });
EXO_TEST(cred_to_string_4, { return !strcmp(auth_cred_to_string(auth_cred_user),     "user");     });
EXO_TEST(cred_to_string_5, { return !strcmp(auth_cred_to_string(auth_cred_operator), "operator"); });
EXO_TEST(cred_to_string_6, { return !strcmp(auth_cred_to_string(auth_cred_super),    "super");    });
EXO_TEST(cred_to_string_7, { return !strcmp(auth_cred_to_string(auth_cred_link),     "link");     });
EXO_TEST(cred_to_string_8, { return !strcmp(auth_cred_to_string(auth_cred_admin),    "admin");    });

#define CRED_FROM_STRING(STR, EXPECT) enum auth_credentials cred; return auth_string_to_cred(STR, &cred) && cred == EXPECT;

EXO_TEST(cred_from_string_1,  { CRED_FROM_STRING("none",     auth_cred_none);     });
EXO_TEST(cred_from_string_2,  { CRED_FROM_STRING("bot",      auth_cred_bot);      });
EXO_TEST(cred_from_string_3,  { CRED_FROM_STRING("guest",    auth_cred_guest);    });
EXO_TEST(cred_from_string_4,  { CRED_FROM_STRING("user",     auth_cred_user);     });
EXO_TEST(cred_from_string_5,  { CRED_FROM_STRING("reg",      auth_cred_user);     });
EXO_TEST(cred_from_string_6,  { CRED_FROM_STRING("operator", auth_cred_operator); });
EXO_TEST(cred_from_string_7,  { CRED_FROM_STRING("op",       auth_cred_operator); });
EXO_TEST(cred_from_string_8,  { CRED_FROM_STRING("super",    auth_cred_super);    });
EXO_TEST(cred_from_string_9,  { CRED_FROM_STRING("link",     auth_cred_link);     });
EXO_TEST(cred_from_string_10, { CRED_FROM_STRING("admin",    auth_cred_admin);    });

