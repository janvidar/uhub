#include "revision.h"

#ifndef PRODUCT
#define PRODUCT "uhub"
#endif

#ifndef VERSION
#define VERSION "0.3.3"
#endif

#ifndef GIT_REVISION
#define REVISION ""
#define PRODUCT_STRING PRODUCT "/" VERSION
#else
#define REVISION "(git: " GIT_REVISION ")"
#ifdef GIT_VERSION
#define PRODUCT_STRING PRODUCT "/" VERSION " (" GIT_VERSION ")"
#else
#define PRODUCT_STRING PRODUCT "/" VERSION " " REVISION
#endif
#endif

#ifndef COPYRIGHT
#define COPYRIGHT "Copyright (c) 2007-2010, Jan Vidar Krey <janvidar@extatic.org>"
#endif
