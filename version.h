#include "revision.h"

#ifndef PRODUCT
#define PRODUCT "uHub"
#endif

#ifndef VERSION
#define VERSION "0.3.0"
#endif

#ifndef GIT_REVISION
#define REVISION ""
#define PRODUCT_STRING PRODUCT "/" VERSION
#else
#define REVISION "(git: " GIT_REVISION ")"
#define PRODUCT_STRING PRODUCT "/" VERSION " " REVISION
#endif

#ifndef COPYRIGHT
#define COPYRIGHT "Copyright (c) 2007-2010, Jan Vidar Krey <janvidar@extatic.org>"
#endif
