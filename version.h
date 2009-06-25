#ifndef PRODUCT
#define PRODUCT "uHub"
#endif

#ifndef GIT_REVISION
#define REVISION ""
#else
#define REVISION " (git: " GIT_REVISION ")"
#endif

#ifndef VERSION
#define VERSION "0.3.0-rc3" REVISION
#endif

#ifndef COPYRIGHT
#define COPYRIGHT "Copyright (c) 2007-2009, Jan Vidar Krey <janvidar@extatic.org>"
#endif
