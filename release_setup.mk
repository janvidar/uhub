ifeq ($(RELEASE),YES)
HOST_SYSTEM   ?= $(shell uname -s | tr [:upper:] [:lower:] | sed s/darwin/macosx/ )

ifeq ($(HOST_SYSTEM), macosx)
HOST_MACHINE  ?= $(shell uname -p | tr [:upper:] [:lower:] )
else
HOST_MACHINE  ?= $(shell uname -m | tr [:upper:] [:lower:] | sed s/i686/i386/ | sed s/x86_64/amd64/ | sed s/ppc64/powerpc/ )
endif

ifeq ($(HOST_SYSTEM), mingw32_nt-5.1)
HOST_SYSTEM   = win32
endif

VERSION       ?= $(shell grep define\ VERSION version.h | cut -f 3 -d " " | tr -d [=\"=] )
SNAPSHOT      ?= $(shell date '+%Y%m%d' )
REVISION      ?= HEAD
PACKAGE       ?= uhub-$(VERSION)
PACKAGE_SRC   ?= $(PACKAGE)-src
PACKAGE_BIN   ?= $(PACKAGE)-$(HOST_SYSTEM)-$(HOST_MACHINE)

URL_ARCHIVE='build-archive:~/uhub/'
URL_PUBLISH='domeneshop:~/www/downloads/uhub/'
URL_SNAPSHOT='domeneshop:~/www/downloads/uhub/snapshots/'

else
autotest_TMP = autotest.c
endif

