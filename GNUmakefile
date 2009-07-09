 ##
## Makefile for uhub (Use GNU make)
## Copyright (C) 2007-2009, Jan Vidar Krey <janvidar@extatic.org>
 #

CC            = gcc
LD            := $(CC)
MV            := mv
RANLIB        := ranlib
CFLAGS        += -pipe -Wall
USE_PCH       ?= YES
USE_SSL       ?= NO
USE_BIGENDIAN ?= AUTO
BITS          ?= AUTO
SILENT        ?= YES
LDLIBS        += -levent
TERSE         ?= NO
STACK_PROTECT ?= NO

ifeq ($(OS), Windows_NT)
WINDOWS       ?= YES
endif

ifeq ($(WINDOWS),YES)
USE_BIGENDIAN := NO
LDLIBS        += -lws2_32
UHUB_CONF_DIR ?= c:/uhub/
UHUB_PREFIX   ?= c:/uhub/
CFLAGS        += -mno-cygwin
LDFLAGS       += -mno-cygwin
BIN_EXT       ?= .exe
GIT_REVISION  ?= NO
else
DESTDIR       ?= /
UHUB_CONF_DIR ?= $(DESTDIR)/etc/uhub
UHUB_PREFIX   ?= $(DESTDIR)/usr/local
CFLAGS        += -I/usr/local/include
LDFLAGS       += -L/usr/local/lib
BIN_EXT       ?=
endif

ifeq ($(SILENT),YES)
	MSG_CC=@echo "  CC:" $(notdir $^) &&
	MSG_PCH=@echo " PCH:" $(notdir $@) &&
	MSG_LD=@echo "  LD:" $(notdir $@) &&
	MSG_AR=@echo "  AR:" $(notdir $@) &&
else
	MSG_CC=
	MSG_PCH=
	MSG_LD=
	MSG_AR=
endif

ifeq ($(TERSE), YES)
	MSG_CC=@
	MSG_PCH=@
	MSG_LD=@
	MSG_AR=@
	MSG_CLEAN=-n ""
else
	MSG_CLEAN="Clean as a whistle"
endif

CFLAGS        += -I/source/libevent
LDFLAGS       += -L/source/libevent

ifeq ($(RELEASE),YES)
CFLAGS        += -O3 -DNDEBUG
GIT_REVISION  ?= NO
else
CFLAGS        += -ggdb -DDEBUG
GIT_REVISION  ?= YES
endif

ifeq ($(STACK_PROTECT),YES)
CFLAGS        += -fstack-protector-all
endif


ifeq ($(PROFILING),YES)
CFLAGS        += -pg
LDFLAGS       += -pg
endif

ifeq ($(FUNCTRACE),YES)
CFLAGS        += -finstrument-functions
CFLAGS        += -DDEBUG_FUNCTION_TRACE
endif

ifeq ($(USE_PCH),YES)
PCHSRC=src/uhub.h
PCH=src/uhub.h.gch
else
PCH=
endif

ifneq ($(BITS), AUTO)
ifeq ($(BITS), 64)
CFLAGS        += -m64
LDFLAGS       += -m64
else
ifeq ($(BITS), 32)
CFLAGS        += -m32
LDFLAGS       += -m32
endif
endif
endif

ifeq ($(USE_BIGENDIAN),AUTO)
ifeq ($(shell perl -e 'print pack("L", 0x554E4958)'),UNIX)
CFLAGS        += -DARCH_BIGENDIAN
endif
else
ifeq ($(USE_BIGENDIAN),YES)
CFLAGS        += -DARCH_BIGENDIAN
endif
endif

ifeq ($(USE_SSL),YES)
CFLAGS        += -DSSL_SUPPORT
LDLIBS        += -lssl
endif

ifneq ($(LIBEVENT_PATH),)
CFLAGS        += -I$(LIBEVENT_PATH)
LDFLAGS       += -L$(LIBEVENT_PATH)
endif

ifeq ($(GIT_REVISION),YES)
CFLAGS        += -DGIT_REVISION=\"$(shell git show --abbrev-commit | head -n 1 | cut -f 2 -d " ")\"
endif

# Sources
libuhub_SOURCES := \
		src/auth.c \
		src/commands.c \
		src/config.c \
		src/eventqueue.c \
		src/hub.c \
		src/hubevent.c \
		src/hubio.c \
		src/inf.c \
		src/ipcalc.c \
		src/list.c \
		src/log.c \
		src/memory.c \
		src/message.c \
		src/misc.c \
		src/netevent.c \
		src/network.c \
		src/rbtree.c \
		src/route.c \
		src/sid.c \
		src/tiger.c \
		src/user.c \
		src/usermanager.c

uhub_SOURCES := src/main.c

adcrush_SOURCES := src/adcrush.c

admin_SOURCES := src/admin.c

uhub_HEADERS := \
		src/adcconst.h \
		src/auth.h \
		src/config.h \
		src/eventid.h \
		src/eventqueue.h \
		src/hub.h \
		src/hubevent.h \
		src/hubio.h \
		src/inf.h \
		src/ipcalc.h \
		src/list.h \
		src/log.h \
		src/memory.h \
		src/message.h \
		src/misc.h \
		src/netevent.h \
		src/network.h \
		src/rbtree.h \
		src/route.h \
		src/sid.h \
		src/tiger.h \
		src/uhub.h \
		src/user.h \
		src/usermanager.h

autotest_SOURCES := \
		autotest/test_message.tcc \
		autotest/test_list.tcc \
		autotest/test_memory.tcc \
		autotest/test_ipfilter.tcc \
		autotest/test_inf.tcc \
		autotest/test_hub.tcc \
		autotest/test_misc.tcc \
		autotest/test_tiger.tcc \
		autotest/test_usermanager.tcc \
		autotest/test_eventqueue.tcc

autotest_OBJECTS = autotest.o

# Source to objects
libuhub_OBJECTS := $(libuhub_SOURCES:.c=.o)
uhub_OBJECTS    := $(uhub_SOURCES:.c=.o)
adcrush_OBJECTS := $(adcrush_SOURCES:.c=.o)
admin_OBJECTS   := $(admin_SOURCES:.c=.o)

all_OBJECTS     := $(libuhub_OBJECTS) $(uhub_OBJECTS) $(adcrush_OBJECTS) $(autotest_OBJECTS) $(admin_OBJECTS)

LIBUHUB=libuhub.a
uhub_BINARY=uhub$(BIN_EXT)
adcrush_BINARY=adcrush$(BIN_EXT)
admin_BINARY=uhub-admin$(BIN_EXT)
autotest_BINARY=autotest/test$(BIN_EXT)

%.o: %.c
	$(MSG_CC) $(CC) -c $(CFLAGS) -o $@ $^

all: $(uhub_BINARY) $(PCH)

$(adcrush_BINARY): $(PCH) $(LIBUHUB) $(adcrush_OBJECTS)
	$(MSG_LD) $(CC) -o $@ $(adcrush_OBJECTS) $(LIBUHUB) $(LDFLAGS) $(LDLIBS)

$(admin_BINARY): $(PCH) $(LIBUHUB) $(admin_OBJECTS)
	$(MSG_LD) $(CC) -o $@ $(admin_OBJECTS) $(LIBUHUB) $(LDFLAGS) $(LDLIBS)

$(uhub_BINARY): $(PCH) $(LIBUHUB) $(uhub_OBJECTS)
	$(MSG_LD) $(CC) -o $@ $(uhub_OBJECTS) $(LIBUHUB) $(LDFLAGS) $(LDLIBS)

$(LIBUHUB): $(libuhub_OBJECTS)
	$(MSG_AR) $(AR) rc $@ $^ && $(RANLIB) $@

ifeq ($(USE_PCH),YES)
$(PCH): $(uhub_HEADERS)
	$(MSG_PCH) $(CC) $(CFLAGS) -o $@ $(PCHSRC)
endif

autotest.c: $(autotest_SOURCES)
	$(shell exotic --standalone $(autotest_SOURCES) > $@)

$(autotest_OBJECTS): autotest.c
	$(MSG_CC) $(CC) -c $(CFLAGS) -Isrc -o $@ $<

$(autotest_BINARY): $(autotest_OBJECTS) $(LIBUHUB)
	$(MSG_LD) $(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

autotest: $(autotest_BINARY)
	@./$(autotest_BINARY) -s -f

ifeq ($(WINDOWS),YES)
install:
	@echo "Cannot install automatically on windows."
else
install: $(uhub_BINARY)
	@echo Copying $(uhub_BINARY) to $(UHUB_PREFIX)/bin/
	@cp $(uhub_BINARY) $(UHUB_PREFIX)/bin/
	@if [ ! -d $(UHUB_CONF_DIR) ]; then echo Creating $(UHUB_CONF_DIR); mkdir -p $(UHUB_CONF_DIR); fi
	@if [ ! -f $(UHUB_CONF_DIR)/uhub.conf ]; then cp doc/uhub.conf $(UHUB_CONF_DIR); fi
	@if [ ! -f $(UHUB_CONF_DIR)/users.conf ]; then cp doc/users.conf  $(UHUB_CONF_DIR); fi
	@touch $(UHUB_CONF_DIR)/motd.txt
	@echo done.
endif

dist-clean:
	@rm -rf $(all_OBJECTS) $(PCH) *~ core

clean:
	@rm -rf $(libuhub_OBJECTS) $(PCH) *~ core $(uhub_BINARY) $(LIBUHUB) $(all_OBJECTS) && \
	echo $(MSG_CLEAN)


