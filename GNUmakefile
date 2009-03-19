 ##
## Makefile for uhub (Use GNU make)
## Copyright (C) 2007-2008, Jan Vidar Krey <janvidar@extatic.org>
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

-include release_setup.mk
ifeq ($(RELEASE),YES)
CFLAGS        += -Os -DNDEBUG
else
CFLAGS        += -g -DDEBUG
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

# Sources
libuhub_SOURCES := \
		src/auth.c \
		src/commands.c \
		src/config.c \
		src/eventqueue.c \
		src/hubevent.c \
		src/hub.c \
		src/inf.c \
		src/ipcalc.c \
		src/list.c \
		src/log.c \
		src/memory.c \
		src/message.c \
		src/misc.c \
		src/netevent.c \
		src/network.c \
		src/route.c \
		src/sid.c \
		src/tiger.c \
		src/user.c \
		src/usermanager.c

uhub_SOURCES := src/main.c

adcrush_SOURCES := src/adcrush.c

uhub_HEADERS := \
		src/adcconst.h \
		src/auth.h \
		src/config.h \
		src/eventid.h \
		src/eventqueue.h \
		src/hubevent.h \
		src/hub.h \
		src/inf.h \
		src/ipcalc.h \
		src/list.h \
		src/log.h \
		src/memory.h \
		src/message.h \
		src/misc.h \
		src/netevent.h \
		src/network.h \
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
		autotest/test_eventqueue.tcc

autotest_OBJECTS = autotest.o

# Source to objects
libuhub_OBJECTS := $(libuhub_SOURCES:.c=.o)
uhub_OBJECTS    := $(uhub_SOURCES:.c=.o)
adcrush_OBJECTS := $(adcrush_SOURCES:.c=.o)

all_OBJECTS     := $(libuhub_OBJECTS) $(uhub_OBJECTS) $(adcrush_OBJECTS) $(autotest_OBJECTS)

LIBUHUB=libuhub.a
uhub_BINARY=uhub$(BIN_EXT)
adcrush_BINARY=adcrush$(BIN_EXT)
autotest_BINARY=autotest/test$(BIN_EXT)

%.o: %.c
	$(MSG_CC) $(CC) -c $(CFLAGS) -o $@.tmp $^ && \
	$(MV) $@.tmp $@

all: $(uhub_BINARY) $(PCH)

$(adcrush_BINARY): $(PCH) $(LIBUHUB) $(adcrush_OBJECTS)
	$(MSG_LD) $(CC) -o $@.tmp $(adcrush_OBJECTS) $(LIBUHUB) $(LDFLAGS) $(LDLIBS) && \
        $(MV) $@.tmp $@

$(uhub_BINARY): $(PCH) $(LIBUHUB) $(uhub_OBJECTS)
	$(MSG_LD) $(CC) -o $@.tmp $(uhub_OBJECTS) $(LIBUHUB) $(LDFLAGS) $(LDLIBS) && \
	$(MV) $@.tmp $@

$(LIBUHUB): $(libuhub_OBJECTS)
	$(MSG_AR) $(AR) rc $@.tmp $^ && \
	$(RANLIB) $@.tmp && \
	$(MV) $@.tmp $@

ifeq ($(USE_PCH),YES)
$(PCH): $(uhub_HEADERS)
	$(MSG_PCH) $(CC) $(CFLAGS) -o $@.tmp $(PCHSRC) && \
	$(MV) $@.tmp $@
endif

autotest.c: $(autotest_SOURCES)
	$(shell exotic --standalone $(autotest_SOURCES) > $@)

$(autotest_OBJECTS): autotest.c
	$(MSG_CC) $(CC) -c $(CFLAGS) -Isrc -o $@.tmp $< && \
	$(MV) $@.tmp $@

$(autotest_BINARY): $(autotest_OBJECTS) $(LIBUHUB)
	$(MSG_LD) $(CC) -o $@.tmp $^ $(LDFLAGS) $(LDLIBS) && \
	$(MV) $@.tmp $@

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

-include release_targets.mk

