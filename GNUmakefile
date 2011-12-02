 ##
## Makefile for uhub (Use GNU make)
## Copyright (C) 2007-2010, Jan Vidar Krey <janvidar@extatic.org>
 #

-include Makefile.private

CC            = gcc
LD            := $(CC)
MV            := mv
RANLIB        := ranlib
CFLAGS        += -pipe -Wall
USE_SSL       ?= YES
USE_PLUGINS   ?= YES
USE_BIGENDIAN ?= AUTO
BITS          ?= AUTO
SILENT        ?= YES
TERSE         ?= NO
STACK_PROTECT ?= NO

ifeq ($(OS), Windows_NT)
WINDOWS       ?= YES
OPSYS ?= Windows
else
OPSYS ?= $(shell uname)
endif

ifeq ($(OPSYS),SunOS)
LDLIBS        += -lsocket -lnsl
endif

ifeq ($(OPSYS),Haiku)
LDLIBS        += -lnetwork
endif

CFLAGS        += -I./src/

ifeq ($(OPSYS),Windows)
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
UHUB_MOD_DIR  ?= $(DESTDIR)/var/lib/uhub
CFLAGS        += -I/usr/local/include
LDFLAGS       += -L/usr/local/lib
BIN_EXT       ?=
endif

ifeq ($(SILENT),YES)
	MSG_CC=@echo "  CC:" $(notdir $<) &&
	MSG_LD=@echo "  LD:" $(notdir $@) &&
	MSG_AR=@echo "  AR:" $(notdir $@) &&
else
	MSG_CC=
	MSG_LD=
	MSG_AR=
endif

ifeq ($(TERSE), YES)
	MSG_CC=@
	MSG_LD=@
	MSG_AR=@
	MSG_CLEAN=-n ""
else
	MSG_CLEAN="Clean as a whistle"
endif

ifeq ($(RELEASE),YES)
CFLAGS        += -O3 -DNDEBUG
else
CFLAGS        += -ggdb -DDEBUG
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
LDLIBS        += -lssl -lcrypto
endif

GIT_VERSION=$(shell git describe --tags 2>/dev/null || echo "")
GIT_REVISION=$(shell git show --abbrev-commit  2>/dev/null | head -n 1 | cut -f 2 -d " " || echo "")
OLD_REVISION=$(shell grep GIT_REVISION revision.h 2>/dev/null | cut -f 3 -d " " | tr -d "\"")

# Sources
libuhub_SOURCES := \
		src/core/auth.c \
		src/core/commands.c \
		src/core/config.c \
		src/core/eventqueue.c \
		src/core/hub.c \
		src/core/hubevent.c \
		src/core/hubio.c \
		src/core/inf.c \
		src/core/netevent.c \
		src/core/probe.c \
		src/core/route.c \
		src/core/user.c \
		src/core/usermanager.c \
		src/core/plugininvoke.c \
		src/core/pluginloader.c \
		src/network/backend.c \
		src/network/connection.c \
		src/network/epoll.c \
		src/network/kqueue.c \
		src/network/network.c \
		src/network/select.c \
		src/network/timeout.c \
		src/network/timer.c


libadc_common_SOURCES := \
		src/adc/message.c \
		src/adc/sid.c

libutils_SOURCES := \
		src/util/config_token.c \
		src/util/credentials.c \
		src/util/floodctl.c \
		src/util/ipcalc.c \
		src/util/list.c \
		src/util/log.c \
		src/util/memory.c \
		src/util/misc.c \
		src/util/rbtree.c \
		src/util/tiger.c

libadc_client_SOURCES := \
		src/tools/adcclient.c

uhub_SOURCES := src/core/main.c

adcrush_SOURCES := src/tools/adcrush.c

admin_SOURCES := src/tools/admin.c

autotest_SOURCES := \
		autotest/test_credentials.tcc \
		autotest/test_eventqueue.tcc \
		autotest/test_hub.tcc \
		autotest/test_inf.tcc \
		autotest/test_ipfilter.tcc \
		autotest/test_list.tcc \
		autotest/test_memory.tcc \
		autotest/test_message.tcc \
		autotest/test_misc.tcc \
		autotest/test_sid.tcc \
		autotest/test_tiger.tcc \
		autotest/test_timer.tcc \
		autotest/test_tokenizer.tcc \
		autotest/test_usermanager.tcc

autotest_OBJECTS = autotest.o

# Plugin targets:
plugin_example_SOURCES := src/plugins/mod_example.c
plugin_example_TARGET  := mod_example.so

plugin_logging_SOURCES := src/plugins/mod_logging.c
plugin_logging_TARGET  := mod_logging.so

plugin_auth_SOURCES    := src/plugins/mod_auth_simple.c
plugin_auth_TARGET     := mod_auth_simple.so

plugin_auth_sqlite_SOURCES := src/plugins/mod_auth_sqlite.c
plugin_auth_sqlite_TARGET  := mod_auth_sqlite.so
plugin_auth_sqlite_LIBS    := -lsqlite3


# Source to objects
libuhub_OBJECTS       := $(libuhub_SOURCES:.c=.o)
libutils_OBJECTS      := $(libutils_SOURCES:.c=.o)
libadc_client_OBJECTS := $(libadc_client_SOURCES:.c=.o)
libadc_common_OBJECTS := $(libadc_common_SOURCES:.c=.o)

uhub_OBJECTS          := $(uhub_SOURCES:.c=.o)
adcrush_OBJECTS       := $(adcrush_SOURCES:.c=.o)
admin_OBJECTS         := $(admin_SOURCES:.c=.o)

all_OBJECTS     := $(libuhub_OBJECTS) $(uhub_OBJECTS) $(libutils_OBJECTS) $(adcrush_OBJECTS) $(autotest_OBJECTS) $(admin_OBJECTS) $(libadc_common_OBJECTS) $(libadc_client_OBJECTS)
all_plugins     :=

uhub_BINARY=uhub$(BIN_EXT)
adcrush_BINARY=adcrush$(BIN_EXT)
admin_BINARY=uhub-admin$(BIN_EXT)
autotest_BINARY=autotest/test$(BIN_EXT)

ifeq ($(USE_PLUGINS),YES)
all_plugins     := $(plugin_example_TARGET) $(plugin_logging_TARGET) $(plugin_auth_TARGET) $(plugin_auth_sqlite_TARGET)
all_OBJECTS     += $(all_plugins)
endif

.PHONY: revision.h.tmp all plugins

%.o: %.c version.h revision.h
	$(MSG_CC) $(CC) -fPIC -c $(CFLAGS) -o $@ $<

all: $(uhub_BINARY) plugins

plugins: $(uhub_BINARY) $(all_plugins)

$(plugin_auth_TARGET): $(plugin_auth_SOURCES) $(libutils_OBJECTS)
	$(MSG_CC) $(CC) -shared -fPIC -o $@ $^ $(CFLAGS)

$(plugin_auth_sqlite_TARGET): $(plugin_auth_sqlite_SOURCES) $(libutils_OBJECTS) 
	$(MSG_CC) $(CC) -shared -fPIC -o $@ $^ $(CFLAGS) $(LDFLAGS) $(plugin_auth_sqlite_LIBS)

$(plugin_example_TARGET): $(plugin_example_SOURCES)
	$(MSG_CC) $(CC) -shared -fPIC -o $@ $^ $(CFLAGS)

$(plugin_logging_TARGET): $(plugin_logging_SOURCES) $(libutils_OBJECTS) $(libadc_common_OBJECTS) src/network/network.o
	$(MSG_CC) $(CC) -shared -fPIC -o $@ $^ $(CFLAGS)

$(adcrush_BINARY): $(adcrush_OBJECTS) $(libuhub_OBJECTS) $(libutils_OBJECTS) $(libadc_common_OBJECTS) $(libadc_client_OBJECTS)
	$(MSG_LD) $(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

$(admin_BINARY): $(admin_OBJECTS) $(libuhub_OBJECTS) $(libutils_OBJECTS) $(libadc_common_OBJECTS) $(libadc_client_OBJECTS)
	$(MSG_LD) $(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

$(uhub_BINARY): $(uhub_OBJECTS) $(libuhub_OBJECTS) $(libutils_OBJECTS) $(libadc_common_OBJECTS)
	$(MSG_LD) $(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

autotest.c: $(autotest_SOURCES)
	$(shell exotic --standalone $(autotest_SOURCES) > $@)

revision.h.tmp:
	@rm -f $@
	@echo "/* AUTOGENERATED FILE - DO NOT EDIT */" > $@
	@if [ -n '$(GIT_VERSION)' ]; then echo \#define GIT_VERSION \"$(GIT_VERSION)\" >> $@; fi
	@if [ -n '$(GIT_REVISION)' ]; then echo \#define GIT_REVISION \"$(GIT_REVISION)\" >> $@; fi

version.h: revision.h

revision.h: revision.h.tmp
	@if [ '$(GIT_REVISION)' != '$(OLD_REVISION)' ]; then cp $@.tmp $@; fi
	@if [ ! -f $@ ]; then cp $@.tmp $@; fi

$(autotest_OBJECTS): autotest.c
	$(MSG_CC) $(CC) -c $(CFLAGS) -Isrc -o $@ $<

$(autotest_BINARY): $(autotest_OBJECTS) $(libuhub_OBJECTS) $(libutils_OBJECTS) $(libadc_common_OBJECTS) $(libadc_client_OBJECTS)
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
	@if [ ! -f $(UHUB_CONF_DIR)/rules.txt ]; then cp doc/rules.txt  $(UHUB_CONF_DIR); fi
	@if [ ! -f $(UHUB_CONF_DIR)/plugins.conf ]; then cp doc/plugins.conf  $(UHUB_CONF_DIR); fi
	@if [ ! -d $(UHUB_MOD_DIR) ]; then echo Creating $(UHUB_MOD_DIR); mkdir -p $(UHUB_MOD_DIR); fi
	@cp -f mod_*.so $(UHUB_MOD_DIR)
	@touch $(UHUB_CONF_DIR)/motd.txt
	@echo done.
endif

dist-clean:
	@rm -rf $(all_OBJECTS) *~ core

clean:
	@rm -rf $(libuhub_OBJECTS) *~ core $(uhub_BINARY) $(admin_BINARY) $(autotest_BINARY) $(adcrush_BINARY) $(all_OBJECTS) $(all_plugins) autotest.c revision.h revision.h.tmp && \
	echo $(MSG_CLEAN)


