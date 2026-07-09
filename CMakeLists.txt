##
## Makefile for uhub
## Copyright (C) 2007-2026, Jan Vidar Krey <janvidar@extatic.org>
 #

cmake_minimum_required (VERSION 3.21)

project (uhub
	VERSION 0.7.1
	LANGUAGES C)

# Build everything as C23 (gnu23 - _GNU_SOURCE and friends are still needed).
set (CMAKE_C_STANDARD 23)
set (CMAKE_C_STANDARD_REQUIRED ON)
set (CMAKE_C_EXTENSIONS ON)
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

# version.h.in still refers to these by their old names.
set (UHUB_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set (UHUB_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set (UHUB_VERSION_PATCH ${PROJECT_VERSION_PATCH})

# Historically PROJECT_SOURCE_DIR (a built-in) was overwritten to point at
# src/; use a dedicated variable instead of shadowing the built-in.
set (UHUB_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")

option(RELEASE "Release build, debug build if disabled" ON)
option(LOWLEVEL_DEBUG "Enable low level debug messages." OFF)
option(SYSTEMD_SUPPORT "Enable systemd notify and journal logging" OFF)
option(ADC_STRESS "Enable the stress tester client" OFF)
option(FUZZING "Build libFuzzer fuzz targets (requires clang)" OFF)

find_package(Git)
find_package(SQLite3 REQUIRED)
# autotest/test.c is generated at build time from the *.tcc sources by the
# exotic Perl script (see the autotest-bin target below).
find_package(Perl REQUIRED)

include(CheckSymbolExists)
include(CheckIncludeFile)
include(CheckTypeSize)

# Some functions need this to be found.
add_compile_definitions(_GNU_SOURCE)
set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -D_GNU_SOURCE")

if (CMAKE_C_BYTE_ORDER STREQUAL "BIG_ENDIAN")
	add_compile_definitions(ARCH_BIGENDIAN)
endif()

if (NOT RELEASE)
	add_compile_definitions(DEBUG)
elseif (NOT MSVC)
	# Optimize release builds. Besides the obvious, this is a prerequisite for
	# _FORTIFY_SOURCE (added by the hardening block below): the fortified libc
	# checks are compiled in only when optimization is enabled.
	add_compile_options(-O2)
endif()

# Give the codebase defined behaviour for the two things it relies on that are
# otherwise UB: signed integer overflow (-fwrapv, wrap instead of UB) and
# type-punning through casts (-fno-strict-aliasing). This makes the build
# correct regardless of optimization level rather than depending on the
# compiler not exploiting the UB.
if (NOT MSVC)
	add_compile_options(-fwrapv -fno-strict-aliasing)
endif()

# Always treat warnings as errors. -Wall/-Wextra are turned on alongside so
# -Werror has warnings to act on -- the rest of the CMake build sets no warning
# level, whereas build.zig keeps -Wall -W on unconditionally.
if (MSVC)
	add_compile_options(/W4 /WX)
else()
	add_compile_options(-Wall -Wextra -Werror)
endif()

# --- Binary hardening -------------------------------------------------------
# Standard exploit-mitigation flags on GCC/Clang: stack canaries, FORTIFY,
# full RELRO + BIND_NOW, a non-executable stack, and a position-independent
# executable (ASLR for the main binary, not just the PIC libs). Every flag is
# feature-probed, so a toolchain/linker that lacks one (e.g. the macOS linker
# has no "-z relro") simply skips it rather than failing the build. Skipped for
# MSVC (different model) and for fuzzing builds (the sanitizer runtime brings
# its own hardening and FORTIFY conflicts with the ASan interceptors).
if (NOT MSVC AND NOT FUZZING)
	include(CheckCCompilerFlag)
	include(CheckLinkerFlag)
	include(CheckPIESupported)

	check_pie_supported(LANGUAGES C)
	if (CMAKE_C_LINK_PIE_SUPPORTED)
		set(CMAKE_POSITION_INDEPENDENT_CODE ON)
	endif()

	# On clang a flag that is recognized but does nothing for the target (e.g.
	# -fstack-clash-protection on arm64 macOS) only warns "argument unused", so
	# the probe would pass and then spam that warning on every TU. Promote it to
	# an error during the probe so such flags are dropped instead of added.
	set(_hardening_probe_flags "")
	if (CMAKE_C_COMPILER_ID MATCHES "Clang")
		set(_hardening_probe_flags "-Werror=unused-command-line-argument")
	endif()
	foreach (_flag -fstack-protector-strong -fstack-clash-protection)
		string(MAKE_C_IDENTIFIER "HAVE_CFLAG_${_flag}" _var)
		set(CMAKE_REQUIRED_FLAGS "${_hardening_probe_flags}")
		check_c_compiler_flag("${_flag}" ${_var})
		unset(CMAKE_REQUIRED_FLAGS)
		if (${_var})
			add_compile_options("${_flag}")
		endif()
	endforeach()

	if (RELEASE)
		# Redefinition is harmless but noisy if the toolchain predefines it.
		add_compile_options(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)
	endif()

	foreach (_lflag "-Wl,-z,relro" "-Wl,-z,now" "-Wl,-z,noexecstack")
		string(MAKE_C_IDENTIFIER "HAVE_LDFLAG_${_lflag}" _var)
		check_linker_flag(C "${_lflag}" ${_var})
		if (${_var})
			add_link_options("${_lflag}")
		endif()
	endforeach()
endif()
# ---------------------------------------------------------------------------

if (FUZZING)
	if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
		message(FATAL_ERROR "FUZZING requires clang (libFuzzer). Re-run cmake with CC=clang.")
	endif()
	# Instrument every translation unit (adc/util/network libs included) so
	# the fuzzer gets coverage feedback and ASan/UBSan checks across the whole
	# parse path, not just the harness object. The fuzz target itself adds the
	# libFuzzer runtime at link time below.
	set(FUZZ_SANITIZERS "address,undefined,fuzzer-no-link")
	string(APPEND CMAKE_C_FLAGS " -fsanitize=${FUZZ_SANITIZERS} -fno-omit-frame-pointer -g -O1")
endif()

# TLS is mandatory. find_package(OpenSSL) also locates LibreSSL (point it at a
# LibreSSL prefix with -DOPENSSL_ROOT_DIR=... when both are installed).
find_package(OpenSSL REQUIRED)

# FindOpenSSL does not distinguish LibreSSL, which masquerades as OpenSSL 2.0.0
# via OPENSSL_VERSION_NUMBER. Report the real provider so a LibreSSL build is
# obvious in the configure output.
unset(LIBRESSL_VERSION)
if (EXISTS "${OPENSSL_INCLUDE_DIR}/openssl/opensslv.h")
	file(STRINGS "${OPENSSL_INCLUDE_DIR}/openssl/opensslv.h" _libressl_text
		REGEX "^#[ \t]*define[ \t]+LIBRESSL_VERSION_TEXT")
	if (_libressl_text)
		string(REGEX MATCH "\"([^\"]+)\"" _m "${_libressl_text}")
		set(LIBRESSL_VERSION "${CMAKE_MATCH_1}")
	endif()
endif()
# uhub requires OpenSSL >= 3.0 or the contemporaneous LibreSSL >= 3.4 (both ship
# the opaque-struct API and TLS 1.3 unconditionally). Fail early at configure
# time; openssl.c also enforces this with a compile-time #error.
if (LIBRESSL_VERSION)
	message(STATUS "TLS provider: ${LIBRESSL_VERSION}")
	string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" _libressl_ver "${LIBRESSL_VERSION}")
	if (_libressl_ver AND _libressl_ver VERSION_LESS 3.4.0)
		message(FATAL_ERROR "uhub requires LibreSSL >= 3.4.0 (found ${_libressl_ver})")
	endif()
else()
	message(STATUS "TLS provider: OpenSSL ${OPENSSL_VERSION}")
	if (OPENSSL_VERSION AND OPENSSL_VERSION VERSION_LESS 3.0.0)
		message(FATAL_ERROR "uhub requires OpenSSL >= 3.0.0 (found ${OPENSSL_VERSION})")
	endif()
endif()

if (SYSTEMD_SUPPORT)
	find_package(PkgConfig REQUIRED)
	pkg_check_modules(SD REQUIRED IMPORTED_TARGET libsystemd)
endif()

if (MSVC)
	add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

check_include_file(stdint.h HAVE_STDINT_H)
check_include_file(sys/types.h HAVE_SYS_TYPES_H)
if (HAVE_SYS_TYPES_H)
	list(APPEND CMAKE_EXTRA_INCLUDE_FILES "sys/types.h")
endif()
check_include_file(sys/uio.h HAVE_SYS_UIO_H)
check_type_size(ssize_t SSIZE_T)
check_symbol_exists(memmem string.h HAVE_MEMMEM)
check_symbol_exists(strndup string.h HAVE_STRNDUP)
check_symbol_exists(writev sys/uio.h HAVE_FUNC_WRITEV)

# These directories hold sources and generated headers (version.h/system.h);
# every uhub target needs them, so keep them at directory scope.
include_directories("${UHUB_SOURCE_DIR}")
include_directories("${PROJECT_BINARY_DIR}")

# system.h pulls in <openssl/*.h>, so every translation unit (including the
# openssl.c in the network static lib and the plugins) must compile against the
# same TLS headers it will link against. The link libraries alone do not carry
# this to the static libs, so apply the include dir at directory scope -- this
# is what lets a LibreSSL prefix (-DOPENSSL_ROOT_DIR=...) build correctly.
include_directories("${OPENSSL_INCLUDE_DIR}")

file (GLOB uhub_SOURCES CONFIGURE_DEPENDS ${UHUB_SOURCE_DIR}/core/*.c)
list (REMOVE_ITEM uhub_SOURCES
	${UHUB_SOURCE_DIR}/core/gen_config.c
	${UHUB_SOURCE_DIR}/core/main.c
)

file (GLOB adc_SOURCES     CONFIGURE_DEPENDS ${UHUB_SOURCE_DIR}/adc/*.c)
file (GLOB network_SOURCES CONFIGURE_DEPENDS ${UHUB_SOURCE_DIR}/network/*.c)
file (GLOB utils_SOURCES   CONFIGURE_DEPENDS ${UHUB_SOURCE_DIR}/util/*.c)

set (adcclient_SOURCES
	${UHUB_SOURCE_DIR}/tools/adcclient.c
	${UHUB_SOURCE_DIR}/core/ioqueue.c
)

add_library(adc       STATIC ${adc_SOURCES})
add_library(network   STATIC ${network_SOURCES})
add_library(utils     STATIC ${utils_SOURCES})

# utils and network are linked into the loadable mod_*.so plugins, so they
# need position-independent code.
set_target_properties(utils network PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_dependencies(adc utils)
add_dependencies(network utils)

# Generate the autotest driver (autotest/test.c) from the *.tcc test sources.
# This replaces the manual `autotest/update.sh` step: editing or adding a .tcc
# file re-runs exotic at build time. CONFIGURE_DEPENDS re-globs when a .tcc is
# added or removed; the explicit DEPENDS re-runs exotic when one is edited.
set (AUTOTEST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/autotest")
set (AUTOTEST_GENERATED "${PROJECT_BINARY_DIR}/autotest_test.c")
file (GLOB autotest_TCC CONFIGURE_DEPENDS ${AUTOTEST_DIR}/test_*.tcc)
list (SORT autotest_TCC)
# exotic embeds each argument verbatim as #include "<arg>", so pass bare
# basenames and run from AUTOTEST_DIR; autotest-bin adds AUTOTEST_DIR to its
# include path so those quoted includes resolve from the build tree.
set (autotest_TCC_NAMES "")
foreach (_tcc ${autotest_TCC})
	get_filename_component (_tcc_name ${_tcc} NAME)
	list (APPEND autotest_TCC_NAMES ${_tcc_name})
endforeach()
add_custom_command(
	OUTPUT ${AUTOTEST_GENERATED}
	COMMAND ${PERL_EXECUTABLE} ${AUTOTEST_DIR}/exotic ${autotest_TCC_NAMES} > ${AUTOTEST_GENERATED}
	DEPENDS ${AUTOTEST_DIR}/exotic ${autotest_TCC}
	WORKING_DIRECTORY ${AUTOTEST_DIR}
	COMMENT "Generating autotest driver from *.tcc (exotic)"
	VERBATIM)

add_executable(uhub ${UHUB_SOURCE_DIR}/core/main.c ${uhub_SOURCES})
# mod_auth_sqlite.c is compiled into the test binary (not just built as a
# loadable module) so test_mod_auth_sqlite.tcc can drive its auth functions
# directly via plugin_register(); it pulls in SQLite, hence the extra link.
add_executable(autotest-bin ${AUTOTEST_GENERATED} ${uhub_SOURCES} ${UHUB_SOURCE_DIR}/plugins/mod_auth_sqlite.c)
target_include_directories(autotest-bin PRIVATE ${AUTOTEST_DIR})
# Absolute path to the autotest/ dir so tests can locate checked-in fixtures
# (e.g. the TLS test certificate) regardless of the working directory.
target_compile_definitions(autotest-bin PRIVATE UHUB_TEST_DIR="${AUTOTEST_DIR}")
add_executable(uhub-passwd ${UHUB_SOURCE_DIR}/tools/uhub-passwd.c)

add_library(mod_example MODULE ${UHUB_SOURCE_DIR}/plugins/mod_example.c)
add_library(mod_welcome MODULE ${UHUB_SOURCE_DIR}/plugins/mod_welcome.c)
add_library(mod_logging MODULE ${UHUB_SOURCE_DIR}/plugins/mod_logging.c ${UHUB_SOURCE_DIR}/adc/sid.c)
add_library(mod_auth_simple MODULE ${UHUB_SOURCE_DIR}/plugins/mod_auth_simple.c)
add_library(mod_chat_history MODULE ${UHUB_SOURCE_DIR}/plugins/mod_chat_history.c)
add_library(mod_chat_history_sqlite MODULE ${UHUB_SOURCE_DIR}/plugins/mod_chat_history_sqlite.c)
add_library(mod_chat_only MODULE ${UHUB_SOURCE_DIR}/plugins/mod_chat_only.c)
add_library(mod_topic MODULE ${UHUB_SOURCE_DIR}/plugins/mod_topic.c)
add_library(mod_ucmd MODULE ${UHUB_SOURCE_DIR}/plugins/mod_ucmd.c)
add_library(mod_no_guest_downloads MODULE ${UHUB_SOURCE_DIR}/plugins/mod_no_guest_downloads.c)
add_library(mod_flood MODULE ${UHUB_SOURCE_DIR}/plugins/mod_flood.c)
add_library(mod_auth_sqlite MODULE ${UHUB_SOURCE_DIR}/plugins/mod_auth_sqlite.c)
add_library(mod_selfregister MODULE ${UHUB_SOURCE_DIR}/plugins/mod_selfregister.c)

set_target_properties(
	mod_example
	mod_welcome
	mod_logging
	mod_auth_simple
	mod_auth_sqlite
	mod_selfregister
	mod_chat_history
	mod_chat_history_sqlite
	mod_chat_only
	mod_no_guest_downloads
	mod_flood
	mod_topic
	mod_ucmd
	PROPERTIES PREFIX "")

target_link_libraries(uhub ${CMAKE_DL_LIBS} adc network utils)
target_link_libraries(uhub-passwd SQLite::SQLite3 utils)
target_link_libraries(autotest-bin ${CMAKE_DL_LIBS} adc network utils SQLite::SQLite3)
target_link_libraries(mod_example utils)
target_link_libraries(mod_welcome network utils)
target_link_libraries(mod_auth_simple utils)
target_link_libraries(mod_auth_sqlite SQLite::SQLite3 utils)
target_link_libraries(mod_selfregister utils)
target_link_libraries(mod_chat_history utils)
target_link_libraries(mod_chat_history_sqlite SQLite::SQLite3 utils)
target_link_libraries(mod_no_guest_downloads utils)
target_link_libraries(mod_flood utils)
target_link_libraries(mod_chat_only utils)
target_link_libraries(mod_logging network utils)
target_link_libraries(mod_topic utils)
target_link_libraries(mod_ucmd utils)

if(WIN32)
	target_link_libraries(uhub ws2_32)
	target_link_libraries(autotest-bin ws2_32)
	target_link_libraries(mod_logging ws2_32)
	target_link_libraries(mod_welcome ws2_32)
endif()

if(UNIX)
	add_library(adcclient STATIC ${adcclient_SOURCES})
	add_executable(uhub-admin ${UHUB_SOURCE_DIR}/tools/admin.c)
	target_link_libraries(uhub-admin adcclient adc network utils pthread)
	target_link_libraries(uhub pthread)
	target_link_libraries(autotest-bin pthread)

	if (ADC_STRESS)
		add_executable(adcrush ${UHUB_SOURCE_DIR}/tools/adcrush.c ${adcclient_SOURCES})
		target_link_libraries(adcrush adcclient adc network utils pthread)

		add_executable(linktest ${UHUB_SOURCE_DIR}/tools/linktest.c ${adcclient_SOURCES})
		target_link_libraries(linktest adcclient adc network utils pthread)
	endif()
endif()

if (NOT UHUB_REVISION AND GIT_FOUND)
	execute_process(COMMAND ${GIT_EXECUTABLE} show -s --pretty=format:%h
					WORKING_DIRECTORY ${UHUB_SOURCE_DIR}
					OUTPUT_VARIABLE UHUB_REVISION_TEMP
					OUTPUT_STRIP_TRAILING_WHITESPACE)
	if (UHUB_REVISION_TEMP)
		set (UHUB_REVISION "git-${UHUB_REVISION_TEMP}")
	endif()
endif()

if (NOT UHUB_REVISION)
	set (UHUB_REVISION "release")
endif()

set (UHUB_GIT_VERSION "${UHUB_VERSION_MAJOR}.${UHUB_VERSION_MINOR}.${UHUB_VERSION_PATCH}-${UHUB_REVISION}")
message (STATUS "Configuring uhub version: ${UHUB_GIT_VERSION}")

set(SSL_LIBS OpenSSL::SSL OpenSSL::Crypto)

target_link_libraries(uhub ${SSL_LIBS})
target_link_libraries(autotest-bin ${SSL_LIBS})
if(UNIX)
	target_link_libraries(uhub-admin ${SSL_LIBS})
endif()
target_link_libraries(mod_welcome ${SSL_LIBS})
target_link_libraries(mod_logging ${SSL_LIBS})
if (ADC_STRESS)
	target_link_libraries(adcrush ${SSL_LIBS})
	target_link_libraries(linktest ${SSL_LIBS})
endif()

if (SYSTEMD_SUPPORT)
	target_link_libraries(uhub PkgConfig::SD)
	target_link_libraries(autotest-bin PkgConfig::SD)
	target_link_libraries(uhub-passwd PkgConfig::SD)
	target_link_libraries(uhub-admin PkgConfig::SD)
	add_compile_definitions(SYSTEMD)
endif()

if (FUZZING)
	# Define a fuzz target. Extra args after the name are additional sources
	# (e.g. the core objects needed by the command parser).
	macro(add_fuzzer name)
		add_executable(${name} ${ARGN})
		target_link_libraries(${name} adc network utils ${CMAKE_DL_LIBS} ${SSL_LIBS})
		if (UNIX)
			target_link_libraries(${name} pthread)
		endif()
		# Pull in the libFuzzer runtime (provides main()) plus the runtime
		# sanitizers for the harness object itself.
		set_target_properties(${name} PROPERTIES
			LINK_FLAGS "-fsanitize=address,undefined,fuzzer")
	endmacro()

	add_fuzzer(fuzz_message      ${UHUB_SOURCE_DIR}/tools/fuzz_message.c)
	add_fuzzer(fuzz_adc_escape   ${UHUB_SOURCE_DIR}/tools/fuzz_adc_escape.c)
	add_fuzzer(fuzz_ipcalc       ${UHUB_SOURCE_DIR}/tools/fuzz_ipcalc.c)
	add_fuzzer(fuzz_config_token ${UHUB_SOURCE_DIR}/tools/fuzz_config_token.c)
	# command_parse() lives in the hub core, so compile the core objects in
	# (same source set as autotest-bin, minus main.c / gen_config.c).
	add_fuzzer(fuzz_command_parser ${UHUB_SOURCE_DIR}/tools/fuzz_command_parser.c ${uhub_SOURCES})
	# metrics_classify_request() likewise lives in the hub core.
	add_fuzzer(fuzz_metrics        ${UHUB_SOURCE_DIR}/tools/fuzz_metrics.c ${uhub_SOURCES})
	# hub_handle_info_login() (the connect-time INF checks) is in the hub core too.
	add_fuzzer(fuzz_login          ${UHUB_SOURCE_DIR}/tools/fuzz_login.c ${uhub_SOURCES})
endif()

configure_file ("${UHUB_SOURCE_DIR}/version.h.in" "${PROJECT_BINARY_DIR}/version.h")
configure_file ("${UHUB_SOURCE_DIR}/system.h.in" "${PROJECT_BINARY_DIR}/system.h")

if (LOWLEVEL_DEBUG)
	add_compile_definitions(LOWLEVEL_DEBUG)
endif()

if (UNIX)
	install( TARGETS uhub uhub-passwd RUNTIME DESTINATION bin )
	install( TARGETS mod_example mod_welcome mod_logging mod_auth_simple mod_auth_sqlite mod_selfregister mod_chat_history mod_chat_history_sqlite mod_chat_only mod_topic mod_no_guest_downloads mod_flood mod_ucmd DESTINATION /usr/lib/uhub/ OPTIONAL )
	install( FILES ${CMAKE_CURRENT_SOURCE_DIR}/doc/uhub.conf ${CMAKE_CURRENT_SOURCE_DIR}/doc/plugins.conf ${CMAKE_CURRENT_SOURCE_DIR}/doc/rules.txt ${CMAKE_CURRENT_SOURCE_DIR}/doc/motd.txt DESTINATION /etc/uhub OPTIONAL )
endif()
