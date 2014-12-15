 ##
## Makefile for uhub
## Copyright (C) 2007-2013, Jan Vidar Krey <janvidar@extatic.org>
 #

cmake_minimum_required (VERSION 2.8.2)

project (uhub NONE)
enable_language(C)

set (UHUB_VERSION_MAJOR 0)
set (UHUB_VERSION_MINOR 5)
set (UHUB_VERSION_PATCH 0)

set (PROJECT_SOURCE_DIR "${CMAKE_SOURCE_DIR}/src")
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake/Modules)

option(RELEASE "Release build, debug build if disabled" ON)
option(LOWLEVEL_DEBUG, "Enable low level debug messages." OFF)
option(SSL_SUPPORT "Enable SSL support" ON)
option(USE_OPENSSL "Use OpenSSL's SSL support" ON )
option(SYSTEMD_SUPPORT "Enable systemd notify and journal logging" OFF)
option(ADC_STRESS "Enable the stress tester client" OFF)

find_package(Git)
find_package(Sqlite3)

include(TestBigEndian)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckTypeSize)

#Some functions need this to be found
add_definitions(-D_GNU_SOURCE)
set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -D_GNU_SOURCE")

TEST_BIG_ENDIAN(BIGENDIAN)
if (BIGENDIAN)
	add_definitions(-DARCH_BIGENDIAN)
endif()

if (NOT RELEASE)
        add_definitions(-DDEBUG)
endif()

if (SSL_SUPPORT)
	if (USE_OPENSSL)
		find_package(OpenSSL)
	else()
		find_package(GnuTLS)
	endif()
	if (NOT GNUTLS_FOUND AND NOT OPENSSL_FOUND)
		message(FATAL_ERROR "Neither OpenSSL nor GnuTLS were found!")
	endif()
endif()

if (SYSTEMD_SUPPORT)
        INCLUDE(FindPkgConfig)
        pkg_search_module(SD_DAEMON REQUIRED libsystemd-daemon)
        pkg_search_module(SD_JOURNAL REQUIRED libsystemd-journal)
endif()

if (MSVC)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

check_include_file(stdint.h HAVE_STDINT_H)
check_include_file(sys/types.h HAVE_SYS_TYPES_H)
if (HAVE_SYS_TYPES_H)
set (CMAKE_EXTRA_INCLUDE_FILES ${CMAKE_EXTRA_INCLUDE_FILES} "sys/types.h")
endif()

check_include_file(sys/uio.h HAVE_SYS_UIO_H)
if (HAVE_SYS_UIO_H)
set (CMAKE_EXTRA_INCLUDE_FILES ${CMAKE_EXTRA_INCLUDE_FILES} "sys/uio.h")
endif()

check_type_size(ssize_t SSIZE_T)
check_symbol_exists(memmem string.h HAVE_MEMMEM)
check_symbol_exists(strndup string.h HAVE_STRNDUP)
check_function_exists(writev HAVE_FUNC_WRITEV)
check_function_exists(pwritev HAVE_FUNC_PWRITEV)
check_function_exists(readv HAVE_FUNC_WRITEV)
check_function_exists(preadv HAVE_FUNC_PWRITEV)

include_directories("${PROJECT_SOURCE_DIR}")
include_directories(${SQLITE3_INCLUDE_DIRS})
link_directories(${SQLITE3_LIBRARY_DIRS})

file (GLOB uhub_SOURCES ${PROJECT_SOURCE_DIR}/core/*.c)
list (REMOVE_ITEM uhub_SOURCES
	${PROJECT_SOURCE_DIR}/core/gen_config.c
	${PROJECT_SOURCE_DIR}/core/main.c
)

file (GLOB adc_SOURCES ${PROJECT_SOURCE_DIR}/adc/*.c)
file (GLOB network_SOURCES ${PROJECT_SOURCE_DIR}/network/*.c)
file (GLOB utils_SOURCES ${PROJECT_SOURCE_DIR}/util/*.c)

set (adcclient_SOURCES
	${PROJECT_SOURCE_DIR}/tools/adcclient.c
	${PROJECT_SOURCE_DIR}/core/ioqueue.c
)

add_library(adc       STATIC ${adc_SOURCES})
add_library(network   STATIC ${network_SOURCES})
add_library(utils     STATIC ${utils_SOURCES})
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
	set_target_properties(utils PROPERTIES COMPILE_FLAGS -fPIC)
	set_target_properties(network PROPERTIES COMPILE_FLAGS -fPIC)
endif()

add_dependencies(adc utils)
add_dependencies(network utils)

add_executable(uhub ${PROJECT_SOURCE_DIR}/core/main.c ${uhub_SOURCES} )
add_executable(test ${CMAKE_SOURCE_DIR}/autotest/test.c ${uhub_SOURCES} )
add_executable(uhub-passwd ${PROJECT_SOURCE_DIR}/tools/uhub-passwd.c)

add_library(mod_example MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_example.c)
add_library(mod_welcome MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_welcome.c)
add_library(mod_logging MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_logging.c ${PROJECT_SOURCE_DIR}/adc/sid.c)
add_library(mod_auth_simple MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_auth_simple.c )
add_library(mod_chat_history MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_chat_history.c )
add_library(mod_chat_history_sqlite MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_chat_history_sqlite.c )
add_library(mod_chat_only MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_chat_only.c)
add_library(mod_topic MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_topic.c)
add_library(mod_no_guest_downloads MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_no_guest_downloads.c)
add_library(mod_auth_sqlite MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_auth_sqlite.c)

if(WIN32)
	target_link_libraries(uhub ws2_32)
	target_link_libraries(test ws2_32)
	target_link_libraries(mod_logging ws2_32)
	target_link_libraries(mod_welcome ws2_32)
endif()

set_target_properties(
	mod_example
	mod_welcome
	mod_logging
	mod_auth_simple
	mod_auth_sqlite
	mod_chat_history
	mod_chat_history_sqlite
	mod_chat_only
	mod_no_guest_downloads
	mod_topic
	PROPERTIES PREFIX "")

target_link_libraries(uhub ${CMAKE_DL_LIBS} adc network utils)
target_link_libraries(uhub-passwd ${SQLITE3_LIBRARIES} utils)
target_link_libraries(test ${CMAKE_DL_LIBS} adc network utils)
target_link_libraries(mod_example utils)
target_link_libraries(mod_welcome utils)
target_link_libraries(mod_auth_simple utils)
target_link_libraries(mod_auth_sqlite ${SQLITE3_LIBRARIES} utils)
target_link_libraries(mod_chat_history utils)
target_link_libraries(mod_chat_history_sqlite ${SQLITE3_LIBRARIES} utils)
target_link_libraries(mod_no_guest_downloads utils)
target_link_libraries(mod_chat_only utils)
target_link_libraries(mod_logging utils)
target_link_libraries(mod_topic utils)
target_link_libraries(utils network)
target_link_libraries(mod_welcome network)
target_link_libraries(mod_logging network)


if(UNIX)
	add_library(adcclient STATIC ${adcclient_SOURCES})
	add_executable(uhub-admin ${PROJECT_SOURCE_DIR}/tools/admin.c)
	target_link_libraries(uhub-admin adcclient adc network utils pthread)
	target_link_libraries(uhub pthread)
	target_link_libraries(test pthread)

	if (ADC_STRESS)
		add_executable(adcrush ${PROJECT_SOURCE_DIR}/tools/adcrush.c ${adcclient_SOURCES})
		target_link_libraries(adcrush adcclient adc network utils pthread)
	endif()
endif()

if (NOT UHUB_REVISION AND GIT_FOUND)
	execute_process(COMMAND ${GIT_EXECUTABLE} show -s --pretty=format:%h
					WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
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

if(OPENSSL_FOUND)
	set(SSL_LIBS ${OPENSSL_LIBRARIES})
	add_definitions(-DSSL_SUPPORT=1 -DSSL_USE_OPENSSL=1)
	include_directories(${OPENSSL_INCLUDE_DIR})
endif()

if (GNUTLS_FOUND)
	set(SSL_LIBS ${GNUTLS_LIBRARIES})
	add_definitions(-DSSL_SUPPORT=1 -DSSL_USE_GNUTLS=1 ${GNUTLS_DEFINITIONS})
	include_directories(${GNUTLS_INCLUDE_DIR})
endif()

if(SSL_SUPPORT)
	target_link_libraries(uhub ${SSL_LIBS})
	target_link_libraries(test ${SSL_LIBS})
	if(UNIX)
		target_link_libraries(uhub-admin ${SSL_LIBS})
	endif()
	target_link_libraries(mod_welcome ${SSL_LIBS})
	target_link_libraries(mod_logging ${SSL_LIBS})
	if (ADC_STRESS)
		target_link_libraries(adcrush ${SSL_LIBS})
	endif()
endif()

if (SYSTEMD_SUPPORT)
        target_link_libraries(uhub ${SD_DAEMON_LIBRARIES})
        target_link_libraries(uhub ${SD_JOURNAL_LIBRARIES})
        target_link_libraries(test ${SD_DAEMON_LIBRARIES})
        target_link_libraries(test ${SD_JOURNAL_LIBRARIES})
        target_link_libraries(uhub-passwd ${SD_JOURNAL_LIBRARIES})
        target_link_libraries(uhub-admin ${SD_JOURNAL_LIBRARIES})
        include_directories(${SD_DAEMON_INCLUDE_DIRS})
        include_directories(${SD_JOURNAL_INCLUDE_DIRS})
        add_definitions(-DSYSTEMD)
endif()

configure_file ("${PROJECT_SOURCE_DIR}/version.h.in" "${PROJECT_SOURCE_DIR}/version.h")
configure_file ("${PROJECT_SOURCE_DIR}/system.h.in" "${PROJECT_SOURCE_DIR}/system.h")

# mark_as_advanced(FORCE CMAKE_BUILD_TYPE)
# if (RELEASE)
#	set(CMAKE_BUILD_TYPE Release)
#	add_definitions(-DNDEBUG)
#else()
#	set(CMAKE_BUILD_TYPE Debug)
#	add_definitions(-DDEBUG)
#endif()

if (LOWLEVEL_DEBUG)
	add_definitions(-DLOWLEVEL_DEBUG)
endif()

if (UNIX)
	install( TARGETS uhub uhub-passwd RUNTIME DESTINATION bin )
	install( TARGETS mod_example mod_welcome mod_logging mod_auth_simple mod_auth_sqlite mod_chat_history mod_chat_history_sqlite mod_chat_only mod_topic mod_no_guest_downloads DESTINATION /usr/lib/uhub/ OPTIONAL )
	install( FILES ${CMAKE_SOURCE_DIR}/doc/uhub.conf ${CMAKE_SOURCE_DIR}/doc/plugins.conf ${CMAKE_SOURCE_DIR}/doc/rules.txt ${CMAKE_SOURCE_DIR}/doc/motd.txt DESTINATION /etc/uhub OPTIONAL )
endif()


