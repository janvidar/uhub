 ##
## Makefile for uhub
## Copyright (C) 2007-2012, Jan Vidar Krey <janvidar@extatic.org>
 #

cmake_minimum_required (VERSION 2.8.3)

project (uhub NONE)
enable_language(C)

set (UHUB_VERSION_MAJOR 0)
set (UHUB_VERSION_MINOR 4)
set (UHUB_VERSION_PATCH 1)

set (PROJECT_SOURCE_DIR "${CMAKE_SOURCE_DIR}/src")

option(RELEASE "Release build, debug build if disabled" ON)
option(LINK_SUPPORT "Allow hub linking" OFF)
option(SSL_SUPPORT "Enable SSL support" ON)
option(SQLITE_SUPPORT "Enable SQLite support" ON)
option(ADC_STRESS "Enable the stress tester client" OFF)

find_package(Git)

if (SSL_SUPPORT)
	find_package(OpenSSL REQUIRED)
endif()

if (MSVC)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

include_directories("${PROJECT_SOURCE_DIR}")

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
if(CMAKE_COMPILER_IS_GNUCC)
	set_target_properties(utils PROPERTIES COMPILE_FLAGS -fPIC)
	set_target_properties(network PROPERTIES COMPILE_FLAGS -fPIC)
endif()

add_dependencies(adc utils)
add_dependencies(network utils)

add_executable(uhub ${PROJECT_SOURCE_DIR}/core/main.c ${uhub_SOURCES} )

add_library(mod_example MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_example.c)
add_library(mod_welcome MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_welcome.c)
add_library(mod_logging MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_logging.c ${PROJECT_SOURCE_DIR}/adc/sid.c)
add_library(mod_auth_simple MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_auth_simple.c )
add_library(mod_chat_history MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_chat_history.c )
add_library(mod_chat_only MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_chat_only.c)
add_library(mod_topic MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_topic.c)

if (SQLITE_SUPPORT)
	add_library(mod_auth_sqlite MODULE ${PROJECT_SOURCE_DIR}/plugins/mod_auth_sqlite.c)
	add_executable(uhub-passwd ${PROJECT_SOURCE_DIR}/tools/uhub-passwd.c)

	target_link_libraries(mod_auth_sqlite sqlite3 utils)
	target_link_libraries(uhub-passwd sqlite3 utils)
	set_target_properties(mod_auth_sqlite PROPERTIES PREFIX "")

	if (UNIX)
		target_link_libraries(uhub pthread)
	endif()
endif()


if(WIN32)
	target_link_libraries(uhub ws2_32)
	target_link_libraries(mod_logging ws2_32)
	target_link_libraries(mod_welcome ws2_32)
endif()

set_target_properties(
	mod_example
	mod_welcome
	mod_logging
	mod_auth_simple
	mod_chat_history
	mod_chat_only
	mod_topic
	PROPERTIES PREFIX "")

target_link_libraries(uhub ${CMAKE_DL_LIBS} adc network utils)
target_link_libraries(mod_example utils)
target_link_libraries(mod_welcome utils)
target_link_libraries(mod_auth_simple utils)
target_link_libraries(mod_chat_history utils)
target_link_libraries(mod_chat_only utils)
target_link_libraries(mod_logging utils)
target_link_libraries(mod_topic utils)

target_link_libraries(mod_welcome network)
target_link_libraries(mod_logging network)

if(UNIX)
	add_library(adcclient STATIC ${adcclient_SOURCES})
	add_executable(uhub-admin ${PROJECT_SOURCE_DIR}/tools/admin.c)
	target_link_libraries(uhub-admin adcclient adc network utils)

	if (ADC_STRESS)
		add_executable(adcrush ${PROJECT_SOURCE_DIR}/tools/adcrush.c ${adcclient_SOURCES})
		target_link_libraries(adcrush adcclient adc network utils)
	endif()
endif()

if (NOT UHUB_REVISION AND GIT_FOUND)
	execute_process(COMMAND ${GIT_EXECUTABLE} show -s --pretty=format:%h OUTPUT_VARIABLE UHUB_REVISION_TEMP)
	if (UHUB_REVISION_TEMP)
		set (UHUB_REVISION "git-${UHUB_REVISION_TEMP}")
	endif()
endif()

if (NOT UHUB_REVISION)
	set (UHUB_REVISION "release")
endif()

set (UHUB_GIT_VERSION "${UHUB_VERSION_MAJOR}.${UHUB_VERSION_MINOR}.${UHUB_VERSION_PATCH}-${UHUB_REVISION}")
message (STATUS "Current uHub version: ${UHUB_GIT_VERSION}")

if(OPENSSL_FOUND)
	add_definitions(-DSSL_SUPPORT=1)
	include_directories(${OPENSSL_INCLUDE_DIR})
	target_link_libraries(uhub ${OPENSSL_LIBRARIES})
	if(UNIX)
		target_link_libraries(uhub-admin ${OPENSSL_LIBRARIES})
	endif()
	target_link_libraries(mod_welcome ${OPENSSL_LIBRARIES})
	target_link_libraries(mod_logging ${OPENSSL_LIBRARIES})
	if (ADC_STRESS)
		target_link_libraries(adcrush ${OPENSSL_LIBRARIES})
	endif()
endif()

configure_file ("${PROJECT_SOURCE_DIR}/version.h.in" "${PROJECT_SOURCE_DIR}/version.h")

mark_as_advanced(FORCE CMAKE_BUILD_TYPE)
if (RELEASE)
	set(CMAKE_BUILD_TYPE Release)
else()
	set(CMAKE_BUILD_TYPE Debug)
	# add_definitions(-DDEBUG)
endif()

if (UNIX)
	install( TARGETS uhub RUNTIME DESTINATION bin )
	install( TARGETS mod_example mod_welcome mod_logging mod_auth_simple mod_auth_sqlite mod_chat_history mod_chat_only mod_topic DESTINATION /usr/lib/uhub/ OPTIONAL )
	install( FILES ${CMAKE_SOURCE_DIR}/doc/uhub.conf ${CMAKE_SOURCE_DIR}/doc/plugins.conf ${CMAKE_SOURCE_DIR}/doc/rules.txt ${CMAKE_SOURCE_DIR}/doc/motd.txt DESTINATION /etc/uhub OPTIONAL )

	if (SQLITE_SUPPORT)
		install( TARGETS uhub-passwd RUNTIME DESTINATION bin )
	endif()
endif()


