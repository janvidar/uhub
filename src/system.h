/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2009, Jan Vidar Krey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef HAVE_UHUB_SYSTEM_H
#define HAVE_UHUB_SYSTEM_H

#define _FILE_OFFSET_BITS 64

#if USE_REGPARM && __GNUC__ >= 3
#define REGPRM1 __attribute__((regparm(1)))
#define REGPRM2 __attribute__((regparm(2)))
#define REGPRM3 __attribute__((regparm(3)))
#else
#define REGPRM1
#define REGPRM2
#define REGPRM3
#endif

#ifndef FORCEINLINE
#if __GNUC__ < 3
#define FORCEINLINE inline
#else
#define FORCEINLINE inline __attribute__((always_inline))
#endif
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__bsdi__) || defined(__DragonFly__) || (defined(__APPLE__) && defined(__MACH__))
#define BSD_LIKE
#endif

#if defined(__CYGWIN__) || defined(__MINGW32__)
#ifndef WINSOCK
#define WINSOCK
#endif
#endif

#ifdef WINSOCK
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#ifndef __sun__
#include <getopt.h>
#include <stdint.h>
#endif

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if !defined(WIN32)
#include <grp.h>
#include <pwd.h>
#include <sys/resource.h>
#define HAVE_STRNDUP
#ifndef __HAIKU__
#define HAVE_MEMMEM
#endif
#define HAVE_GETRLIMIT
#endif

/* printf and size_t support */
#if defined(WIN32)
/* Windows uses %Iu for size_t */
#define PRINTF_SIZE_T "%Iu"
#else
#define PRINTF_SIZE_T "%zu"
#endif

#ifdef SSL_SUPPORT
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "../version.h"

#define uhub_assert assert

#ifdef __linux__
#define USE_EPOLL
#include <sys/epoll.h>
#endif

#ifdef BSD_LIKE
#define USE_KQUEUE
#include <sys/event.h>
#endif

#define USE_SELECT
#ifndef WINSOCK
#include <sys/select.h>
#endif

#if defined(BSD_LIKE) || defined(__sun__)
#undef HAVE_STRNDUP
#undef HAVE_MEMMEM
#endif


/*
 * Detect operating system info.
 * See: http://predef.sourceforge.net/
 */
#if defined(__linux__)
#define OPSYS "Linux"
#endif

#if defined(_WIN32) || defined(__MINGW32__) || defined(_WIN64) || defined(__WIN32__) || defined(__WINDOWS__)
#define OPSYS "Windows"
#endif

#if defined(__APPLE__) && defined(__MACH__)
#define OPSYS "MacOSX"
#endif

#if defined(__FreeBSD__)
#define OPSYS "FreeBSD"
#endif

#if defined(__OpenBSD__)
#define OPSYS "OpenBSD"
#endif

#if defined(__NetBSD__)
#define OPSYS "NetBSD"
#endif

#if defined(__sun__)
#if defined(__SVR4) || defined(__svr4__)
#define OPSYS "Solaris"
#else
#define OPSYS "SunOS"
#endif
#endif

#if defined(__HAIKU__)
#define OPSYS "Haiku"
#endif

/* Detect CPUs */
#if defined(__alpha__) || defined(__alpha)
#define CPUINFO "Alpha"
#endif

#if defined(__x86_64__) || defined(__x86_64) || defined(__amd64__) || defined(__amd64) || defined(_M_X64)
#define CPUINFO "AMD64"
#endif

#if defined(__arm__) || defined(__thumb__) || defined(_ARM) || defined(__TARGET_ARCH_ARM)
#define CPUINFO "ARM"
#endif

#if defined(__i386__) || defined(__i386) || defined(i386) || defined(_M_IX86) || defined(__X86__) || defined(_X86_) || defined(__I86__) || defined(__INTEL__) || defined(__THW_INTEL__)
#define CPUINFO "i386"
#endif

#if defined(__ia64__) || defined(_IA64) || defined(__IA64__) || defined(__ia64) || defined(_M_IA64)
#define CPUINFO "IA64"
#endif

#if defined(__hppa__) || defined(__hppa)
#define CPUINFO "PARISC"
#endif

#if defined(__m68k__) || defined(M68000)
#define CPUINFO "M68K"
#endif

#if defined(__mips__) || defined(mips) || defined(__mips) || defined(__MIPS__)
#define CPUINFO "MIPS"
#endif

#if defined(__POWERPC__) || defined(__ppc__) || defined(_ARCH_PPC) || defined(__powerpc) || defined(__powerpc__)
#define CPUINFO "PowerPC"
#endif

#if defined(__sparc__) || defined(__sparc)
#define CPUINFO "SPARC"
#endif

#if defined(__sh__)
#define CPUINFO "SuperH"
#endif

/* Misc */
#ifdef MSG_NOSIGNAL
#define UHUB_SEND_SIGNAL MSG_NOSIGNAL
#else
#ifdef MSG_NOPIPE
#define UHUB_SEND_SIGNAL MSG_NOPIPE
#else
#define UHUB_SEND_SIGNAL 0
#endif
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#endif /* HAVE_UHUB_SYSTEM_H */
