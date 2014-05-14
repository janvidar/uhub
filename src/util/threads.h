/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2014, Jan Vidar Krey
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

#ifndef HAVE_UHUB_UTIL_THREADS_H
#define HAVE_UHUB_UTIL_THREADS_H

typedef void*(*uhub_thread_start)(void*) ;

#ifdef POSIX_THREAD_SUPPORT
typedef struct pthread_data uhub_thread_t;
typedef pthread_mutex_t uhub_mutex_t;
#endif

#ifdef WINTHREAD_SUPPORT
struct winthread_data;
typedef struct winthread_data uhub_thread_t;
typedef CRITICAL_SECTION uhub_mutex_t;
#endif

// Mutexes
extern void uhub_mutex_init(uhub_mutex_t* mutex);
extern void uhub_mutex_destroy(uhub_mutex_t* mutex);
extern void uhub_mutex_lock(uhub_mutex_t* mutex);
extern void uhub_mutex_unlock(uhub_mutex_t* mutex);
extern int uhub_mutex_trylock(uhub_mutex_t* mutex);

// Threads
uhub_thread_t* uhub_thread_create(uhub_thread_start start, void* arg);
void uhub_thread_cancel(uhub_thread_t* thread);
void* uhub_thread_join(uhub_thread_t* thread);

#endif /* HAVE_UHUB_UTIL_THREADS_H */

