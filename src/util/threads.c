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

#include "uhub.h"

#ifdef POSIX_THREAD_SUPPORT

struct pthread_data
{
	pthread_t handle;
};

void uhub_mutex_init(uhub_mutex_t* mutex)
{
	pthread_mutex_init(mutex, NULL);
}

void uhub_mutex_destroy(uhub_mutex_t* mutex)
{
	pthread_mutex_destroy(mutex);
}

void uhub_mutex_lock(uhub_mutex_t* mutex)
{
	pthread_mutex_lock(mutex);
}

void uhub_mutex_unlock(uhub_mutex_t* mutex)
{
	pthread_mutex_unlock(mutex);
}

int uhub_mutex_trylock(uhub_mutex_t* mutex)
{
	int ret = pthread_mutex_trylock(mutex);
	return (ret == 0);
}

uhub_thread_t* uhub_thread_create(uhub_thread_start start, void* arg)
{
	struct pthread_data* thread = (struct pthread_data*) hub_malloc_zero(sizeof(struct pthread_data));
	int ret = pthread_create(&thread->handle, NULL, start, arg);
	if (ret != 0)
	{
		hub_free(thread);
		thread = NULL;
	}
	return thread;
}

void uhub_thread_cancel(uhub_thread_t* thread)
{
	pthread_cancel(thread->handle);
}

void* uhub_thread_join(uhub_thread_t* thread)
{
	void* ret = NULL;
	pthread_join(thread->handle, &ret);
	hub_free(thread);
	return ret;
}


#endif /* POSIX_THREAD_SUPPORT */

#ifdef WINTHREAD_SUPPORT

struct winthread_data
{
	uhub_thread_t* handle;
	uhub_thread_start start;
	void* arg;
};

static DWORD WINAPI uhub_winthread_start(void* ptr)
{
	struct winthread_data* data = (struct winthread_data*) ptr;
	DWORD ret = (DWORD) data->start(data->arg);
	return ret;
}

void uhub_mutex_init(uhub_mutex_t* mutex)
{
	InitializeCriticalSection(mutex);
}

void uhub_mutex_destroy(uhub_mutex_t* mutex)
{
	DeleteCriticalSection(mutex);
}

void uhub_mutex_lock(uhub_mutex_t* mutex)
{
	EnterCriticalSection(mutex);
}

void uhub_mutex_unlock(uhub_mutex_t* mutex)
{
	LeaveCriticalSection(mutex);
}

int uhub_mutex_trylock(uhub_mutex_t* mutex)
{
	return TryEnterCriticalSection(mutex);
}

uhub_thread_t* uhub_thread_create(uhub_thread_start start, void* arg)
{
	struct winthread_data* thread = (struct winthread_data*) hub_malloc_zero(sizeof(struct winthread_data));
	thread->start = start;
	thread->arg = arg;
	thread->handle = CreateThread(NULL, 0, uhub_winthread_start, thread, 0, 0);
	return thread;
}

void uhub_thread_cancel(uhub_thread_t* thread)
{
	TerminateThread(thread->handle, 0);
}

void* uhub_thread_join(uhub_thread_t* thread)
{
	void* ret = NULL;
	DWORD exitCode;
	WaitForSingleObject(thread->handle, INFINITE);
	GetExitCodeThread(thread->handle, &exitCode);
	ret = &exitCode;
	CloseHandle(thread->handle);
	hub_free(thread);
	return ret;
}
#endif /* WINTHREAD_SUPPORT */
