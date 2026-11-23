#include <signal.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include "system.h"
#include "adc/message.h"
#include "util/log.h"
#include "util/memory.h"

/*
 * adc_message reference counting. Each test makes its own message and drops
 * every reference it took, so each one runs alone or in any order.
 */

static struct adc_message* refc_message(void)
{
	return adc_msg_create("IMSG Hello\\sWorld!");
}

EXO_TEST(test_message_refc_1, {
	struct adc_message* msg = refc_message();
	int ok = msg != NULL;
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(test_message_refc_2, {
	struct adc_message* msg = refc_message();
	int ok = msg->references == 1;
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(test_message_refc_3, {
	struct adc_message* msg = refc_message();
	int ok;
	adc_msg_incref(msg);
	ok = msg->references == 2;
	adc_msg_free(msg);
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(test_message_refc_4, {
	struct adc_message* msg = refc_message();
	int ok;
	adc_msg_incref(msg);
	adc_msg_incref(msg);
	ok = msg->references == 3;
	adc_msg_free(msg);
	adc_msg_free(msg);
	adc_msg_free(msg);
	return ok;
});

/* Each free drops one reference, and the message lives while any is left. */
EXO_TEST(test_message_refc_5, {
	struct adc_message* msg = refc_message();
	int ok;
	adc_msg_incref(msg);
	adc_msg_incref(msg);
	adc_msg_free(msg);
	ok = msg->references == 2;
	adc_msg_free(msg);
	adc_msg_free(msg);
	return ok;
});

EXO_TEST(test_message_refc_6, {
	struct adc_message* msg = refc_message();
	int ok;
	adc_msg_incref(msg);
	adc_msg_free(msg);
	ok = msg->references == 1;
	adc_msg_free(msg);
	return ok;
});

/* The last free releases it. */
EXO_TEST(test_message_refc_7, {
	adc_msg_free(refc_message());
	return 1;
});

/*
 * Out of memory. The allocators never return NULL: they log a fatal line and
 * abort. Each case runs in a child, and passes if the child died of SIGABRT
 * having written that line to stderr.
 */

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define OOM_SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || __has_feature(memory_sanitizer)
#define OOM_SANITIZED 1
#endif
#endif

/* Defeats the compiler's view of the size, so it neither warns about it nor
   assumes the allocation fails. */
static volatile size_t oom_huge = SIZE_MAX;

enum oom_case { oom_direct, oom_malloc, oom_malloc_zero, oom_realloc };

static void oom_child(enum oom_case what)
{
	void* p = NULL;
	switch (what)
	{
		case oom_direct:      hub_out_of_memory(12345); break;
		case oom_malloc:      p = hub_malloc(oom_huge); break;
		case oom_malloc_zero: p = hub_malloc_zero(oom_huge); break;
		case oom_realloc:     p = hub_realloc(NULL, oom_huge); break;
	}
	/* Reaching here means the allocator returned. */
	hub_free(p);
}

/* Returns 1 if the child aborted and its stderr contains 'expect'. */
static int oom_run(enum oom_case what, const char* expect)
{
	char out[4096];
	size_t len = 0;
	ssize_t n;
	int fds[2];
	int status = 0;
	pid_t pid;

	if (pipe(fds) != 0)
		return 0;

	pid = fork();
	if (pid < 0)
	{
		close(fds[0]);
		close(fds[1]);
		return 0;
	}

	if (pid == 0)
	{
		struct rlimit nocore = { 0, 0 };
		setrlimit(RLIMIT_CORE, &nocore); /* an expected abort is not a crash to collect */
		dup2(fds[1], STDERR_FILENO);
		close(fds[0]);
		close(fds[1]);
		/* Another test may have pointed the log elsewhere or silenced it. */
		hub_log_initialize(NULL, 0);
		hub_set_log_verbosity(log_info);
		oom_child(what);
		_exit(0);
	}

	close(fds[1]);
	while (len < sizeof(out) - 1 && (n = read(fds[0], out + len, sizeof(out) - 1 - len)) > 0)
		len += (size_t) n;
	out[len] = '\0';
	close(fds[0]);

	if (waitpid(pid, &status, 0) != pid)
		return 0;
	return WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT && strstr(out, expect) != NULL;
}

EXO_TEST(memory_oom_logs_and_aborts, {
	return oom_run(oom_direct, "FATAL: Out of memory allocating 12345 bytes, aborting");
});

/* Under a sanitizer the sanitizer's own allocator rejects the size first and
   ends the process its own way, so these need a plain build. */
#ifdef OOM_SANITIZED
#define OOM_NEEDS_PLAIN_BUILD() EXO_SKIP("the sanitizer allocator handles an oversized request itself")
#else
#define OOM_NEEDS_PLAIN_BUILD() do { } while (0)
#endif

EXO_TEST(memory_oom_malloc_aborts, {
	OOM_NEEDS_PLAIN_BUILD();
	return oom_run(oom_malloc, "Out of memory allocating");
});

EXO_TEST(memory_oom_malloc_zero_aborts, {
	OOM_NEEDS_PLAIN_BUILD();
	return oom_run(oom_malloc_zero, "Out of memory allocating");
});

EXO_TEST(memory_oom_realloc_aborts, {
	OOM_NEEDS_PLAIN_BUILD();
	return oom_run(oom_realloc, "Out of memory allocating");
});
