/*
 * kill_report extension: records tracees that were killed from outside the guest.
 *
 * Android's phantom process killer reaps an app's child processes once there are more of them
 * than it allows, and a PRoot session is nothing but child processes.  What the user sees is
 * parts of their desktop disappearing one at a time, and eventually the session dying, with no
 * error anywhere: SIGKILL cannot be caught, so nothing in the guest gets a chance to complain.
 *
 * Nothing outside the guest can see it either.  Measured on a Pixel 8, a session that lost 30
 * processes this way produced no ActivityManager kill record, no cgroup OOM, no lmkd entry and
 * no ApplicationExitInfo -- the app process itself survived, so as far as Android was concerned
 * nothing happened.  PRoot is the only vantage point that sees these deaths, because it is the
 * tracer: every tracee's exit comes back to it through waitpid(2) with the signal that caused
 * it.
 *
 * So this writes them down, for the app to find afterwards and offer the user the fix.
 *
 * Two things make a record trustworthy:
 *
 *   - A SIGKILL raised *inside* the guest looks identical from the outside, and guests kill
 *     their own processes all the time.  PRoot sees the kill(2), tkill(2) and tgkill(2) that
 *     tracees make, so a SIGKILL with no matching syscall is one the guest did not ask for.
 *     Only the tracer can draw that distinction.
 *
 *   - PRoot is itself a candidate for the same treatment, and is among the oldest processes in
 *     the session, which is the order the killer works in.  Every record is therefore flushed
 *     to disk as it happens rather than at exit, and a clean shutdown is marked explicitly: a
 *     report that starts and never finishes says the session was killed even when PRoot did not
 *     survive to say so.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "cli/note.h"
#include "extension/extension.h"
#include "syscall/seccomp.h"
#include "syscall/sysnum.h"
#include "tracee/reg.h"

/*
 * Process-wide rather than per-extension state.
 *
 * The extension is inherited by every tracee, so per-tracee copies would mean one report file
 * per process in the session.  There is one PRoot process and one report, so the file and the
 * record of recent kills belong to the process.
 */
static int report_fd = -1;

/* Kills the guest asked for, waiting to be matched against the deaths they cause. */
#define MAX_PENDING_KILLS 64

typedef struct {
	pid_t target;
	int signal;
} GuestKill;

static GuestKill pending_kills[MAX_PENDING_KILLS];
static size_t next_pending_kill;

static void append(const char *line, size_t length)
{
	if (report_fd < 0)
		return;

	/* A failed or short write loses one record.  There is nothing useful to do about it
	 * here -- complaining would land in the guest's own output -- and a truncated line is
	 * discarded by whoever reads the report.  */
	if (write(report_fd, line, length) != (ssize_t) length)
		return;

	/* Flushed as it happens: PRoot may be the next thing killed, and anything still sitting
	 * in a buffer would go with it.  */
	(void) fsync(report_fd);
}

static void record_clean_exit(void)
{
	char line[64];
	int length;

	if (report_fd < 0)
		return;

	length = snprintf(line, sizeof(line), "clean pid=%d unix=%lld\n",
			(int) getpid(), (long long) time(NULL));
	if (length > 0)
		append(line, (size_t) length);

	(void) close(report_fd);
	report_fd = -1;
}

/**
 * Opens @path for the report, once per PRoot process.
 */
static int open_report(Tracee *tracee, const char *path)
{
	char line[64];
	int length;

	if (report_fd >= 0)
		return 0;

	if (path == NULL || path[0] == '\0') {
		note(tracee, WARNING, USER, "kill-report: no path given");
		return -1;
	}

	report_fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (report_fd < 0) {
		note(tracee, WARNING, SYSTEM, "kill-report: can't open '%s'", path);
		return -1;
	}

	length = snprintf(line, sizeof(line), "start pid=%d unix=%lld\n",
			(int) getpid(), (long long) time(NULL));
	if (length > 0)
		append(line, (size_t) length);

	/* Runs on every ordinary exit and on none of the deaths this extension is about, which
	 * is exactly the distinction the report needs to record.  */
	(void) atexit(record_clean_exit);

	return 0;
}

/**
 * Remembers that a tracee asked to send @signal to @target.
 */
static void remember_guest_kill(pid_t target, int signal)
{
	pending_kills[next_pending_kill].target = target;
	pending_kills[next_pending_kill].signal = signal;
	next_pending_kill = (next_pending_kill + 1) % MAX_PENDING_KILLS;
}

/**
 * Whether the guest asked for @pid to be killed; forgets the request if so.
 *
 * Consumed on the first match so that one kill(2) cannot excuse two deaths.
 */
static bool guest_asked_for(pid_t pid, int signal)
{
	size_t i;

	for (i = 0; i < MAX_PENDING_KILLS; i++) {
		if (pending_kills[i].target != pid || pending_kills[i].signal != signal)
			continue;

		pending_kills[i].target = 0;
		pending_kills[i].signal = 0;
		return true;
	}

	return false;
}

/**
 * Notes a kill(2), tkill(2) or tgkill(2) as the tracee makes it.
 *
 * The signal has not been delivered yet, so this only records the intent; whether anything
 * died of it is settled later, when the death arrives.
 */
static void handle_kill_syscall(Tracee *tracee)
{
	word_t target;
	word_t signal;

	switch (get_sysnum(tracee, ORIGINAL)) {
	case PR_kill:
	case PR_tkill:
		target = peek_reg(tracee, CURRENT, SYSARG_1);
		signal = peek_reg(tracee, CURRENT, SYSARG_2);
		break;

	case PR_tgkill:
		/* tgkill(tgid, tid, sig): the thread is what dies.  */
		target = peek_reg(tracee, CURRENT, SYSARG_2);
		signal = peek_reg(tracee, CURRENT, SYSARG_3);
		break;

	default:
		return;
	}

	remember_guest_kill((pid_t) target, (int) signal);
}

/**
 * Writes down a tracee that was killed.
 *
 * Only signals that cannot be caught are worth recording.  A tracee that dies of SIGTERM or
 * SIGHUP had the chance to refuse, so something in the guest was talking to it; SIGKILL is the
 * one that arrives without discussion.
 */
static void handle_death(Tracee *tracee, int wait_status)
{
	const char *origin;
	char line[160];
	int length;
	int signal;

	if (!WIFSIGNALED(wait_status))
		return;

	signal = WTERMSIG(wait_status);
	if (signal != SIGKILL)
		return;

	origin = guest_asked_for(tracee->pid, signal) ? "guest" : "external";

	length = snprintf(line, sizeof(line),
			"kill vpid=%llu pid=%d signal=%d origin=%s unix=%lld\n",
			(unsigned long long) tracee->vpid, (int) tracee->pid, signal,
			origin, (long long) time(NULL));
	if (length > 0)
		append(line, (size_t) length);
}

/**
 * Handler for this @extension.  See ExtensionEvent for the meaning of @data1 and @data2.
 */
int kill_report_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2 UNUSED)
{
	switch (event) {
	case INITIALIZATION: {
		static FilteredSysnum filtered_sysnums[] = {
			{ PR_kill,   0 },
			{ PR_tkill,  0 },
			{ PR_tgkill, 0 },
			FILTERED_SYSNUM_END,
		};
		extension->filtered_sysnums = filtered_sysnums;
		return open_report(TRACEE(extension), (const char *) data1);
	}

	/* Every tracee needs it: the deaths worth recording are of processes deep in the
	 * session, not of the one PRoot started with.  */
	case INHERIT_PARENT:
		return 0;

	case SYSCALL_ENTER_END:
		handle_kill_syscall(TRACEE(extension));
		return 0;

	case NEW_STATUS:
		handle_death(TRACEE(extension), (int) data1);
		return 0;

	default:
		return 0;
	}
}
