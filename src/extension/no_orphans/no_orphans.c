/*
 * no_orphans extension: ensures all tracees appear to have PRoot as their
 * parent, preventing orphaned processes.  A virtual process tree tracks
 * what the PPID relationships would be without this extension.  getppid(2)
 * and /proc/<pid>/stat and /proc/<pid>/status reads are rewritten to report the
 * virtual (real) PPID rather than PRoot's PID.  When a virtual parent
 * dies, its virtual children are reparented in the virtual tree, and
 * SIGHUP is delivered if the dying process was a session leader.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <talloc.h>

#include "extension/extension.h"
#include "syscall/seccomp.h"
#include "syscall/sysnum.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "cli/note.h"

/* ---------------------------------------------------------------------- */
/* Virtual process tree                                                     */
/* ---------------------------------------------------------------------- */

typedef struct vproc {
	pid_t pid;
	pid_t virtual_ppid;
	bool  is_session_leader;
	LIST_ENTRY(vproc) link;
} VProc;

LIST_HEAD(vproc_list, vproc);

typedef struct shared_state {
	pid_t proot_pid;
	struct vproc_list procs;
} SharedState;

/* One instance per proot invocation, outlives all extension instances. */
static SharedState *global_shared = NULL;

static VProc *find_vproc(pid_t pid)
{
	VProc *vp;
	if (global_shared == NULL)
		return NULL;
	LIST_FOREACH(vp, &global_shared->procs, link) {
		if (vp->pid == pid)
			return vp;
	}
	return NULL;
}

static VProc *add_vproc(pid_t pid, pid_t virtual_ppid)
{
	VProc *vp;

	if (global_shared == NULL || pid == 0)
		return NULL;

	/* Avoid duplicates. */
	vp = find_vproc(pid);
	if (vp != NULL)
		return vp;

	vp = talloc_zero(NULL, VProc);
	if (vp == NULL)
		return NULL;

	vp->pid = pid;
	vp->virtual_ppid = virtual_ppid;
	/* Check if already a session leader (pid == its own SID). */
	vp->is_session_leader = (getsid(pid) == pid);

	LIST_INSERT_HEAD(&global_shared->procs, vp, link);
	return vp;
}

/* Called when a tracee process dies.  Reparents its virtual children to
 * its virtual parent, sends SIGHUP to those children if it was a session
 * leader, then removes it from the tree. */
static void handle_vproc_death(pid_t dying_pid)
{
	VProc *vp, *child;

	if (global_shared == NULL)
		return;

	vp = find_vproc(dying_pid);
	if (vp == NULL)
		return;

	LIST_FOREACH(child, &global_shared->procs, link) {
		if (child->virtual_ppid != dying_pid)
			continue;
		child->virtual_ppid = vp->virtual_ppid;
		if (vp->is_session_leader)
			kill(child->pid, SIGHUP);
	}

	LIST_REMOVE(vp, link);
	talloc_free(vp);
}

/* Add a tracee to the virtual tree if it is not already present.  The
 * virtual PPID is taken from the proot tracee parent pointer when
 * available, falling back to PRoot's own PID. */
static void ensure_in_virtual_tree(Tracee *tracee)
{
	pid_t virtual_ppid;

	if (global_shared == NULL || tracee->pid == 0)
		return;
	if (find_vproc(tracee->pid) != NULL)
		return;

	if (tracee->parent != NULL && tracee->parent->pid != 0)
		virtual_ppid = tracee->parent->pid;
	else
		virtual_ppid = global_shared->proot_pid;

	add_vproc(tracee->pid, virtual_ppid);
}

/* ---------------------------------------------------------------------- */
/* Per-tracee fd tracking for /proc/<pid>/stat and /proc/<pid>/status       */
/* ---------------------------------------------------------------------- */

typedef struct fd_entry {
	int   fd;
	pid_t target_pid;
	bool  is_status;   /* false = /proc/<pid>/stat, true = /proc/<pid>/status */
	LIST_ENTRY(fd_entry) link;
} FdEntry;

LIST_HEAD(fd_list, fd_entry);

typedef struct config {
	struct fd_list open_fds;
} Config;

/* ---------------------------------------------------------------------- */
/* Path parsing helpers                                                     */
/* ---------------------------------------------------------------------- */

/* Check whether path refers to /proc/<pid>/stat[us].  On match, sets
 * *out_pid to the target PID and *out_is_status accordingly.
 * self_pid is used when the path contains "self" or "thread-self". */
static bool parse_proc_stat_path(const char *path, pid_t self_pid,
				pid_t *out_pid, bool *out_is_status)
{
	const char *p;
	pid_t target_pid;

	if (strncmp(path, "/proc/", 6) != 0)
		return false;
	p = path + 6;

	if (strncmp(p, "self/", 5) == 0) {
		target_pid = self_pid;
		p += 5;
	} else if (strncmp(p, "thread-self/", 12) == 0) {
		target_pid = self_pid;
		p += 12;
	} else if (*p >= '0' && *p <= '9') {
		char *endp;
		long pid = strtol(p, &endp, 10);
		if (*endp != '/')
			return false;
		target_pid = (pid_t)pid;
		p = endp + 1;
	} else {
		return false;
	}

	if (strcmp(p, "stat") == 0) {
		*out_pid      = target_pid;
		*out_is_status = false;
		return true;
	}
	if (strcmp(p, "status") == 0) {
		*out_pid      = target_pid;
		*out_is_status = true;
		return true;
	}
	return false;
}

/* ---------------------------------------------------------------------- */
/* Buffer patching                                                          */
/* ---------------------------------------------------------------------- */

/* Replace the PPID field in /proc/<pid>/stat content held in buf[0..len).
 * buf_capacity is the total size of buf (may be larger than len to allow
 * in-place expansion).  Returns the new length, or -1 on error. */
static ssize_t patch_stat_ppid(char *buf, ssize_t len, ssize_t buf_capacity,
				pid_t new_ppid)
{
	char *last_rparen;
	char *p;
	char *field_start, *field_end;
	char  new_str[32];
	int   new_str_len;
	ssize_t old_field_len, delta, new_len;

	/* /proc/<pid>/stat format: "pid (comm) state ppid ..."
	 * comm can contain spaces, so find the last ')'. */
	last_rparen = NULL;
	for (ssize_t i = len - 1; i >= 0; i--) {
		if (buf[i] == ')') {
			last_rparen = buf + i;
			break;
		}
	}
	if (last_rparen == NULL)
		return -1;

	p = last_rparen + 1;
	/* Expect: ' ' state ' ' ppid */
	if (p >= buf + len || *p != ' ') return -1;
	p++;
	if (p >= buf + len) return -1;
	p++;  /* skip state character */
	if (p >= buf + len || *p != ' ') return -1;
	p++;  /* skip space */

	field_start = p;
	field_end   = p;
	while (field_end < buf + len && *field_end >= '0' && *field_end <= '9')
		field_end++;

	if (field_end == field_start)
		return -1;

	new_str_len   = snprintf(new_str, sizeof(new_str), "%d", (int)new_ppid);
	old_field_len = field_end - field_start;
	delta         = new_str_len - old_field_len;
	new_len       = len + delta;

	if (new_len > buf_capacity)
		return -1;

	/* Shift the tail of the buffer to make room (or close the gap). */
	memmove(field_start + new_str_len, field_end,
		(size_t)(len - (field_end - buf)));
	memcpy(field_start, new_str, (size_t)new_str_len);

	return new_len;
}

/* Replace the PPid line in /proc/<pid>/status content.
 * Returns the new length, or -1 on error. */
static ssize_t patch_status_ppid(char *buf, ssize_t len, ssize_t buf_capacity,
				pid_t new_ppid)
{
	char  *p;
	char  *field_start, *field_end;
	char   new_str[32];
	int    new_str_len;
	ssize_t old_field_len, delta, new_len;

	/* Locate "PPid:" anywhere in the buffer. */
	p = (char *)memmem(buf, (size_t)len, "PPid:", 5);
	if (p == NULL)
		return -1;
	p += 5;

	/* Skip optional whitespace (typically a tab). */
	while (p < buf + len && (*p == ' ' || *p == '\t'))
		p++;

	field_start = p;
	field_end   = p;
	while (field_end < buf + len && *field_end >= '0' && *field_end <= '9')
		field_end++;

	if (field_end == field_start)
		return -1;

	new_str_len   = snprintf(new_str, sizeof(new_str), "%d", (int)new_ppid);
	old_field_len = field_end - field_start;
	delta         = new_str_len - old_field_len;
	new_len       = len + delta;

	if (new_len > buf_capacity)
		return -1;

	memmove(field_start + new_str_len, field_end,
		(size_t)(len - (field_end - buf)));
	memcpy(field_start, new_str, (size_t)new_str_len);

	return new_len;
}

/* ---------------------------------------------------------------------- */
/* fd tracking helpers                                                      */
/* ---------------------------------------------------------------------- */

static FdEntry *find_fd_entry(Config *config, int fd)
{
	FdEntry *fe;
	LIST_FOREACH(fe, &config->open_fds, link) {
		if (fe->fd == fd)
			return fe;
	}
	return NULL;
}

static void remove_fd_entry(Config *config, int fd)
{
	FdEntry *fe = find_fd_entry(config, fd);
	if (fe == NULL)
		return;
	LIST_REMOVE(fe, link);
	talloc_free(fe);
}

static void add_fd_entry(Config *config, int fd, pid_t target_pid,
			bool is_status)
{
	FdEntry *fe;

	/* Replace any stale entry for this fd. */
	remove_fd_entry(config, fd);

	fe = talloc_zero(NULL, FdEntry);
	if (fe == NULL)
		return;
	fe->fd         = fd;
	fe->target_pid = target_pid;
	fe->is_status  = is_status;
	LIST_INSERT_HEAD(&config->open_fds, fe, link);
}

/* ---------------------------------------------------------------------- */
/* Syscall handlers                                                         */
/* ---------------------------------------------------------------------- */

static void handle_openat_exit(Tracee *tracee, Config *config)
{
	word_t result;
	word_t path_addr;
	char   path[PATH_MAX];
	pid_t  target_pid;
	bool   is_status;
	int    fd;
	int    status;

	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	fd = (int)(word_t)result;
	if (fd < 0)
		return;

	/* openat(dirfd, path, flags, ...) — path is SYSARG_2. */
	path_addr = peek_reg(tracee, ORIGINAL, SYSARG_2);
	status = read_path(tracee, path, path_addr);
	if (status < 0)
		return;

	if (!parse_proc_stat_path(path, tracee->pid, &target_pid, &is_status))
		return;

	add_fd_entry(config, fd, target_pid, is_status);
}

static void handle_read_exit(Tracee *tracee, Config *config)
{
	word_t  result;
	word_t  buf_addr;
	word_t  buf_size;
	ssize_t nread;
	int     fd;
	FdEntry *fe;
	VProc   *vp;
	char    *local_buf;
	ssize_t  new_len;
	int      status;

	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	nread  = (ssize_t)(word_t)result;
	if (nread <= 0)
		return;

	fd = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
	fe = find_fd_entry(config, fd);
	if (fe == NULL)
		return;

	vp = find_vproc(fe->target_pid);
	if (vp == NULL)
		return;

	buf_addr = peek_reg(tracee, ORIGINAL, SYSARG_2);
	buf_size = peek_reg(tracee, ORIGINAL, SYSARG_3);

	/* Allocate a local buffer large enough for possible expansion. */
	local_buf = talloc_size(tracee->ctx, (size_t)(nread + 32));
	if (local_buf == NULL)
		return;

	status = read_data(tracee, local_buf, buf_addr, (word_t)nread);
	if (status < 0)
		return;

	if (fe->is_status)
		new_len = patch_status_ppid(local_buf, nread,
					(ssize_t)buf_size, vp->virtual_ppid);
	else
		new_len = patch_stat_ppid(local_buf, nread,
					(ssize_t)buf_size, vp->virtual_ppid);

	if (new_len < 0)
		return;

	status = write_data(tracee, buf_addr, local_buf, (word_t)new_len);
	if (status < 0)
		return;

	if (new_len != nread)
		poke_reg(tracee, SYSARG_RESULT, (word_t)(size_t)new_len);
}

static void handle_close_exit(Tracee *tracee, Config *config)
{
	word_t result;
	int    fd;

	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if ((int)(word_t)result != 0)
		return;  /* close() failed; fd is still open */

	fd = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
	remove_fd_entry(config, fd);
}

static void handle_dup_exit(Tracee *tracee, Config *config, Sysnum sysnum)
{
	word_t  result;
	int     old_fd, new_fd;
	FdEntry *fe;

	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	new_fd = (int)(word_t)result;
	if (new_fd < 0)
		return;

	switch (sysnum) {
	case PR_dup:
		old_fd = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
		break;
	case PR_dup2:
	case PR_dup3:
		old_fd = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
		/* new_fd is the second argument, but the result holds the
		 * actual new fd (same value on success). */
		break;
	default:
		return;
	}

	fe = find_fd_entry(config, old_fd);
	if (fe == NULL)
		return;

	add_fd_entry(config, new_fd, fe->target_pid, fe->is_status);
}

static void handle_clone_enter(Tracee *tracee)
{
	word_t flags = peek_reg(tracee, CURRENT, SYSARG_1);
	if (!(flags & CLONE_THREAD))
		poke_reg(tracee, SYSARG_1, flags | CLONE_PARENT);
}

static void handle_clone3_enter(Tracee *tracee)
{
	word_t   args_ptr;
	uint64_t flags;
	int      status;

	args_ptr = peek_reg(tracee, CURRENT, SYSARG_1);
	status = read_data(tracee, &flags, args_ptr, sizeof(flags));
	if (status < 0)
		return;
	if (flags & CLONE_THREAD)
		return;
	flags |= CLONE_PARENT;
	(void)write_data(tracee, args_ptr, &flags, sizeof(flags));
}

/* Rewrite fork() as clone(SIGCHLD|CLONE_PARENT, NULL, ...) so the new
 * child is a direct kernel child of proot rather than the calling tracee. */
static void handle_fork_enter(Tracee *tracee)
{
	set_sysnum(tracee, PR_clone);
	poke_reg(tracee, SYSARG_1, (word_t)(SIGCHLD | CLONE_PARENT));
	poke_reg(tracee, SYSARG_2, 0);
	poke_reg(tracee, SYSARG_3, 0);
	poke_reg(tracee, SYSARG_4, 0);
	poke_reg(tracee, SYSARG_5, 0);
	poke_reg(tracee, SYSARG_6, 0);
}

/* Rewrite vfork() as clone(SIGCHLD|CLONE_VFORK|CLONE_VM|CLONE_PARENT, NULL, ...)
 * preserving vfork semantics while making the child a kernel child of proot. */
static void handle_vfork_enter(Tracee *tracee)
{
	set_sysnum(tracee, PR_clone);
	poke_reg(tracee, SYSARG_1,
		 (word_t)(SIGCHLD | CLONE_VFORK | CLONE_VM | CLONE_PARENT));
	poke_reg(tracee, SYSARG_2, 0);
	poke_reg(tracee, SYSARG_3, 0);
	poke_reg(tracee, SYSARG_4, 0);
	poke_reg(tracee, SYSARG_5, 0);
	poke_reg(tracee, SYSARG_6, 0);
}

static void handle_execve_exit(Tracee *tracee UNUSED, Config *config)
{
	FdEntry *fe;

	/* After a successful exec, FD_CLOEXEC descriptors are gone and we
	 * don't track which fds had that flag set.  Wipe the table; any
	 * /proc/<pid>/stat fds the new image needs will be re-tracked on open. */
	while (!LIST_EMPTY(&config->open_fds)) {
		fe = LIST_FIRST(&config->open_fds);
		LIST_REMOVE(fe, link);
		talloc_free(fe);
	}
}

/* Called at SYSCALL_EXIT_END for any fork/clone that creates a new process
 * (not a thread).  Registers the child in the virtual tree so getppid and
 * /proc reads report the biological parent rather than proot. */
static void handle_fork_clone_exit(Tracee *tracee, word_t clone_flags)
{
	pid_t child_pid;

	if (clone_flags & CLONE_THREAD)
		return;  /* threads share the thread-group leader's PPID */

	child_pid = (pid_t)(int)(word_t)peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (child_pid > 0)
		add_vproc(child_pid, tracee->pid);
}

static void handle_setsid_exit(Tracee *tracee)
{
	word_t result;
	VProc *vp;

	result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	/* setsid() returns the new SID (== calling process's PID) on success. */
	if ((pid_t)(word_t)result != tracee->pid)
		return;

	vp = find_vproc(tracee->pid);
	if (vp != NULL)
		vp->is_session_leader = true;
}

/* ---------------------------------------------------------------------- */
/* Syscall filter list                                                      */
/* ---------------------------------------------------------------------- */

static FilteredSysnum filtered_sysnums[] = {
	{ PR_getppid,  FILTER_SYSEXIT },
	{ PR_openat,   FILTER_SYSEXIT },
	{ PR_read,     FILTER_SYSEXIT },
	{ PR_pread64,  FILTER_SYSEXIT },
	{ PR_close,    FILTER_SYSEXIT },
	{ PR_dup,      FILTER_SYSEXIT },
	{ PR_dup2,     FILTER_SYSEXIT },
	{ PR_dup3,     FILTER_SYSEXIT },
	{ PR_setsid,   FILTER_SYSEXIT },
	/* Enter+exit: add CLONE_PARENT at enter, update virtual tree at exit. */
	{ PR_clone,    FILTER_SYSEXIT },
	{ PR_clone3,   FILTER_SYSEXIT },
	{ PR_fork,     FILTER_SYSEXIT },
	{ PR_vfork,    FILTER_SYSEXIT },
	/* Sysexit: clear fd table after exec (FD_CLOEXEC may have closed fds). */
	{ PR_execve,   FILTER_SYSEXIT },
	{ PR_execveat, FILTER_SYSEXIT },
	FILTERED_SYSNUM_END,
};

/* ---------------------------------------------------------------------- */
/* Extension callback                                                       */
/* ---------------------------------------------------------------------- */

int no_orphans_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2 UNUSED)
{
	switch (event) {

	case INITIALIZATION: {
		Config *config;

		/* Set up the global shared state once. */
		if (global_shared == NULL) {
			global_shared = talloc_zero(NULL, SharedState);
			if (global_shared == NULL)
				return -1;
			global_shared->proot_pid = getpid();
			LIST_INIT(&global_shared->procs);

			/* Become the subreaper so orphaned tracees are
			 * reparented to PRoot rather than to init. */
			(void)prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
		}

		config = talloc_zero(extension, Config);
		if (config == NULL)
			return -1;
		LIST_INIT(&config->open_fds);

		extension->config          = config;
		extension->filtered_sysnums = filtered_sysnums;
		return 0;
	}

	case INHERIT_PARENT:
		/* Ask for INHERIT_CHILD so each tracee gets its own config
		 * (separate fd table) while sharing global_shared. */
		return 1;

	case INHERIT_CHILD: {
		Extension *parent_ext = (Extension *)data1;
		Tracee    *child      = TRACEE(extension);
		Tracee    *parent     = TRACEE(parent_ext);
		Config    *config;

		config = talloc_zero(extension, Config);
		if (config == NULL)
			return -1;
		LIST_INIT(&config->open_fds);

		extension->config           = config;
		extension->filtered_sysnums = filtered_sysnums;

		/* Record the child in the virtual tree with its real parent
		 * as the virtual PPID. */
		add_vproc(child->pid, parent->pid);
		return 0;
	}

	case REMOVED: {
		Tracee *tracee = TRACEE(extension);
		Config *config = talloc_get_type_abort(extension->config, Config);
		FdEntry *fe;

		/* Clean up the virtual tree entry for this tracee. */
		handle_vproc_death(tracee->pid);

		/* Free all fd tracking entries. */
		while (!LIST_EMPTY(&config->open_fds)) {
			fe = LIST_FIRST(&config->open_fds);
			LIST_REMOVE(fe, link);
			talloc_free(fe);
		}
		return 0;
	}

	case SYSCALL_EXIT_END: {
		Tracee  *tracee = TRACEE(extension);
		Config  *config = talloc_get_type_abort(extension->config, Config);
		Sysnum   sysnum = get_sysnum(tracee, ORIGINAL);

		/* Ensure this tracee is registered in the virtual tree. */
		ensure_in_virtual_tree(tracee);

		switch (sysnum) {

		case PR_getppid: {
			VProc *vp = find_vproc(tracee->pid);
			if (vp != NULL)
				poke_reg(tracee, SYSARG_RESULT,
					(word_t)(size_t)(unsigned)vp->virtual_ppid);
			return 0;
		}

		case PR_openat:
			handle_openat_exit(tracee, config);
			return 0;

		case PR_read:
		case PR_pread64:
			handle_read_exit(tracee, config);
			return 0;

		case PR_close:
			handle_close_exit(tracee, config);
			return 0;

		case PR_dup:
		case PR_dup2:
		case PR_dup3:
			handle_dup_exit(tracee, config, sysnum);
			return 0;

		case PR_setsid:
			handle_setsid_exit(tracee);
			return 0;

		case PR_clone: {
			word_t flags = peek_reg(tracee, ORIGINAL, SYSARG_1);
			handle_fork_clone_exit(tracee, flags);
			return 0;
		}

		case PR_clone3: {
			uint64_t flags = 0;
			word_t args_ptr = peek_reg(tracee, ORIGINAL, SYSARG_1);
			(void)read_data(tracee, &flags, args_ptr, sizeof(flags));
			handle_fork_clone_exit(tracee, (word_t)flags);
			return 0;
		}

		case PR_fork:
		case PR_vfork:
			handle_fork_clone_exit(tracee, 0);
			return 0;

		case PR_execve:
		case PR_execveat: {
			word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
			if ((int)(word_t)result == 0)
				handle_execve_exit(tracee, config);
			return 0;
		}

		default:
			return 0;
		}
	}

	case SYSCALL_ENTER_START: {
		Tracee *tracee = TRACEE(extension);
		Sysnum  sysnum = get_sysnum(tracee, CURRENT);

		switch (sysnum) {
		case PR_clone:
			handle_clone_enter(tracee);
			return 0;
		case PR_clone3:
			handle_clone3_enter(tracee);
			return 0;
		case PR_fork:
			handle_fork_enter(tracee);
			return 0;
		case PR_vfork:
			handle_vfork_enter(tracee);
			return 0;
		default:
			return 0;
		}
	}

	default:
		return 0;
	}
}
