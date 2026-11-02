/*
 * droid_files: reaches the parts of /sdcard an Android app can no longer open itself.
 *
 * Since scoped storage, UserLAnd's own uid can see the top level of shared storage but not
 * what is inside other apps' folders. The app can still get at a folder the user grants it
 * through Android's folder picker (the Storage Access Framework), but only through Android's
 * document APIs, never through plain paths. This extension intercepts the syscalls the guest
 * makes on such paths and hands each one to the droid_files server running in the UserLAnd
 * app (see UserLAndLibrary's DroidFiles.kt and libdroid_files.c), over a Unix socket.
 *
 * The conversation runs as syscalls chained into the tracee itself -- socket, connect, write
 * the request, recvmsg the reply -- because an open has to end with the server's file
 * descriptor installed in the tracee, and SCM_RIGHTS into the tracee's own socket is how that
 * fd gets there. The tracee blocks in recvmsg while the server waits on the user (the folder
 * picker), which stalls only that one tracee.
 *
 * The calls the kernel can sometimes answer for the app run as they are first, and only a
 * failure goes further: stat() and access() then ask the server; truncate() truncates a
 * writable fd the server opens; statfs() reports /sdcard's own filesystem; and changing times,
 * mode or owner -- which the Storage Access Framework can't do -- succeeds if the file exists,
 * so cp -p, tar and touch carry on. A rename() is the server's within one granted folder, and
 * EXDEV across the edge of one, which makes mv(1) copy instead.
 *
 * Paths. The server is always asked about guest paths ("/sdcard/Documents/x"). The guest
 * path is worked out from the host path proot has already resolved at syscall entry, which is
 * absolute and already accounts for the cwd and for any directory fd -- so "cd" and *at()
 * calls need nothing special. A file descriptor the server opens points somewhere else again,
 * the documents provider's view of shared storage (/mnt/user/0/emulated/0/...): that prefix is
 * learned from the first fd received, exactly, from the fd's path and the guest path it was
 * opened for, and paths under it are mapped back to /sdcard as well, which covers getdents()
 * on those fds. UserLAnd also binds that prefix to shared storage, so the paths tools like
 * find(1) derive from the fds (fchdir() into one, then relative calls) resolve too.
 *
 * Other extensions. Once a syscall is taken over, its registers hold the socket calls' arguments,
 * and an extension that reads them as the original syscall's gets garbage. This extension
 * returns a positive status for those events, which ends notify_extensions() there -- so it
 * has to come first in the list, i.e. --droid_files has to be the last extension option on the
 * command line (see inherit_extensions(), which keeps that order in child processes).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <talloc.h>

#include "cli/note.h"
#include "path/path.h"
#include "tracee/mem.h"
#include "tracee/abi.h"
#include "syscall/chain.h"
#include "extension/extension.h"
#include "extension/fake_id0/helper_functions.h"  /* IGNORE_SYSARG */

/* A new name for the new protocol: an older app's server never sees requests it can't read. */
#define DF_SOCKNAME "/support/common/droid_files_socket2"
#define DF_SDCARD "/sdcard"

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_STATX_SYNC_TYPE
#define AT_STATX_SYNC_TYPE 0x6000
#endif

/* --- Wire format: keep in sync with libdroid_files.c. ------------------------------------ */

enum {
	DF_OP_OPEN = 1,      /* reply carries the fd */
	DF_OP_STAT,          /* reply carries an O_RDONLY fd to fstat() or statx() */
	DF_OP_ACCESS,
	DF_OP_MKDIR,
	DF_OP_UNLINK,
	DF_OP_RMDIR,
	DF_OP_GETDENTS64,    /* reply payload: linux_dirent64 records */
	DF_OP_GETDENTS,      /* reply payload: linux_dirent records */
	DF_OP_RENAME,        /* path -> new_path; flags are renameat2()'s */
};

typedef struct {
	uint32_t op;
	uint32_t flags;      /* open(2) flags, or access(2) mode */
	uint32_t mode;
	uint32_t count;      /* getdents: room in the caller's buffer */
	uint64_t offset;     /* getdents: index of the first entry wanted */
	char path[PATH_MAX]; /* guest path, always under /sdcard/ */
	char new_path[PATH_MAX]; /* rename: the destination, likewise */
} df_request_t;

typedef struct {
	int32_t err;         /* 0, or a positive errno */
	uint32_t len;        /* getdents: payload bytes that follow */
	uint64_t next_offset;
} df_response_t;

/* --- State. ------------------------------------------------------------------------------- */

/* Host paths that mean /sdcard, shared by every tracee of this proot. */
static char sdcard_host[PATH_MAX];  /* where the /sdcard binding points, resolved once */
static char saf_prefix[PATH_MAX];   /* where the server's fds point; learned, see header */

/* How a syscall is handled; see the header. */
typedef enum {
	KIND_TAKEOVER = 0,   /* the server does it */
	KIND_FALLBACK,       /* kernel first, then the server's answer (stat, access) */
	KIND_QUIET,          /* kernel first, then success if the file exists (times, mode, owner) */
	KIND_QUIET_FD,       /* the same, on an fd */
	KIND_TRUNCATE,       /* kernel first, then ftruncate() a writable fd from the server */
	KIND_STATFS,         /* kernel first, then statfs() of /sdcard */
	KIND_RESULT,         /* answered at once with state->result */
} Kind;

typedef enum {
	STEP_IDLE = 0,
	STEP_NATIVE,         /* let the kernel try first; see Kind */
	STEP_RESULT,
	STEP_SOCKET,
	STEP_CONNECT,
	STEP_WRITE,
	STEP_RECVMSG,
	STEP_USE_FD,         /* fstat()/statx()/ftruncate() on the server's fd */
	STEP_CLOSE_FD,
	STEP_LSEEK,
	STEP_CLOSE_SOCK,
	STEP_PASSTHROUGH,    /* a last chained syscall whose own result is the answer */
} Step;

/* One per tracee: a tracee is a thread, so it is in at most one intercepted syscall. */
typedef struct {
	Step step;
	Kind kind;
	uint32_t op;
	char guest_path[PATH_MAX];
	char new_guest_path[PATH_MAX];  /* rename */
	int dir_fd;          /* getdents, and the fd of a KIND_QUIET_FD call */
	word_t sock;
	word_t fd;           /* received from the server */
	word_t result;       /* what the tracee sees once the chain is done */
	word_t mem_req, mem_resp, mem_iov, mem_ctrl, mem_msg;
	word_t mem_empty;    /* "" for statx(fd, "", AT_EMPTY_PATH) */
} DroidFilesState;

/* Room for one SCM_RIGHTS fd. */
#define DF_CONTROL_SIZE CMSG_SPACE(sizeof(int))

/* --- Paths. ------------------------------------------------------------------------------- */

static void strip_trailing_slash(char *path)
{
	size_t length = strlen(path);
	while (length > 1 && path[length - 1] == '/')
		path[--length] = '\0';
}

/* Resolves where /sdcard lives on the host, once; the bindings never change. */
static bool init_sdcard_host(Tracee *tracee)
{
	if (sdcard_host[0] != '\0')
		return true;
	if (translate_path(tracee, sdcard_host, AT_FDCWD, DF_SDCARD, true) < 0) {
		sdcard_host[0] = '\0';
		return false;
	}
	strip_trailing_slash(sdcard_host);
	return true;
}

/*
 * Rewrites the absolute @path in place without "." and ".." components or repeated slashes.
 * proot's translation leaves them in when it joins a directory fd's path and a relative one
 * (mkdir -p's mkdirat() arrives as ".../0/./Documents"), and the server needs the plain path.
 */
static void normalize(char *path)
{
	char *out = path;
	const char *in = path;

	while (*in != '\0') {
		const char *end;
		size_t length;

		while (*in == '/')
			in++;
		if (*in == '\0')
			break;
		end = strchr(in, '/');
		if (end == NULL)
			end = in + strlen(in);
		length = end - in;

		if (length == 1 && in[0] == '.') {
			/* Drop it. */
		} else if (length == 2 && in[0] == '.' && in[1] == '.') {
			while (out > path && *(out - 1) != '/')
				out--;
			if (out > path)
				out--;
		} else {
			*out++ = '/';
			memmove(out, in, length);
			out += length;
		}
		in = end;
	}
	if (out == path)
		*out++ = '/';
	*out = '\0';
}

/* @rel (the part after /sdcard/) if @host is under @prefix, otherwise NULL. */
static const char *under(const char *host, const char *prefix)
{
	size_t length = strlen(prefix);
	if (length == 0 || strncmp(host, prefix, length) != 0)
		return NULL;
	if (host[length] != '/' || host[length + 1] == '\0')
		return NULL;
	return host + length + 1;
}

/*
 * Fills @guest with the /sdcard path for @host, if it is one this extension handles, and
 * returns whether it is. @deep_only leaves top-level entries under /sdcard to the kernel: the
 * app can stat the folders directly under /sdcard itself, and asking the server would put up
 * a folder picker for each one a directory listing happens to stat.
 */
static bool guest_path_for(const char *host, char guest[PATH_MAX], bool deep_only,
	bool *from_server_fd)
{
	const char *rel = under(host, sdcard_host);
	*from_server_fd = (rel == NULL);
	if (rel == NULL) {
		/* Only the server's own fds lead here, so the folder is granted already, and the
		 * kernel can't stat these paths for the app at all. */
		rel = under(host, saf_prefix);
		deep_only = false;
	}
	if (rel == NULL)
		return false;

	/* Android/ is the app's own storage, reachable directly. Download itself can't be granted
	 * through the picker (only folders inside it can), so it is left as the kernel sees it. */
	if (strcmp(rel, "Android") == 0 || strncmp(rel, "Android/", 8) == 0)
		return false;
	if (strcmp(rel, "Download") == 0)
		return false;
	if (deep_only && strchr(rel, '/') == NULL)
		return false;

	if (snprintf(guest, PATH_MAX, DF_SDCARD "/%s", rel) >= PATH_MAX)
		return false;
	strip_trailing_slash(guest);
	return true;
}

/* Learns where the server's fds point from one of them and the guest path it was opened for. */
static void learn_saf_prefix(Tracee *tracee, int fd, const char *guest)
{
	char fd_path[PATH_MAX];
	const char *rel = guest + strlen(DF_SDCARD);  /* "/x/y" */
	size_t fd_length, rel_length = strlen(rel);

	if (readlink_proc_pid_fd(tracee->pid, fd, fd_path) < 0)
		return;
	strip_trailing_slash(fd_path);
	fd_length = strlen(fd_path);
	if (fd_length <= rel_length || strcmp(fd_path + fd_length - rel_length, rel) != 0)
		return;
	fd_path[fd_length - rel_length] = '\0';
	if (strcmp(fd_path, sdcard_host) == 0 || strcmp(fd_path, saf_prefix) == 0)
		return;
	strcpy(saf_prefix, fd_path);
	VERBOSE(tracee, 2, "droid_files: server fds live under %s", saf_prefix);
}

/* The tracee's current position in @fd, from /proc; getdents keeps its place there. */
static uint64_t fd_position(const Tracee *tracee, int fd)
{
	char path[64], line[128];
	uint64_t position = 0;
	FILE *file;

	snprintf(path, sizeof(path), "/proc/%d/fdinfo/%d", tracee->pid, fd);
	file = fopen(path, "r");
	if (file == NULL)
		return 0;
	while (fgets(line, sizeof(line), file) != NULL) {
		if (sscanf(line, "pos: %" SCNu64, &position) == 1)
			break;
	}
	fclose(file);
	return position;
}

/* --- Syscall entry. ----------------------------------------------------------------------- */

/*
 * What a syscall becomes: its request, its Kind, and where its path is (@path_reg), or its fd
 * (@fd_reg) when it works on one. @new_path_reg is a rename's destination. Returns false for
 * syscalls this extension doesn't touch.
 */
static bool classify(Tracee *tracee, word_t sysnum, uint32_t *op, Kind *kind,
	Reg *path_reg, Reg *fd_reg, Reg *new_path_reg)
{
	*kind = KIND_TAKEOVER;
	*path_reg = SYSARG_2;
	*fd_reg = IGNORE_SYSARG;
	*new_path_reg = IGNORE_SYSARG;

	switch (sysnum) {
	case PR_open:
	case PR_creat:
		*path_reg = SYSARG_1;
		*op = DF_OP_OPEN;
		return true;
	case PR_openat:
		*op = DF_OP_OPEN;
		return true;
	case PR_mkdir:
		*path_reg = SYSARG_1;
		*op = DF_OP_MKDIR;
		return true;
	case PR_mkdirat:
		*op = DF_OP_MKDIR;
		return true;
	case PR_unlink:
		*path_reg = SYSARG_1;
		*op = DF_OP_UNLINK;
		return true;
	case PR_rmdir:
		*path_reg = SYSARG_1;
		*op = DF_OP_RMDIR;
		return true;
	case PR_unlinkat:
		*op = (peek_reg(tracee, ORIGINAL, SYSARG_3) & AT_REMOVEDIR) ? DF_OP_RMDIR : DF_OP_UNLINK;
		return true;
	case PR_getdents64:
	case PR_getdents:
		*fd_reg = SYSARG_1;
		*op = sysnum == PR_getdents64 ? DF_OP_GETDENTS64 : DF_OP_GETDENTS;
		return true;
	case PR_rename:
		*path_reg = SYSARG_1;
		*new_path_reg = SYSARG_2;
		*op = DF_OP_RENAME;
		return true;
	case PR_renameat:
	case PR_renameat2:
		*new_path_reg = SYSARG_4;
		*op = DF_OP_RENAME;
		return true;

	case PR_fstatat64:
	case PR_newfstatat:
	case PR_statx:
		*kind = KIND_FALLBACK;
		*op = DF_OP_STAT;
		return true;
	case PR_faccessat:
	case PR_faccessat2:
		*kind = KIND_FALLBACK;
		*op = DF_OP_ACCESS;
		return true;

	case PR_truncate:
		*kind = KIND_TRUNCATE;
		*path_reg = SYSARG_1;
		*op = DF_OP_OPEN;
		return true;
	case PR_statfs:
		*kind = KIND_STATFS;
		*path_reg = SYSARG_1;
		*op = 0;
		return true;

	/* Times, mode and owner: the server is only asked whether the file exists. */
	case PR_chmod:
	case PR_chown:
	case PR_lchown:
	case PR_utime:
	case PR_utimes:
		*path_reg = SYSARG_1;
		/* Fall through. */
	case PR_fchmodat:
	case PR_futimesat:
		*kind = KIND_QUIET;
		*op = DF_OP_ACCESS;
		return true;
	case PR_utimensat:
		/* utimensat(fd, NULL, ...) is futimens(). */
		*kind = KIND_QUIET;
		*op = DF_OP_ACCESS;
		if (peek_reg(tracee, ORIGINAL, SYSARG_2) == 0) {
			*kind = KIND_QUIET_FD;
			*fd_reg = SYSARG_1;
		}
		return true;
	case PR_fchownat:
		*kind = KIND_QUIET;
		*op = DF_OP_ACCESS;
		if (peek_reg(tracee, ORIGINAL, SYSARG_5) & AT_EMPTY_PATH) {
			char empty;
			if (read_data(tracee, &empty, peek_reg(tracee, ORIGINAL, SYSARG_2), 1) == 0 &&
			    empty == '\0') {
				*kind = KIND_QUIET_FD;
				*fd_reg = SYSARG_1;
			}
		}
		return true;
	case PR_fchmod:
	case PR_fchown:
		*kind = KIND_QUIET_FD;
		*fd_reg = SYSARG_1;
		*op = 0;
		return true;

	default:
		return false;
	}
}

/* The host path a syscall works on: its fd's, or its path argument as proot translated it
 * (absolute, and resolved against the cwd or dirfd), normalized. False if there isn't one. */
static bool host_path_of(Tracee *tracee, Reg path_reg, Reg fd_reg, char host[PATH_MAX])
{
	int status;

	if (fd_reg != IGNORE_SYSARG) {
		status = readlink_proc_pid_fd(tracee->pid, (int) peek_reg(tracee, ORIGINAL, fd_reg), host);
	} else {
		status = read_string(tracee, host, peek_reg(tracee, CURRENT, path_reg), PATH_MAX);
		if (status >= PATH_MAX)
			status = -ENAMETOOLONG;
	}
	if (status < 0 || host[0] != '/')
		return false;
	normalize(host);
	return true;
}

static int handle_sysenter_end(Tracee *tracee, DroidFilesState *state)
{
	char host[PATH_MAX];
	bool from_server_fd, new_from_server_fd;
	word_t sysnum = get_sysnum(tracee, ORIGINAL);
	Reg path_reg, fd_reg, new_path_reg;
	uint32_t op;
	Kind kind;
	bool deep_only;

	if (!classify(tracee, sysnum, &op, &kind, &path_reg, &fd_reg, &new_path_reg))
		return 0;
	state->new_guest_path[0] = '\0';
	/* The chained syscalls below lay out msghdr/iovec for this ABI only. */
	if (is_32on64_mode(tracee))
		return 0;
	if (!init_sdcard_host(tracee))
		return 0;

	/* What the kernel may answer itself leaves the folders directly under /sdcard to it, and
	 * so does a rename, where a top-level entry can be the app's own. */
	deep_only = kind == KIND_FALLBACK || kind == KIND_QUIET || kind == KIND_STATFS ||
		op == DF_OP_RENAME;

	if (!host_path_of(tracee, path_reg, fd_reg, host))
		return 0;
	if (!guest_path_for(host, state->guest_path, deep_only, &from_server_fd)) {
		state->guest_path[0] = '\0';
		if (op != DF_OP_RENAME)
			return 0;
	}
	if (fd_reg != IGNORE_SYSARG)
		state->dir_fd = (int) peek_reg(tracee, ORIGINAL, fd_reg);

	if (op == DF_OP_RENAME) {
		bool to_sdcard = host_path_of(tracee, new_path_reg, IGNORE_SYSARG, host) &&
			guest_path_for(host, state->new_guest_path, true, &new_from_server_fd);
		bool from_sdcard = state->guest_path[0] != '\0';

		if (!from_sdcard && !to_sdcard)
			return 0;
		/* Into or out of a granted folder: not something one rename can do. mv(1) copies. */
		if (from_sdcard != to_sdcard) {
			VERBOSE(tracee, 2, "droid_files: rename across the edge of /sdcard, EXDEV");
			state->kind = KIND_RESULT;
			state->result = (word_t) -EXDEV;
			state->step = STEP_RESULT;
			set_sysnum(tracee, PR_void);
			return 1;
		}
	}

	VERBOSE(tracee, 2, "droid_files: op %u (kind %d) on %s", op, kind, state->guest_path);

	state->op = op;
	state->kind = kind;
	state->sock = (word_t) -1;
	state->fd = (word_t) -1;
	state->result = 0;
	state->mem_req  = alloc_mem(tracee, sizeof(df_request_t));
	state->mem_resp = alloc_mem(tracee, sizeof(df_response_t));
	state->mem_iov  = alloc_mem(tracee, 2 * sizeof(struct iovec));
	state->mem_ctrl = alloc_mem(tracee, DF_CONTROL_SIZE);
	state->mem_msg  = alloc_mem(tracee, sizeof(struct msghdr));
	state->mem_empty = alloc_mem(tracee, 8);
	if (state->mem_req == 0 || state->mem_resp == 0 || state->mem_iov == 0 ||
	    state->mem_ctrl == 0 || state->mem_msg == 0 || state->mem_empty == 0)
		return 0;

	/* The kernel can stat what is under /sdcard -- listing a folder with ls -l went from 0.3s
	 * to 1.9s when every entry went to the server instead -- it just can't open it. So these
	 * run as they are, and only one that fails goes further (see SYSCALL_EXIT_START). Paths
	 * under the server's own fds are the exception for stat and access: the kernel can't see
	 * those at all. The memory above is reserved now regardless: alloc_mem() only works at
	 * syscall entry. */
	if (kind != KIND_TAKEOVER && !(kind == KIND_FALLBACK && from_server_fd)) {
		state->step = STEP_NATIVE;
		return 0;
	}

	/* The original syscall becomes the first step of the conversation. A blocking
	 * SEQPACKET socket: each request and reply is one whole message. */
	state->step = STEP_SOCKET;
	set_sysnum(tracee, PR_socket);
	poke_reg(tracee, SYSARG_1, AF_UNIX);
	poke_reg(tracee, SYSARG_2, SOCK_SEQPACKET | SOCK_CLOEXEC);
	poke_reg(tracee, SYSARG_3, 0);

	/* Stop the other extensions here: this is no longer the file syscall they would act on,
	 * and its registers now hold socket() arguments. Read as a path, those fail -- fake_id0's
	 * permission check turned every unlink by a non-root user into EFAULT. A positive status
	 * ends notify_extensions() without failing the syscall.
	 *
	 * That only shields the others if this extension comes first, and extensions run in the
	 * reverse of the order they were enabled in: --droid_files has to be the last extension
	 * option on proot's command line, as UserLAnd passes it. */
	return 1;
}

/* --- Syscall exit. ------------------------------------------------------------------------ */

/* Ends the conversation: closes the socket if there is one and reports @result. */
static void finish(Tracee *tracee, DroidFilesState *state, word_t result)
{
	state->result = result;
	if ((int) state->sock >= 0) {
		state->step = STEP_CLOSE_SOCK;
		register_chained_syscall(tracee, PR_close, state->sock, 0, 0, 0, 0, 0);
		force_chain_final_result(tracee, result);
	} else {
		state->step = STEP_IDLE;
		poke_reg(tracee, SYSARG_RESULT, result);
	}
}

static void send_request(Tracee *tracee, DroidFilesState *state)
{
	df_request_t request;
	word_t sysnum = get_sysnum(tracee, ORIGINAL);

	memset(&request, 0, sizeof(request));
	request.op = state->op;
	strcpy(request.path, state->guest_path);
	strcpy(request.new_path, state->new_guest_path);

	switch (sysnum) {
	case PR_open:
		request.flags = peek_reg(tracee, ORIGINAL, SYSARG_2);
		request.mode  = peek_reg(tracee, ORIGINAL, SYSARG_3);
		break;
	case PR_openat:
		request.flags = peek_reg(tracee, ORIGINAL, SYSARG_3);
		request.mode  = peek_reg(tracee, ORIGINAL, SYSARG_4);
		break;
	case PR_creat:
		request.flags = O_CREAT | O_WRONLY | O_TRUNC;
		request.mode  = peek_reg(tracee, ORIGINAL, SYSARG_2);
		break;
	case PR_faccessat:
	case PR_faccessat2:
		request.flags = peek_reg(tracee, ORIGINAL, SYSARG_3);
		break;
	case PR_getdents:
	case PR_getdents64:
		request.count  = peek_reg(tracee, ORIGINAL, SYSARG_3);
		request.offset = fd_position(tracee, state->dir_fd);
		break;
	case PR_renameat2:
		request.flags = peek_reg(tracee, ORIGINAL, SYSARG_5);
		break;
	case PR_truncate:
		/* Writable, and not truncated by the open: ftruncate() sets the length. */
		request.flags = O_WRONLY;
		break;
	default:
		/* An access() asking whether it exists, for the quiet calls. */
		break;
	}

	write_data(tracee, state->mem_req, &request, sizeof(request));
	state->step = STEP_WRITE;
	register_chained_syscall(tracee, PR_write, state->sock, state->mem_req, sizeof(request), 0, 0, 0);
}

static void receive_reply(Tracee *tracee, DroidFilesState *state)
{
	struct iovec iov[2];
	struct msghdr message;
	bool getdents = (state->op == DF_OP_GETDENTS64 || state->op == DF_OP_GETDENTS);
	int flags = MSG_CMSG_CLOEXEC;

	/* The reply header, then for getdents the caller's own buffer: the records land there. */
	iov[0].iov_base = (void *) state->mem_resp;
	iov[0].iov_len  = sizeof(df_response_t);
	iov[1].iov_base = (void *) peek_reg(tracee, ORIGINAL, SYSARG_2);
	iov[1].iov_len  = getdents ? peek_reg(tracee, ORIGINAL, SYSARG_3) : 0;
	write_data(tracee, state->mem_iov, iov, sizeof(iov));

	memset(&message, 0, sizeof(message));
	message.msg_iov        = (struct iovec *) state->mem_iov;
	message.msg_iovlen     = getdents ? 2 : 1;
	message.msg_control    = (void *) state->mem_ctrl;
	message.msg_controllen = DF_CONTROL_SIZE;
	write_data(tracee, state->mem_msg, &message, sizeof(message));

	/* The fd the tracee keeps from an open honours its O_CLOEXEC; any other is temporary. */
	if (state->op == DF_OP_OPEN && state->kind == KIND_TAKEOVER) {
		word_t sysnum = get_sysnum(tracee, ORIGINAL);
		word_t open_flags = sysnum == PR_open ? peek_reg(tracee, ORIGINAL, SYSARG_2)
			: sysnum == PR_openat ? peek_reg(tracee, ORIGINAL, SYSARG_3) : 0;
		if (!(open_flags & O_CLOEXEC))
			flags = 0;
	}

	state->step = STEP_RECVMSG;
	register_chained_syscall(tracee, PR_recvmsg, state->sock, state->mem_msg, flags, 0, 0, 0);
}

/* The fd in the reply's SCM_RIGHTS, or -1. */
static int received_fd(Tracee *tracee, DroidFilesState *state)
{
	struct msghdr message;
	union {
		char buffer[DF_CONTROL_SIZE];
		struct cmsghdr align;
	} control;
	struct cmsghdr *cmsg;

	if (read_data(tracee, &message, state->mem_msg, sizeof(message)) < 0)
		return -1;
	if (message.msg_controllen < CMSG_LEN(sizeof(int)))
		return -1;
	if (read_data(tracee, control.buffer, state->mem_ctrl, DF_CONTROL_SIZE) < 0)
		return -1;
	message.msg_control = control.buffer;
	cmsg = CMSG_FIRSTHDR(&message);
	if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
		return -1;
	return *(int *) CMSG_DATA(cmsg);
}

static void handle_reply(Tracee *tracee, DroidFilesState *state, word_t received)
{
	df_response_t response;
	int fd;

	if ((int) received < 0) {
		finish(tracee, state, received);
		return;
	}
	if (received < sizeof(response) ||
	    read_data(tracee, &response, state->mem_resp, sizeof(response)) < 0) {
		finish(tracee, state, -EIO);
		return;
	}
	if (response.err != 0) {
		finish(tracee, state, -response.err);
		return;
	}

	switch (state->op) {
	case DF_OP_OPEN:
	case DF_OP_STAT:
		fd = received_fd(tracee, state);
		if (fd < 0) {
			finish(tracee, state, -EIO);
			return;
		}
		state->fd = fd;
		learn_saf_prefix(tracee, fd, state->guest_path);
		if (state->kind == KIND_TRUNCATE) {
			state->step = STEP_USE_FD;
			register_chained_syscall(tracee, PR_ftruncate, fd,
						peek_reg(tracee, ORIGINAL, SYSARG_2), 0, 0, 0, 0);
			return;
		}
		if (state->op == DF_OP_OPEN) {
			finish(tracee, state, fd);
			return;
		}
		/* stat: stat the server's fd into the caller's buffer, then drop the fd. */
		state->step = STEP_USE_FD;
		if (get_sysnum(tracee, ORIGINAL) == PR_statx) {
			static const char empty = '\0';
			write_data(tracee, state->mem_empty, &empty, 1);
			register_chained_syscall(tracee, PR_statx, fd, state->mem_empty,
				AT_EMPTY_PATH | (peek_reg(tracee, ORIGINAL, SYSARG_3) & AT_STATX_SYNC_TYPE),
				peek_reg(tracee, ORIGINAL, SYSARG_4), peek_reg(tracee, ORIGINAL, SYSARG_5), 0);
		} else {
			register_chained_syscall(tracee, PR_fstat, fd,
						peek_reg(tracee, ORIGINAL, SYSARG_3), 0, 0, 0, 0);
		}
		return;

	case DF_OP_GETDENTS64:
	case DF_OP_GETDENTS:
		state->result = response.len;
		if (response.len == 0) {
			finish(tracee, state, 0);
			return;
		}
		/* Keep the place in the fd itself, as a real directory does: rewinddir() and
		 * seekdir() then work, and a dup'd fd shares the position. */
		state->step = STEP_LSEEK;
		register_chained_syscall(tracee, PR_lseek, state->dir_fd, response.next_offset,
					SEEK_SET, 0, 0, 0);
		return;

	default:
		finish(tracee, state, 0);
		return;
	}
}

/* Returns 1 for the exits of a syscall this extension has taken over, which keeps the other
 * extensions away from them (see handle_sysenter_end()), and 0 otherwise. */
static int handle_sysexit_end(Tracee *tracee, DroidFilesState *state)
{
	word_t result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	struct sockaddr_un address;
	char host[PATH_MAX];

	if (state->step == STEP_IDLE)
		return 0;

	switch (state->step) {
	case STEP_IDLE:
	case STEP_NATIVE:
	case STEP_RESULT:
		break;

	case STEP_PASSTHROUGH:
		state->step = STEP_IDLE;
		return 1;

	case STEP_SOCKET:
		if ((int) result < 0) {
			finish(tracee, state, result);
			return 1;
		}
		state->sock = result;
		memset(&address, 0, sizeof(address));
		address.sun_family = AF_UNIX;
		/* translate_path() fills a PATH_MAX buffer; sun_path is far smaller. */
		if (translate_path(tracee, host, AT_FDCWD, DF_SOCKNAME, true) < 0 ||
		    strlen(host) >= sizeof(address.sun_path)) {
			finish(tracee, state, -EIO);
			return 1;
		}
		strcpy(address.sun_path, host);
		/* Reuses the request buffer; the request is written after the connect. */
		write_data(tracee, state->mem_req, &address, sizeof(address));
		state->step = STEP_CONNECT;
		register_chained_syscall(tracee, PR_connect, state->sock, state->mem_req,
					sizeof(address), 0, 0, 0);
		return 1;

	case STEP_CONNECT:
		if ((int) result < 0) {
			/* No server: an older app, or one that isn't running. */
			VERBOSE(tracee, 2, "droid_files: can't reach the server (%d)", (int) result);
			finish(tracee, state, -EACCES);
			return 1;
		}
		send_request(tracee, state);
		return 1;

	case STEP_WRITE:
		if ((int) result < 0 || result != sizeof(df_request_t)) {
			finish(tracee, state, (int) result < 0 ? result : (word_t) -EIO);
			return 1;
		}
		receive_reply(tracee, state);
		return 1;

	case STEP_RECVMSG:
		handle_reply(tracee, state, result);
		return 1;

	case STEP_USE_FD:
		state->result = result;
		state->step = STEP_CLOSE_FD;
		register_chained_syscall(tracee, PR_close, state->fd, 0, 0, 0, 0, 0);
		return 1;

	case STEP_CLOSE_FD:
		finish(tracee, state, state->result);
		return 1;

	case STEP_LSEEK:
		finish(tracee, state, state->result);
		return 1;

	case STEP_CLOSE_SOCK:
		/* force_chain_final_result() delivers the result. */
		state->step = STEP_IDLE;
		return 1;
	}
	return 1;
}

/* The exit of a syscall the kernel tried first (see Kind). Returns 1 once it is taken over. */
static int handle_native_exit(Tracee *tracee, DroidFilesState *state)
{
	if ((int) peek_reg(tracee, CURRENT, SYSARG_RESULT) >= 0) {
		state->step = STEP_IDLE;
		return 0;
	}

	switch (state->kind) {
	case KIND_QUIET_FD:
		/* An fd under /sdcard exists by definition. */
		poke_reg(tracee, SYSARG_RESULT, 0);
		state->step = STEP_IDLE;
		return 1;

	case KIND_STATFS:
		/* Every folder under /sdcard is on the same filesystem as /sdcard. */
		write_data(tracee, state->mem_req, sdcard_host, strlen(sdcard_host) + 1);
		state->step = STEP_PASSTHROUGH;
		register_chained_syscall(tracee, PR_statfs, state->mem_req,
					peek_reg(tracee, ORIGINAL, SYSARG_2), 0, 0, 0, 0);
		return 1;

	default:
		/* Ask the server, as if the syscall had been taken over at entry. */
		state->step = STEP_SOCKET;
		register_chained_syscall(tracee, PR_socket, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC,
					0, 0, 0, 0);
		return 1;
	}
}

/* --- Extension plumbing. ------------------------------------------------------------------ */

static DroidFilesState *new_state(Extension *extension)
{
	extension->config = talloc_zero(extension, DroidFilesState);
	return extension->config;
}

int droid_files_callback(Extension *extension, ExtensionEvent event,
	intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
	DroidFilesState *state = extension->config;

	switch (event) {
	case INITIALIZATION: {
		static FilteredSysnum filtered_sysnums[] = {
			{ PR_open,       FILTER_SYSEXIT },
			{ PR_openat,     FILTER_SYSEXIT },
			{ PR_creat,      FILTER_SYSEXIT },
			{ PR_mkdir,      FILTER_SYSEXIT },
			{ PR_mkdirat,    FILTER_SYSEXIT },
			{ PR_unlink,     FILTER_SYSEXIT },
			{ PR_unlinkat,   FILTER_SYSEXIT },
			{ PR_rmdir,      FILTER_SYSEXIT },
			{ PR_getdents,   FILTER_SYSEXIT },
			{ PR_getdents64, FILTER_SYSEXIT },
			{ PR_newfstatat, FILTER_SYSEXIT },
			{ PR_fstatat64,  FILTER_SYSEXIT },
			{ PR_statx,      FILTER_SYSEXIT },
			{ PR_faccessat,  FILTER_SYSEXIT },
			{ PR_faccessat2, FILTER_SYSEXIT },
			{ PR_rename,     FILTER_SYSEXIT },
			{ PR_renameat,   FILTER_SYSEXIT },
			{ PR_renameat2,  FILTER_SYSEXIT },
			{ PR_truncate,   FILTER_SYSEXIT },
			{ PR_statfs,     FILTER_SYSEXIT },
			{ PR_chmod,      FILTER_SYSEXIT },
			{ PR_fchmod,     FILTER_SYSEXIT },
			{ PR_fchmodat,   FILTER_SYSEXIT },
			{ PR_chown,      FILTER_SYSEXIT },
			{ PR_lchown,     FILTER_SYSEXIT },
			{ PR_fchown,     FILTER_SYSEXIT },
			{ PR_fchownat,   FILTER_SYSEXIT },
			{ PR_utime,      FILTER_SYSEXIT },
			{ PR_utimes,     FILTER_SYSEXIT },
			{ PR_futimesat,  FILTER_SYSEXIT },
			{ PR_utimensat,  FILTER_SYSEXIT },
			FILTERED_SYSNUM_END,
		};
		extension->filtered_sysnums = filtered_sysnums;
		return new_state(extension) == NULL ? -ENOMEM : 0;
	}

	/* Each tracee gets its own state: they make syscalls independently. */
	case INHERIT_PARENT:
		return 1;

	case INHERIT_CHILD:
		return new_state(extension) == NULL ? -ENOMEM : 0;

	case SYSCALL_ENTER_END:
		if (state == NULL)
			return 0;
		state->step = STEP_IDLE;
		return handle_sysenter_end(TRACEE(extension), state);

	/* The first exit is the socket() that replaced the tracee's syscall. It is handled before
	 * proot's own exit translation, which would otherwise treat it as the original call --
	 * statx() is emulated there, and that overwrote the socket's fd -- and a positive status
	 * skips that translation altogether. */
	case SYSCALL_EXIT_START:
		if (state == NULL)
			return 0;
		if (state->step == STEP_RESULT) {
			poke_reg(TRACEE(extension), SYSARG_RESULT, state->result);
			state->step = STEP_IDLE;
			return 1;
		}
		if (state->step == STEP_NATIVE)
			return handle_native_exit(TRACEE(extension), state);
		if (state->step != STEP_SOCKET)
			return 0;
		return handle_sysexit_end(TRACEE(extension), state);

	case SYSCALL_CHAINED_EXIT:
		if (state == NULL)
			return 0;
		return handle_sysexit_end(TRACEE(extension), state);

	default:
		return 0;
	}
}
