#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <fcntl.h>
#include <string.h>

#include "cli/note.h"
#include "path/path.h"
#include "tracee/mem.h"
#include "syscall/chain.h"
#include "extension/extension.h"
#include "extension/fake_id0/helper_functions.h"

#define DROID_FILES_SOCKNAME "/support/common/droid_files_socket"

typedef struct {
    word_t sysCall;
    char path[4096];
    word_t sysargs[5];
} sock_req_t;

int handle_open_sysenter_end(Tracee *tracee, Reg path_sysarg) {
    int status, size;
    char check_path[] = "/sdcard/";
    char orig_path[PATH_MAX];
    
    size = read_string(tracee, orig_path, peek_reg(tracee, ORIGINAL, path_sysarg), PATH_MAX);
    if (size < 0) //return errors
        return size;
    if (size >= PATH_MAX)
        return -ENAMETOOLONG;
    if(strlen(orig_path) > 0)
        if(belongs_to_guestfs(tracee, orig_path)) //easy early abort if the path is part of the guestfs
            return 1;

    VERBOSE(tracee, 1, "droid_files path: %s", orig_path);

    if (strncmp(orig_path, check_path, strlen(check_path)) != 0)
        return 0;

    set_sysnum(tracee, PR_socket);
    poke_reg(tracee, SYSARG_1, AF_UNIX);
    poke_reg(tracee, SYSARG_2, SOCK_STREAM);
    poke_reg(tracee, SYSARG_3, 0);

    //Allocate memory we are going to need later
    tracee->word_store[0] = alloc_mem(tracee, sizeof(struct sockaddr_un));
    tracee->word_store[1] = alloc_mem(tracee, sizeof(word_t)); //socket file handle
    tracee->word_store[2] = alloc_mem(tracee, sizeof(word_t)); //final file handle
    tracee->word_store[3] = alloc_mem(tracee, sizeof(sock_req_t));
    tracee->word_store[4] = alloc_mem(tracee, 1);
    tracee->word_store[5] = alloc_mem(tracee, sizeof(struct iovec));
    struct {
        struct cmsghdr align;
        int fd[1];
    } ancillary_data_buffer;
    tracee->word_store[6] = alloc_mem(tracee, sizeof(ancillary_data_buffer));
    tracee->word_store[7] = alloc_mem(tracee, sizeof(struct msghdr));

    return 0;
}

int handle_open_sysexit_end(Tracee *tracee, Reg path_sysarg) {
    word_t sysnum;
    word_t result;
    size_t size;
    int shmid;

    sysnum = get_sysnum(tracee, CURRENT);
    switch (sysnum) {
    case PR_socket:
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if ((int)result < 0) {
            VERBOSE(tracee, 4, "%s: cannot create UNIX socket", __PRETTY_FUNCTION__);
            return -EINVAL;
        }
        struct sockaddr_un sockaddr;
        memset(&sockaddr, 0, sizeof(sockaddr));
        sockaddr.sun_family = AF_UNIX;
        char sock_path[PATH_MAX];
	translate_path(tracee, sock_path, AT_FDCWD, DROID_FILES_SOCKNAME, true);
        sprintf(sockaddr.sun_path, sock_path);
        VERBOSE(tracee, 1, "droid_files path: %s", sock_path);
        write_data(tracee, tracee->word_store[0], &sockaddr, sizeof(struct sockaddr_un));
        tracee->word_store[1] = result;
        tracee->word_store[2] = (word_t)-1;
        register_chained_syscall(tracee, PR_connect, result, tracee->word_store[0], sizeof(sockaddr), 0, 0, 0);
        return 0;
    case PR_connect:
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if ((int)result != 0) {
            VERBOSE(tracee, 4, "%s: Cannot connect to UNIX socket", __PRETTY_FUNCTION__);
            return -EINVAL;
        }
        sock_req_t sock_req;
        sock_req.sysCall = 1;
        char orig_path[PATH_MAX];
        size = read_string(tracee, orig_path, peek_reg(tracee, ORIGINAL, path_sysarg), PATH_MAX);
        strcpy(sock_req.path, orig_path);
        write_data(tracee, tracee->word_store[3], &sock_req, sizeof(sock_req_t));
        register_chained_syscall(tracee, PR_write, tracee->word_store[1], tracee->word_store[3], sizeof(sock_req), 0, 0, 0);
    case PR_write:
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if ((size_t)result != sizeof(sock_req_t)) {
            VERBOSE(tracee, 4, "%s: Failed to write UNIX socket", __PRETTY_FUNCTION__);
            register_chained_syscall(tracee, PR_close, tracee->word_store[1], 0, 0, 0, 0, 0);
            return 0;
        }

        char nothing = '!';
        write_data(tracee, tracee->word_store[4], &nothing, 1);
        struct iovec nothing_ptr = { .iov_base = (void *)tracee->word_store[4], .iov_len = 1 };
        write_data(tracee, tracee->word_store[5], &nothing_ptr, sizeof(nothing_ptr));
        struct {
            struct cmsghdr align;
            int fd[1];
        } ancillary_data_buffer;
        ancillary_data_buffer.fd[0] = -1;
        write_data(tracee, tracee->word_store[6], &ancillary_data_buffer, sizeof(ancillary_data_buffer));

        struct msghdr message_header = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = (struct iovec *)tracee->word_store[5],
            .msg_iovlen = 1,
            .msg_flags = 0,
            .msg_control = (void *)tracee->word_store[6],
            .msg_controllen = sizeof(struct cmsghdr) + sizeof(int)
        };
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&message_header);
        cmsg->cmsg_len = message_header.msg_controllen; // sizeof(int);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        write_data(tracee, tracee->word_store[7], &message_header, sizeof(struct msghdr));

        register_chained_syscall(tracee, PR_recvmsg, tracee->word_store[1], tracee->word_store[7], 0, 0, 0, 0);
        return 0;
    case PR_recvmsg:
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if ((int)result < 0) {
            VERBOSE(tracee, 4, "%s: recvmesg() failed on socket", __PRETTY_FUNCTION__);
            register_chained_syscall(tracee, PR_close, tracee->word_store[1], 0, 0, 0, 0, 0);
            return 0;
        }

        struct msghdr message_header_2;
        read_data(tracee, &message_header_2, tracee->word_store[7], sizeof(struct msghdr));

        struct {
            struct cmsghdr align;
            int fd[1];
        } ancillary_data_buffer_2;
        read_data(tracee, &ancillary_data_buffer_2, (word_t)message_header_2.msg_control, sizeof(ancillary_data_buffer_2));

        tracee->word_store[2] = ancillary_data_buffer_2.fd[0];
        register_chained_syscall(tracee, PR_close, tracee->word_store[1], 0, 0, 0, 0, 0);
        return 0;
    case PR_close: {
        poke_reg(tracee, SYSARG_RESULT, tracee->word_store[2]);
        if ((int)tracee->word_store[2] == -1)
            return -EINVAL;
    }
    default:
        return 0;
    }

    return 0;
}


static int handle_sysenter_end(Tracee *tracee)
{
    word_t sysnum;

    sysnum = get_sysnum(tracee, ORIGINAL);
    switch (sysnum) {
    /* int openat(int dirfd, const char *pathname, int flags, mode_t mode) */
    /* int open(const char *pathname, int flags, mode_t mode) */
    /* int creat(const char *pathname, mode_t mode) */
    case PR_openat:
        return handle_open_sysenter_end(tracee, SYSARG_2);
    case PR_open:
    case PR_creat:
        return handle_open_sysenter_end(tracee, SYSARG_1);

    default:
        return 0;
    }
}

static int handle_sysexit_end(Tracee *tracee)
{
    word_t sysnum;

    sysnum = get_sysnum(tracee, ORIGINAL);
    switch (sysnum) {
    /* int openat(int dirfd, const char *pathname, int flags, mode_t mode) */
    /* int open(const char *pathname, int flags, mode_t mode) */
    /* int creat(const char *pathname, mode_t mode) */
    case PR_openat:
        return handle_open_sysexit_end(tracee, SYSARG_2);
    case PR_open:
    case PR_creat:
        return handle_open_sysexit_end(tracee, SYSARG_1);

    default:
        return 0;
    }
}

/**
 * Handler for this @extension.  It is triggered each time an @event
 * occured.  See ExtensionEvent for the meaning of @data1 and @data2.
 */
int droid_files_callback(Extension *extension, ExtensionEvent event,
        intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    switch (event) {
    case INITIALIZATION: {
        /* List of syscalls handled by this extension */
        static FilteredSysnum filtered_sysnums[] = {
            { PR_open,   FILTER_SYSEXIT },
            { PR_openat, FILTER_SYSEXIT },
            { PR_creat,  FILTER_SYSEXIT },
            FILTERED_SYSNUM_END,
        };
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }

    case SYSCALL_ENTER_END: {
        return handle_sysenter_end(TRACEE(extension));
    }

    case SYSCALL_CHAINED_EXIT:
    case SYSCALL_EXIT_END: {
        return handle_sysexit_end(TRACEE(extension));
    }

    default:
        return 0;
    }
}



