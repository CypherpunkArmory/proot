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
#define DROID_FILES_GETDENTSNAME "/support/common/droid_files_getdents"

//these paths will be used to determine if this system call should be acted upon
#define DROID_FILES_CHECKPATH "/sdcard/"
//this is a path we will get from an fd passed from the droid_files server
char check_path2[PATH_MAX];

typedef struct {
    word_t sysCall;
    char path[4096];
    char new_path[4096];
    word_t sysargs[5];
} sock_req_t;

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

struct linux_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

int check_paths(Tracee *tracee, Reg fd_sysarg, Reg path_sysarg) {
    int size, status;
    char check_path[] = DROID_FILES_CHECKPATH;
    char translated_check_path[PATH_MAX];
    char orig_path[PATH_MAX];
    
    if (path_sysarg != IGNORE_SYSARG) {
        size = read_string(tracee, orig_path, peek_reg(tracee, CURRENT, path_sysarg), PATH_MAX);
    } else {
        size = readlink_proc_pid_fd(tracee->pid, peek_reg(tracee, CURRENT, fd_sysarg), orig_path);
        VERBOSE(tracee, 4, "%s: droid_files orig_path = %s", __PRETTY_FUNCTION__, orig_path);
    }
    if (size < 0)
        return size;
    if (size >= PATH_MAX)
        return -ENAMETOOLONG;
    
    status = translate_path(tracee, translated_check_path, AT_FDCWD, check_path, true);
    if (status < 0)
        return status;

    VERBOSE(tracee, 4, "%s: droid_files translated_check_path = %s", __PRETTY_FUNCTION__, translated_check_path);

    if (strlen(orig_path) > strlen(translated_check_path))
        if (strncmp(orig_path, translated_check_path, strlen(translated_check_path)) == 0)
            return 1;

    VERBOSE(tracee, 4, "%s: droid_files check_path2 = %s", __PRETTY_FUNCTION__, check_path2);

    if (strlen(check_path2) > 1)
        if (strlen(orig_path) > strlen(check_path2))
            if (strncmp(orig_path, check_path2, strlen(check_path2)) == 0)
                return 1;

    return 0;
}

int find_common_suffix_len(const char* str1, const char* str2) {
    int len1 = strlen(str1);
    int len2 = strlen(str2);
    int i = len1 - 1;
    int j = len2 - 1;
    int count = 0;

    while (i >= 0 && j >= 0 && str1[i] == str2[j]) {
        i--;
        j--;
        count++;
    }

    return count;
}

int update_check_path2(Tracee *tracee, int fd, Reg path_sysarg) {
    int size;
    char fd_path[PATH_MAX];
    char orig_path[PATH_MAX];
    int common_length;

    size = readlink_proc_pid_fd(tracee->pid, fd, fd_path);
    if (size < 0) {
        return size;
    }
    VERBOSE(tracee, 4, "%s: droid_files fd_path = %s", __PRETTY_FUNCTION__, fd_path);
    
    size = read_string(tracee, orig_path, peek_reg(tracee, ORIGINAL, path_sysarg), PATH_MAX);
    if (size < 0)
        return size;
    if (size >= PATH_MAX)
        return -ENAMETOOLONG;
    VERBOSE(tracee, 4, "%s: droid_files orig_path = %s", __PRETTY_FUNCTION__, orig_path);
    
    common_length = find_common_suffix_len(orig_path, fd_path);
    strncpy(check_path2, fd_path, strlen(fd_path) - common_length);
    VERBOSE(tracee, 4, "%s: droid_files check_path2 = %s", __PRETTY_FUNCTION__, check_path2);

    return 0;
}

void modify_path(Tracee *tracee, char *path) {
    int status;
    char check_path[] = DROID_FILES_CHECKPATH;
    char translated_check_path[PATH_MAX];
    char saved_path[PATH_MAX];

    if (strlen(check_path2) <= 1) {
        return;
    }

    if (strncmp(path, check_path2, strlen(check_path2)) != 0) {
        return;
    }

    status = translate_path(tracee, translated_check_path, AT_FDCWD, check_path, true);
    if (status < 0)
        return;

    strcpy(saved_path, path);
    strcpy(path, translated_check_path);
    strcat(path, saved_path + strlen(check_path2));
    VERBOSE(tracee, 4, "%s: droid_files path = %s", __PRETTY_FUNCTION__, path);
    return;
}

int handle_open_sysenter_end(Tracee *tracee, Reg fd_sysarg, Reg path_sysarg) {
    int status;
    
    status = check_paths(tracee, fd_sysarg, path_sysarg);
    if (status <= 0)
        return status;

    VERBOSE(tracee, 4, "%s: droid_files path match found", __PRETTY_FUNCTION__);

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
    tracee->word_store[8] = alloc_mem(tracee, sizeof(word_t)); //status / error code

    return 0;
}

int handle_open_sysexit_end(Tracee *tracee, Reg fd_sysarg, Reg path_sysarg, Reg flags_sysarg, Reg mode_sysarg) {
    word_t sysnum, orig_sysnum;
    word_t result;
    size_t size;
    int status;

    orig_sysnum = get_sysnum(tracee, ORIGINAL);
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
        sprintf(sockaddr.sun_path, "%s", sock_path);
        write_data(tracee, tracee->word_store[0], &sockaddr, sizeof(struct sockaddr_un));
        tracee->word_store[1] = result;
        tracee->word_store[2] = (word_t)0;
        if ((orig_sysnum == PR_open) || (orig_sysnum == PR_openat) || (orig_sysnum == PR_creat))
            tracee->word_store[2] = (word_t)-1;
        word_t init_status = 0;
        write_data(tracee, tracee->word_store[8], &init_status, sizeof(word_t));
        register_chained_syscall(tracee, PR_connect, result, tracee->word_store[0], sizeof(sockaddr), 0, 0, 0);
        return 0;
    case PR_connect:
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if ((int)result != 0) {
            VERBOSE(tracee, 4, "%s: Cannot connect to UNIX socket", __PRETTY_FUNCTION__);
            return -EINVAL;
        }
        sock_req_t sock_req;
        if (orig_sysnum == PR_open) {
            sock_req.sysCall = 0; //should come up with some sort of enum or similar
        } else if (orig_sysnum == PR_openat) {
            sock_req.sysCall = 1;
        } else if (orig_sysnum == PR_creat) {
            sock_req.sysCall = 2;
        } else if (orig_sysnum == PR_mkdir) {
            sock_req.sysCall = 3;
        } else if (orig_sysnum == PR_mkdirat) {
            sock_req.sysCall = 4;
        } else if (orig_sysnum == PR_unlink) {
            sock_req.sysCall = 5;
        } else if (orig_sysnum == PR_unlinkat) {
            sock_req.sysCall = 6;
        } else if (orig_sysnum == PR_getdents) {
            sock_req.sysCall = 7;
        } else if (orig_sysnum == PR_getdents64) {
            sock_req.sysCall = 8;
        }
        if (orig_sysnum == PR_creat) {
            sock_req.sysargs[0] = O_CREAT | O_WRONLY | O_TRUNC;
        } else if (flags_sysarg != IGNORE_SYSARG) {
            sock_req.sysargs[0] = peek_reg(tracee, ORIGINAL, flags_sysarg);
        } else {
            sock_req.sysargs[0] = 0;
        }
        if (mode_sysarg != IGNORE_SYSARG) {
            sock_req.sysargs[1] = peek_reg(tracee, ORIGINAL, mode_sysarg);
        } else {
            sock_req.sysargs[1] = 0;
        }
        char orig_path[PATH_MAX];
        char path[PATH_MAX];
        if (path_sysarg != IGNORE_SYSARG) {
            size = read_string(tracee, orig_path, peek_reg(tracee, ORIGINAL, path_sysarg), PATH_MAX);
            status = translate_path(tracee, path, AT_FDCWD, orig_path, true);
            if (status < 0)
                return status;
	} else {
            size = readlink_proc_pid_fd(tracee->pid, peek_reg(tracee, ORIGINAL, fd_sysarg), path);
	    modify_path(tracee, path);
	}
	status = detranslate_path(tracee, path, NULL);
        strcpy(sock_req.path, path);
        write_data(tracee, tracee->word_store[3], &sock_req, sizeof(sock_req_t));
        register_chained_syscall(tracee, PR_write, tracee->word_store[1], tracee->word_store[3], sizeof(sock_req), 0, 0, 0);
        return 0;
    case PR_write:
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if ((size_t)result != sizeof(sock_req_t)) {
            VERBOSE(tracee, 4, "%s: Failed to write UNIX socket", __PRETTY_FUNCTION__);
            register_chained_syscall(tracee, PR_close, tracee->word_store[1], 0, 0, 0, 0, 0);
            return 0;
        }
        register_chained_syscall(tracee, PR_read, tracee->word_store[1], tracee->word_store[8], sizeof(word_t), 0, 0, 0);
        return 0;
    case PR_read:
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if ((size_t)result != sizeof(word_t)) {
            VERBOSE(tracee, 4, "%s: Failed to read UNIX socket errno = %d, strerror = %s", __PRETTY_FUNCTION__, -result, strerror(-result));
            register_chained_syscall(tracee, PR_close, tracee->word_store[1], 0, 0, 0, 0, 0);
            return 0;
        }
        word_t curr_status = 2;
        read_data(tracee, &curr_status, tracee->word_store[8], sizeof(word_t));
        if (((orig_sysnum == PR_getdents) || (orig_sysnum == PR_getdents64)) && (curr_status == 1)) {
            VERBOSE(tracee, 4, "%s: Should be last getdents call", __PRETTY_FUNCTION__);
            tracee->word_store[2] = (word_t)0;
            word_t new_status = 0;
            write_data(tracee, tracee->word_store[8], &new_status, sizeof(word_t));
            register_chained_syscall(tracee, PR_close, tracee->word_store[1], 0, 0, 0, 0, 0);
            return 0;
        }
        if (curr_status != 0) {
            VERBOSE(tracee, 4, "%s: Error code received", __PRETTY_FUNCTION__);
            register_chained_syscall(tracee, PR_close, tracee->word_store[1], 0, 0, 0, 0, 0);
            return 0;
        }
        if ((orig_sysnum == PR_mkdir) || (orig_sysnum == PR_mkdirat)) {
            register_chained_syscall(tracee, PR_close, tracee->word_store[1], 0, 0, 0, 0, 0);
            return 0;
        }
        if ((orig_sysnum == PR_unlink) || (orig_sysnum == PR_unlinkat)) {
            register_chained_syscall(tracee, PR_close, tracee->word_store[1], 0, 0, 0, 0, 0);
            return 0;
        }

        if ((orig_sysnum == PR_getdents) || (orig_sysnum == PR_getdents64)) {
            char dirents_path[PATH_MAX];
            int dirents_fd;
            char dirents_buf[1000];
            translate_path(tracee, dirents_path, AT_FDCWD, DROID_FILES_GETDENTSNAME, true);
            dirents_fd = open(dirents_path, O_RDONLY);
            size = read(dirents_fd, dirents_buf, 1000);
            VERBOSE(tracee, 4, "%s: dirents read size = %lu", __PRETTY_FUNCTION__, size);

            if (orig_sysnum == PR_getdents) {
                char *ptr = dirents_buf;
                struct linux_dirent *curr32;
                curr32 = (struct linux_dirent *)ptr;
                VERBOSE(tracee, 4, "dirents d_ino = %lu d_off = %lu d_reclen = %hu d_name = %s",  curr32->d_ino, curr32->d_off, curr32->d_reclen, curr32->d_name);
            } else {
                char *ptr = dirents_buf;
                struct linux_dirent64 *curr64;
                curr64 = (struct linux_dirent64 *)ptr;
                VERBOSE(tracee, 4, "dirents d_ino = %llu d_off = %llu d_reclen = %hu d_type = %u d_name = %s",  curr64->d_ino, curr64->d_off, curr64->d_reclen, curr64->d_type, curr64->d_name);
            }

            close(dirents_fd);
            write_data(tracee, peek_reg(tracee, ORIGINAL, SYSARG_2), dirents_buf, size);
            tracee->word_store[2] = (word_t)size;
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
        ancillary_data_buffer.align.cmsg_len = sizeof(struct cmsghdr) + sizeof(int);
        ancillary_data_buffer.align.cmsg_level = SOL_SOCKET;
        ancillary_data_buffer.align.cmsg_type = SCM_RIGHTS;
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

	update_check_path2(tracee, ancillary_data_buffer_2.fd[0], path_sysarg); 

        tracee->word_store[2] = ancillary_data_buffer_2.fd[0];
        register_chained_syscall(tracee, PR_close, tracee->word_store[1], 0, 0, 0, 0, 0);
        return 0;
    case PR_close: {
        word_t curr_status = 1;
        poke_reg(tracee, SYSARG_RESULT, tracee->word_store[2]);
        result = read_data(tracee, &curr_status, tracee->word_store[8], sizeof(word_t));
        if (curr_status != 0)
            return -curr_status;
        if ((orig_sysnum == PR_mkdir) || (orig_sysnum == PR_mkdirat))
            return 0;
        if ((orig_sysnum == PR_unlink) || (orig_sysnum == PR_unlinkat))
            return 0;
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
    case PR_unlinkat:
    case PR_mkdirat:
    case PR_openat:
        return handle_open_sysenter_end(tracee, IGNORE_SYSARG, SYSARG_2);
    case PR_unlink:
    case PR_mkdir:
    case PR_open:
    case PR_creat:
        return handle_open_sysenter_end(tracee, IGNORE_SYSARG, SYSARG_1);
    case PR_getdents:
    case PR_getdents64:
        return handle_open_sysenter_end(tracee, SYSARG_1, IGNORE_SYSARG);

    default:
        return 0;
    }
}

static int handle_sysexit_end(Tracee *tracee)
{
    word_t sysnum;

    sysnum = get_sysnum(tracee, ORIGINAL);
    switch (sysnum) {
    case PR_openat:
        return handle_open_sysexit_end(tracee, IGNORE_SYSARG, SYSARG_2, SYSARG_3, SYSARG_4);
    case PR_open:
        return handle_open_sysexit_end(tracee, IGNORE_SYSARG, SYSARG_1, SYSARG_2, SYSARG_3);
    case PR_mkdir:
    case PR_creat:
        return handle_open_sysexit_end(tracee, IGNORE_SYSARG, SYSARG_1, IGNORE_SYSARG, SYSARG_2);
    case PR_mkdirat:
        return handle_open_sysexit_end(tracee, IGNORE_SYSARG, SYSARG_2, IGNORE_SYSARG, SYSARG_3);
    case PR_unlinkat:
        return handle_open_sysexit_end(tracee, IGNORE_SYSARG, SYSARG_2, IGNORE_SYSARG, IGNORE_SYSARG);
    case PR_unlink:
        return handle_open_sysexit_end(tracee, IGNORE_SYSARG, SYSARG_1, IGNORE_SYSARG, IGNORE_SYSARG);
    case PR_getdents:
    case PR_getdents64:
        return handle_open_sysexit_end(tracee, SYSARG_1, IGNORE_SYSARG, IGNORE_SYSARG, IGNORE_SYSARG);

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
            { PR_open,       FILTER_SYSEXIT },
            { PR_openat,     FILTER_SYSEXIT },
            { PR_creat,      FILTER_SYSEXIT },
            { PR_mkdir,      FILTER_SYSEXIT },
            { PR_mkdirat,    FILTER_SYSEXIT },
            { PR_unlink,     FILTER_SYSEXIT },
            { PR_unlinkat,   FILTER_SYSEXIT },
            { PR_getdents,   FILTER_SYSEXIT },
            { PR_getdents64, FILTER_SYSEXIT },
            //{ PR_rename,    FILTER_SYSEXIT }, TODO: need to handle these, but need to figure out when it spans directories possibly inside and outside of the rootfs
            //{ PR_renameat,  FILTER_SYSEXIT },
            //{ PR_renameat2, FILTER_SYSEXIT },
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



