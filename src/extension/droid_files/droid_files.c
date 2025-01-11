#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <fcntl.h>
#include <string.h>

#include "cli/note.h"
#include "tracee/mem.h"
#include "extension/extension.h"
#include "extension/fake_id0/helper_functions.h"

static int handle_sysenter_end(Tracee *tracee, Config *config)
{
    word_t sysnum;

    sysnum = get_sysnum(tracee, ORIGINAL);
    switch (sysnum) {
    /* int openat(int dirfd, const char *pathname, int flags, mode_t mode) */
    /* int open(const char *pathname, int flags, mode_t mode) */
    /* int creat(const char *pathname, mode_t mode) */
    case PR_openat:
        return handle_open_enter_end(tracee, SYSARG_2);
    case PR_open:
    case PR_creat:
        return handle_open_enter_end(tracee, SYSARG_1);

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
            { PR_open,   0 },
            { PR_openat, 0 },
            { PR_creat,  0 },
            FILTERED_SYSNUM_END,
        };
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }

    case SYSCALL_ENTER_END: {
        Config *config = talloc_get_type_abort(extension->config, Config);
        return handle_sysenter_end(TRACEE(extension), config);
    }

    default:
        return 0;
    }
}


/*
 JNIEXPORT jint JNICALL Java_tech_ula_library_ServerService_droidFileClientRun( JNIEnv *env, __attribute__((__unused__)) jobject thiz, jstring jSockPath, jstring jFilePath) {
    int server_fd, fd_got;
    struct sockaddr_un server_addr;
    __attribute__((__unused__)) char buf[1024];
    sock_req_t sock_req;

    const char *sockPath = (*env)->GetStringUTFChars(env, jSockPath, 0);
    __attribute__((__unused__)) const char *filePath = (*env)->GetStringUTFChars(env, jFilePath, 0);

    // Create a socket
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd == -1) {
        __android_log_print(ANDROID_LOG_ERROR,  "droid_files", "Client: socket");
        return(-1);
    }
    __android_log_print(ANDROID_LOG_DEBUG,  "droid_files", "Client: socket");

    //Connect to the socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, sockPath, sizeof(server_addr.sun_path) - 1);
    if (connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        __android_log_print(ANDROID_LOG_ERROR,  "droid_files", "Client: connect");
        return(-1);
    }
    __android_log_print(ANDROID_LOG_DEBUG,  "droid_files", "Client: connect");

    sock_req.sysCall = 1;
    strcpy(sock_req.path, filePath);
    if (write(server_fd, &sock_req, sizeof(sock_req_t)) != sizeof(sock_req_t)) {
        __android_log_print(ANDROID_LOG_ERROR,  "droid_files", "Client: write");
    }
    __android_log_print(ANDROID_LOG_DEBUG,  "droid_files", "Client: write");

    // Get the file descriptor
    if (ancil_get_fd(server_fd, &fd_got) != 0) {
        __android_log_print(ANDROID_LOG_ERROR,  "droid_files", "Client: recvmsg");
        return(-1);
    }
    __android_log_print(ANDROID_LOG_DEBUG,  "droid_files", "Client: recvmsg %d", fd_got);

    // Print file contents
    //if (read(fd_got, buf, 1024) == -1) {
        //__android_log_print(ANDROID_LOG_ERROR,  "droid_files", "Client: read");
        //return(-1);
    //}
    //__android_log_print(ANDROID_LOG_DEBUG,  "droid_files", "Content of this file are: %s", buf);

    // Close the file descriptor
    close(fd_got);
    __android_log_print(ANDROID_LOG_DEBUG,  "droid_files", "Client close %d", fd_got);

    // Close the sockets
    close(server_fd);
    __android_log_print(ANDROID_LOG_DEBUG,  "droid_files", "Client close socket");

    return 0;
}
 */


typedef struct {
    word_t sysCall;
    char path[4096];
    word_t sysargs[5];
} sock_req_t;

typedef struct {
    struct cmsghdr align;
    int fd[1];
} ancillary_data_buffer;

int handle_open_sysenter_end(Tracee *tracee, Reg path_sysarg) {
    int status;
    char check_path[] = "/sdcard/";
    char orig_path[PATH_MAX];
    
    status = read_sysarg_path(tracee, orig_path, path_sysarg, ORIGINAL);
    if (status < 0) //return errors
        return status;
    if (status == 0) //skip any path that is part of the guestfs
        return 0;

    VERBOSE(tracee, 1, "droid_files path: %s", orig_path);

    if (strncmp(orig_path, check_path, strlen(check_path)) != 0)
        return 0;

    set_sysnum(tracee, PR_socket);
    poke_reg(tracee, SYSARG_1, AF_UNIX);
    poke_reg(tracee, SYSARG_2, SOCK_STREAM);
    poke_reg(tracee, SYSARG_3, 0);

    //Allocate memory we are going to need later
    //tracee->word_store[0] = alloc_mem(tracee, sizeof(struct sockaddr_un));
    //tracee->word_store[1] = alloc_mem(tracee, sizeof(int));
    //tracee->word_store[2] = alloc_mem(tracee, sizeof(struct sock_req_t));
    //tracee->word_store[3] = alloc_mem(tracee, sizeof(ancillary_data_buffer));
    //tracee->word_store[4] = alloc_mem(tracee, sizeof(struct msghdr));

    return 0;
}

/* Attach shared memory segment. */
/*
int handle_open_sysexit_end(Tracee *tracee)
{
    word_t sysnum;
    word_t result;
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
        sprintf(&sockaddr.sun_path[1], ANDROID_SHMEM_SOCKNAME, ashv_local_socket_id);
        int addrlen = sizeof(sockaddr.sun_family) + strlen(&sockaddr.sun_path[1]) + 1;
        write_data(tracee, tracee->word_store[0], &sockaddr, sizeof(struct sockaddr_un));
        tracee->word_store[8] = result;
        tracee->word_store[9] = (word_t)-1;
        register_chained_syscall(tracee, PR_connect, result, tracee->word_store[0], addrlen, 0, 0, 0);
        return 0;
    case PR_connect:
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if ((int)result != 0) {
            VERBOSE(tracee, 4, "%s: Cannot connect to UNIX socket", __PRETTY_FUNCTION__);
            return -EINVAL;
        }
        shmid = (int)peek_reg(tracee, stage, SYSARG_1);
        write_data(tracee, tracee->word_store[1], &shmid, sizeof(int));
        register_chained_syscall(tracee, PR_sendto, tracee->word_store[8], tracee->word_store[1], sizeof(int), 0, 0, 0);
        return 0;
    case PR_sendto:
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if ((int)result != sizeof(shmid)) {
            VERBOSE(tracee, 4, "%s: send() failed on socket", __PRETTY_FUNCTION__);
            register_chained_syscall(tracee, PR_close, tracee->word_store[8], 0, 0, 0, 0, 0);
            return 0;
        }
        register_chained_syscall(tracee, PR_read, tracee->word_store[8], tracee->word_store[2], sizeof(key_t), 0, 0, 0);
        return 0;
    case PR_read:
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if ((int)result != sizeof(key_t)) {
            VERBOSE(tracee, 4, "%s: read() failed on socket", __PRETTY_FUNCTION__);
            register_chained_syscall(tracee, PR_close, tracee->word_store[8], 0, 0, 0, 0, 0);
            return 0;
        }

        char nothing = '!';
        write_data(tracee, tracee->word_store[3], &nothing, 1);
        struct iovec nothing_ptr = { .iov_base = (void *)tracee->word_store[3], .iov_len = 1 };
        write_data(tracee, tracee->word_store[4], &nothing_ptr, sizeof(nothing_ptr));

        struct {
            struct cmsghdr align;
            int fd[1];
        } ancillary_data_buffer;
        ancillary_data_buffer.fd[0] = -1;
        write_data(tracee, tracee->word_store[5], &ancillary_data_buffer, sizeof(ancillary_data_buffer));

        struct msghdr message_header = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = (struct iovec *)tracee->word_store[4],
            .msg_iovlen = 1,
            .msg_flags = 0,
            .msg_control = (void *)tracee->word_store[5],
            .msg_controllen = sizeof(struct cmsghdr) + sizeof(int)
        };
        write_data(tracee, tracee->word_store[6], &message_header, sizeof(struct msghdr));

        register_chained_syscall(tracee, PR_recvmsg, tracee->word_store[8], tracee->word_store[6], 0, 0, 0, 0);
        return 0;
    case PR_recvmsg:
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if ((int)result < 0) {
            VERBOSE(tracee, 4, "%s: recvmesg() failed on socket", __PRETTY_FUNCTION__);
            register_chained_syscall(tracee, PR_close, tracee->word_store[8], 0, 0, 0, 0, 0);
            return 0;
        }

        struct msghdr message_header_2;
        read_data(tracee, &message_header_2, tracee->word_store[6], sizeof(struct msghdr));

        struct {
            struct cmsghdr align;
            int fd[1];
        } ancillary_data_buffer_2;
        read_data(tracee, &ancillary_data_buffer_2, (word_t)message_header_2.msg_control, sizeof(ancillary_data_buffer_2));

        tracee->word_store[9] = ancillary_data_buffer_2.fd[0];
        register_chained_syscall(tracee, PR_close, tracee->word_store[8], 0, 0, 0, 0, 0);
        return 0;
    case PR_close: {
        if ((int)tracee->word_store[9] == -1)
            return -EINVAL;

        int shmid = (int)peek_reg(tracee, stage, SYSARG_1);
        void *shmaddr = (void *)peek_reg(tracee, stage, SYSARG_2);
        int shmflg = (int)peek_reg(tracee, stage, SYSARG_3);
        int idx = ashv_find_index(shmid);
        if (idx == -1) {
            VERBOSE(tracee, 4, "%s: shmid %x does not exist", __PRETTY_FUNCTION__, shmid);
            return -EINVAL;
        }

        word_t mmap_sysnum = detranslate_sysnum(get_abi(tracee), PR_mmap2) != SYSCALL_AVOIDER
                        ? PR_mmap2
                        : PR_mmap;
        register_chained_syscall(tracee, mmap_sysnum, (word_t)shmaddr, (word_t)shmem[idx].size, (word_t)(PROT_READ | (shmflg == 0 ? PROT_WRITE : 0)), (word_t)MAP_SHARED, tracee->word_store[9], 0);
        return 0;
    }
    case PR_mmap:
    case PR_mmap2: {
        result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
        if ((void *)result == MAP_FAILED) {
            VERBOSE(tracee, 4, "%s: mmap() failed", __PRETTY_FUNCTION__);
            return -EINVAL;
        }

        int shmid = (int)peek_reg(tracee, stage, SYSARG_1);
        int idx = ashv_find_index(shmid);
        if (idx == -1) {
            VERBOSE(tracee, 4, "%s: shmid %x does not exist", __PRETTY_FUNCTION__, shmid);
            return -EINVAL;
        }
        android_shmem_addr_attach(idx, (void *)result);
        VERBOSE(tracee, 4, "%s: shmid %x, nattach %d", __PRETTY_FUNCTION__, shmid, shmem[idx].nattach);
        return 0;
    }
    default:
        return 0;
    }

    return 0;
}
*/
