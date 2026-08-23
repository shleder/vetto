#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/io_uring.h>
#include <linux/perf_event.h>
#include <linux/userfaultfd.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static long run_probe(const char *name) {
    if (strcmp(name, "ptrace") == 0)
        return syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);

    char source = 's';
    char target = 't';
    struct iovec local = {.iov_base = &target, .iov_len = 1};
    struct iovec remote = {.iov_base = &source, .iov_len = 1};
    if (strcmp(name, "process_vm_readv") == 0)
        return syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);
    if (strcmp(name, "process_vm_writev") == 0)
        return syscall(SYS_process_vm_writev, getpid(), &remote, 1, &local, 1, 0);

#if defined(SYS_pidfd_open) && defined(SYS_pidfd_getfd)
    if (strcmp(name, "pidfd_getfd") == 0) {
        int pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
        if (pidfd < 0)
            return -1;
        long result = syscall(SYS_pidfd_getfd, pidfd, STDOUT_FILENO, 0);
        int saved = errno;
        close(pidfd);
        errno = saved;
        return result;
    }
#endif

    if (strcmp(name, "mount") == 0)
        return syscall(SYS_mount, "none", "/", "tmpfs", 0, "");
    if (strcmp(name, "umount2") == 0)
        return syscall(SYS_umount2, ".env", 0);
    if (strcmp(name, "pivot_root") == 0)
        return syscall(SYS_pivot_root, ".", ".");

#ifdef SYS_perf_event_open
    if (strcmp(name, "perf_event_open") == 0) {
        struct perf_event_attr attr = {0};
        attr.size = sizeof(attr);
        return syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
    }
#endif
#ifdef SYS_bpf
    if (strcmp(name, "bpf") == 0) {
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        return syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    }
#endif
#ifdef SYS_kexec_load
    if (strcmp(name, "kexec_load") == 0)
        return syscall(SYS_kexec_load, 0, 0, NULL, 0);
#endif
#ifdef SYS_kexec_file_load
    if (strcmp(name, "kexec_file_load") == 0)
        return syscall(SYS_kexec_file_load, -1, -1, 0, "", 0);
#endif
#ifdef SYS_init_module
    if (strcmp(name, "init_module") == 0)
        return syscall(SYS_init_module, NULL, 0, "");
#endif
#ifdef SYS_finit_module
    if (strcmp(name, "finit_module") == 0)
        return syscall(SYS_finit_module, -1, "", 0);
#endif
#ifdef SYS_delete_module
    if (strcmp(name, "delete_module") == 0)
        return syscall(SYS_delete_module, "vetto_probe", 0);
#endif
#ifdef SYS_reboot
    if (strcmp(name, "reboot") == 0)
        return syscall(SYS_reboot, 0, 0, 0, NULL);
#endif
#ifdef SYS_swapon
    if (strcmp(name, "swapon") == 0)
        return syscall(SYS_swapon, "/definitely/not/a/swapfile", 0);
#endif
#ifdef SYS_swapoff
    if (strcmp(name, "swapoff") == 0)
        return syscall(SYS_swapoff, "/definitely/not/a/swapfile");
#endif

#ifdef SYS_io_uring_setup
    if (strcmp(name, "io_uring_setup") == 0) {
        struct io_uring_params params = {0};
        return syscall(SYS_io_uring_setup, 1, &params);
    }
#endif
#ifdef SYS_io_uring_enter
    if (strcmp(name, "io_uring_enter") == 0)
        return syscall(SYS_io_uring_enter, -1, 0, 0, 0, NULL, 0);
#endif
#ifdef SYS_io_uring_register
    if (strcmp(name, "io_uring_register") == 0)
        return syscall(SYS_io_uring_register, -1, 0, NULL, 0);
#endif
#ifdef SYS_userfaultfd
    if (strcmp(name, "userfaultfd") == 0)
        return syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
#endif

    fprintf(stderr, "unsupported probe: %s\n", name);
    return -2;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: seccomp_probe OPERATION\n");
        return 64;
    }
    errno = 0;
    long result = run_probe(argv[1]);
    int saved = errno;
    if (result == -2)
        return 77;
    if (result == -1 && saved == EPERM) {
        printf("blocked:%s:EPERM\n", argv[1]);
        return 0;
    }
    fprintf(stderr, "probe was not blocked: %s result=%ld errno=%d\n", argv[1], result, saved);
    return 1;
}
