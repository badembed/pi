/* Trusted namespace bridge and mandatory seccomp launcher. No shell or dynamic commands. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__aarch64__)
#define EXPECTED_ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define EXPECTED_ARCH AUDIT_ARCH_X86_64
#else
#error Corporate Linux isolation supports only aarch64 and x86_64
#endif

#define DENY(call) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##call, 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)

static int install_filter(void) {
    static const struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, EXPECTED_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* Reject the x32 syscall ABI as well as foreign audit architectures. */
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 8),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* Node's piped subprocess stdio uses connected anonymous stream pairs.
         * Datagram pairs could reconnect to a named host socket: deny them. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socketpair, 0, 7),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* libc falls back to clone for normal threads/processes. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        DENY(ptrace), DENY(process_vm_readv), DENY(process_vm_writev), DENY(pidfd_getfd),
        DENY(mount), DENY(umount2), DENY(pivot_root), DENY(setns), DENY(unshare),
        DENY(open_by_handle_at), DENY(name_to_handle_at), DENY(bpf), DENY(perf_event_open),
        DENY(userfaultfd), DENY(io_uring_setup), DENY(fsopen), DENY(fsconfig), DENY(fsmount),
        DENY(open_tree), DENY(move_mount), DENY(mount_setattr), DENY(reboot),
        DENY(kexec_load), DENY(init_module), DENY(finit_module), DENY(delete_module),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5412 /* TIOCSTI */, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x541c /* TIOCLINUX */, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = sizeof(filter) / sizeof(filter[0]), .filter = (struct sock_filter *)filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) {
        perror("Corporate seccomp setup failed");
        return -1;
    }
    return 0;
}

static int copy_bytes(int from, int to) {
    char buffer[65536];
    ssize_t size;
    do { size = read(from, buffer, sizeof(buffer)); } while (size < 0 && errno == EINTR);
    if (size <= 0) return -1;
    for (ssize_t offset = 0; offset < size;) {
        ssize_t sent = write(to, buffer + offset, size - offset);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return -1;
        offset += sent;
    }
    return 0;
}

static void relay_connection(int client, const char *path) {
    int upstream = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (upstream < 0 || strlen(path) >= sizeof(address.sun_path)) _exit(1);
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (connect(upstream, (struct sockaddr *)&address, sizeof(address))) _exit(1);
    struct pollfd peers[] = { { .fd = client, .events = POLLIN }, { .fd = upstream, .events = POLLIN } };
    for (;;) {
        int ready = poll(peers, 2, -1);
        if (ready < 0) { if (errno == EINTR) continue; _exit(1); }
        for (int i = 0; i < 2; ++i) {
            if ((peers[i].revents & POLLIN) && copy_bytes(peers[i].fd, peers[1-i].fd)) _exit(0);
            if (peers[i].revents & (POLLERR | POLLNVAL)) _exit(0);
            if ((peers[i].revents & POLLHUP) && !(peers[i].revents & POLLIN)) _exit(0);
        }
    }
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc < 5) { fputs("Usage: corporate-linux-helper socket port executable entry [args]\n", stderr); return 1; }
    char *end = NULL;
    long port = strtol(argv[2], &end, 10);
    if (!end || *end || port < 1 || port > 65535) return 1;
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons((unsigned short)port) };
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 128)) {
        perror("Corporate namespace bridge failed"); return 1;
    }
    pid_t relay = fork();
    if (relay < 0) { perror("Corporate bridge fork failed"); return 1; }
    if (relay == 0) {
        /* Pi must not inspect or rewrite the bridge through /proc/PID/mem. */
        if (prctl(PR_SET_DUMPABLE, 0)) _exit(1);
        signal(SIGCHLD, SIG_IGN);
        signal(SIGPIPE, SIG_IGN);
        for (;;) {
            int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
            if (client < 0) { if (errno == EINTR) continue; _exit(1); }
            pid_t connection = fork();
            if (connection == 0) { close(listener); relay_connection(client, argv[1]); }
            close(client);
        }
    }
    close(listener);
    if (install_filter()) { kill(relay, SIGKILL); return 1; }
    execv(argv[3], &argv[3]);
    perror("Corporate child exec failed");
    kill(relay, SIGKILL);
    return 1;
}
