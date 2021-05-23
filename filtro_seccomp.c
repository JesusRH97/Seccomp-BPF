#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <string.h>

static int install_filter(int nr, int arch, int error) {

    struct sock_filter filter[] = {
        /* Cargamos la arquitectura */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                (offsetof(struct seccomp_data, arch))),

        /* Si la arquitectura no es la esperada matamos el proceso */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* Cargamos el número de syscall */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                (offsetof(struct seccomp_data, nr))),

        /* Se permiten todas las syscall menos la siguiente */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA))
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("Fallo en prctl(PR_SET_SECCOMP)");
        return 1;
    }

    return 0;
}

int main(int argc, char const *argv[]) {

    if(argc < 2) {
        printf("Uso: %s <programa>\n", argv[0]);
        return 1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("Fallo en prctl(NO_NEW_PRIVS)");
        return 1;
    }
    

    install_filter(__NR_execve, AUDIT_ARCH_X86_64, EPERM);


    execlp(argv[1], argv[1], "", argv[0], (char *) NULL);
    perror("Fallo en execlp\n");

    return 255;
}