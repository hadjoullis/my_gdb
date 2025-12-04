#ifndef _H_ELF_READER
#define _H_ELF_READER

/* C standard library */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <sys/user.h>
#include <unistd.h>

/* Linux */
#include <capstone/capstone.h>
#include <elf.h>
#include <gelf.h>
#include <libelf.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <syscall.h>

#define BUF_LEN 256
#define TOOL "min_gdb"

#define die(...)                                                               \
    do {                                                                       \
        fprintf(stderr, TOOL ": " __VA_ARGS__);                                \
        fputc('\n', stderr);                                                   \
        exit(EXIT_FAILURE);                                                    \
    } while (0)

typedef struct {
    Elf64_Addr addr;
    char *func_name;
} fn_t;

void load_ELF(char *filename, fn_t **fns);

#endif
