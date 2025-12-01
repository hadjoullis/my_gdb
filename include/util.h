#ifndef _H_UTIL
#define _H_UTIL

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
} function_t;

void load_ELF(char *filename, function_t **functions);
void check_symtab(Elf *elf, function_t **functions);
Elf_Scn *get_elf_section(Elf *elf, char *section);

#endif
