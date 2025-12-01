#ifndef _H_COMMAND
#define _H_COMMAND

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <util.h>

#define BREAKPOINT_BASE 256
#define MAX_INSTRUCTIONS 11
#define MAX_READS 6
#define INSTRUCTIONS_BUF (MAX_READS * 19) + 1

typedef struct {
    const char *command;
    void (*function)(pid_t, char *, function_t *);
} command_t;

typedef struct {
    Elf64_Addr *addr;
    long *bytes;
    bool *active;
    int size;
    int current;
} breakpoint_t;

extern command_t commands[];

void breakpoint(pid_t pid, char *buffer, function_t *functions);
void list(pid_t pid, char *buffer, function_t *functions);
void delete_br(pid_t pid, char *buffer, function_t *functions);
pid_t run(pid_t pid, char **argv);
pid_t cont(pid_t pid);
void quit(pid_t pid, char *buffer, function_t *functions);
void disas_wrapper(pid_t pid, char *buffer, function_t *functions);
pid_t single_instruction(pid_t pid);
#endif
