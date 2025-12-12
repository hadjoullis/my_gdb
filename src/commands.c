#include <commands.h>

// X macro
#define CMD_ENTRIES                                                            \
    CMD_ENTRY("b", "break", breakpoint, "Place breakpoint at addr or symbol")  \
    CMD_ENTRY("c", "continue", cont,                                           \
              "Continue program being debugged, after signal or breakpoint")   \
    CMD_ENTRY("d", "delete", delete_break, "Delete specified breakpoint")      \
    CMD_ENTRY("disas", "disassembly", disas_wrapper,                           \
              "Disassemble current location")                                  \
    CMD_ENTRY("h", "help", help, "Display this help message")                  \
    CMD_ENTRY("l", "list", list, "List current breakpoints")                   \
    CMD_ENTRY("q", "quit", quit, "Quit program")                               \
    CMD_ENTRY("r", "run", run, "Run debugged program from start")              \
    CMD_ENTRY("si", "stepi", stepi, "Step one instruction exactly")            \
    CMD_ENTRY("sym", "symbols", symbols, "List all available symbols")

#define CMD_ENTRY(short, long, fn, description) {short, long, fn, description},
cmd_entry_t cmd_registry[] = {CMD_ENTRIES{NULL, NULL, NULL, NULL}};
#undef CMD_ENTRY

static breakpoint_t breakpoints = {.len = 0};

static Elf64_Addr symbol_addr(fn_t *fns, char *symbol) {
    for (int i = 0; fns[i].func_name != NULL; i++) {
        if (strcmp(fns[i].func_name, symbol) == 0) {
            return fns[i].addr;
        }
    }
    return 0;
}

static bool is_active_breakpoint(Elf64_Addr addr) {
    for (int i = 0; i < breakpoints.len; i++) {
        if (breakpoints.addr[i] == addr && breakpoints.active[i]) {
            return true;
        }
    }
    return false;
}

static bool is_set_breakpoint(Elf64_Addr addr) {
    for (int i = 0; i < breakpoints.len; i++) {
        if (breakpoints.addr[i] == addr && breakpoints.byte[i] != -1) {
            return true;
        }
    }
    return false;
}

static int get_breakpoint_index(Elf64_Addr addr) {
    for (int i = 0; i < breakpoints.len; i++) {
        if (breakpoints.addr[i] == addr) {
            return i;
        }
    }
    return -1;
}

static void new_breakpoint(Elf64_Addr addr, long byte) {
    for (int i = 0; i < breakpoints.len; i++) {
        if (breakpoints.addr[i] == addr) {
            fprintf(stderr, "breakpoint already found at given address\n");
            return;
        }
    }

    if (breakpoints.len == MAX_BREAKPOINTS) {
        fprintf(stderr, "reached maximum number of breakpoints(%d)",
                MAX_BREAKPOINTS);
        return;
    }

    breakpoints.addr[breakpoints.len] = addr;
    breakpoints.byte[breakpoints.len] = byte;
    breakpoints.active[breakpoints.len] = false;
    breakpoints.len++;
    fprintf(stderr, "Breakpoint %d at 0x%lx\n", breakpoints.len - 1, addr);
}

void breakpoint(cmd_args_t *cmd_args) {
    if (cmd_args->argc != 2) {
        fprintf(stderr, "provide a single breakpoint\n");
        return;
    }
    // convert possible symbol into address

    Elf64_Addr addr = 0;
    bool is_addr = cmd_args->argv[1][0] == '*';
    addr = (is_addr ? (Elf64_Addr)strtol(cmd_args->argv[1] + 1, NULL, 16)
                    : symbol_addr(cmd_args->fns, cmd_args->argv[1]));
    if (addr == 0) {
        fprintf(stderr, "symbol not found\n");
        return;
    }

    if (cmd_args->pid == 0) {
        new_breakpoint(addr, -1);
        return;
    }

    long bytes = ptrace(PTRACE_PEEKDATA, cmd_args->pid, (void *)addr, 0);
    if (bytes == -1) {
        die("(breakpoint: peekdata) %s", strerror(errno));
    }
    long byte = bytes & 0xFF;
    new_breakpoint(addr, byte);
    /* Insert the breakpoint. */
    long trap = (bytes & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, cmd_args->pid, (void *)addr, (void *)trap) ==
        -1) {
        die("(breakpoint: pokedata) %s", strerror(errno));
    }
}

void list(cmd_args_t *cmd_args) {
    (void)cmd_args;
    for (int i = 0; i < breakpoints.len; i++) {
        printf("\t%d: 0x%lx\tactive: %d\n", i, breakpoints.addr[i],
               breakpoints.active[i]);
    }
}

void delete_break(cmd_args_t *cmd_args) {
    // handle if no breakpoint is given
    if (cmd_args->argc != 2) {
        fprintf(stderr, "provide a single breakpoint\n");
        return;
    }
    int index = atoi(cmd_args->argv[1]);
    if (index >= breakpoints.len) {
        fprintf(stderr, "breakpoint does not exist\n");
        return;
    }

    if (cmd_args->pid != 0) {
        // correct instruction
        Elf64_Addr addr = breakpoints.addr[index];
        long byte = breakpoints.byte[index];

        long bytes = ptrace(PTRACE_PEEKDATA, cmd_args->pid, (void *)addr, 0);
        if (bytes == -1) {
            die("(breakpoint: peekdata) %s", strerror(errno));
        }
        bytes = (bytes & (~0xFF)) | byte;

        if (ptrace(PTRACE_POKEDATA, cmd_args->pid,
                   (void *)addr,
                   (void *)bytes) == -1) {
            die("(delete_break: pokedata) %s", strerror(errno));
        }
        // if breakpoint is active, rip needs to fixed now, since it won't be
        // fixed later
        if (is_active_breakpoint(addr)) {
            struct user_regs_struct regs;

            if (ptrace(PTRACE_GETREGS, cmd_args->pid, 0, &regs) == -1) {
                die("(delete_break: getregs) %s", strerror(errno));
            }

            regs.rip--;

            if (ptrace(PTRACE_SETREGS, cmd_args->pid, 0, &regs) == -1) {
                die("(delete_break: setregs) %s", strerror(errno));
            }
        }
    }

    for (int i = index; i < breakpoints.len - 1; i++) {
        breakpoints.addr[i] = breakpoints.addr[i + 1];
        breakpoints.byte[i] = breakpoints.byte[i + 1];
        breakpoints.active[i] = breakpoints.active[i + 1];
    }
    if (breakpoints.len == 1) {
        breakpoints.addr[0] = 0;
        breakpoints.byte[0] = -1;
        breakpoints.byte[0] = false;
    }
    breakpoints.len--;
}

static void serve_breakpoint(pid_t pid) {
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        die("(serve_breakpoint: getregs) %s", strerror(errno));
    }

    Elf64_Addr addr = (--regs.rip);
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        die("(serve_breakpoint: setregs) %s", strerror(errno));
    }

    int index = get_breakpoint_index(addr);
    if (index == -1) {
        die("(serve_breakpoint) breakpoint not found");
    }
    long byte = breakpoints.byte[index];
    breakpoints.active[index] = false;

    long bytes = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
    if (bytes == -1) {
        die("(serve_breakpoint: peekdata) %s", strerror(errno));
    }
    bytes = (bytes & ~0xFF) | byte;

    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)bytes) == -1) {
        die("(serve_breakpoint: pokedata) %s", strerror(errno));
    }

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1) {
        die("(serve_breakpoint: singlestep) %s", strerror(errno));
    }

    if (waitpid(pid, NULL, 0) == -1) {
        die("(waitpid) %s", strerror(errno));
    }

    /* Insert the breakpoint. */
    long trap = (bytes & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)trap) == -1) {
        die("(serve_breakpoint: pokedata) %s", strerror(errno));
    }
}

static void fix_buffer(unsigned char *instructions, int base, Elf64_Addr addr) {
    // fix interrupts into actual instructions
    for (size_t offset = 0; offset < sizeof(long); offset++) {
        if (is_set_breakpoint(addr + offset)) {
            int index = get_breakpoint_index(addr + offset);
            instructions[base + offset] = breakpoints.byte[index];
        }
    }
}

static void disas(pid_t pid, Elf64_Addr addr) {
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        die("(disas: cs_open) %s", cs_strerror(cs_errno(handle)));
    }
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    unsigned char instructions[INSTRUCTIONS_BUF] = "";
    long instruction;
    int i, offset;
    for (i = 0, offset = 0; i < MAX_READS; i++, offset += sizeof(instruction)) {
        instruction = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + offset), 0);
        if (instruction == -1) {
            die("(disas: peekdata) %s", strerror(errno));
        }
        memcpy(instructions + offset, &instruction, sizeof(instruction));
        fix_buffer(instructions, offset, addr + offset);
    }

    cs_insn *insn;
    size_t count;
    count = cs_disasm(handle, (void *)instructions, offset, addr, 0, &insn);

    if (count <= 0) {
        die("(disas: cs_disasm) failed to disassemble code");
    }

    fprintf(stderr, ">");
    for (size_t j = 0; j < count && j < MAX_INSTRUCTIONS; j++) {
        fprintf(stderr, "\t0x%lx: ", insn[j].address);
        fprintf(stderr, "\t%s\t%s\n", insn[j].mnemonic, insn[j].op_str);
        if (insn[j].id == X86_INS_RET || insn[j].id == X86_INS_RETF ||
            insn[j].id == X86_INS_RETFQ) {
            break;
        }
    }

    cs_free(insn, count);
    cs_close(&handle);
}

void disas_wrapper(cmd_args_t *cmd_args) {
    if (cmd_args->pid == 0) {
        fprintf(stderr, "The program is not being run\n");
        return;
    }
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, cmd_args->pid, 0, &regs) == -1) {
        die("(disas_wrapper: getregs) %s", strerror(errno));
    }

    Elf64_Addr addr = regs.rip;
    if (is_active_breakpoint(addr - 1)) {
        addr--;
    }
    disas(cmd_args->pid, addr);
}

static void unset_breakpoints() {
    for (int i = 0; i < breakpoints.len; i++) {
        breakpoints.byte[i] = -1;
        breakpoints.active[i] = false;
    }
}

static void load_breakpoints(pid_t pid) {
    Elf64_Addr addr;
    for (int i = 0; i < breakpoints.len; i++) {
        addr = breakpoints.addr[i];

        long bytes = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
        if (bytes == -1) {
            die("(load_breakpoints: peekdata) %s", strerror(errno));
        }
        breakpoints.byte[i] = bytes & 0xFF;

        /* Insert the breakpoint. */
        long trap = (bytes & 0xFFFFFFFFFFFFFF00) | 0xCC;
        if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)trap) == -1) {
            die("(load_breakpoints: pokedata) %s", strerror(errno));
        }
    }
}

void run(cmd_args_t *cmd_args) {
    char *argv[] = {cmd_args->target, NULL};
    if (cmd_args->pid != 0) {
        kill(cmd_args->pid, SIGKILL);
        unset_breakpoints();
    }

    /* fork() for executing the program that is analyzed.  */
    cmd_args->pid = fork();
    switch (cmd_args->pid) {
    case -1: // error
        die("(run: fork) %s", strerror(errno));
    case 0:
        // child
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execvp(argv[0], argv);
        die("(run: execvp) %s", strerror(errno));
    }
    // parent
    cmd_args->pid = cmd_args->pid;
    ptrace(PTRACE_SETOPTIONS, cmd_args->pid, 0, PTRACE_O_EXITKILL);
    waitpid(cmd_args->pid, NULL, 0);

    load_breakpoints(cmd_args->pid);

    if (ptrace(PTRACE_CONT, cmd_args->pid, 0, 0) == -1) {
        die("(run: cont) %s", strerror(errno));
    }

    int status;
    waitpid(cmd_args->pid, &status, 0);

    if (WIFEXITED(status)) {
        unset_breakpoints();
        fprintf(stderr, "process %u exited with code %d\n", cmd_args->pid,
                WEXITSTATUS(status));
        cmd_args->pid = 0;
        return;
    }

#ifdef DEBUG
    if (WIFSIGNALED(status)) {
        unset_breakpoints();
        fprintf(stderr, "process %u was terminated with signal %s\n",
                cmd_args->pid, strsignal(WTERMSIG(status)));
        // exit(EXIT_SUCCESS);
        cmd_args->pid = 0;
        return;
    }
#endif

    if (WIFSTOPPED(status)) {
#ifdef DEBUG
        fprintf(stderr, "process %u was stopped with signal %s\n",
                cmd_args->pid, strsignal(WSTOPSIG(status)));
#endif
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, cmd_args->pid, 0, &regs) == -1) {
            die("(run: getregs) %s", strerror(errno));
        }

        Elf64_Addr addr = regs.rip - 1;
        int index = get_breakpoint_index(addr);
        breakpoints.active[index] = true;
        printf("Breakpoint %d, 0x%lx\n", index, addr);
        disas(cmd_args->pid, addr);
    }
}

void cont(cmd_args_t *cmd_args) {
    if (cmd_args->pid == 0) {
        fprintf(stderr, "The program is not being run\n");
        return;
    }

    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, cmd_args->pid, 0, &regs) == -1) {
        die("(cont: getregs) %s", strerror(errno));
    }

    // len of int3 is 1 byte
    Elf64_Addr addr = regs.rip - 1;
    if (is_active_breakpoint(addr)) {
        serve_breakpoint(cmd_args->pid);
    }
    if (ptrace(PTRACE_CONT, cmd_args->pid, 0, 0) == -1) {
        die("(run: cont) %s", strerror(errno));
    }

    fprintf(stderr, "Continuing.\n");
    int status;
    waitpid(cmd_args->pid, &status, 0);

    if (WIFEXITED(status)) {
        unset_breakpoints();
        fprintf(stderr, "process %u exited with code %d\n", cmd_args->pid,
                WEXITSTATUS(status));
        cmd_args->pid = 0;
        return;
    }

#ifdef DEBUG
    if (WIFSIGNALED(status)) {
        unset_breakpoints();
        fprintf(stderr, "process %u was terminated with signal %s\n",
                cmd_args->pid, strsignal(WTERMSIG(status)));
        // exit(EXIT_SUCCESS);
        cmd_args->pid = 0;
        return;
    }
#endif

    if (WIFSTOPPED(status)) {
#ifdef DEBUG
        fprintf(stderr, "process %u was stopped with signal %s\n",
                cmd_args->pid, strsignal(WSTOPSIG(status)));
#endif
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, cmd_args->pid, 0, &regs) == -1) {
            die("(cont: getregs) %s", strerror(errno));
        }

        Elf64_Addr addr = regs.rip - 1;
        int index = get_breakpoint_index(addr);
        breakpoints.active[index] = true;
        printf("Breakpoint %d, 0x%lx\n", index, addr);
    }
}

void quit(cmd_args_t *cmd_args) {
    (void)cmd_args;
    exit(EXIT_SUCCESS);
}

void stepi(cmd_args_t *cmd_args) {
    if (cmd_args->pid == 0) {
        fprintf(stderr, "The program is not being run\n");
        return;
    }

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, cmd_args->pid, 0, &regs) == -1) {
        die("%s", strerror(errno));
    }

    if (is_active_breakpoint(regs.rip - 1)) {
        serve_breakpoint(cmd_args->pid);

        if (ptrace(PTRACE_GETREGS, cmd_args->pid, 0, &regs) == -1) {
            die("%s", strerror(errno));
        }
        if (is_set_breakpoint(regs.rip)) {
            int index = get_breakpoint_index(regs.rip);
            breakpoints.active[index] = true;
            printf("Breakpoint %d, 0x%llx\n", index, regs.rip);
            // maintain concept of active
            regs.rip++;
            if (ptrace(PTRACE_SETREGS, cmd_args->pid, 0, &regs) == -1) {
                die("(cont: getregs) %s", strerror(errno));
            }
        }
        return;
    }

    if (ptrace(PTRACE_SINGLESTEP, cmd_args->pid, 0, 0) == -1) {
        die("(singlestep) %s", strerror(errno));
    }

    int status;
    waitpid(cmd_args->pid, &status, 0);

    if (WIFEXITED(status)) {
        unset_breakpoints();
        fprintf(stderr, "process %u exited with code %d\n", cmd_args->pid,
                WEXITSTATUS(status));
        cmd_args->pid = 0;
        return;
    }

#ifdef DEBUG
    if (WIFSIGNALED(status)) {
        unset_breakpoints();
        fprintf(stderr, "process %u was terminated with signal %s\n",
                cmd_args->pid, strsignal(WTERMSIG(status)));
        // exit(EXIT_SUCCESS);
        cmd_args->pid = 0;
        return;
    }
#endif

    if (WIFSTOPPED(status)) {
#ifdef DEBUG
        fprintf(stderr, "process %u was stopped with signal %s\n",
                cmd_args->pid, strsignal(WSTOPSIG(status)));
#endif
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, cmd_args->pid, 0, &regs) == -1) {
            die("(cont: getregs) %s", strerror(errno));
        }
        // something wrong here
        // is it really active
        if (is_set_breakpoint(regs.rip)) {
            int index = get_breakpoint_index(regs.rip);
            breakpoints.active[index] = true;
            printf("Breakpoint %d, 0x%llx\n", index, regs.rip);
            // maintain concept of active
            regs.rip++;
            if (ptrace(PTRACE_SETREGS, cmd_args->pid, 0, &regs) == -1) {
                die("(cont: getregs) %s", strerror(errno));
            }
        }
    }
}

void symbols(cmd_args_t *cmd_args) {
    fprintf(stderr, "Symbols found:\n");
    for (int i = 0; cmd_args->fns->name[i] != NULL; i++) {
        fprintf(stderr, "\t%s\n", cmd_args->fns->name[i]);
    }
}

void help(cmd_args_t *cmd_args) {
    (void)cmd_args;
    fprintf(stderr, "Commands -> Action:\n");
    for (int i = 0; cmd_registry[i].shortname != NULL; i++) {
        fprintf(stderr, "\t'%s', '%s' -> %s.\n", cmd_registry[i].shortname,
                cmd_registry[i].longname, cmd_registry[i].description);
    }
}
