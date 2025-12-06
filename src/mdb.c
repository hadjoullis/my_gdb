#include <commands.h>
#include <elf_reader.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void command_prompt(char *target, fn_t *fns);

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: ./mdb.out <filename>\n");
        return EXIT_FAILURE;
    }
    char *target = argv[1];

    fn_t *fns = NULL;
    load_ELF(target, &fns);
    command_prompt(target, fns);

    return EXIT_SUCCESS;
}

/* Read a string, and return a pointer to it.
   Returns NULL on EOF. */
char *rl_gets() {
    static char *line_read = NULL;
    static char prev_read[MAX_CMD_LEN] = "";
    if (line_read) {
        free(line_read);
        line_read = NULL;
    }

    char *prompt = "(mdb) ";
    line_read = readline(prompt);

    // EOF
    if (!line_read) {
        return "quit";
    }

    // non-empty input -> add to history
    if (*line_read) {
        if (strlen(line_read) >= MAX_CMD_LEN) {
            fprintf(stderr, "ERROR: exceeded maximum command length(%d)\n",
                    MAX_CMD_LEN);
            return "";
        }
        strcpy(prev_read, line_read);
        add_history(line_read);
        return line_read;
    }

    // empty input -> reuse prev input
    return prev_read;
}

/* Generate argc and argv that represend user input while not exceeding
 * MAX_CMD_ARG. Memory of input is reused for tokens since the buffer will not
 * be freed until command is over executing. */
int tokenize_input(char *input, int *argc, char **argv) {
    const char *delim = " \t";
    char *token = strtok(input, delim);
    if (token == NULL) {
        *argc = 0;
        return EXIT_SUCCESS;
    }
    *argc = 1;
    argv[0] = token;
    while ((token = strtok(NULL, delim))) {
        if (*argc == MAX_CMD_ARGC) {
            fprintf(stderr, "ERROR: exceeded maximum command argc(%d)\n",
                    MAX_CMD_ARGC);
            return EXIT_FAILURE;
        }
        argv[*argc] = token;
        (*argc)++;
    }
    return EXIT_SUCCESS;
}

void get_cmd(cmd_t *cmd, cmd_args_t *cmd_args) {
    for (;;) {
        char *input = rl_gets();
        cmd_args->argc = 0;
        int ret = tokenize_input(input, &(cmd_args->argc), cmd_args->argv);
        if (ret == EXIT_FAILURE || cmd_args->argc == 0) {
            continue;
        }

        // TODO: create foreach macro to loop this prettier...
        for (int i = 0; cmd_registry[i].shortname != NULL; i++) {
            if (strcmp(cmd_registry[i].shortname, cmd_args->argv[0]) == 0 ||
                strcmp(cmd_registry[i].longname, cmd_args->argv[0]) == 0) {
                *cmd = cmd_registry[i].cmd;
                return;
            }
        }
        fprintf(stderr, "invalid command given\n");
    }
}

void command_prompt(char *target, fn_t *fns) {
    cmd_t cmd = NULL;
    cmd_args_t cmd_args = {.target = target, .fns = fns, .pid = 0};

    for (;;) {
        get_cmd(&cmd, &cmd_args);
        cmd(&cmd_args);
    }
}
