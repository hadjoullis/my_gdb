#include "commands.h"
#include "util.h"

void command_prompt(char **argv, function_t *functions);

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: ./a.out <filename>\n");
    return EXIT_FAILURE;
  }

  function_t *functions = NULL;
  load_ELF(argv[1], &functions);
  command_prompt(argv + 1, functions);

  return EXIT_SUCCESS;
}

void handle_input(char **argv, pid_t *pid, char *buffer, void **function) {
  static char previous_buffer[BUF_LEN] = "r";

  while (1) {
    printf("(mdb) ");
    if (fgets(buffer, BUF_LEN, stdin) == NULL) {
      die("(input) %s", strerror(errno));
    }
    // repeat previous command for empty input
    (buffer[0] == '\n') ? (strcpy(buffer, previous_buffer))
                        : (strcpy(previous_buffer, buffer));

    buffer[strlen(buffer) - 1] = '\0'; // remove newline
    size_t word_len = strcspn(buffer, " ");
    if (strncmp("r", buffer, word_len) == 0 ||
        strncmp("run", buffer, word_len) == 0) {
      *pid = run(*pid, argv);
      continue;
    }

    if (strncmp("c", buffer, word_len) == 0 ||
        strncmp("cont", buffer, word_len) == 0) {
      *pid = cont(*pid);
      continue;
    }

    if (strncmp("si", buffer, word_len) == 0) {
      *pid = single_instruction(*pid);
      continue;
    }

    int i;
    for (i = 0; commands[i].function != NULL; i++) {
      // compare until first space
      if (strncmp(commands[i].command, buffer, word_len) == 0) {
        *function = commands[i].function;
        return;
      }
    }
    fprintf(stderr, "invalid command given\n");
  }
}

void command_prompt(char **argv, function_t *functions) {
  char buffer[BUF_LEN] = "";
  void (*function)(int, char *, function_t *) = NULL;
  pid_t pid = 0;

  while (1) {
    handle_input(argv, &pid, buffer, (void **)&function);
    function(pid, buffer, functions);
  }
}
