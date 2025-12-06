#include <stdio.h>

void bar(void) {
    puts("bar");
}

void foo(void) {
    puts("foo");
    bar();
}

int main(int argc, char *argv[]) {
    for (int i = 0; i < argc; i++) {
        puts(argv[i]);
    }
    foo();
    return 0;
}
