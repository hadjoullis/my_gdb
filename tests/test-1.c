#include <stdio.h>

void bar(void) {
    puts("bar");
}

void foo(void) {
    puts("foo");
    bar();
}

int main(void) {
    puts("main");
    foo();
    return 0;
}
