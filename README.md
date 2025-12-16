# minimal_debugger
- minimal db implementation that supports simple breakpoints, and single step
- can handle both PIE and non-PIE executables
- cannot place breakpoint in functions of shared objects that are linked with
target at runtime

## BUILDING
Install dependencies:
- libelf
- capstone
- readline

Run:
```
make
make debug    # build with debug info and extra loggin to assiting in debugging
make tests    # compilte test files in tests dir
```

## Usage/Features
- readline is used for commandline interaction, so expect usual behaviour
- breakpoints can be given both as function names and hex addresses (use * for the latter)
- dissasembly of x86_64 through capstone
- the debugger suports the following options:
    * 'b', 'break' -> Place breakpoint at addr or symbol.
    * 'c', 'continue' -> Continue program being debugged, after signal or breakpoint.
    * 'd', 'delete' -> Delete specified breakpoint.
    * 'disas', 'disassembly' -> Disassemble current location.
    * 'h', 'help' -> Display this help message.
    * 'l', 'list' -> List current breakpoints.
    * 'q', 'quit' -> Quit program.
    * 'r', 'run' -> Run debugged program from start.
    * 'si', 'stepi' -> Step one instruction exactly.
    * 'sym', 'symbols' -> List all available symbols.

## Purpose
- this project is used as a way to get familiar with ELF binaries as well as
linux ptrace. It is not meant as a production ready tool.
