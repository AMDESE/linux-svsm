# C Run-Time (CRT) Library

The libcrt is a subset of the [musl libc](https://musl.libc.org/). It provides
only the libc functions required to build the SVSM external dependencies.

# Code organization

The `libcrt.h` header centralizes all definitions, the other header files are
just a proxy for the `libcrt.h`. Hence, when we include a header in a source
file, we are actually including the entire `libcrt.h`. That allow us to build
openssl without having to patch it to include missing headers.

In order to build the SVSM dependencies, some functions are required to be
defined at build time, however, not all of them are executed at runtime. For
those cases, we just stub out the function by printing a message and returning
an error. For easy tracking, all the function we stub out can be found in
`src/stub.c`.
