# vita-analyze
Conforming to POSIX.1-2008 and C11. Designed for GCC 5-6.

# Disabling sanitizers

Sanitizers don't work on some platforms. If you encountered a problem, disable
with `CFLAGS`

```
make "CFLAGS=-std=c11 -O2 -Wall -Wextra -pedantic -pie -fPIC -flto `pkg-config jansson --cflags`"
```
