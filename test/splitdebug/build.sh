#!/bin/bash
# Regenerates the split-debuginfo ELF fixtures in this directory.  Requires
# `gcc` and `objcopy`.  `libfoo.so` defines versioned symbols (`.gnu.version_d`)
# and needs versioned glibc symbols (`.gnu.version_r`).  `libfoo.so.debug` is
# its `objcopy --only-keep-debug` counterpart: it keeps every section header,
# but the loadable sections (`.dynamic`, `.dynsym`, `.dynstr`, `.gnu.version*`,
# ...) become `SHT_NOBITS` and have no contents in the file.
set -euo pipefail
cd "$(dirname "$0")"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

cat > "${tmp}/foo.c" <<'SRC'
#include <stdio.h>
#include <string.h>
int foo(const char *s) { printf("%s\n", s); return (int)strlen(s); }
SRC
printf 'FOO_1.0 { global: foo; local: *; };\n' > "${tmp}/foo.map"

gcc -shared -fPIC -g -O2 -Wl,--build-id=none -Wl,--version-script="${tmp}/foo.map" \
    -o libfoo.so "${tmp}/foo.c"
objcopy --only-keep-debug libfoo.so libfoo.so.debug
