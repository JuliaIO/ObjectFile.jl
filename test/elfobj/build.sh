#!/bin/bash
# Regenerates the ELF relocatable object fixture in this directory.  Requires
# `gcc`.  `foo.o` is an `ET_REL` object: it has `.symtab`, `.strtab` and
# relocation sections, but no program headers and none of the dynamic-linking
# sections (`.dynamic`, `.dynsym`, `.dynstr`, `.gnu.version*`).
set -euo pipefail
cd "$(dirname "$0")"
echo 'extern int bar(void); int foo(void) { return bar() + 1; }' | \
    gcc -O2 -fPIC -c -x c -o foo.o -
