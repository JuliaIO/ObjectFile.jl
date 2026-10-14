#!/bin/bash
# Regenerates the static archive fixtures in this directory.  Requires `clang`,
# `llvm-ar`, `llvm-lib` and `llvm-dlltool`.  The object file names are chosen to
# exercise both short member names and those that need a long name table.
set -euo pipefail
cd "$(dirname "$0")"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

echo 'int foo(int x) { return x + 1; }' > "${tmp}/foo.c"
echo 'int foo(int x); int bar(int x) { return foo(x) * 2; }' > "${tmp}/bar_with_a_long_name.c"

compile() {
    for src in foo bar_with_a_long_name; do
        clang --target="$@" -O2 -c -o "${tmp}/${src}.o" "${tmp}/${src}.c"
    done
}
# `archive <format> <output> [ops]`, where `ops` defaults to `rcsD` (with a symbol table)
archive() {
    local format="$1" out="$2" ops="${3:-rcsD}"
    rm -f "${out}"
    (cd "${tmp}" && llvm-ar --format="${format}" "${ops}" "${OLDPWD}/${out}" foo.o bar_with_a_long_name.o)
}

compile x86_64-linux-gnu
archive gnu libfoo_gnu.a
archive gnu libfoo_gnu_nosymtab.a rcSD
# (`SYM64_THRESHOLD` forces a 64-bit symbol table)
SYM64_THRESHOLD=0 archive gnu libfoo_gnu64.a
# Some archivers record member paths relative to the archive, so build those beside them
(cd "${tmp}" && llvm-ar --format=gnu --thin rcsD libfoo_thin.a foo.o bar_with_a_long_name.o)
mv "${tmp}/libfoo_thin.a" libfoo_thin.a

compile x86_64-apple-macos
archive darwin libfoo_darwin.a
SYM64_THRESHOLD=0 archive darwin libfoo_darwin64.a
archive bsd libfoo_bsd_nosymtab.a rcSD

# (`-mno-incremental-linker-compatible` keeps timestamps out of COFF objects)
compile x86_64-pc-windows-msvc -mno-incremental-linker-compatible
(cd "${tmp}" && llvm-lib /out:foo.lib foo.o bar_with_a_long_name.o)
mv "${tmp}/foo.lib" foo.lib

# An import library: an archive too, but of short import objects
printf 'LIBRARY foo.dll\nEXPORTS\nfoo\nbar\n' > "${tmp}/foo.def"
rm -f libfoo.dll.a
llvm-dlltool -m i386:x86-64 -d "${tmp}/foo.def" -l libfoo.dll.a
