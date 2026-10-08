#!/bin/bash
# Regenerates the COFF object fixtures in this directory.  Requires `clang`.
set -euo pipefail
cd "$(dirname "$0")"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

echo 'int foo(int x) { return x + 1; }' > "${tmp}/foo.c"

# (`-mno-incremental-linker-compatible` keeps timestamps out of COFF objects)
for arch in x86_64 i686 aarch64 thumbv7; do
    clang --target="${arch}-pc-windows-msvc" -O2 -mno-incremental-linker-compatible \
          -c -o "foo_${arch}.obj" "${tmp}/foo.c"
done
