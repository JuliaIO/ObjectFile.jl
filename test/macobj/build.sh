#!/bin/bash
# Regenerates the Mach-O object fixture in this directory.  Requires `clang`.
set -euo pipefail
cd "$(dirname "$0")"
echo 'int foo(void) { return 1; }' | clang --target=x86_64-apple-macos10.10 -O2 -c -x c -o foo.o -
