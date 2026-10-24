#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build/linux}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
CC_BIN="${CC:-cc}"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v cmake >/dev/null 2>&1 || fail "CMake is missing. On Debian/Ubuntu: sudo apt install build-essential cmake libzstd-dev"
command -v "$CC_BIN" >/dev/null 2>&1 || fail "C compiler '$CC_BIN' was not found. Set CC to gcc or clang."

# Verify zstd headers and linker library before starting CMake, so missing deps are obvious.
tmp_c="$(mktemp "${TMPDIR:-/tmp}/zvpn-zstd-check-XXXXXX.c")"
tmp_bin="${tmp_c%.c}"
trap 'rm -f "$tmp_c" "$tmp_bin"' EXIT
cat > "$tmp_c" <<'SRC'
#include <zstd.h>
int main(void) { return ZSTD_versionNumber() == 0; }
SRC
if ! "$CC_BIN" "$tmp_c" -lzstd -o "$tmp_bin" >/dev/null 2>&1; then
    fail "Zstandard development files are missing. On Debian/Ubuntu: sudo apt install libzstd-dev"
fi

printf '== ZVPN Linux build ==\n'
printf 'Source: %s\nBuild:  %s\nType:   %s\n\n' "$ROOT_DIR" "$BUILD_DIR" "$BUILD_TYPE"
cmake -S "$ROOT_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DCMAKE_C_COMPILER="$CC_BIN"
cmake --build "$BUILD_DIR" --parallel

printf '\nBUILD SUCCEEDED\nBinary: %s\n' "$BUILD_DIR/zvpn-server"
printf 'Run with: sudo "%s" --verbose\n' "$BUILD_DIR/zvpn-server"
