#!/usr/bin/env bash
# Build the seeded C target with sanitizers and run its own tests.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if command -v clang >/dev/null 2>&1; then
  CC=clang
elif command -v gcc >/dev/null 2>&1; then
  CC=gcc
  echo "[build] clang not found; using gcc (libFuzzer will be unavailable)"
else
  echo "[build] no C compiler found. This target needs clang or gcc." >&2
  echo "[build] On Windows use WSL2, or use examples/vulnerable-demo instead." >&2
  exit 1
fi

echo "[build] plain build"
make CC="$CC" build

echo "[build] sanitizer build"
make CC="$CC" asan

echo "[build] running target tests"
make CC="$CC" test

if [ "$CC" = "clang" ]; then
  echo "[build] libFuzzer harness"
  make CC="$CC" fuzz
fi

echo "[build] ok"
