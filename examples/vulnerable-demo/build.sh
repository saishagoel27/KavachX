#!/usr/bin/env bash
# Build + self-test for the seeded vulnerable demo target.
# There is no native compilation step; this exists so KavachX drives the same
# build -> observe -> validate path it uses on a compiled target.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"

echo "[build] byte-compiling sources"
"$PY" -m compileall -q "$ROOT/src"

echo "[build] running target test suite"
cd "$ROOT"
"$PY" -m pytest tests -q

echo "[build] ok"
