#!/usr/bin/env bash
# Build the vendored fuzzing runtime used by triad/runtime.py.
#
# Builds the executor (C++, runs inside the VM), syz-execprog (single-program
# runner used by QemuRuntime) and syz-manager (the fuzzing manager). Binaries
# land in ./bin/linux_<arch>/.
#
# Usage (Ubuntu 22.04/24.04, from the repository root):
#   bash fuzzer/build-runtime.sh [amd64|arm64]
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
  echo "[1/2] installing Go toolchain"
  sudo apt-get update
  sudo apt-get install --no-install-recommends -y golang-go
fi

echo "[2/2] building executor, syz-execprog and syz-manager"
make TARGETOS=linux TARGETARCH="${1:-amd64}" execprog executor manager

echo "done. binaries: bin/linux_${1:-amd64}/ (syz-execprog, syz-executor, syz-manager)"
