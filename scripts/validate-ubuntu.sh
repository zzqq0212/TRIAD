#!/usr/bin/env bash
set -euo pipefail

# Stop before running project Python on unsupported systems.
if [[ "$(uname -s)" != Linux || ! -r /etc/os-release ]]; then
  echo 'Run this validation only on Ubuntu 22.04/24.04.' >&2
  exit 2
fi
. /etc/os-release
if [[ "$ID" != ubuntu || ( "$VERSION_ID" != 22.04 && "$VERSION_ID" != 24.04 ) ]]; then
  echo 'Supported validation systems: Ubuntu 22.04/24.04.' >&2
  exit 2
fi
cd "$(dirname "$0")/.."

echo "== doctor =="
python3 -m triad doctor

echo "== unit tests =="
python3 -m unittest discover -s tests -v

echo "== offline M1-M4 dry-run (no kernel, VM, model key or fuzzing runtime) =="
python3 -m triad run-example --n-c 5

echo "== allowlisted release export (self-check) =="
rm -rf dist/TRIAD-artifact-support.tar.gz
python3 -m triad export --output dist/TRIAD-artifact-support.tar.gz

echo "Ubuntu validation completed successfully."
