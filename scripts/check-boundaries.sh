#!/usr/bin/env bash
# Workspace boundary check (see xtask/src/boundaries.rs). Runs from the repo top level.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec cargo run --quiet --locked -p xtask -- check-boundaries "$@"
