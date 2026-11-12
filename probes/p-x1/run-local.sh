#!/usr/bin/env bash
# P-X1: which workspace crates cross-check locally for Windows (P9). Runs on a developer Mac,
# read-only: `cargo check --target x86_64-pc-windows-msvc -p <crate>` for every workspace package
# (cargo writes only to target/), and the control `cargo check --target ... --manifest-path
# probes/transport/Cargo.toml`, which must FAIL: ring's build script needs a Windows C
# toolchain, so a failure there shows build scripts really ran. Writes
# probe-results/P-X1.json (gitignored) and prints the passing set. Needs cargo and jq. No guard:
# this probe changes nothing outside target/ and the result file. bash 3.2.
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
repo=$(cd "$here/../.." && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../lib/result.sh
. "$here/../lib/result.sh"

cd "$repo"
export PROBE_RESULTS_DIR=${PROBE_RESULTS_DIR:-$repo/probe-results}
probe_begin P-X1
triple=x86_64-pc-windows-msvc
probe_detail target "$triple"
probe_detail host "$(uname -s) $(uname -m)"

names=$(cargo metadata --no-deps --format-version 1 --locked | jq -r '.packages[].name' | sort)
passing=
failing=
count=0
for name in $names; do
  count=$((count + 1))
  rc=0
  cargo check --quiet --locked --target "$triple" -p "$name" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then passing="$passing $name"; else failing="$failing $name"; fi
done
probe_detail package_count "$count"
probe_detail passing "${passing# }"
probe_detail failing "${failing# }"

# Control: the transport probe crate must not cross-check without a Windows C toolchain.
control_rc=0
cargo check --quiet --locked --target "$triple" --manifest-path probes/transport/Cargo.toml >/dev/null 2>&1 || control_rc=$?
probe_detail control_transport_exit_code "$control_rc"
control=failed
if [ "$control_rc" -ne 0 ]; then control=ok; fi

verdict=PASS
if [ -n "$failing" ]; then verdict=FAIL; fi
probe_finish "$verdict" "$control"
echo "p-x1: $count packages; passing:${passing:- none}"
echo "p-x1: failing:${failing:- none}; control exit code $control_rc ($control)"
echo "p-x1: result in $PROBE_RESULTS_DIR/P-X1.json"
