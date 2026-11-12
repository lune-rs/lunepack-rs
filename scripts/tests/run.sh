#!/usr/bin/env bash
# Run every scripts/tests/test-*.sh; print pass/fail/skip per file; exit nonzero on any failure.
set -euo pipefail

self=${BASH_SOURCE[0]}
case $self in
  */*) dir=${self%/*} ;;
  *) dir=. ;;
esac
dir=$(cd "$dir" && pwd)

pass=0
fail=0
skip=0
found=0
for t in "$dir"/test-*.sh; do
  if [ ! -f "$t" ]; then continue; fi
  found=1
  name=${t##*/}
  rc=0
  bash "$t" || rc=$?
  case $rc in
    0) echo "PASS $name"; pass=$((pass + 1)) ;;
    77) echo "SKIP $name"; skip=$((skip + 1)) ;;
    *) echo "FAIL $name"; fail=$((fail + 1)) ;;
  esac
done

if [ "$found" -eq 0 ]; then
  echo "no tests found in $dir" >&2
  exit 1
fi
echo "shell tests: $pass passed, $fail failed, $skip skipped"
if [ "$fail" -ne 0 ]; then exit 1; fi
