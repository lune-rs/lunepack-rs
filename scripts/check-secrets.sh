#!/usr/bin/env bash
# Secret check: gitleaks over history (merge diffs included) and over the tracked files, the
# private denylist scan (`xtask denylist-scan`) and the key-container file check (`xtask
# key-files`). All parts always run; the exit status is nonzero if any fails.
#   check-secrets.sh [--staged | --range <a>..<b>] [--require-denylist]
# Never prints the environment, a config file or the denylist, and never names the
# denylist path on a command line (the scanner finds it from the environment).
set -euo pipefail

usage() {
  echo "usage: check-secrets.sh [--staged | --range <a>..<b>] [--require-denylist]" >&2
}

self=${BASH_SOURCE[0]}
case $self in
  */*) script_dir=${self%/*} ;;
  *) script_dir=. ;;
esac
script_dir=$(cd "$script_dir" && pwd)

mode=history
range=
require=0
while [ $# -gt 0 ]; do
  case $1 in
    --staged)
      if [ "$mode" != history ]; then usage; exit 2; fi
      mode=staged
      ;;
    --range)
      if [ "$mode" != history ] || [ $# -lt 2 ] || [ -z "$2" ]; then usage; exit 2; fi
      mode=range
      range=$2
      shift
      ;;
    --require-denylist) require=1 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "check-secrets: gitleaks not found on PATH (install it; the check never skips silently)" >&2
  exit 2
fi

if ! top=$(git rev-parse --show-toplevel 2>/dev/null); then
  echo "check-secrets: not inside a git repository" >&2
  exit 2
fi

# The scanner runs from the repo that owns this script (for its pinned toolchain), so a
# relative explicit denylist path must be made absolute first.
if [ -n "${LUNEPACK_DENYLIST:-}" ]; then
  case $LUNEPACK_DENYLIST in
    /* | [A-Za-z]:*) ;;
    *)
      LUNEPACK_DENYLIST=$PWD/$LUNEPACK_DENYLIST
      export LUNEPACK_DENYLIST
      ;;
  esac
fi

# gitleaks runs `git log -p`, which prints no diff for merge commits unless `-m` is given, so a
# credential added while resolving a merge would pass; `-m` is in the log options of both
# history forms (history mode passes the options the default would use, plus `-m`).
gl_args=(git --redact --no-banner)
case $mode in
  staged) gl_args+=(--staged) ;;
  range) gl_args+=("--log-opts=-m $range") ;;
  *) gl_args+=("--log-opts=-m --full-history --all") ;;
esac

# Key-container files (.pfx, .p12, .p8, .key, .pem, .jks, ...) are binary to `git log -p`, so
# gitleaks never reads them: fail on the tracked path (and, per mode, on the history of paths).
kf_args=(key-files --repo "$top")
case $mode in
  range) kf_args+=(--range "$range") ;;
  history) kf_args+=(--all) ;;
esac

dl_args=(denylist-scan --repo "$top")
if [ -n "$range" ]; then dl_args+=(--range "$range"); fi
if [ "$require" = 1 ]; then dl_args+=(--require-denylist); fi

gl_status=0
(cd "$top" && gitleaks "${gl_args[@]}") || gl_status=$?

# gitleaks also scans the tracked files as they are in the index (`gitleaks dir` on an export),
# which reads text secrets inside files that `git log -p` classifies as binary (a NUL byte).
tree_status=0
tree_tmp=$(mktemp -d "${TMPDIR:-/tmp}/lunepack-secrets.XXXXXX")
trap 'rm -rf "$tree_tmp"' EXIT
if git -C "$top" checkout-index -a --prefix="$tree_tmp/"; then
  gitleaks dir --redact --no-banner "$tree_tmp" || tree_status=$?
else
  tree_status=2
fi

dl_status=0
(cd "$script_dir/.." && cargo run --quiet --locked --manifest-path "$script_dir/../Cargo.toml" -p xtask -- "${dl_args[@]}") || dl_status=$?

kf_status=0
(cd "$script_dir/.." && cargo run --quiet --locked --manifest-path "$script_dir/../Cargo.toml" -p xtask -- "${kf_args[@]}") || kf_status=$?

rc=0
if [ "$gl_status" -ne 0 ]; then
  echo "check-secrets: gitleaks FAILED (exit $gl_status)" >&2
  rc=1
fi
if [ "$tree_status" -ne 0 ]; then
  echo "check-secrets: gitleaks (tracked files) FAILED (exit $tree_status)" >&2
  rc=1
fi
if [ "$dl_status" -ne 0 ]; then
  echo "check-secrets: denylist-scan FAILED (exit $dl_status)" >&2
  rc=1
  if [ "$dl_status" -eq 2 ]; then rc=2; fi
fi
if [ "$kf_status" -ne 0 ]; then
  echo "check-secrets: key-files FAILED (exit $kf_status)" >&2
  rc=1
  if [ "$kf_status" -eq 2 ]; then rc=2; fi
fi
if [ "$rc" -eq 0 ]; then
  echo "check-secrets: ok"
fi
exit "$rc"
