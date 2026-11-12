#!/usr/bin/env bash
# Minimal bash-3.2 test helpers; source from a scripts/tests/test-*.sh file.
# Exit codes of a test file: 0 pass, 1 fail, 77 skip.
# shellcheck shell=bash

T_FAILS=0
T_CHECKS=0
T_TMP=
OUT=
RC=0

t_cleanup() {
  # Only ever removes the directory t_init created.
  if [ -n "$T_TMP" ] && [ -d "$T_TMP" ]; then
    rm -rf "$T_TMP"
  fi
}

# Create the scratch dir and export an isolated git environment (no user or system config).
t_init() {
  T_TMP=$(mktemp -d "${TMPDIR:-/tmp}/lunepack-test.XXXXXX")
  trap t_cleanup EXIT
  OUT=$T_TMP/out.txt
  : >"$T_TMP/gitconfig"
  export GIT_CONFIG_GLOBAL=$T_TMP/gitconfig
  export GIT_CONFIG_NOSYSTEM=1
  export GIT_AUTHOR_NAME="Synth Author" GIT_AUTHOR_EMAIL="author@example.invalid"
  export GIT_COMMITTER_NAME="Synth Committer" GIT_COMMITTER_EMAIL="committer@example.invalid"
  export GIT_TERMINAL_PROMPT=0
  export GIT_CEILING_DIRECTORIES=$T_TMP
}

# git with signing and hooks off.
g() {
  git -c commit.gpgsign=false -c core.hooksPath= -c core.autocrlf=false "$@"
}

t_fail() {
  T_FAILS=$((T_FAILS + 1))
  echo "  FAIL: $1" >&2
}

t_check() { # label, then a command; passes when the command succeeds
  local label=$1
  shift
  T_CHECKS=$((T_CHECKS + 1))
  if "$@"; then
    echo "  ok: $label"
  else
    t_fail "$label"
  fi
}

# Run a command capturing combined stdout+stderr into $OUT and its status into $RC.
run_cmd() {
  RC=0
  "$@" >"$OUT" 2>&1 || RC=$?
}

rc_is() { [ "$RC" -eq "$1" ]; }
rc_nonzero() { [ "$RC" -ne 0 ]; }
out_has() { grep -qiF -- "$1" "$OUT"; }
out_lacks() { ! grep -qiF -- "$1" "$OUT"; }

t_skip() {
  echo "  SKIP: $1" >&2
  exit 77
}

t_finish() {
  if [ "$T_FAILS" -ne 0 ]; then
    echo "  $T_FAILS of $T_CHECKS checks failed" >&2
    exit 1
  fi
  echo "  $T_CHECKS checks passed"
  exit 0
}
