#!/usr/bin/env bash
# Tests for scripts/check-secrets.sh. Temp repos only, isolated git config, synthetic data.
# The real denylist is never consulted: every run either names a temp LUNEPACK_DENYLIST or
# points XDG_CONFIG_HOME at an empty temp dir.
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
SCRIPT=$here/../check-secrets.sh
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

if ! command -v gitleaks >/dev/null 2>&1; then
  if [ "${LUNEPACK_REQUIRE_GITLEAKS:-}" = 1 ]; then
    echo "  FAIL: gitleaks not found and LUNEPACK_REQUIRE_GITLEAKS=1" >&2
    exit 1
  fi
  t_skip "gitleaks not found"
fi

t_init
unset LUNEPACK_DENYLIST
mkdir -p "$T_TMP/xdg"
export XDG_CONFIG_HOME=$T_TMP/xdg

run_in() { # dir, command...
  local d=$1 old=$PWD
  shift
  cd "$d"
  run_cmd "$@"
  cd "$old"
}

new_repo() { # name -> path in $REPO
  REPO=$T_TMP/$1
  mkdir -p "$REPO"
  g -C "$REPO" init -q -b main
}

commit_file() { # repo, name, content, message
  printf '%s\n' "$3" >"$1/$2"
  g -C "$1" add -- "$2"
  g -C "$1" commit -q -m "$4"
}

# A private-key-shaped block; the header is assembled at run time so this file itself
# never contains a complete PEM header. Sets PEM (the file text) and BODY_MARK (a body
# fragment that must never show up in any output).
make_pem() {
  local body
  body=$(head -c 192 /dev/urandom | base64 | tr -d '\n=' | fold -w 64)
  BODY_MARK=$(printf '%s\n' "$body" | head -n 1 | cut -c 1-32)
  PEM=$(printf '%s\n%s\n%s\n' "-----BEGIN ""PRIVATE KEY-----" "$body" "-----END ""PRIVATE KEY-----")
}
make_pem
if [ "${#BODY_MARK}" -lt 32 ]; then t_fail "could not generate a PEM body"; fi

# --- clean repo, no denylist: ok -------------------------------------------------------
new_repo clean
commit_file "$REPO" hello.txt "hello" "init"
run_in "$REPO" "$SCRIPT"
t_check "clean repo exits 0" rc_is 0
t_check "clean repo reports ok" out_has "check-secrets: ok"
t_check "absent denylist is a notice, not a failure" out_has "denylist not found; scan skipped"

# --- planted key in history ------------------------------------------------------------
new_repo planted
commit_file "$REPO" ok.txt "fine" "init"
commit_file "$REPO" planted.txt "$PEM" "add file"
run_in "$REPO" "$SCRIPT"
t_check "planted key: nonzero" rc_nonzero
t_check "planted key: gitleaks named as the failing part" out_has "gitleaks FAILED"
t_check "planted key: body not in output" out_lacks "$BODY_MARK"
planted=$REPO

# --- staged mode -----------------------------------------------------------------------
new_repo staged
commit_file "$REPO" ok.txt "fine" "init"
run_in "$REPO" "$SCRIPT" --staged
t_check "staged clean exits 0" rc_is 0
printf '%s\n' "$PEM" >"$REPO/planted.txt"
g -C "$REPO" add planted.txt
run_in "$REPO" "$SCRIPT" --staged
t_check "staged key: nonzero" rc_nonzero
t_check "staged key: body not in output" out_lacks "$BODY_MARK"

# --- range mode ------------------------------------------------------------------------
new_repo range
commit_file "$REPO" a.txt "one" "first"
base=$(g -C "$REPO" rev-parse HEAD)
commit_file "$REPO" b.txt "two" "second"
run_in "$REPO" "$SCRIPT" --range "$base..HEAD"
t_check "clean range exits 0" rc_is 0
commit_file "$REPO" planted.txt "$PEM" "third"
run_in "$REPO" "$SCRIPT" --range "$base..HEAD"
t_check "range with a planted key: nonzero" rc_nonzero
t_check "range with a planted key: body not in output" out_lacks "$BODY_MARK"

# --- denylist term in a commit ---------------------------------------------------------
new_repo deny
commit_file "$REPO" ok.txt "fine" "init"
commit_file "$REPO" leak.txt "mentions zqxsynthterm here" "add leak"
printf '# synthetic\nzqxsynthterm\n' >"$T_TMP/deny.txt"
chmod 600 "$T_TMP/deny.txt"
export LUNEPACK_DENYLIST=$T_TMP/deny.txt
run_in "$REPO" "$SCRIPT"
t_check "denylist term: nonzero" rc_nonzero
t_check "denylist term: denylist-scan named as the failing part" out_has "denylist-scan FAILED"
t_check "denylist term: term not in output" out_lacks "zqxsynthterm"
run_in "$REPO" "$SCRIPT" --range "HEAD~1..HEAD"
t_check "denylist term via --range: nonzero" rc_nonzero
t_check "denylist term via --range: term not in output" out_lacks "zqxsynthterm"
# The same denylist passes on a repo without the term.
run_in "$planted" "$SCRIPT" --staged
t_check "denylist term absent from a repo: denylist part passes" out_lacks "denylist-scan FAILED"

# --- --require-denylist with a missing explicit denylist -------------------------------
export LUNEPACK_DENYLIST=$T_TMP/does-not-exist.txt
run_in "$T_TMP/clean" "$SCRIPT" --require-denylist
t_check "required but missing denylist: nonzero" rc_nonzero
t_check "required but missing denylist: denylist-scan named" out_has "denylist-scan FAILED"
unset LUNEPACK_DENYLIST

# --- usage errors and missing gitleaks -------------------------------------------------
run_in "$T_TMP/clean" "$SCRIPT" --bogus
t_check "unknown flag exits 2" rc_is 2
t_check "unknown flag prints usage" out_has "usage:"
run_in "$T_TMP/clean" "$SCRIPT" --staged --range "a..b"
t_check "--staged with --range exits 2" rc_is 2
run_in "$T_TMP/clean" "$SCRIPT" --range
t_check "--range without a value exits 2" rc_is 2

mkdir -p "$T_TMP/emptybin"
old_path=$PATH
# shellcheck disable=SC2123  # deliberately emptying PATH to hide gitleaks
PATH=$T_TMP/emptybin
run_in "$T_TMP/clean" "$BASH" "$SCRIPT"
PATH=$old_path
t_check "missing gitleaks exits 2 (no silent skip)" rc_is 2
t_check "missing gitleaks says so" out_has "gitleaks not found"

t_finish
