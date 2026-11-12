#!/usr/bin/env bash
# Tests for .claude/hooks/guard-bash.sh: the blocked set, the allowed set, fail-closed input.
# Synthetic command strings only; nothing here reads a file named in them.
# shellcheck disable=SC2016  # literal $ in single quotes is the point of the cases
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
HOOK=$here/../../.claude/hooks/guard-bash.sh
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
. "$here/lib.sh"

t_init

hook_json() { # command -> JSON on stdout
  jq -cn --arg c "$1" '{tool_name: "Bash", tool_input: {command: $c}}'
}

run_hook() { # command
  RC=0
  hook_json "$1" | "$HOOK" >"$OUT" 2>&1 || RC=$?
}

expect_blocked() {
  run_hook "$1"
  t_check "blocked: $1" rc_is 2
  t_check "blocked reason on one line, command not echoed: $1" blocked_ok "$1"
}

# shellcheck disable=SC2329  # called through t_check
blocked_ok() {
  [ "$(wc -l <"$OUT" | tr -d ' ')" -eq 1 ] && out_has "guard-bash: blocked" && out_lacks "$1"
}

expect_allowed() {
  run_hook "$1"
  t_check "allowed: $1" rc_is 0
  t_check "allowed is silent: $1" test ! -s "$OUT"
}

expect_blocked 'cat secret.key'
expect_blocked 'cat certs/server.PEM'
expect_blocked 'openssl pkcs12 -in a.p12'
expect_blocked 'cat AuthKey_ABC.p8'
expect_blocked 'base64 < x.pfx'
expect_blocked 'cat .env'
expect_blocked 'source .env.local'
expect_blocked 'cat ~/.config/lunepack-rs/denylist.txt'
expect_blocked 'cat "$LUNEPACK_DENYLIST"'
expect_blocked 'cat "${XDG_CONFIG_HOME}/lunepack-rs/denylist.txt"'
expect_blocked 'cat "${LUNEPACK_DENYLIST:-x}"'
expect_blocked 'cat a/.env && echo done'
expect_blocked 'cat .env.example.bak'

expect_allowed 'cargo test --workspace'
expect_allowed 'cargo test -p xtask'
expect_allowed 'git status'
expect_allowed 'cat .env.example'
expect_allowed 'ls keys/'
expect_allowed 'cargo build -p lunepack-crypto'
expect_allowed './scripts/check-secrets.sh --require-denylist'
expect_allowed './scripts/gate.sh'
expect_allowed 'grep -rn process.env src'

# Fail closed on bad input.
RC=0
printf 'not json' | "$HOOK" >"$OUT" 2>&1 || RC=$?
t_check "invalid JSON blocks" rc_is 2
RC=0
: | "$HOOK" >"$OUT" 2>&1 || RC=$?
t_check "empty input blocks" rc_is 2
RC=0
printf '{"tool_input":{}}' | "$HOOK" >"$OUT" 2>&1 || RC=$?
t_check "missing command blocks" rc_is 2

# jq missing: a PATH with only the tools the hook needs, minus jq.
mkdir -p "$T_TMP/nojq"
for tool in cat grep sed; do
  p=$(command -v "$tool")
  ln -s "$p" "$T_TMP/nojq/$tool"
done
RC=0
hook_json 'git status' | PATH=$T_TMP/nojq "$BASH" "$HOOK" >"$OUT" 2>&1 || RC=$?
t_check "jq missing blocks" rc_is 2
t_check "jq missing says so" out_has "jq missing"

t_finish
