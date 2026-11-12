#!/bin/bash
# PreToolUse hook for Bash: block commands that name key files, .env files or the denylist.
# Best-effort guard against reading secrets by accident, not a sandbox: patterns are fixed
# here, matching is case-insensitive, and the reason names the class, never the command.
# Fail closed: no jq, empty input or unparseable JSON blocks (exit 2).
# bash 3.2 compatible.

block() {
  echo "guard-bash: blocked ($1); run a narrower command or ask the user" >&2
  exit 2
}

command -v jq >/dev/null 2>&1 || block "jq missing"
input=$(cat)
[ -n "$input" ] || block "empty hook input"
cmd=$(printf '%s' "$input" | jq -er '.tool_input.command | select(type == "string")') || block "unparseable hook input"
[ -n "$cmd" ] || exit 0

# key-file extension followed by a non-word character or end of string
if printf '%s\n' "$cmd" | grep -Eiq '\.(key|pem|p8|p12|pfx)($|[^A-Za-z0-9_])'; then
  block "key-file extension"
fi

# .env path component or .env.<x>, except exactly .env.example
env_view=$(printf '%s\n' "$cmd" | sed -E 's/\.env\.example($|[^A-Za-z0-9_.-])/\1/g')
if printf '%s\n' "$env_view" | grep -Eiq '(^|[^A-Za-z0-9_.-])\.env($|[^A-Za-z0-9_-])'; then
  block ".env file"
fi

# the denylist file or the variable that points at it
# shellcheck disable=SC2016  # literal $ is intended
if printf '%s\n' "$cmd" | grep -iqF -e 'lunepack-rs/denylist' -e 'denylist.txt' -e '$LUNEPACK_DENYLIST' -e '${LUNEPACK_DENYLIST'; then
  block "denylist"
fi
exit 0
