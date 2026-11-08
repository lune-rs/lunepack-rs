#!/bin/bash
file=$(jq -r '.tool_input.file_path // empty')
[ -n "$file" ] || exit 0
case "$file" in *.rs) ;; *) exit 0 ;; esac   # only Rust sources; skip .md and the rest
# bare rustfmt defaults to edition 2015 and rejects `async fn`; pass the edition explicitly
if ! out=$(rustfmt --edition 2024 "$file" 2>&1); then
  echo "$out" >&2
  exit 2
fi
