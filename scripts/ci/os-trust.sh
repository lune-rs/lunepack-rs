#!/usr/bin/env bash
# CI job `os-trust` (Linux and macOS): the production transport (ureq + platform verifier + system
# proxy, through crates/lunepack-http/examples/os_trust.rs) honours the operating system's trust
# store and proxy settings. A regression check, ported from probe P-N1 (sub-probes ii and iii).
#   (ii)  a loopback TLS server whose chain ends in a run-time root (rcgen; the root key is never
#         written to disk). Control: the fetch is rejected before the root certificate is added to
#         the OS store. PASS: it is accepted after. The root is removed on every exit path.
#         macOS: `security add-trusted-cert` can wait for a GUI prompt; under its 60 s limit that
#         is a recorded notice and (ii)=skipped, not a failure.
#   (iii) a loopback CONNECT proxy. Linux: the HTTPS_PROXY environment variable. macOS: the system
#         HTTPS proxy (networksetup), read through hyper-util. Control: with the proxy off the
#         proxy log stays empty. PASS: with it on the log shows CONNECT.
# Writes one line `os-trust <os> (ii)=<verdict> (iii)=<verdict>` to the job summary and stdout.
# Exit: 0 pass (ii may be skipped), 1 a sub-check failed or the script broke, 3 not on CI.
# Changes the runner's trust store and proxy settings: refuses to run unless CI=true and
# GITHUB_ACTIONS=true, so it never touches a developer machine. bash 3.2; needs python3.
set -euo pipefail

if [ "${CI:-}" != true ] || [ "${GITHUB_ACTIONS:-}" != true ]; then
  echo "os-trust: refusing to run outside CI (it changes the OS trust store and proxy settings)" >&2
  exit 3
fi

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
repo=$(cd "$here/../.." && pwd)

os=$(uname -s)
case $os in
  Linux) label=linux ;;
  Darwin) label=macos ;;
  *)
    echo "os-trust: unsupported OS: $os" >&2
    exit 2
    ;;
esac

tls_port=18443
proxy_port=18080
target=https://127.0.0.1:$tls_port/
work=$(mktemp -d "${TMPDIR:-/tmp}/lp-os-trust.XXXXXX")
tls_pid=
proxy_pid=
trust_added=1
net_service=
proxy_set=1
ii=not-run
iii=not-run
notes=
summary_done=1

# limited <seconds> <command...>: run in its own session, stdin closed, with a hard time limit;
# prints at most 4000 bytes of combined output and returns the command's status, or 124 after
# killing the process group. A privileged call that waits for a prompt nobody answers (the macOS
# runner did this to P-N1's cleanup) cannot hang the job past its limit.
limited() {
  python3 -I - "$@" <<'PY'
import os, signal, subprocess, sys
secs = int(sys.argv[1])
try:
    p = subprocess.Popen(sys.argv[2:], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, start_new_session=True)
except OSError as e:
    sys.stdout.write("cannot start: %s\n" % type(e).__name__)
    sys.exit(127)
try:
    out, _ = p.communicate(timeout=secs)
    rc = p.returncode
except subprocess.TimeoutExpired:
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        out, _ = p.communicate(timeout=3)
    except Exception:
        out = b""
    rc = 124
sys.stdout.write(out[:4000].decode("utf-8", "replace"))
sys.exit(rc)
PY
}

summary() { # writes the verdict line once
  if [ "$summary_done" -eq 0 ]; then return 0; fi
  summary_done=0
  local line="os-trust $label (ii)=$ii (iii)=$iii"
  if [ -n "$notes" ]; then line="$line; $notes"; fi
  echo "$line"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$line" >>"$GITHUB_STEP_SUMMARY" || true
  fi
}

# shellcheck disable=SC2329  # run by the EXIT trap
cleanup() {
  # Every privileged call is time-limited and every step is best effort; the runner is disposable,
  # so a skipped undo is harmless, a hang is not.
  if [ -n "$tls_pid" ]; then kill -9 "$tls_pid" >/dev/null 2>&1 || true; fi
  if [ -n "$proxy_pid" ]; then kill -9 "$proxy_pid" >/dev/null 2>&1 || true; fi
  if [ "$os" = Darwin ] && [ "$proxy_set" -eq 0 ] && [ -n "$net_service" ]; then
    limited 30 sudo -n networksetup -setsecurewebproxystate "$net_service" off >/dev/null 2>&1 || true
  fi
  if [ "$trust_added" -eq 0 ]; then
    if [ "$os" = Linux ]; then
      limited 60 sudo -n rm -f /usr/local/share/ca-certificates/lunepack-os-trust-root.crt >/dev/null 2>&1 || true
      limited 60 sudo -n update-ca-certificates --fresh >/dev/null 2>&1 || true
    else
      limited 30 sudo -n security remove-trusted-cert -d "$work/certs/root.pem" >/dev/null 2>&1 || true
    fi
  fi
  rm -rf "$work"
}

# shellcheck disable=SC2329  # run by the EXIT trap
on_exit() {
  local rc=$?
  summary
  cleanup
  exit "$rc"
}
trap on_exit EXIT
# A cancelled or timed-out step is a SIGINT or SIGTERM: turn it into an exit so the trap runs.
trap 'exit 143' INT TERM HUP

kv() { # key, text on stdin -> value of the first `key=value` line (or empty)
  sed -n "s/^$1=//p" | head -n 1
}

line_count() { # file -> number of lines (0 when missing)
  if [ -f "$1" ]; then wc -l <"$1" | tr -d ' '; else echo 0; fi
}

wait_listening() { # logfile
  local i=0
  while [ "$i" -lt 20 ]; do
    if grep -q '^listening=' "$1" 2>/dev/null; then return 0; fi
    sleep 0.5
    i=$((i + 1))
  done
  return 1
}

no_env_proxy() { # command... : run with every proxy variable removed
  env -u HTTPS_PROXY -u https_proxy -u ALL_PROXY -u all_proxy -u HTTP_PROXY -u http_proxy \
    -u NO_PROXY -u no_proxy "$@"
}

# --- build ---------------------------------------------------------------------------------
(cd "$repo" && cargo build --release --locked -p lunepack-http --example os_trust --target-dir "$work/target" >"$work/build.log" 2>&1) || {
  echo "os-trust: build failed; last lines of the log:" >&2
  tail -n 20 "$work/build.log" >&2
  exit 1
}
bin=$work/target/release/examples/os_trust

# --- (ii) trust store ------------------------------------------------------------------------
"$bin" gen-certs "$work/certs" >"$work/gen.log" 2>&1
"$bin" serve-tls "$work/certs" "$tls_port" >"$work/tls.log" 2>&1 &
tls_pid=$!
wait_listening "$work/tls.log" || notes="$notes tls server did not report listening;"

before=$(no_env_proxy "$bin" fetch "$target" 2>&1 || true)
before_result=$(printf '%s\n' "$before" | kv result)
echo "(ii) before: result=${before_result:-none} kind=$(printf '%s\n' "$before" | kv kind)"

trust_rc=0
if [ "$os" = Linux ]; then
  sudo -n cp "$work/certs/root.pem" /usr/local/share/ca-certificates/lunepack-os-trust-root.crt
  trust_added=0 # set before the update so a half-done add is undone too
  limited 60 sudo -n update-ca-certificates >/dev/null 2>&1 || trust_rc=$?
  if [ "$trust_rc" -ne 0 ]; then trust_added=1; limited 60 sudo -n rm -f /usr/local/share/ca-certificates/lunepack-os-trust-root.crt >/dev/null 2>&1 || true; fi
else
  limited 60 sudo -n security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$work/certs/root.pem" >/dev/null 2>&1 || trust_rc=$?
  if [ "$trust_rc" -eq 0 ]; then trust_added=0; fi
fi
echo "(ii) add to the OS store: exit $trust_rc"

if [ "$trust_added" -eq 0 ]; then
  after=$(no_env_proxy "$bin" fetch "$target" 2>&1 || true)
  after_result=$(printf '%s\n' "$after" | kv result)
  echo "(ii) after: result=${after_result:-none} status=$(printf '%s\n' "$after" | kv status)"
  if [ "$before_result" = error ] && [ "$after_result" = ok ]; then
    ii=PASS
  else
    ii=FAIL
  fi
elif [ "$os" = Darwin ]; then
  ii=skipped
  notes="$notes (ii) skipped: the macOS runner would not add a trusted root without a prompt (exit $trust_rc);"
else
  ii=FAIL
  notes="$notes the root could not be added to the OS store (exit $trust_rc);"
fi

# --- (iii) proxy -----------------------------------------------------------------------------
proxy_log=$work/proxy.log
"$bin" proxy-serve "$proxy_port" "$proxy_log" >"$work/proxy.out" 2>&1 &
proxy_pid=$!
wait_listening "$work/proxy.out" || notes="$notes proxy did not report listening;"

off_lines=0
on_lines=0
if [ "$os" = Linux ]; then
  no_env_proxy "$bin" fetch "$target" >"$work/iii-off.txt" 2>&1 || true
  off_lines=$(line_count "$proxy_log")
  env -u NO_PROXY -u no_proxy HTTPS_PROXY="http://127.0.0.1:$proxy_port" "$bin" fetch "$target" >"$work/iii-on.txt" 2>&1 || true
  on_lines=$(line_count "$proxy_log")
  iii_ready=0
else
  net_service=$(limited 30 networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | grep -v '^\*' | head -n 1 || true)
  if [ -z "$net_service" ]; then
    notes="$notes no network service to set a system proxy on;"
    iii_ready=1
  else
    proxy_set=0 # set before the change so a half-done change is undone too
    limited 30 sudo -n networksetup -setsecurewebproxystate "$net_service" off >/dev/null 2>&1 || true
    no_env_proxy "$bin" fetch "$target" >"$work/iii-off.txt" 2>&1 || true
    off_lines=$(line_count "$proxy_log")
    iii_ready=0
    limited 30 sudo -n networksetup -setsecurewebproxy "$net_service" 127.0.0.1 "$proxy_port" >/dev/null 2>&1 || iii_ready=1
    limited 30 sudo -n networksetup -setsecurewebproxystate "$net_service" on >/dev/null 2>&1 || iii_ready=1
    if [ "$iii_ready" -ne 0 ]; then notes="$notes could not set the system proxy;"; fi
    no_env_proxy "$bin" fetch "$target" >"$work/iii-on.txt" 2>&1 || true
    on_lines=$(line_count "$proxy_log")
  fi
fi
if [ "$iii_ready" -ne 0 ]; then
  iii=FAIL
else
  echo "(iii) proxy_selected off=$(kv proxy_selected <"$work/iii-off.txt") on=$(kv proxy_selected <"$work/iii-on.txt")"
  echo "(iii) proxy log lines: off=$off_lines on=$on_lines"
  if [ "$off_lines" -eq 0 ] && [ "$on_lines" -gt 0 ] && grep -q '^CONNECT ' "$proxy_log" 2>/dev/null; then
    iii=PASS
  else
    iii=FAIL
  fi
fi

summary
if [ "$ii" = FAIL ] || [ "$iii" = FAIL ]; then exit 1; fi
exit 0
