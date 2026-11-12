#!/usr/bin/env bash
# P-N1 (Linux and macOS): does the default transport (ureq + platform verifier + system proxy)
# meet D23? Builds the probe crate, then runs three sub-probes:
#   (i)   Range: bytes=0-99 on a GitHub release asset; known answer 206, content-range
#         bytes 0-99/1787248, 100 bytes; control: curl in the same job gets the same.
#   (ii)  a local TLS server whose chain ends in a run-time root; only the root CERTIFICATE is added
#         to the OS store (Linux: CA dir + update-ca-certificates; macOS: sudo security
#         add-trusted-cert with a timeout, else skipped); PASS = accepted after, control = rejected before.
#   (iii) system proxy: macOS via networksetup + hyper-util's matcher; Linux: environment proxy
#         sanity check only; PASS = the proxy log shows CONNECT, control = log stays empty with the proxy off.
# Verdict FAIL if (ii) or (iii) fails; skipped (ii) is not a failure. Runner-only (guard); bash 3.2.
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
probe_guard

os=$(uname -s)
case $os in
  Linux) id=P-N1-linux ;;
  Darwin) id=P-N1-macos ;;
  *) echo "run.sh: unsupported OS" >&2; exit 2 ;;
esac
probe_begin "$id"

asset=https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-aarch64-apple-darwin.tar.gz
tls_port=18443
proxy_port=18080
target=https://127.0.0.1:$tls_port/
work=$(mktemp -d "${TMPDIR:-/tmp}/lpprobe-n1.XXXXXX")
tls_pid=
proxy_pid=
trust_added=1
net_service=

cleanup() {
  # Every privileged call is time-limited: on the macOS runner a trust-store or network-setting
  # change can wait for an authorisation prompt that nobody answers, which hung the job after the
  # verdict was already written. The runner is disposable, so a skipped undo is harmless.
  if [ -n "$tls_pid" ]; then kill -9 "$tls_pid" >/dev/null 2>&1 || true; fi
  if [ -n "$proxy_pid" ]; then kill -9 "$proxy_pid" >/dev/null 2>&1 || true; fi
  if [ "$os" = Darwin ] && [ -n "$net_service" ]; then
    probe_limited 30 sudo -n networksetup -setsecurewebproxystate "$net_service" off >/dev/null 2>&1 || true
  fi
  if [ "$trust_added" -eq 0 ]; then
    if [ "$os" = Linux ]; then
      probe_limited 60 sudo -n rm -f /usr/local/share/ca-certificates/lunepack-probe-root.crt >/dev/null 2>&1 || true
      probe_limited 60 sudo -n update-ca-certificates --fresh >/dev/null 2>&1 || true
    else
      probe_limited 30 sudo -n security remove-trusted-cert -d "$work/certs/root.pem" >/dev/null 2>&1 || true
    fi
  fi
  rm -rf "$work"
}
probe_cleanup_on_exit cleanup

kv() { # key, text on stdin -> value of the first `key=value` line (or empty)
  sed -n "s/^$1=//p" | head -n 1
}

line_count() { # file -> number of lines (0 when missing)
  if [ -f "$1" ]; then wc -l <"$1" | tr -d ' '; else echo 0; fi
}

# Run a command with a time limit (probe_limited, no coreutils timeout on macOS); status only.
run_limited() { # seconds, command...
  probe_limited "$@" >/dev/null
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

# --- build -----------------------------------------------------------------------------
(cd "$repo" && cargo build --release --locked --manifest-path probes/transport/Cargo.toml --target-dir "$work/target" >"$work/build.log" 2>&1)
bin=$work/target/release/transport-probe
probe_detail build "ok"

# --- (i) Range ---------------------------------------------------------------------------
out=$("$bin" range "$asset" 2>&1 || true)
r_status=$(printf '%s\n' "$out" | kv status)
r_cr=$(printf '%s\n' "$out" | kv content_range)
r_len=$(printf '%s\n' "$out" | kv body_len)
probe_detail i_ureq_status "${r_status:-none}"
probe_detail i_ureq_content_range "${r_cr:-none}"
probe_detail i_ureq_body_len "${r_len:-none}"
curl -sL --max-time 90 -r 0-99 -D "$work/curl.hdr" -o "$work/curl.bin" "$asset" || true
c_status=$(grep -i '^HTTP/' "$work/curl.hdr" 2>/dev/null | tail -n 1 | awk '{print $2}' || true)
c_cr=$(grep -i '^content-range:' "$work/curl.hdr" 2>/dev/null | tail -n 1 | sed 's/^[^:]*: *//' | tr -d '\r' || true)
c_len=$(wc -c <"$work/curl.bin" 2>/dev/null | tr -d ' ' || echo 0)
probe_detail i_curl_status "${c_status:-none}"
probe_detail i_curl_content_range "${c_cr:-none}"
probe_detail i_curl_body_len "${c_len:-none}"
i_pass=FAIL
if [ "$r_status" = 206 ] && [ "$r_cr" = "bytes 0-99/1787248" ] && [ "$r_len" = 100 ]; then i_pass=PASS; fi
i_control=failed
if [ "$c_status" = 206 ] && [ "$c_cr" = "bytes 0-99/1787248" ] && [ "$c_len" = 100 ]; then i_control=ok; fi
probe_detail i_result "$i_pass"
probe_detail i_control "$i_control"

# --- (ii) trust store ----------------------------------------------------------------------
"$bin" gen-certs "$work/certs" >"$work/gen.log" 2>&1
"$bin" serve-tls "$work/certs" "$tls_port" >"$work/tls.log" 2>&1 &
tls_pid=$!
wait_listening "$work/tls.log" || probe_detail note "tls server did not report listening"
before=$("$bin" fetch "$target" 2>&1 || true)
ii_before=$(printf '%s\n' "$before" | kv result)
probe_detail ii_before_result "${ii_before:-none}"
probe_detail ii_before_error "$(printf '%s\n' "$before" | kv error)"

trust_rc=1
if [ "$os" = Linux ]; then
  sudo -n cp "$work/certs/root.pem" /usr/local/share/ca-certificates/lunepack-probe-root.crt
  trust_rc=0
  sudo -n update-ca-certificates >/dev/null 2>&1 || trust_rc=$?
  if [ "$trust_rc" -eq 0 ]; then trust_added=0; fi
  probe_detail ii_add_trust_exit_code "$trust_rc"
else
  trust_rc=0
  run_limited 60 sudo -n security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$work/certs/root.pem" || trust_rc=$?
  if [ "$trust_rc" -eq 0 ]; then trust_added=0; fi
  probe_detail ii_add_trust_exit_code "$trust_rc"
fi
ii_result=skipped
ii_control=ok
ii_after=none
if [ "$trust_added" -eq 0 ]; then
  after=$("$bin" fetch "$target" 2>&1 || true)
  ii_after=$(printf '%s\n' "$after" | kv result)
  probe_detail ii_after_result "${ii_after:-none}"
  probe_detail ii_after_status "$(printf '%s\n' "$after" | kv status)"
  if [ "$ii_before" = error ] && [ "$ii_after" = ok ]; then ii_result=PASS; else ii_result=FAIL; fi
  if [ "$ii_before" != error ]; then ii_control=failed; fi
else
  probe_detail note "root could not be added to the OS store here; (ii) skipped"
fi
probe_detail ii_result "$ii_result"

# --- (iii) system / environment proxy ------------------------------------------------------
proxy_log=$work/proxy.log
"$bin" proxy-serve "$proxy_port" "$proxy_log" >"$work/proxy.out" 2>&1 &
proxy_pid=$!
wait_listening "$work/proxy.out" || probe_detail note "proxy did not report listening"

no_env_proxy() { # command... : run with every proxy variable removed
  env -u HTTPS_PROXY -u https_proxy -u ALL_PROXY -u all_proxy -u HTTP_PROXY -u http_proxy "$@"
}

if [ "$os" = Linux ]; then
  probe_detail iii_kind "environment proxy sanity check only"
  # control first: proxy off, the log stays empty
  no_env_proxy "$bin" fetch-proxy "$target" >"$work/iii-off.txt" 2>&1 || true
  off_lines=$(line_count "$proxy_log")
  HTTPS_PROXY="http://127.0.0.1:$proxy_port" "$bin" fetch-proxy "$target" >"$work/iii-on.txt" 2>&1 || true
else
  probe_detail iii_kind "macOS system proxy via networksetup and hyper-util Matcher::from_system()"
  net_service=$(probe_limited 30 networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | grep -v '^\*' | head -n 1 || true)
  probe_detail iii_network_service_found "$([ -n "$net_service" ] && echo yes || echo no)"
  if [ -z "$net_service" ]; then
    probe_detail note "no network service to set a system proxy on"
    probe_finish FAIL failed
    exit 0
  fi
  run_limited 30 sudo -n networksetup -setsecurewebproxystate "$net_service" off || true
  no_env_proxy "$bin" fetch-proxy "$target" >"$work/iii-off.txt" 2>&1 || true
  off_lines=$(line_count "$proxy_log")
  run_limited 30 sudo -n networksetup -setsecurewebproxy "$net_service" 127.0.0.1 "$proxy_port"
  run_limited 30 sudo -n networksetup -setsecurewebproxystate "$net_service" on
  no_env_proxy "$bin" fetch-proxy "$target" >"$work/iii-on.txt" 2>&1 || true
fi
on_lines=$(line_count "$proxy_log")
probe_detail iii_off_proxy_selected "$(kv proxy_selected <"$work/iii-off.txt")"
probe_detail iii_on_proxy_selected "$(kv proxy_selected <"$work/iii-on.txt")"
probe_detail iii_on_fetch_result "$(kv result <"$work/iii-on.txt" | cut -c 1-120)"
probe_detail iii_log_lines_with_proxy_off "$off_lines"
probe_detail iii_log_lines_with_proxy_on "$on_lines"
connect_logged=1
if grep -q '^CONNECT ' "$proxy_log" 2>/dev/null; then connect_logged=0; fi
probe_detail_bool iii_connect_logged "$connect_logged"
iii_result=FAIL
if [ "$connect_logged" -eq 0 ] && [ "$on_lines" -gt "$off_lines" ]; then iii_result=PASS; fi
iii_control=failed
if [ "$off_lines" -eq 0 ]; then iii_control=ok; fi
probe_detail iii_result "$iii_result"

# --- verdict -----------------------------------------------------------------------------
control=failed
if [ "$i_control" = ok ] && [ "$ii_control" = ok ] && [ "$iii_control" = ok ]; then control=ok; fi
verdict=PASS
if [ "$ii_result" = FAIL ] || [ "$iii_result" = FAIL ]; then verdict=FAIL; fi
probe_finish "$verdict" "$control"
echo "p-n1: $id recorded (requested $verdict, control $control; i=$i_pass ii=$ii_result iii=$iii_result)"
