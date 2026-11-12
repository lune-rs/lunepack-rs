#!/usr/bin/env bash
# shellcheck disable=SC2016  # the bash -c bodies in the self-test are deliberately single-quoted
# Probe helpers (bash 3.2): runner guard and result writer. Source this from a probe script:
#   . "$(dirname "$0")/../lib/result.sh"
#   probe_guard                      # first thing: exit 3, touching nothing, off a hosted runner
#   probe_begin P-X0                 # arms a trap that writes INVALID if the script dies early
#   probe_detail name value          # named fields only; never an environment or file dump
#   probe_finish PASS|FAIL ok|failed # control other than "ok" forces INVALID
# Result file: ${PROBE_RESULTS_DIR:-probe-results}/<id>.json
#   {"id","verdict","control","runner":{"os","image_os","image_version"},"details":{...}}
# `bash probes/lib/result.sh --self-test` exercises the writer in a temp dir (no guard).

# Refuse unless this is a GitHub-hosted runner. RUNNER_ENVIRONMENT=github-hosted is the
# primary signal; if the runner does not set it, GITHUB_ACTIONS=true plus a non-empty ImageOS
# is the weaker fallback (a self-hosted value of RUNNER_ENVIRONMENT always refuses).
probe_guard() {
  if [ "${GITHUB_ACTIONS:-}" != true ]; then
    echo "probe: refusing to run outside GitHub Actions (probes change runner state)" >&2
    exit 3
  fi
  if [ -n "${RUNNER_ENVIRONMENT:-}" ]; then
    if [ "$RUNNER_ENVIRONMENT" != github-hosted ]; then
      echo "probe: refusing to run on a non-hosted runner" >&2
      exit 3
    fi
    PROBE_GUARD_BASIS=runner-environment
  elif [ -n "${ImageOS:-}" ]; then
    PROBE_GUARD_BASIS=image-os-fallback
  else
    echo "probe: refusing to run: no hosted-runner signal (RUNNER_ENVIRONMENT, ImageOS)" >&2
    exit 3
  fi
}

PROBE_ID=
PROBE_DONE=1
PROBE_DETAILS=
PROBE_DIR=
PROBE_GUARD_BASIS=
PROBE_CLEANUP=true

probe__clean() { # collapse newlines/tabs so a value stays on one line
  printf '%s' "$1" | tr '\n\t\r' '   '
}

# probe_write <dir> <id> <verdict> <control> <details-file>: pure writer (no guard, no trap).
probe_write() {
  python3 -I - "$1" "$2" "$3" "$4" "$5" <<'PY'
import json, os, sys
out_dir, pid, verdict, control, details_file = sys.argv[1:6]
details = {}
if os.path.exists(details_file):
    with open(details_file, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            key, kind, value = line.split("\t", 2)
            details[key] = (value == "true") if kind == "b" else value
if verdict not in ("PASS", "FAIL", "INVALID"):
    details["reason"] = "unknown verdict forced to INVALID"
    verdict = "INVALID"
if control != "ok":
    if verdict != "INVALID":
        details["reason"] = "control did not hold; verdict forced to INVALID"
    verdict = "INVALID"
    control = "failed"
doc = {
    "id": pid,
    "verdict": verdict,
    "control": control,
    "runner": {
        "os": os.environ.get("RUNNER_OS", ""),
        "image_os": os.environ.get("ImageOS", ""),
        "image_version": os.environ.get("ImageVersion", ""),
    },
    "details": details,
}
os.makedirs(out_dir, exist_ok=True)
with open(os.path.join(out_dir, pid + ".json"), "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
}

probe__on_exit() {
  local rc=$?
  if [ "$PROBE_DONE" -eq 0 ]; then
    PROBE_DONE=1
    probe_detail error "script exited before a verdict (status $rc)"
    probe_write "$PROBE_DIR" "$PROBE_ID" INVALID failed "$PROBE_DETAILS" || true
  fi
  if [ -n "$PROBE_DETAILS" ]; then rm -f "$PROBE_DETAILS"; fi
}

probe_begin() { # id
  PROBE_ID=$1
  PROBE_DIR=${PROBE_RESULTS_DIR:-probe-results}
  PROBE_DETAILS=$(mktemp "${TMPDIR:-/tmp}/probe-details.XXXXXX")
  PROBE_DONE=0
  if [ -n "$PROBE_GUARD_BASIS" ]; then probe_detail guard "$PROBE_GUARD_BASIS"; fi
  trap probe__on_exit EXIT
}

# probe_cleanup_on_exit <function>: run <function> (best effort) on exit, then the result trap,
# keeping the script's exit status. Call after probe_begin.
probe_cleanup_on_exit() {
  PROBE_CLEANUP=$1
  trap probe__exit_with_cleanup EXIT
}

probe__exit_with_cleanup() {
  local rc=$?
  "$PROBE_CLEANUP" || true
  (exit "$rc")
  probe__on_exit
}

probe_detail() { # key value
  printf '%s\ts\t%s\n' "$(probe__clean "$1")" "$(probe__clean "$2")" >>"$PROBE_DETAILS"
}

probe_detail_bool() { # key 0|1 (0 = true, like a shell status)
  local v=false
  if [ "$2" -eq 0 ]; then v=true; fi
  printf '%s\tb\t%s\n' "$(probe__clean "$1")" "$v" >>"$PROBE_DETAILS"
}

probe_finish() { # PASS|FAIL ok|failed
  probe_write "$PROBE_DIR" "$PROBE_ID" "$1" "$2" "$PROBE_DETAILS"
  PROBE_DONE=1
}

probe__self_test() {
  local tmp fails=0 d
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/probe-selftest.XXXXXX")
  d=$tmp/details
  check() { # label, python expression over the loaded result `r`
    if python3 -I - "$tmp/$2.json" "$3" <<'PY'
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
sys.exit(0 if eval(sys.argv[2]) else 1)
PY
    then echo "  ok: $1"; else echo "  FAIL: $1" >&2; fails=$((fails + 1)); fi
  }
  printf 'note\ts\ta "quoted" \\ back\\slash\nflag\tb\ttrue\n' >"$d"
  probe_write "$tmp" T-pass PASS ok "$d"
  check "PASS with control ok stays PASS" T-pass 'r["verdict"]=="PASS" and r["control"]=="ok"'
  check "details escape and typed bool" T-pass 'r["details"]["note"]=="a \"quoted\" \\ back\\slash" and r["details"]["flag"] is True'
  check "runner keys present" T-pass 'set(r["runner"])=={"os","image_os","image_version"}'
  probe_write "$tmp" T-ctl PASS failed "$d"
  check "control failed forces INVALID" T-ctl 'r["verdict"]=="INVALID" and r["control"]=="failed"'
  probe_write "$tmp" T-ctlfail FAIL failed "$d"
  check "FAIL with control failed becomes INVALID" T-ctlfail 'r["verdict"]=="INVALID"'
  probe_write "$tmp" T-bad MAYBE ok "$d"
  check "unknown verdict becomes INVALID" T-bad 'r["verdict"]=="INVALID"'
  probe_write "$tmp" T-fail FAIL ok "$d"
  check "FAIL with control ok stays FAIL" T-fail 'r["verdict"]=="FAIL"'
  # The EXIT trap: a script that dies before a verdict leaves an INVALID result.
  local self=${BASH_SOURCE[0]}
  PROBE_RESULTS_DIR=$tmp bash -c '. "$1"; probe_begin T-die; probe_detail step "before death"; exit 7' _ "$self" || true
  check "death before a verdict writes INVALID with the error" T-die 'r["verdict"]=="INVALID" and "status 7" in r["details"]["error"]'
  PROBE_RESULTS_DIR=$tmp bash -c '. "$1"; probe_begin T-done; probe_finish PASS ok; exit 0' _ "$self"
  check "a finished probe is not overwritten by the trap" T-done 'r["verdict"]=="PASS"'
  # Cleanup runs on death, and the INVALID result is still written.
  PROBE_RESULTS_DIR=$tmp bash -c '. "$1"; c() { echo cleaned > "$PROBE_RESULTS_DIR/cleaned.txt"; }; probe_begin T-clean; probe_cleanup_on_exit c; exit 5' _ "$self" || true
  check "cleanup-on-exit still writes INVALID" T-clean 'r["verdict"]=="INVALID" and "status 5" in r["details"]["error"]'
  if [ -f "$tmp/cleaned.txt" ]; then echo "  ok: cleanup function ran"; else echo "  FAIL: cleanup function did not run" >&2; fails=$((fails + 1)); fi
  # The guard refuses off a runner and writes nothing.
  local before after rc=0
  before=$(find "$tmp" -type f | wc -l)
  env -u GITHUB_ACTIONS -u RUNNER_ENVIRONMENT bash -c '. "$1"; probe_guard' _ "$self" >/dev/null 2>&1 || rc=$?
  after=$(find "$tmp" -type f | wc -l)
  if [ "$rc" -eq 3 ] && [ "$before" = "$after" ]; then echo "  ok: guard exits 3 off a runner and writes nothing"; else echo "  FAIL: guard (rc=$rc)" >&2; fails=$((fails + 1)); fi
  rc=0
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=self-hosted bash -c '. "$1"; probe_guard' _ "$self" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 3 ]; then echo "  ok: guard refuses a self-hosted runner"; else echo "  FAIL: self-hosted guard (rc=$rc)" >&2; fails=$((fails + 1)); fi
  rc=0
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted bash -c '. "$1"; probe_guard' _ "$self" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then echo "  ok: guard accepts a hosted runner"; else echo "  FAIL: hosted guard (rc=$rc)" >&2; fails=$((fails + 1)); fi
  rc=0
  env -u RUNNER_ENVIRONMENT -u ImageOS GITHUB_ACTIONS=true bash -c '. "$1"; probe_guard' _ "$self" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 3 ]; then echo "  ok: guard refuses with no hosted-runner signal"; else echo "  FAIL: no-signal guard (rc=$rc)" >&2; fails=$((fails + 1)); fi
  rm -rf "$tmp"
  if [ "$fails" -ne 0 ]; then echo "self-test: $fails failed" >&2; return 1; fi
  echo "self-test: all passed"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  if [ "${1:-}" = "--self-test" ]; then
    set -euo pipefail
    probe__self_test
  else
    echo "usage: result.sh --self-test (otherwise source this file from a probe script)" >&2
    exit 2
  fi
fi
