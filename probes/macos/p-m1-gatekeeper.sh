#!/usr/bin/env bash
# P-M1: Gatekeeper behaviour of updater-swapped bundles can be observed (P4; D10, M7).
# macOS runner (auto-login GUI session; the image changes no spctl policy and grants no App
# Management). A minimal `.app` whose executable writes a marker is ad-hoc signed, then swapped
# with renamex_np(RENAME_SWAP = 0x2) via python3 ctypes. Recorded per location (a temp dir, then
# /Applications): the quarantine xattr, `spctl --assess --type execute -vv`, `syspolicy_check
# distribution` (or "absent"), and whether `open` produced the marker within a timeout.
# Known-negative control: a copy carrying a quarantine attribute must be rejected by spctl and
# must not produce the marker (and at least one unquarantined bundle must have launched, so the
# control is not passing because `open` cannot launch anything); any process a bundle started is
# killed after the timeout.
# Verdict PASS when the swapped, unquarantined bundle ran via `open` in both locations. Every
# external command that could wait on a GUI or a prompt runs under probe_limited (hard time limit),
# so a launch that cannot be observed ends as INVALID (control failed) with the exit codes recorded,
# never as a hung job. Runner-only (guard). bash 3.2.
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../lib/result.sh
. "$here/../lib/result.sh"
probe_guard
probe_begin P-M1

work=$(mktemp -d "${TMPDIR:-/tmp}/lpprobe-m1.XXXXXX")
apps_dir=/Applications
created_apps=
py=$(command -v python3)
wait_seconds=20
open_seconds=30

# shellcheck disable=SC2086  # created_apps holds space-separated paths without spaces
cleanup() {
  local app
  pkill -9 -f "$work/" >/dev/null 2>&1 || true
  pkill -9 -f '/LpProbeM1' >/dev/null 2>&1 || true
  for app in $created_apps; do probe_limited 60 sudo -n rm -rf "$app" >/dev/null 2>&1 || true; done
  rm -rf "$work"
}
probe_cleanup_on_exit cleanup

# make_app <bundle path> <marker path> <sudo|plain>: a one-file C executable that writes the
# marker, in a minimal bundle, ad-hoc signed. Writes into /Applications go through sudo.
make_app() {
  local bundle=$1 marker=$2 mode=$3 src exe stage
  stage=$work/stage-$(basename "$bundle")
  rm -rf "$stage"
  mkdir -p "$stage/Contents/MacOS"
  src=$work/probe-$(basename "$bundle").c
  cat >"$src" <<CSRC
#include <stdio.h>
int main(void) {
    FILE *f = fopen("$marker", "w");
    if (f) { fputs("ran\n", f); fclose(f); }
    return 0;
}
CSRC
  exe=$stage/Contents/MacOS/probe
  probe_limited 120 cc -o "$exe" "$src" >/dev/null
  cat >"$stage/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.lunepack.probe.$(basename "$bundle" .app)</string>
  <key>CFBundleExecutable</key><string>probe</string>
  <key>CFBundleName</key><string>$(basename "$bundle" .app)</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1</string>
</dict></plist>
PLIST
  probe_limited 60 codesign --force --sign - "$stage" >/dev/null
  if [ "$mode" = sudo ]; then
    probe_limited 60 sudo -n rm -rf "$bundle" >/dev/null
    probe_limited 60 sudo -n cp -R "$stage" "$bundle" >/dev/null
    created_apps="$created_apps $bundle"
  else
    rm -rf "$bundle"
    cp -R "$stage" "$bundle"
  fi
}

cat >"$work/swap.py" <<'PY'
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
rc = libc.renamex_np(sys.argv[1].encode(), sys.argv[2].encode(), 0x2)  # RENAME_SWAP
print("swap=ok" if rc == 0 else "swap=error errno=%d" % ctypes.get_errno())
PY

# launch <bundle> <marker>: `open -n` (time-limited), wait for the marker, then kill what it
# started. Sets LAUNCH_RAN to 0 when the marker appeared, 1 otherwise; records open's exit code
# (124 = it did not return in time).
launch() {
  local bundle=$1 marker=$2 i=0 open_rc=0
  rm -f "$marker"
  echo "p-m1: open $(basename "$bundle")"
  probe_limited "$open_seconds" open -n "$bundle" >/dev/null || open_rc=$?
  probe_detail "open_$(basename "$bundle" .app)_exit_code" "$open_rc"
  LAUNCH_RAN=1
  while [ "$i" -lt "$wait_seconds" ]; do
    if [ -f "$marker" ]; then LAUNCH_RAN=0; break; fi
    sleep 1
    i=$((i + 1))
  done
  pkill -9 -f "$bundle/Contents/MacOS/" >/dev/null 2>&1 || true
}

first_line() { # collapse a command's output to one short line
  tr '\n' ' ' | cut -c 1-160
}

# observe <label> <bundle>: record quarantine, spctl and syspolicy_check for a bundle.
observe() {
  local label=$1 bundle=$2 q rc=0 s
  if q=$(xattr -p com.apple.quarantine "$bundle" 2>/dev/null); then
    probe_detail "${label}_quarantine" "present"
    probe_detail "${label}_quarantine_flags" "${q%%;*}"
  else
    probe_detail "${label}_quarantine" "absent"
  fi
  s=$(probe_limited 60 spctl --assess --type execute -vv "$bundle") || rc=$?
  probe_detail "${label}_spctl_exit_code" "$rc"
  probe_detail "${label}_spctl_output" "$(printf '%s' "$s" | first_line)"
  if command -v syspolicy_check >/dev/null 2>&1; then
    rc=0
    s=$(probe_limited 60 syspolicy_check distribution "$bundle") || rc=$?
    probe_detail "${label}_syspolicy_check_exit_code" "$rc"
    probe_detail "${label}_syspolicy_check_output" "$(printf '%s' "$s" | first_line)"
  else
    probe_detail "${label}_syspolicy_check" "absent"
  fi
}

probe_detail macos_version "$(sw_vers -productVersion)"
probe_detail spctl_status "$(probe_limited 30 spctl --status | first_line)"

# run_location <label> <dir> <sudo|plain>: build A (v1) and B (v2), swap, observe, launch A.
# Sets RUN_LOCATION_RAN to 0 when the swapped bundle (now holding v2) ran via `open`.
SWAP_HELPER_FAILED=0
run_location() {
  local label=$1 dir=$2 mode=$3 a b marker_b sw swap_rc
  a=$dir/LpProbeM1-$label-a.app
  b=$dir/LpProbeM1-$label-b.app
  marker_b=$work/marker-$label-b
  make_app "$a" "$work/marker-$label-a" "$mode"
  make_app "$b" "$marker_b" "$mode"
  # A helper that exits nonzero (timeout 124, crash, refused `sudo -n`) is the instrument failing,
  # not a platform result: SWAP_HELPER_FAILED makes the control fail (INVALID). The helper's own
  # "swap=error errno=N" (exit 0) is the OS refusing the swap, a real result, and stays a FAIL.
  swap_rc=0
  if [ "$mode" = sudo ]; then
    sw=$(probe_limited 60 sudo -n "$py" "$work/swap.py" "$a" "$b") || swap_rc=$?
  else
    sw=$(probe_limited 60 "$py" "$work/swap.py" "$a" "$b") || swap_rc=$?
  fi
  if [ "$swap_rc" -ne 0 ]; then
    sw="$sw swap_exit_code=$swap_rc"
    SWAP_HELPER_FAILED=1
  fi
  probe_detail "${label}_swap" "$sw"
  observe "${label}_swapped" "$a"
  launch "$a" "$marker_b"
  probe_detail_bool "${label}_swapped_bundle_ran_v2" "$LAUNCH_RAN"
  RUN_LOCATION_RAN=$LAUNCH_RAN
}

echo "p-m1: stage temp location"
run_location temp "$work" plain
temp_ran=$RUN_LOCATION_RAN
echo "p-m1: stage /Applications location"
run_location apps "$apps_dir" sudo
apps_ran=$RUN_LOCATION_RAN

echo "p-m1: stage quarantined control"
# --- known-negative control: a quarantined copy ------------------------------------------
q_bundle=$work/LpProbeM1-quarantined.app
q_marker=$work/marker-quarantined
make_app "$q_bundle" "$q_marker" plain
xattr -w com.apple.quarantine "0083;$(printf '%x' "$(date +%s)");LunepackProbe;" "$q_bundle"
observe quarantined_copy "$q_bundle"
q_spctl_rc=0
probe_limited 60 spctl --assess --type execute "$q_bundle" >/dev/null || q_spctl_rc=$?
launch "$q_bundle" "$q_marker"
probe_detail_bool control_quarantined_ran "$LAUNCH_RAN"

# The negative control only means something if `open` can launch anything at all, so at least one
# unquarantined bundle must have run; otherwise the instrument is blind and the verdict is INVALID.
control=failed
# Only spctl's real rejection exit (3) counts as "rejected": 124 (hung) and 127 (cannot start) mean
# spctl was blind, so the control fails. A failed swap helper also fails the control.
if [ "$q_spctl_rc" -eq 3 ] && [ "$LAUNCH_RAN" -ne 0 ] && [ "$SWAP_HELPER_FAILED" -eq 0 ] \
  && { [ "$temp_ran" -eq 0 ] || [ "$apps_ran" -eq 0 ]; }; then
  control=ok
fi
verdict=FAIL
if [ "$temp_ran" -eq 0 ] && [ "$apps_ran" -eq 0 ]; then verdict=PASS; fi
probe_finish "$verdict" "$control"
echo "p-m1: recorded (requested $verdict, control $control)"
