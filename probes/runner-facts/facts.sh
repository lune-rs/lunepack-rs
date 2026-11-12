#!/usr/bin/env bash
# P-R0 (Linux and macOS): do we have admin rights on the hosted runner, and what is it?
# Verdict PASS when admin rights hold. Control: a non-admin identity (`nobody`) must NOT be
# root, which shows the instrument can tell the difference. Named fields only.
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

os=$(uname -s)
case $os in
  Linux) id=P-R0-linux ;;
  Darwin) id=P-R0-macos ;;
  *) echo "facts.sh: unsupported OS" >&2; exit 2 ;;
esac
probe_begin "$id"
probe_detail os_kernel "$os $(uname -r)"

if [ "$os" = Linux ]; then
  pretty=$(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || true)
  probe_detail os_version "${pretty:-unknown}"
  probe_detail pid1_name "$(tr -d '\n' </proc/1/comm 2>/dev/null || echo unknown)"
else
  probe_detail os_version "$(sw_vers -productVersion 2>/dev/null || echo unknown)"
fi
probe_detail image_os "${ImageOS:-}"
probe_detail image_version "${ImageVersion:-}"

admin_group=1
if [ "$os" = Darwin ]; then
  if id -Gn | tr ' ' '\n' | grep -qx admin; then admin_group=0; fi
  probe_detail_bool admin_group_member "$admin_group"
fi

sudo_ok=1
if sudo -n true >/dev/null 2>&1; then sudo_ok=0; fi
probe_detail_bool sudo_without_password "$sudo_ok"

# Control: another identity must not be root.
control=failed
nobody_uid=$(sudo -n -u nobody id -u 2>/dev/null || true)
probe_detail control_nobody_uid "${nobody_uid:-unavailable}"
case $nobody_uid in
  '' | 0 | *[!0-9-]*) ;;
  *) control=ok ;;
esac

verdict=FAIL
if [ "$sudo_ok" -eq 0 ] && { [ "$os" = Linux ] || [ "$admin_group" -eq 0 ]; }; then verdict=PASS; fi
probe_finish "$verdict" "$control"
echo "facts.sh: $id recorded (requested $verdict, control $control)"
