#!/usr/bin/env bash
# P-L1: a non-root user can trigger a socket-activated root service (D12 Linux).
# Ubuntu runner, not Docker: PID 1's name is recorded first (not systemd -> INVALID).
# A `.socket` unit (Accept=yes, SocketMode=0666) with a templated root service runs a script that
# records `id -u` in a root-only file; a created non-root user connects. Control: SocketMode=0600
# must refuse the user. Runner-only (guard); units, user and files are removed afterwards.
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
probe_begin P-L1

user=
sock=/run/lpprobe-l1.sock
state=/var/lib/lpprobe-l1
unit_dir=/etc/systemd/system

cleanup() {
  sudo -n systemctl stop lpprobe-l1.socket >/dev/null 2>&1 || true
  sudo -n systemctl stop 'lpprobe-l1@*.service' >/dev/null 2>&1 || true
  sudo -n rm -f "$unit_dir/lpprobe-l1.socket" "$unit_dir/lpprobe-l1@.service" "$sock" >/dev/null 2>&1 || true
  sudo -n systemctl daemon-reload >/dev/null 2>&1 || true
  sudo -n rm -rf "$state" >/dev/null 2>&1 || true
  if [ -n "$user" ]; then sudo -n userdel -r "$user" >/dev/null 2>&1 || true; fi
}
probe_cleanup_on_exit cleanup

pid1=$(tr -d '\n' </proc/1/comm 2>/dev/null || echo unknown)
probe_detail pid1_name "$pid1"
if [ "$pid1" != systemd ]; then
  probe_detail note "PID 1 is not systemd; the premise cannot be observed here"
  probe_finish FAIL failed
  exit 0
fi

write_units() { # socket mode, e.g. 0666
  sudo -n tee "$unit_dir/lpprobe-l1.socket" >/dev/null <<UNIT
[Unit]
Description=lunepack probe P-L1 socket

[Socket]
ListenStream=$sock
Accept=yes
SocketMode=$1

[Install]
WantedBy=sockets.target
UNIT
  sudo -n tee "$unit_dir/lpprobe-l1@.service" >/dev/null <<UNIT
[Unit]
Description=lunepack probe P-L1 service instance

[Service]
User=root
StandardInput=socket
ExecStart=$state/run.sh
UNIT
  sudo -n systemctl daemon-reload
}

# Run the client as the standard user; prints "connect=ok ..." or "connect=error errno=N name=X".
client() {
  sudo -n -u "$user" python3 - "$sock" <<'PY'
import errno, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(sys.argv[1])
    try:
        data = s.recv(64)
    except OSError:
        data = b""
    print("connect=ok reply=" + data.decode("ascii", "replace").strip())
except OSError as e:
    print("connect=error errno=%s name=%s" % (e.errno, errno.errorcode.get(e.errno, "?")))
PY
}

wait_for_record() { # seconds
  local i=0
  while [ "$i" -lt "$1" ]; do
    if sudo -n test -f "$state/uid.txt"; then return 0; fi
    sleep 1
    i=$((i + 1))
  done
  return 1
}

user=lpprobe$(date +%s | tail -c 6)
sudo -n useradd -m -s /bin/bash "$user"
probe_detail non_root_user_uid "$(id -u "$user")"

sudo -n install -d -m 0700 -o root -g root "$state"
sudo -n tee "$state/run.sh" >/dev/null <<EOS
#!/bin/sh
id -u > $state/uid.txt
echo triggered
EOS
sudo -n chmod 0700 "$state/run.sh"
probe_detail record_dir_mode "$(sudo -n stat -c %a "$state")"

# --- the probe: SocketMode=0666 -------------------------------------------------------
write_units 0666
sudo -n systemctl start lpprobe-l1.socket
probe_detail socket_mode_probe "$(sudo -n stat -c %a "$sock" 2>/dev/null || echo missing)"
out=$(client || true)
probe_detail probe_client_result "$out"
recorded=1
if wait_for_record 10; then recorded=0; fi
uid_recorded=$(sudo -n cat "$state/uid.txt" 2>/dev/null | tr -d '\n' || true)
probe_detail probe_recorded_uid "${uid_recorded:-none}"
probe_detail_bool probe_service_ran "$recorded"

# --- control: SocketMode=0600 -----------------------------------------------------------
sudo -n systemctl stop lpprobe-l1.socket
sudo -n systemctl stop 'lpprobe-l1@*.service' >/dev/null 2>&1 || true
sudo -n rm -f "$state/uid.txt"
write_units 0600
sudo -n systemctl start lpprobe-l1.socket
probe_detail socket_mode_control "$(sudo -n stat -c %a "$sock" 2>/dev/null || echo missing)"
cout=$(client || true)
probe_detail control_client_result "$cout"
sleep 2
control_ran=1
if sudo -n test -f "$state/uid.txt"; then control_ran=0; fi
probe_detail_bool control_service_ran "$control_ran"

control=failed
case $cout in
  *connect=error*errno=13*) if [ "$control_ran" -ne 0 ]; then control=ok; fi ;;
esac
verdict=FAIL
case $out in
  connect=ok*) if [ "$recorded" -eq 0 ] && [ "$uid_recorded" = 0 ]; then verdict=PASS; fi ;;
esac
probe_finish "$verdict" "$control"
echo "p-l1: recorded (requested $verdict, control $control)"
