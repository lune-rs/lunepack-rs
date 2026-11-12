#!/usr/bin/env bash
# P-M2: a standard user can trigger a socket-activated root daemon (P5; D12 macOS).
# A root LaunchDaemon with `Sockets` (SockPathMode 438 = 0666) and, for the probe only,
# `inetdCompatibility` runs a root-owned script that records `id -u` in a root-only file and swaps
# a test bundle under /Applications (renamex_np via python3 ctypes). Installed with sudo and
# `launchctl bootstrap system`. A standard user made with sysadminctl (run-time random password,
# never printed) connects with python3. Control: SockPathMode 384 (0600) must refuse that user.
# Runner-only (guard); bootout, user and files are removed afterwards. bash 3.2.
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
probe_begin P-M2

label=com.lunepack.probe.m2
plist=/Library/LaunchDaemons/$label.plist
sock=/var/run/lpprobe-m2.sock
state=/var/db/lpprobe-m2
helper_dir=/usr/local/lpprobe-m2
app_a=/Applications/LpProbeM2-a.app
app_b=/Applications/LpProbeM2-b.app
user=
created_by=
py=$(command -v python3)

cleanup() {
  sudo -n launchctl bootout "system/$label" >/dev/null 2>&1 || true
  sudo -n rm -f "$plist" "$sock" >/dev/null 2>&1 || true
  sudo -n rm -rf "$state" "$helper_dir" "$app_a" "$app_b" >/dev/null 2>&1 || true
  if [ -n "$user" ]; then
    sudo -n sysadminctl -deleteUser "$user" >/dev/null 2>&1 || true
    if [ "$created_by" = dscl ]; then sudo -n dscl . -delete "/Users/$user" >/dev/null 2>&1 || true; fi
    sudo -n rm -rf "/Users/$user" >/dev/null 2>&1 || true
  fi
}
probe_cleanup_on_exit cleanup

write_plist() { # SockPathMode as a decimal integer
  sudo -n tee "$plist" >/dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$helper_dir/run.sh</string></array>
  <key>inetdCompatibility</key><dict><key>Wait</key><false/></dict>
  <key>Sockets</key>
  <dict>
    <key>Listeners</key>
    <dict>
      <key>SockPathName</key><string>$sock</string>
      <key>SockPathMode</key><integer>$1</integer>
    </dict>
  </dict>
</dict>
</plist>
PLIST
  sudo -n chown root:wheel "$plist"
  sudo -n chmod 0644 "$plist"
}

load_daemon() {
  sudo -n launchctl bootout "system/$label" >/dev/null 2>&1 || true
  sudo -n rm -f "$sock"
  sudo -n launchctl bootstrap system "$plist"
}

# Client as the standard user: "connect=ok ..." or "connect=error errno=N name=X".
client() {
  sudo -n -u "$user" "$py" - "$sock" <<'PY'
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

# --- standard user ---------------------------------------------------------------------
pw=$("$py" -c 'import secrets; print(secrets.token_urlsafe(18))')
user=lpprobe$(date +%s | tail -c 6)
created_by=sysadminctl
sudo -n sysadminctl -addUser "$user" -fullName "Lunepack Probe" -password "$pw" -home "/Users/$user" >/dev/null 2>&1 || true
if ! id "$user" >/dev/null 2>&1; then
  # Fallback: a bare directory-service record (no password needed to run a process as the user).
  created_by=dscl
  sudo -n dscl . -create "/Users/$user"
  sudo -n dscl . -create "/Users/$user" UserShell /bin/bash
  sudo -n dscl . -create "/Users/$user" RealName "Lunepack Probe"
  sudo -n dscl . -create "/Users/$user" UniqueID 599
  sudo -n dscl . -create "/Users/$user" PrimaryGroupID 20
  sudo -n dscl . -create "/Users/$user" NFSHomeDirectory "/Users/$user"
fi
pw=
probe_detail user_created_by "$created_by"
probe_detail non_root_user_uid "$(id -u "$user")"
admin_member=1
if id -Gn "$user" | tr ' ' '\n' | grep -qx admin; then admin_member=0; fi
probe_detail_bool user_in_admin_group "$admin_member"

# --- root-owned helper and state ---------------------------------------------------------
sudo -n install -d -m 0700 -o root -g wheel "$state"
sudo -n install -d -m 0755 -o root -g wheel "$helper_dir"
sudo -n mkdir -p "$app_a/Contents" "$app_b/Contents"
sudo -n tee "$helper_dir/swap.py" >/dev/null <<'PY'
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
rc = libc.renamex_np(sys.argv[1].encode(), sys.argv[2].encode(), 0x2)  # RENAME_SWAP
print("swap=ok" if rc == 0 else "swap=error errno=%d" % ctypes.get_errno())
PY
sudo -n tee "$helper_dir/run.sh" >/dev/null <<EOS
#!/bin/bash
id -u > "$state/uid.txt"
$py "$helper_dir/swap.py" "$app_a" "$app_b" > "$state/swap.txt" 2>&1
echo triggered
EOS
sudo -n chmod 0755 "$helper_dir/run.sh" "$helper_dir/swap.py"

# --- the probe: SockPathMode 438 (0666) ---------------------------------------------------
write_plist 438
load_daemon
probe_detail sock_mode_probe "$(sudo -n stat -f %Lp "$sock" 2>/dev/null || echo missing)"
out=$(client || true)
probe_detail probe_client_result "$out"
recorded=1
if wait_for_record 15; then recorded=0; fi
uid_recorded=$(sudo -n cat "$state/uid.txt" 2>/dev/null | tr -d '\n' || true)
probe_detail probe_recorded_uid "${uid_recorded:-none}"
probe_detail_bool probe_daemon_ran "$recorded"
swap=$(sudo -n cat "$state/swap.txt" 2>/dev/null | tr -d '\n' || true)
probe_detail swap_under_applications "${swap:-none}"

# --- control: SockPathMode 384 (0600) -----------------------------------------------------
sudo -n rm -f "$state/uid.txt" "$state/swap.txt"
write_plist 384
load_daemon
probe_detail sock_mode_control "$(sudo -n stat -f %Lp "$sock" 2>/dev/null || echo missing)"
cout=$(client || true)
probe_detail control_client_result "$cout"
sleep 3
control_ran=1
if sudo -n test -f "$state/uid.txt"; then control_ran=0; fi
probe_detail_bool control_daemon_ran "$control_ran"

control=failed
case $cout in
  *connect=error*errno=13*) if [ "$control_ran" -ne 0 ]; then control=ok; fi ;;
esac
verdict=FAIL
case $out in
  connect=ok*) if [ "$recorded" -eq 0 ] && [ "$uid_recorded" = 0 ]; then verdict=PASS; fi ;;
esac
probe_finish "$verdict" "$control"
echo "p-m2: recorded (requested $verdict, control $control)"
