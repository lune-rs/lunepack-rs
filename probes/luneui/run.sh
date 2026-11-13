#!/usr/bin/env bash
# P-U1 (Linux and macOS): can LuneUI's gallery render on a hosted runner? Clones luneui-rs at a
# pinned commit into RUNNER_TEMP (no Cargo dependency, lock or path in this repo refers to it),
# builds the gallery --release with the runner's stable toolchain, then:
#   (i)  `gallery --dump <dir>` headless: PNG count, and the wgpu adapter (name, backend) from the
#        gallery's own `--bench` line (the dump itself prints no adapter);
#   (ii) opens the gallery window for ~5 s and takes one screenshot (Linux: Xvfb + ImageMagick
#        `import`; macOS: `screencapture`). Window and screenshot results are details only.
# Controls (a failed control forces INVALID):
#   - the clone is at the pinned commit; the built binary runs (`--list` prints scene names);
#   - Linux: `--dump` before Mesa is installed must fail to find an adapter, then Mesa is installed;
#   - at least one dumped PNG has more than one distinct colour (pillow in a venv; the checker is
#     first run on a known uniform and a known two-colour image).
# Verdict: PASS = the dump rendered (exit 0, at least one PNG) and the controls hold; FAIL = no
# adapter or no PNG with the controls ok; INVALID otherwise. Runner-only (guard); bash 3.2.
set -euo pipefail

here=${BASH_SOURCE[0]}
case $here in
  */*) here=${here%/*} ;;
  *) here=. ;;
esac
here=$(cd "$here" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../lib/result.sh
. "$here/../lib/result.sh"
probe_guard

os=$(uname -s)
case $os in
  Linux) id=P-U1-linux ;;
  Darwin) id=P-U1-macos ;;
  *) echo "run.sh: unsupported OS" >&2; exit 2 ;;
esac
probe_begin "$id"

repo_url=https://github.com/lune-rs/luneui-rs
pin=ec17ff0
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/lpprobe-u1.XXXXXX")
clone=$work/luneui-rs
xvfb_pid=
win_pid=

cleanup() {
  if [ -n "$win_pid" ]; then kill -9 "$win_pid" >/dev/null 2>&1 || true; fi
  if [ -n "$xvfb_pid" ]; then kill -9 "$xvfb_pid" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
probe_cleanup_on_exit cleanup

finish_invalid() { # reason: a precondition failed, so there is no verdict to give
  probe_detail invalid_reason "$1"
  probe_finish INVALID failed
  echo "run.sh: $id INVALID ($1)"
  exit 0
}

# Run a command with a time limit and capture its status and (at most 4000 bytes of) output.
LIM_RC=0
LIM_OUT=
limited() { # seconds, command...
  LIM_RC=0
  LIM_OUT=$(probe_limited "$@") || LIM_RC=$?
}

png_count() { # dir -> number of .png files (0 when missing)
  if [ -d "$1" ]; then find "$1" -name '*.png' | wc -l | tr -d ' '; else echo 0; fi
}

# --- (0) clone at the pinned commit -------------------------------------------------------
if ! GIT_TERMINAL_PROMPT=0 git clone --quiet "$repo_url" "$clone" >"$work/clone.log" 2>&1; then
  finish_invalid "git clone failed"
fi
if ! git -C "$clone" checkout --quiet "$pin" >"$work/checkout.log" 2>&1; then
  finish_invalid "git checkout of the pinned commit failed"
fi
rev=$(git -C "$clone" rev-parse HEAD)
probe_detail luneui_rev "$rev"
case $rev in
  "$pin"*) ;;
  *) finish_invalid "checked-out commit does not start with the pin" ;;
esac

# --- (1) build with the runner's stable toolchain, from inside the clone ---------------------
# RUSTUP_TOOLCHAIN overrides the clone's rust-toolchain.toml; the clone is outside this repo, so
# lunepack's own rust-toolchain.toml does not apply either.
probe_detail rustc "$(cd "$clone" && RUSTUP_TOOLCHAIN=stable rustc --version 2>&1 | head -n 1)"
build_rc=0
(cd "$clone" && RUSTUP_TOOLCHAIN=stable cargo build --release --locked -p gallery) >"$work/build.log" 2>&1 || build_rc=$?
if [ "$build_rc" -ne 0 ]; then
  probe_detail build_exit_code "$build_rc"
  probe_detail build_log_tail "$(tail -c 600 "$work/build.log")"
  finish_invalid "gallery build failed"
fi
probe_detail build ok
bin=$clone/target/release/gallery
if [ ! -x "$bin" ]; then finish_invalid "gallery binary not found after build"; fi

# Control: the binary runs and knows its scenes (so a later dump failure is the GPU, not the binary).
list_n=$("$bin" --list </dev/null 2>/dev/null | wc -l | tr -d ' ') || list_n=0
probe_detail scene_count "$list_n"
binary_ok=1
if [ "$list_n" -ge 1 ]; then binary_ok=0; fi

# --- pixel checker (pillow in a venv) ------------------------------------------------------
py=$work/venv/bin/python
pix_ready=1
if python3 -m venv "$work/venv" >/dev/null 2>&1 &&
  "$py" -m pip install --quiet --disable-pip-version-check pillow >/dev/null 2>&1; then
  pix_ready=0
fi

pixcheck() { # dir|selftest -> prints "multi=N uniform=M" (distinct colours per PNG: >1 or 1)
  "$py" -I - "$1" <<'PY'
import os, sys, tempfile
from PIL import Image

def classify(path):
    with Image.open(path) as im:
        colors = im.convert("RGBA").getcolors(maxcolors=2)
    return "multi" if colors is None or len(colors) > 1 else "uniform"

def count(directory):
    n = {"multi": 0, "uniform": 0}
    for name in sorted(os.listdir(directory)):
        if name.endswith(".png"):
            n[classify(os.path.join(directory, name))] += 1
    return n

arg = sys.argv[1]
if arg == "selftest":
    with tempfile.TemporaryDirectory() as d:
        Image.new("RGBA", (4, 4), (1, 2, 3, 255)).save(os.path.join(d, "one.png"))
        two = Image.new("RGBA", (4, 4), (1, 2, 3, 255))
        two.putpixel((0, 0), (9, 9, 9, 255))
        two.save(os.path.join(d, "two.png"))
        arg = d
        n = count(d)
else:
    n = count(arg)
print("multi=%d uniform=%d" % (n["multi"], n["uniform"]))
PY
}

pix_selftest_ok=1
if [ "$pix_ready" -eq 0 ]; then
  if [ "$(pixcheck selftest 2>/dev/null || true)" = "multi=1 uniform=1" ]; then pix_selftest_ok=0; fi
fi
probe_detail_bool pixel_checker_selftest_ok "$pix_selftest_ok"

# --- Linux control: no adapter before Mesa is installed ---------------------------------------
nomesa_ok=0
if [ "$os" = Linux ]; then
  mesa_pre=1
  if dpkg -s mesa-vulkan-drivers >/dev/null 2>&1; then mesa_pre=0; fi
  probe_detail_bool mesa_vulkan_preinstalled "$mesa_pre"
  limited 300 "$bin" --dump "$work/dump-nomesa"
  nomesa_ok=1
  if [ "$LIM_RC" -ne 0 ] && printf '%s' "$LIM_OUT" | grep -qi 'no suitable graphics adapter'; then nomesa_ok=0; fi
  probe_detail control_nomesa_exit_code "$LIM_RC"
  probe_detail_bool control_nomesa_no_adapter "$nomesa_ok"
  probe_detail control_nomesa_png_count "$(png_count "$work/dump-nomesa")"
  inst_rc=0
  probe_limited 900 sudo -n apt-get update -qq >/dev/null || inst_rc=$?
  if [ "$inst_rc" -eq 0 ]; then
    probe_limited 900 sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      mesa-vulkan-drivers xvfb imagemagick >/dev/null || inst_rc=$?
  fi
  probe_detail apt_install_exit_code "$inst_rc"
fi

# --- (i) headless dump -----------------------------------------------------------------------
limited 900 "$bin" --dump "$work/dump"
dump_rc=$LIM_RC
dump_out=$LIM_OUT
pngs=$(png_count "$work/dump")
probe_detail dump_exit_code "$dump_rc"
probe_detail png_count "$pngs"
no_adapter=1
if printf '%s' "$dump_out" | grep -qi 'no suitable graphics adapter'; then no_adapter=0; fi
probe_detail_bool dump_no_adapter "$no_adapter"
if [ "$dump_rc" -ne 0 ]; then probe_detail dump_output_head "$(printf '%s' "$dump_out" | head -c 300)"; fi

# The adapter, from the gallery's own bench line (a short run; the line prints once the device exists).
limited 180 "$bin" --bench --runs 1 --frames 1 --size 64x64
bench_line=$(printf '%s\n' "$LIM_OUT" | grep -m1 '^bench: adapter=' || true)
a_name=$(printf '%s\n' "$bench_line" | sed -n 's/^bench: adapter=\(.*\) backend=.*/\1/p')
a_backend=$(printf '%s\n' "$bench_line" | sed -n 's/.* backend=\([A-Za-z0-9]*\) .*/\1/p')
probe_detail adapter_name "${a_name:-not reported}"
probe_detail adapter_backend "${a_backend:-not reported}"
case $a_name in
  *llvmpipe* | *lavapipe* | *SwiftShader* | *swiftshader* | *Basic\ Render* | *WARP* | *Software* | *software*)
    probe_detail adapter_device_type "software (inferred from the name; the gallery does not print it)" ;;
  '') probe_detail adapter_device_type "not reported" ;;
  *) probe_detail adapter_device_type "not software by name (the gallery does not print the type)" ;;
esac

# Control: at least one dumped PNG has more than one distinct colour.
multi_ok=1
if [ "$pngs" -gt 0 ] && [ "$pix_selftest_ok" -eq 0 ]; then
  pix=$(pixcheck "$work/dump" 2>/dev/null || true)
  probe_detail pixel_result "${pix:-unavailable}"
  case $pix in
    multi=0\ *) ;;
    multi=*) multi_ok=0 ;;
  esac
fi

# --- (ii) window for ~5 s and one screenshot (details only; never decides the verdict) ----------
shots=$work/shots
mkdir -p "$shots"
shot_rc=unavailable
win_alive=1
if [ "$os" = Linux ]; then
  if command -v Xvfb >/dev/null 2>&1 && command -v import >/dev/null 2>&1; then
    Xvfb :99 -screen 0 1280x800x24 >"$work/xvfb.log" 2>&1 &
    xvfb_pid=$!
    i=0
    while [ ! -S /tmp/.X11-unix/X99 ] && [ "$i" -lt 20 ]; do
      sleep 0.5
      i=$((i + 1))
    done
    DISPLAY=:99 "$bin" >"$work/window.log" 2>&1 </dev/null &
    win_pid=$!
    sleep 5
    if kill -0 "$win_pid" >/dev/null 2>&1; then win_alive=0; fi
    shot_rc=0
    probe_limited 30 import -display :99 -window root "$shots/window.png" >/dev/null || shot_rc=$?
  else
    probe_detail window_note "Xvfb or ImageMagick missing (apt install failed?)"
  fi
else
  "$bin" >"$work/window.log" 2>&1 </dev/null &
  win_pid=$!
  sleep 5
  if kill -0 "$win_pid" >/dev/null 2>&1; then win_alive=0; fi
  shot_rc=0
  probe_limited 30 screencapture -x "$shots/window.png" >/dev/null || shot_rc=$?
fi
if [ -n "$win_pid" ]; then
  kill "$win_pid" >/dev/null 2>&1 || true
  sleep 1
  kill -9 "$win_pid" >/dev/null 2>&1 || true
  wait "$win_pid" >/dev/null 2>&1 || true
  win_pid=
fi
probe_detail_bool window_alive_after_5s "$win_alive"
probe_detail screenshot_exit_code "$shot_rc"
if [ -f "$work/window.log" ] && [ "$win_alive" -ne 0 ]; then
  probe_detail window_log_head "$(head -c 300 "$work/window.log")"
fi
shot_size=0
if [ -f "$shots/window.png" ]; then shot_size=$(wc -c <"$shots/window.png" | tr -d ' '); fi
probe_detail screenshot_bytes "$shot_size"
if [ "$shot_size" -gt 0 ] && [ "$pix_selftest_ok" -eq 0 ]; then
  probe_detail screenshot_pixels "$(pixcheck "$shots" 2>/dev/null || echo unavailable)"
fi

# --- verdict ---------------------------------------------------------------------------------
control=ok
if [ "$binary_ok" -ne 0 ]; then control=failed; probe_detail control_failed "binary does not list scenes"; fi
if [ "$os" = Linux ] && [ "$nomesa_ok" -ne 0 ]; then control=failed; probe_detail control_failed "dump without Mesa did not fail to find an adapter"; fi
dump_ok=1
if [ "$dump_rc" -eq 0 ] && [ "$pngs" -gt 0 ]; then dump_ok=0; fi
if [ "$dump_ok" -eq 0 ]; then
  if [ "$pix_selftest_ok" -ne 0 ]; then control=failed; probe_detail control_failed "pixel checker self-test did not hold"; fi
  if [ "$multi_ok" -ne 0 ]; then control=failed; probe_detail control_failed "no dumped PNG has more than one colour"; fi
fi
verdict=FAIL
if [ "$dump_ok" -eq 0 ]; then verdict=PASS; fi
probe_finish "$verdict" "$control"
echo "run.sh: $id recorded (requested $verdict, control $control)"
