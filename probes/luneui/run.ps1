# P-U1 (Windows): can LuneUI's gallery render on a hosted Windows runner? Same plan as run.sh:
# clone luneui-rs at a pinned commit into RUNNER_TEMP (no Cargo dependency, lock or path in this
# repo refers to it), build the gallery --release with the runner's stable toolchain, then
#   (i)  `gallery.exe --dump <dir>` headless: PNG count and the wgpu adapter (name, backend) from the
#        gallery's own `--bench` line (the dump itself prints no adapter);
#   (ii) open the gallery window for ~5 s and take one screenshot (PowerShell CopyFromScreen);
#        window and screenshot results are details only.
# Controls (a failed control forces INVALID): the clone is at the pinned commit; the built binary
# runs (`--list` prints scene names); at least one dumped PNG has more than one distinct colour
# (pillow in a venv; the checker is first run on a known uniform and a known two-colour image).
# Verdict: PASS = the dump rendered (exit 0, at least one PNG) and the controls hold; FAIL = no
# adapter or no PNG with the controls ok; INVALID otherwise. Runner-only (guard). Run under pwsh.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../lib/result.ps1"
Test-ProbeGuard

$repoUrl = 'https://github.com/lune-rs/luneui-rs'
$pin = 'ec17ff0'

# Python pixel checker: prints "multi=N uniform=M" (PNGs with more than one distinct colour / one).
$pixScript = @'
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
        n = count(d)
else:
    n = count(arg)
print("multi=%d uniform=%d" % (n["multi"], n["uniform"]))
'@

class Invalid : System.Exception {
    Invalid([string]$m) : base($m) {}
}

# Run an exe with a time limit; returns rc (124 on timeout) and at most 4000 chars of stdout+stderr.
function Invoke-Limited([string]$Exe, [string[]]$ArgList, [int]$Seconds, [string]$Tag) {
    $outF = Join-Path $script:work "$Tag.out"
    $errF = Join-Path $script:work "$Tag.err"
    $quoted = @($ArgList | ForEach-Object { '"' + $_ + '"' })
    $p = Start-Process -FilePath $Exe -ArgumentList $quoted -PassThru -NoNewWindow `
        -RedirectStandardOutput $outF -RedirectStandardError $errF
    $null = $p.Handle
    $rc = 124
    if ($p.WaitForExit($Seconds * 1000)) {
        $p.WaitForExit()
        $rc = $p.ExitCode
    }
    else {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
    $text = ''
    foreach ($f in @($outF, $errF)) {
        if (Test-Path -LiteralPath $f) { $text += [System.IO.File]::ReadAllText($f) + "`n" }
    }
    if ($text.Length -gt 4000) { $text = $text.Substring(0, 4000) }
    return [pscustomobject]@{ Rc = $rc; Out = $text }
}

function Get-PngCount([string]$Dir) {
    if (Test-Path -LiteralPath $Dir) { return @(Get-ChildItem -LiteralPath $Dir -Filter *.png -File).Count }
    return 0
}

function Invoke-Pix([string]$Arg) {
    try {
        $r = $script:pixScript | & $script:py -I - $Arg 2>$null
        if ($LASTEXITCODE -ne 0) { return '' }
        return ([string]$r).Trim()
    }
    catch { return '' }
}

Start-Probe 'P-U1-windows'
$work = Join-Path ($(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() })) ('lpprobe-u1-' + [guid]::NewGuid().ToString('N'))
$win = $null
$invalid = ''
try {
    New-Item -ItemType Directory -Path $work | Out-Null
    $clone = Join-Path $work 'luneui-rs'

    # --- (0) clone at the pinned commit ----------------------------------------------------
    $env:GIT_TERMINAL_PROMPT = '0'
    & git clone --quiet $repoUrl $clone *> (Join-Path $work 'clone.log')
    if ($LASTEXITCODE -ne 0) { throw [Invalid]::new('git clone failed') }
    & git -C $clone checkout --quiet $pin *> (Join-Path $work 'checkout.log')
    if ($LASTEXITCODE -ne 0) { throw [Invalid]::new('git checkout of the pinned commit failed') }
    $rev = ([string](& git -C $clone rev-parse HEAD)).Trim()
    Add-ProbeDetail 'luneui_rev' $rev
    if (-not $rev.StartsWith($pin)) { throw [Invalid]::new('checked-out commit does not start with the pin') }

    # --- (1) build with the runner's stable toolchain, from inside the clone ----------------
    # RUSTUP_TOOLCHAIN overrides the clone's rust-toolchain.toml; the clone is outside this repo, so
    # lunepack's own rust-toolchain.toml does not apply either.
    $env:RUSTUP_TOOLCHAIN = 'stable'
    Push-Location $clone
    try {
        Add-ProbeDetail 'rustc' ([string](& rustc --version 2>&1 | Select-Object -First 1))
        & cargo build --release --locked -p gallery *> (Join-Path $work 'build.log')
        $buildRc = $LASTEXITCODE
    }
    finally { Pop-Location }
    if ($buildRc -ne 0) {
        Add-ProbeDetail 'build_exit_code' $buildRc
        $tail = ((Get-Content -LiteralPath (Join-Path $work 'build.log') -Tail 12) -join ' | ')
        if ($tail.Length -gt 600) { $tail = $tail.Substring($tail.Length - 600) }
        Add-ProbeDetail 'build_log_tail' $tail
        throw [Invalid]::new('gallery build failed')
    }
    Add-ProbeDetail 'build' 'ok'
    $bin = Join-Path $clone 'target\release\gallery.exe'
    if (-not (Test-Path -LiteralPath $bin)) { throw [Invalid]::new('gallery binary not found after build') }

    # Control: the binary runs and knows its scenes (so a later dump failure is the GPU, not the binary).
    $list = @(& $bin --list 2>$null)
    $listN = $list.Count
    Add-ProbeDetail 'scene_count' $listN
    $binaryOk = ($LASTEXITCODE -eq 0) -and ($listN -ge 1)

    # --- pixel checker (pillow in a venv) ----------------------------------------------------
    $py = Join-Path $work 'venv\Scripts\python.exe'
    $pixReady = $false
    try {
        & python -m venv (Join-Path $work 'venv') *> $null
        if ($LASTEXITCODE -eq 0) {
            & $py -m pip install --quiet --disable-pip-version-check pillow *> $null
            $pixReady = ($LASTEXITCODE -eq 0)
        }
    }
    catch { $pixReady = $false }
    $pixSelftestOk = $pixReady -and ((Invoke-Pix 'selftest') -eq 'multi=1 uniform=1')
    Add-ProbeDetail 'pixel_checker_selftest_ok' $pixSelftestOk

    # --- (i) headless dump ---------------------------------------------------------------------
    $dumpDir = Join-Path $work 'dump'
    $dump = Invoke-Limited $bin @('--dump', $dumpDir) 900 'dump'
    $pngs = Get-PngCount $dumpDir
    $noAdapter = $dump.Out -match '(?i)no suitable graphics adapter'
    Add-ProbeDetail 'dump_exit_code' $dump.Rc
    Add-ProbeDetail 'png_count' $pngs
    Add-ProbeDetail 'dump_no_adapter' $noAdapter
    if ($dump.Rc -ne 0) { Add-ProbeDetail 'dump_output_head' $dump.Out.Substring(0, [Math]::Min(300, $dump.Out.Length)) }

    # The adapter, from the gallery's own bench line (a short run; the line prints once the device exists).
    $bench = Invoke-Limited $bin @('--bench', '--runs', '1', '--frames', '1', '--size', '64x64') 180 'bench'
    $aName = ''
    $aBackend = ''
    $line = @($bench.Out -split "`r?`n" | Where-Object { $_ -like 'bench: adapter=*' } | Select-Object -First 1)
    if ($line.Count -gt 0) {
        if ($line[0] -match '^bench: adapter=(.*) backend=') { $aName = $Matches[1] }
        if ($line[0] -match ' backend=([A-Za-z0-9]+) ') { $aBackend = $Matches[1] }
    }
    Add-ProbeDetail 'adapter_name' $(if ($aName) { $aName } else { 'not reported' })
    Add-ProbeDetail 'adapter_backend' $(if ($aBackend) { $aBackend } else { 'not reported' })
    $type = 'not reported'
    if ($aName) {
        $type = 'not software by name (the gallery does not print the type)'
        if ($aName -match '(?i)llvmpipe|lavapipe|swiftshader|basic render|warp|software') {
            $type = 'software (inferred from the name; the gallery does not print it)'
        }
    }
    Add-ProbeDetail 'adapter_device_type' $type

    # Control: at least one dumped PNG has more than one distinct colour.
    $multiOk = $true
    if (($pngs -gt 0) -and $pixSelftestOk) {
        $pix = Invoke-Pix $dumpDir
        Add-ProbeDetail 'pixel_result' $(if ($pix) { $pix } else { 'unavailable' })
        if ($pix -match '^multi=0 ') { $multiOk = $false }
    }

    # --- (ii) window for ~5 s and one screenshot (details only; never decides the verdict) --------
    $shots = Join-Path $work 'shots'
    New-Item -ItemType Directory -Path $shots | Out-Null
    $winAlive = $false
    $shotOk = $false
    try {
        $win = Start-Process -FilePath $bin -PassThru -WindowStyle Normal `
            -RedirectStandardOutput (Join-Path $work 'window.out') -RedirectStandardError (Join-Path $work 'window.err')
        Start-Sleep -Seconds 5
        $winAlive = -not $win.HasExited
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing
        $b = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size)
        $bmp.Save((Join-Path $shots 'window.png'), [System.Drawing.Imaging.ImageFormat]::Png)
        $g.Dispose(); $bmp.Dispose()
        $shotOk = $true
    }
    catch {
        Add-ProbeDetail 'screenshot_error' $_.Exception.GetType().Name
    }
    if ($win -and -not $win.HasExited) { Stop-Process -Id $win.Id -Force -ErrorAction SilentlyContinue }
    Add-ProbeDetail 'window_alive_after_5s' $winAlive
    Add-ProbeDetail 'screenshot_ok' $shotOk
    $shotFile = Join-Path $shots 'window.png'
    if (Test-Path -LiteralPath $shotFile) {
        Add-ProbeDetail 'screenshot_bytes' (Get-Item -LiteralPath $shotFile).Length
        if ($pixSelftestOk) {
            $sp = Invoke-Pix $shots
            Add-ProbeDetail 'screenshot_pixels' $(if ($sp) { $sp } else { 'unavailable' })
        }
    }
    $winErr = Join-Path $work 'window.err'
    if ((-not $winAlive) -and (Test-Path -LiteralPath $winErr)) {
        $head = [System.IO.File]::ReadAllText($winErr)
        Add-ProbeDetail 'window_log_head' ($head.Substring(0, [Math]::Min(300, $head.Length)))
    }

    # --- verdict -----------------------------------------------------------------------------
    $control = 'ok'
    if (-not $binaryOk) { $control = 'failed'; Add-ProbeDetail 'control_failed' 'binary does not list scenes' }
    $dumpOk = ($dump.Rc -eq 0) -and ($pngs -gt 0)
    if ($dumpOk) {
        if (-not $pixSelftestOk) { $control = 'failed'; Add-ProbeDetail 'control_failed' 'pixel checker self-test did not hold' }
        if (-not $multiOk) { $control = 'failed'; Add-ProbeDetail 'control_failed' 'no dumped PNG has more than one colour' }
    }
    $verdict = if ($dumpOk) { 'PASS' } else { 'FAIL' }
    Complete-Probe $verdict $control
    Write-Host "run.ps1: P-U1-windows recorded (requested $verdict, control $control)"
}
catch [Invalid] {
    Add-ProbeDetail 'invalid_reason' $_.Exception.Message
    Complete-Probe 'INVALID' 'failed'
    Write-Host "run.ps1: P-U1-windows INVALID ($($_.Exception.Message))"
}
catch {
    Add-ProbeDetail 'error' $_.Exception.Message
}
finally {
    if ($win -and -not $win.HasExited) { Stop-Process -Id $win.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    Stop-ProbeUnfinished
}
