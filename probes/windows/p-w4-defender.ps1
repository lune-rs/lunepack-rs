# P-W4: Windows Defender can run on the hosted runner (P3; M6 acceptance).
# The runner image sets ForceDefenderPassiveMode=1, excludes C:\ and D:\ and turns off
# real-time, behaviour and IOAV protection. This probe removes that policy value and the
# exclusions, re-enables the protections, records status fields, then builds and runs a minimal
# unsigned Rust launcher and writes/renames/deletes a 1,000-file tree with retries, timing it.
# Decisive control: the industry-standard anti-malware test file, assembled at run time from
# fragments and written once to a temp dir, must be detected within 60 s; if not, INVALID.
# The runner is disposable: nothing is restored. Named fields only; the test string is never
# written to a result or an artifact.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../lib/result.ps1"
Test-ProbeGuard

# Record the named fields of an object as <prefix>_<name> details (never the whole object).
function Add-NamedFields($Object, [string[]]$Names, [string]$Prefix) {
    foreach ($n in $Names) {
        $v = $null
        try { $v = $Object.$n } catch { }
        if ($v -is [array]) { $v = ($v -join ';') }
        if ($null -eq $v) { $v = '' }
        if ($v -isnot [bool]) { $v = [string]$v }
        Add-ProbeDetail "${Prefix}_$n" $v
    }
}

# Run a step, recording <name>_ok and a short error text instead of aborting the probe.
function Invoke-Step([string]$Name, [scriptblock]$Action) {
    try { & $Action | Out-Null; Add-ProbeDetail "${Name}_ok" $true; return $true }
    catch {
        $m = [string]$_.Exception.Message
        if ($m.Length -gt 160) { $m = $m.Substring(0, 160) }
        Add-ProbeDetail "${Name}_ok" $false
        Add-ProbeDetail "${Name}_error" ($m -replace '\s+', ' ')
        return $false
    }
}

# Retry an action; returns the number of retries used (throws after $Max failures).
function Invoke-Retry([scriptblock]$Action, [int]$Max = 10, [int]$DelayMs = 200) {
    $retries = 0
    while ($true) {
        try { & $Action; return $retries }
        catch {
            $retries++
            if ($retries -ge $Max) { throw }
            Start-Sleep -Milliseconds $DelayMs
        }
    }
}

$statusFields = @('AMServiceEnabled', 'AntivirusEnabled', 'AntispywareEnabled', 'RealTimeProtectionEnabled',
    'BehaviorMonitorEnabled', 'IoavProtectionEnabled', 'OnAccessProtectionEnabled', 'AMRunningMode', 'IsTamperProtected')
$prefFields = @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection',
    'DisableScriptScanning', 'ExclusionPath')
$policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'

Start-Probe 'P-W4'
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('lunepack-probe-w4-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $work | Out-Null

    # --- before ---------------------------------------------------------------------
    $pol = (Get-ItemProperty -Path $policyKey -ErrorAction SilentlyContinue).ForceDefenderPassiveMode
    Add-ProbeDetail 'before_ForceDefenderPassiveMode' ([string]$pol)
    Add-ProbeDetail 'before_windefend_status' ([string](Get-Service -Name WinDefend -ErrorAction SilentlyContinue).Status)
    if (Invoke-Step 'before_status' { $script:s0 = Get-MpComputerStatus }) { Add-NamedFields $script:s0 $statusFields 'before_status' }
    if (Invoke-Step 'before_pref' { $script:p0 = Get-MpPreference }) { Add-NamedFields $script:p0 $prefFields 'before_pref' }

    # --- remove the image's policy and exclusions, re-enable protections ----------------
    Invoke-Step 'remove_policy_value' { Remove-ItemProperty -Path $policyKey -Name ForceDefenderPassiveMode -ErrorAction Stop } | Out-Null
    Invoke-Step 'remove_exclusions' {
        $paths = @((Get-MpPreference).ExclusionPath)
        foreach ($p in $paths) { if ($p) { Remove-MpPreference -ExclusionPath $p -ErrorAction Stop } }
    } | Out-Null
    Invoke-Step 'enable_protections' {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false `
            -DisableIOAVProtection $false -DisableScriptScanning $false -ErrorAction Stop
    } | Out-Null
    Invoke-Step 'restart_windefend' { Restart-Service -Name WinDefend -Force -ErrorAction Stop } | Out-Null

    # Give the engine up to 60 s to report real-time protection on.
    $rt = $false
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        try { $st = Get-MpComputerStatus; if ($st.RealTimeProtectionEnabled) { $rt = $true; break } } catch { }
        Start-Sleep -Seconds 2
    }
    Add-ProbeDetail 'realtime_protection_enabled_after' $rt
    if (Invoke-Step 'after_status' { $script:s1 = Get-MpComputerStatus }) { Add-NamedFields $script:s1 $statusFields 'after_status' }
    if (Invoke-Step 'after_pref' { $script:p1 = Get-MpPreference }) { Add-NamedFields $script:p1 $prefFields 'after_pref' }

    # --- decisive control: the anti-malware test file ----------------------------------
    $t0 = Get-Date
    $frag1 = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$'
    $frag2 = 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE'
    $frag3 = '!$H+H*'
    $testDir = Join-Path $work 'amtest'
    New-Item -ItemType Directory -Path $testDir | Out-Null
    $testFile = Join-Path $testDir 'probe-sample.txt'
    $detectedBy = 'none'
    try {
        [System.IO.File]::WriteAllText($testFile, ($frag1 + $frag2 + $frag3), [System.Text.Encoding]::ASCII)
    }
    catch {
        $detectedBy = 'on-access (write refused)'
        Add-ProbeDetail 'sample_write_hresult' ('0x{0:X8}' -f $_.Exception.HResult)
    }
    $frag1 = $null; $frag2 = $null; $frag3 = $null
    $deadline = (Get-Date).AddSeconds(60)
    $scanStarted = $false
    while ($detectedBy -eq 'none' -and (Get-Date) -lt $deadline) {
        $present = Test-Path -LiteralPath $testFile
        $readable = $false
        if ($present) { try { [System.IO.File]::ReadAllBytes($testFile) | Out-Null; $readable = $true } catch { } }
        if ((-not $present) -or (-not $readable)) { $detectedBy = 'on-access'; break }
        $hit = $null
        try { $hit = @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -ge $t0 }) } catch { }
        if ($hit -and $hit.Count -gt 0) { $detectedBy = 'threat-detection'; break }
        if ((-not $scanStarted) -and (((Get-Date) - $t0).TotalSeconds -gt 20)) {
            $scanStarted = $true
            try { Start-MpScan -ScanType CustomScan -ScanPath $testDir -ErrorAction Stop } catch { Add-ProbeDetail 'custom_scan_error' ([string]$_.Exception.Message).Substring(0, [Math]::Min(120, ([string]$_.Exception.Message).Length)) }
        }
        Start-Sleep -Seconds 1
    }
    Add-ProbeDetail 'sample_detected_by' $detectedBy
    Add-ProbeDetail 'sample_detect_seconds' ([int]((Get-Date) - $t0).TotalSeconds)
    Add-ProbeDetail 'custom_scan_started' $scanStarted
    Remove-Item -LiteralPath $testFile -Force -ErrorAction SilentlyContinue
    $control = 'failed'
    if ($detectedBy -ne 'none') { $control = 'ok' }

    # --- minimal unsigned Rust launcher -------------------------------------------------
    $crate = Join-Path $work 'hello'
    New-Item -ItemType Directory -Path (Join-Path $crate 'src') | Out-Null
    Set-Content -LiteralPath (Join-Path $crate 'Cargo.toml') -Encoding ASCII -Value @(
        '[package]', 'name = "hello"', 'version = "0.0.0"', 'edition = "2021"', '', '[workspace]')
    Set-Content -LiteralPath (Join-Path $crate 'src\main.rs') -Encoding ASCII -Value 'fn main() { println!("hello"); }'
    $launcherOk = $false
    if (Invoke-Step 'launcher_build' {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            # Windows PowerShell 5.1 turns native stderr into errors under 'Stop'; cargo logs there.
            $eap = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            & cargo build --release --manifest-path (Join-Path $crate 'Cargo.toml') --target-dir (Join-Path $work 'target') 2>&1 | Out-Null
            $rc = $LASTEXITCODE
            $ErrorActionPreference = $eap
            if ($rc -ne 0) { throw "cargo build exit $rc" }
            $script:buildMs = $sw.ElapsedMilliseconds
        }) {
        Add-ProbeDetail 'launcher_build_ms' $script:buildMs
        $exe = Join-Path $work 'target\release\hello.exe'
        if (Invoke-Step 'launcher_run' {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $o = & $exe
                $script:runMs = $sw.ElapsedMilliseconds
                if ($LASTEXITCODE -ne 0 -or $o -ne 'hello') { throw "unexpected launcher result (exit $LASTEXITCODE)" }
            }) {
            Add-ProbeDetail 'launcher_run_ms' $script:runMs
            $launcherOk = $true
        }
    }

    # --- 1,000-file tree: write, rename, delete, with retries -------------------------
    $tree = Join-Path $work 'tree'
    $tree2 = Join-Path $work 'tree-renamed'
    $payload = [System.Text.Encoding]::ASCII.GetBytes(('x' * 1024))
    $treeOk = $false
    if (Invoke-Step 'tree_write' {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = 0
            for ($d = 0; $d -lt 10; $d++) {
                $sub = Join-Path $tree ('d' + $d)
                New-Item -ItemType Directory -Path $sub -Force | Out-Null
                for ($f = 0; $f -lt 100; $f++) {
                    $r += Invoke-Retry { [System.IO.File]::WriteAllBytes((Join-Path $sub ('f' + $f + '.dat')), $payload) }
                }
            }
            $script:writeMs = $sw.ElapsedMilliseconds; $script:writeRetries = $r
        }) {
        Add-ProbeDetail 'tree_write_ms' $script:writeMs
        Add-ProbeDetail 'tree_write_retries' $script:writeRetries
        Add-ProbeDetail 'tree_file_count' (@(Get-ChildItem -LiteralPath $tree -Recurse -File).Count)
        if (Invoke-Step 'tree_rename' {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $script:renameRetries = Invoke-Retry { [System.IO.Directory]::Move($tree, $tree2) }
                $script:renameMs = $sw.ElapsedMilliseconds
            }) {
            Add-ProbeDetail 'tree_rename_ms' $script:renameMs
            Add-ProbeDetail 'tree_rename_retries' $script:renameRetries
            if (Invoke-Step 'tree_delete' {
                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    $script:deleteRetries = Invoke-Retry { Remove-Item -LiteralPath $tree2 -Recurse -Force -ErrorAction Stop }
                    $script:deleteMs = $sw.ElapsedMilliseconds
                }) {
                Add-ProbeDetail 'tree_delete_ms' $script:deleteMs
                Add-ProbeDetail 'tree_delete_retries' $script:deleteRetries
                $treeOk = $true
            }
        }
    }

    $verdict = 'FAIL'
    if ($rt -and $launcherOk -and $treeOk) { $verdict = 'PASS' }
    Complete-Probe $verdict $control
    Write-Host "p-w4: recorded (requested $verdict, control $control, sample detected by $detectedBy)"
}
catch {
    Add-ProbeDetail 'error' $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    Stop-ProbeUnfinished
}
