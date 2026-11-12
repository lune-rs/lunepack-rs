# Probe helpers (PowerShell): runner guard and result writer. Dot-source from a probe script:
#   . "$PSScriptRoot/../lib/result.ps1"
#   Test-ProbeGuard                     # first thing: exit 3, touching nothing, off a hosted runner
#   Start-Probe 'P-X0'
#   try { Add-ProbeDetail name value; ...; Complete-Probe PASS ok }
#   catch { Add-ProbeDetail error $_.Exception.Message }
#   finally { Stop-ProbeUnfinished }    # writes INVALID if no verdict was recorded
# Result file: $env:PROBE_RESULTS_DIR or probe-results/<id>.json, same shape as result.sh.
# `pwsh -File probes/lib/result.ps1 -SelfTest` exercises the writer in a temp dir (no guard).
param([switch]$SelfTest)

$script:ProbeId = ''
$script:ProbeDone = $true
$script:ProbeDetails = [ordered]@{}
$script:ProbeGuardBasis = ''

function Test-ProbeGuard {
    if ($env:GITHUB_ACTIONS -ne 'true') {
        [Console]::Error.WriteLine('probe: refusing to run outside GitHub Actions (probes change runner state)')
        exit 3
    }
    if ($env:RUNNER_ENVIRONMENT) {
        if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
            [Console]::Error.WriteLine('probe: refusing to run on a non-hosted runner')
            exit 3
        }
        $script:ProbeGuardBasis = 'runner-environment'
    }
    elseif ($env:ImageOS) {
        $script:ProbeGuardBasis = 'image-os-fallback'
    }
    else {
        [Console]::Error.WriteLine('probe: refusing to run: no hosted-runner signal (RUNNER_ENVIRONMENT, ImageOS)')
        exit 3
    }
}

# Pure writer: no guard, no script state. Details is an ordered hashtable of named fields.
function Write-ProbeResult {
    param([string]$Dir, [string]$Id, [string]$Verdict, [string]$Control, $Details)
    $d = [ordered]@{}
    foreach ($k in $Details.Keys) { $d[$k] = $Details[$k] }
    if ($Verdict -notin @('PASS', 'FAIL', 'INVALID')) {
        $d['reason'] = 'unknown verdict forced to INVALID'
        $Verdict = 'INVALID'
    }
    if ($Control -ne 'ok') {
        if ($Verdict -ne 'INVALID') { $d['reason'] = 'control did not hold; verdict forced to INVALID' }
        $Verdict = 'INVALID'
        $Control = 'failed'
    }
    $doc = [ordered]@{
        id      = $Id
        verdict = $Verdict
        control = $Control
        runner  = [ordered]@{
            os            = [string]$env:RUNNER_OS
            image_os      = [string]$env:ImageOS
            image_version = [string]$env:ImageVersion
        }
        details = $d
    }
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    $json = $doc | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText((Join-Path $Dir "$Id.json"), $json + "`n", (New-Object System.Text.UTF8Encoding $false))
}

function Get-ProbeDir {
    if ($env:PROBE_RESULTS_DIR) { return $env:PROBE_RESULTS_DIR }
    return 'probe-results'
}

function Start-Probe {
    param([string]$Id)
    $script:ProbeId = $Id
    $script:ProbeDone = $false
    $script:ProbeDetails = [ordered]@{}
    if ($script:ProbeGuardBasis) { $script:ProbeDetails['guard'] = $script:ProbeGuardBasis }
}

function Add-ProbeDetail {
    param([string]$Name, $Value)
    $script:ProbeDetails[$Name] = $Value
}

function Complete-Probe {
    param([string]$Verdict, [string]$Control)
    Write-ProbeResult -Dir (Get-ProbeDir) -Id $script:ProbeId -Verdict $Verdict -Control $Control -Details $script:ProbeDetails
    $script:ProbeDone = $true
}

# Call from `finally`: records INVALID when the script died before a verdict.
function Stop-ProbeUnfinished {
    if (-not $script:ProbeDone) {
        $script:ProbeDone = $true
        if (-not $script:ProbeDetails.Contains('error')) {
            $script:ProbeDetails['error'] = 'script ended before a verdict'
        }
        Write-ProbeResult -Dir (Get-ProbeDir) -Id $script:ProbeId -Verdict 'INVALID' -Control 'failed' -Details $script:ProbeDetails
    }
}

function Invoke-ProbeSelfTest {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('probe-selftest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    function Check([string]$Label, [bool]$Ok) {
        if ($Ok) { Write-Host "  ok: $Label" } else { [Console]::Error.WriteLine("  FAIL: $Label"); $script:selfFails++ }
    }
    $script:selfFails = 0
    function Read-Result([string]$Id) { Get-Content -Raw -LiteralPath (Join-Path $tmp "$Id.json") | ConvertFrom-Json }
    $details = [ordered]@{ note = 'a "quoted" \ back\slash'; flag = $true }
    Write-ProbeResult $tmp 'T-pass' 'PASS' 'ok' $details
    $r = Read-Result 'T-pass'
    Check 'PASS with control ok stays PASS' (($r.verdict -eq 'PASS') -and ($r.control -eq 'ok'))
    Check 'details escape and typed bool' (($r.details.note -eq 'a "quoted" \ back\slash') -and ($r.details.flag -eq $true))
    Check 'runner keys present' (($r.runner.PSObject.Properties.Name -join ',') -eq 'os,image_os,image_version')
    Write-ProbeResult $tmp 'T-ctl' 'PASS' 'failed' $details
    $r = Read-Result 'T-ctl'
    Check 'control failed forces INVALID' (($r.verdict -eq 'INVALID') -and ($r.control -eq 'failed'))
    Write-ProbeResult $tmp 'T-bad' 'MAYBE' 'ok' $details
    $r = Read-Result 'T-bad'
    Check 'unknown verdict becomes INVALID' ($r.verdict -eq 'INVALID')
    Write-ProbeResult $tmp 'T-fail' 'FAIL' 'ok' $details
    $r = Read-Result 'T-fail'
    Check 'FAIL with control ok stays FAIL' ($r.verdict -eq 'FAIL')
    # finally-path: dying before a verdict leaves INVALID with the error
    $env:PROBE_RESULTS_DIR = $tmp
    Start-Probe 'T-die'
    try { Add-ProbeDetail 'error' 'boom'; throw 'boom' } catch { } finally { Stop-ProbeUnfinished }
    $r = Read-Result 'T-die'
    Check 'death before a verdict writes INVALID with the error' (($r.verdict -eq 'INVALID') -and ($r.details.error -eq 'boom'))
    Start-Probe 'T-done'
    try { Complete-Probe 'PASS' 'ok' } finally { Stop-ProbeUnfinished }
    $r = Read-Result 'T-done'
    Check 'a finished probe is not overwritten' ($r.verdict -eq 'PASS')
    Remove-Item Env:\PROBE_RESULTS_DIR
    # guard, in child processes
    $self = $PSCommandPath
    $shell = (Get-Process -Id $PID).Path
    $saved = @{ A = $env:GITHUB_ACTIONS; R = $env:RUNNER_ENVIRONMENT; I = $env:ImageOS }
    function Guard-Rc([string]$Ga, [string]$Re, [string]$Img) {
        foreach ($n in 'GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'ImageOS') { Remove-Item "Env:\$n" -ErrorAction SilentlyContinue }
        if ($Ga) { $env:GITHUB_ACTIONS = $Ga }
        if ($Re) { $env:RUNNER_ENVIRONMENT = $Re }
        if ($Img) { $env:ImageOS = $Img }
        & $shell -NoProfile -Command ". '$self'; Test-ProbeGuard" *> $null
        return $LASTEXITCODE
    }
    $before = (Get-ChildItem $tmp).Count
    Check 'guard exits 3 off a runner and writes nothing' (((Guard-Rc '' '' '') -eq 3) -and ((Get-ChildItem $tmp).Count -eq $before))
    Check 'guard refuses a self-hosted runner' ((Guard-Rc 'true' 'self-hosted' '') -eq 3)
    Check 'guard accepts a hosted runner' ((Guard-Rc 'true' 'github-hosted' '') -eq 0)
    Check 'guard refuses with no hosted-runner signal' ((Guard-Rc 'true' '' '') -eq 3)
    foreach ($p in @(@('GITHUB_ACTIONS', $saved.A), @('RUNNER_ENVIRONMENT', $saved.R), @('ImageOS', $saved.I))) {
        if ($p[1]) { Set-Item "Env:\$($p[0])" $p[1] } else { Remove-Item "Env:\$($p[0])" -ErrorAction SilentlyContinue }
    }
    Remove-Item -Recurse -Force $tmp
    if ($script:selfFails -ne 0) { [Console]::Error.WriteLine("self-test: $($script:selfFails) failed"); exit 1 }
    Write-Host 'self-test: all passed'
}

if ($SelfTest) { Invoke-ProbeSelfTest }
