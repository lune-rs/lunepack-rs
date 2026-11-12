# P-W1: a running .exe can be renamed (M6 self-replace premise).
# Steps: copy a system exe to a temp dir, start it so it keeps running, rename it.
# Controls: deleting the running image must fail; renaming a stopped copy must succeed.
# Verdict PASS when the running image was renamed. Named fields only.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../lib/result.ps1"
Test-ProbeGuard

function Get-Outcome([scriptblock]$Action) {
    try { & $Action; return @{ ok = $true; type = ''; hresult = '' } }
    catch {
        $e = $_.Exception
        if ($e.InnerException) { $e = $e.InnerException }
        return @{ ok = $false; type = $e.GetType().Name; hresult = ('0x{0:X8}' -f $e.HResult) }
    }
}

Start-Probe 'P-W1'
$dir = Join-Path ([System.IO.Path]::GetTempPath()) ('lunepack-probe-w1-' + [guid]::NewGuid().ToString('N'))
$proc = $null
try {
    New-Item -ItemType Directory -Path $dir | Out-Null
    $orig = Join-Path $dir 'running.exe'
    $renamed = Join-Path $dir 'running-renamed.exe'
    Copy-Item -LiteralPath "$env:windir\System32\ping.exe" -Destination $orig
    # `ping -t` runs until killed, so the image stays mapped.
    $proc = Start-Process -FilePath $orig -ArgumentList '-t', '127.0.0.1' -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $dir 'ping.out.txt')
    Start-Sleep -Seconds 2
    Add-ProbeDetail 'process_running_before_rename' (-not $proc.HasExited)

    $rename = Get-Outcome { [System.IO.File]::Move($orig, $renamed) }
    Add-ProbeDetail 'rename_running_ok' $rename.ok
    Add-ProbeDetail 'rename_running_error_type' $rename.type
    Add-ProbeDetail 'rename_running_hresult' $rename.hresult
    Add-ProbeDetail 'process_running_after_rename' (-not $proc.HasExited)
    Add-ProbeDetail 'renamed_file_exists' (Test-Path -LiteralPath $renamed)
    Add-ProbeDetail 'original_name_gone' (-not (Test-Path -LiteralPath $orig))

    # Control 1: deleting the running image must fail (whichever name it has now).
    $image = $renamed
    if (-not $rename.ok) { $image = $orig }
    $delete = Get-Outcome { [System.IO.File]::Delete($image) }
    $stillThere = Test-Path -LiteralPath $image
    Add-ProbeDetail 'control_delete_running_ok' $delete.ok
    Add-ProbeDetail 'control_delete_running_error_type' $delete.type
    Add-ProbeDetail 'control_delete_running_hresult' $delete.hresult
    Add-ProbeDetail 'control_running_image_still_exists' $stillThere
    $deleteFailed = ((-not $delete.ok) -and $stillThere)

    # Control 2: renaming a stopped copy must succeed.
    $stopped = Join-Path $dir 'stopped.exe'
    Copy-Item -LiteralPath "$env:windir\System32\ping.exe" -Destination $stopped
    $rename2 = Get-Outcome { [System.IO.File]::Move($stopped, (Join-Path $dir 'stopped-renamed.exe')) }
    Add-ProbeDetail 'control_rename_stopped_ok' $rename2.ok
    Add-ProbeDetail 'control_rename_stopped_hresult' $rename2.hresult

    $control = 'failed'
    if ($deleteFailed -and $rename2.ok) { $control = 'ok' }
    $verdict = 'FAIL'
    if ($rename.ok -and (-not $proc.HasExited)) { $verdict = 'PASS' }
    Complete-Probe $verdict $control
    Write-Host "p-w1: recorded (requested $verdict, control $control)"
}
catch {
    Add-ProbeDetail 'error' $_.Exception.Message
}
finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Milliseconds 500
    Remove-Item -Recurse -Force -LiteralPath $dir -ErrorAction SilentlyContinue
    Stop-ProbeUnfinished
}
