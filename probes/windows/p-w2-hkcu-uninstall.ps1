# P-W2: an HKCU ...\Uninstall\<id> entry is listed by Get-Package -ProviderName Programs (D11).
# Run under Windows PowerShell 5.1 (the Programs provider lives in PackageManagement 1.x).
# Control: a preinstalled HKLM program is listed by the same query. Named fields only.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../lib/result.ps1"
Test-ProbeGuard

Start-Probe 'P-W2'
$runId = $env:GITHUB_RUN_ID
if (-not $runId) { $runId = [guid]::NewGuid().ToString('N') }
$keyName = "lunepack-probe-$runId"
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$keyName"
$displayName = "Lunepack Probe $runId"
try {
    Add-ProbeDetail 'powershell_version' ($PSVersionTable.PSVersion.ToString())
    Add-ProbeDetail 'powershell_edition' ([string]$PSVersionTable.PSEdition)

    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name DisplayName -Value $displayName -PropertyType String | Out-Null
    New-ItemProperty -Path $key -Name DisplayVersion -Value '1.2.3' -PropertyType String | Out-Null
    New-ItemProperty -Path $key -Name Publisher -Value 'Lunepack Probe' -PropertyType String | Out-Null
    New-ItemProperty -Path $key -Name UninstallString -Value 'cmd.exe /c exit 0' -PropertyType String | Out-Null

    # Pick a preinstalled HKLM program for the control (name only).
    $hklmRoots = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $hklmNames = @()
    foreach ($root in $hklmRoots) {
        if (Test-Path $root) {
            foreach ($k in Get-ChildItem $root) {
                $p = Get-ItemProperty -LiteralPath $k.PSPath
                if ($p.DisplayName -and -not $p.SystemComponent -and -not $p.ParentKeyName) { $hklmNames += [string]$p.DisplayName }
            }
        }
    }
    Add-ProbeDetail 'hklm_program_candidates' $hklmNames.Count

    $listed = @(Get-Package -ProviderName Programs -ErrorAction Stop)
    Add-ProbeDetail 'get_package_programs_count' $listed.Count
    $listedNames = @($listed | ForEach-Object { [string]$_.Name })

    $hkcuHit = @($listed | Where-Object { $_.Name -eq $displayName })
    Add-ProbeDetail 'hkcu_entry_listed' ($hkcuHit.Count -gt 0)
    if ($hkcuHit.Count -gt 0) { Add-ProbeDetail 'hkcu_entry_version' ([string]$hkcuHit[0].Version) }

    # Control: at least one preinstalled HKLM program appears in the same listing.
    $controlName = ''
    foreach ($n in $hklmNames) { if ($listedNames -contains $n) { $controlName = $n; break } }
    Add-ProbeDetail 'control_hklm_program_listed' ($controlName -ne '')
    if ($controlName) { Add-ProbeDetail 'control_hklm_program_name' $controlName }

    Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
    Add-ProbeDetail 'key_removed' (-not (Test-Path -LiteralPath $key))

    $control = 'failed'
    if ($controlName) { $control = 'ok' }
    $verdict = 'FAIL'
    if ($hkcuHit.Count -gt 0) { $verdict = 'PASS' }
    Complete-Probe $verdict $control
    Write-Host "p-w2: recorded (requested $verdict, control $control)"
}
catch {
    Add-ProbeDetail 'error' $_.Exception.Message
}
finally {
    Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
    Stop-ProbeUnfinished
}
