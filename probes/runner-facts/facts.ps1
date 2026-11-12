# P-R0 (Windows): do we have admin rights on the hosted runner, and what is it?
# Verdict PASS when the current identity is in the Administrators role. Control: the local
# `Guest` account (SID S-1-5-21-...-501) must NOT be a member of Administrators, and the
# group lookup itself must return members; this shows the membership query can say no.
# Named fields only.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../lib/result.ps1"
Test-ProbeGuard

Start-Probe 'P-R0-windows'
try {
    Add-ProbeDetail 'os_version' ([System.Environment]::OSVersion.VersionString)
    Add-ProbeDetail 'image_os' ([string]$env:ImageOS)
    Add-ProbeDetail 'image_version' ([string]$env:ImageVersion)

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Add-ProbeDetail 'is_administrator' $isAdmin

    $control = 'failed'
    $members = @(Get-LocalGroupMember -Group 'Administrators')
    $guestMembers = @($members | Where-Object { $_.SID.Value -match '^S-1-5-21-.*-501$' })
    Add-ProbeDetail 'control_admin_group_member_count' $members.Count
    Add-ProbeDetail 'control_guest_in_administrators' ($guestMembers.Count -gt 0)
    if (($members.Count -gt 0) -and ($guestMembers.Count -eq 0)) { $control = 'ok' }

    $verdict = 'FAIL'
    if ($isAdmin) { $verdict = 'PASS' }
    Complete-Probe $verdict $control
    Write-Host "facts.ps1: P-R0-windows recorded (requested $verdict, control $control)"
}
catch {
    Add-ProbeDetail 'error' $_.Exception.Message
}
finally {
    Stop-ProbeUnfinished
}
