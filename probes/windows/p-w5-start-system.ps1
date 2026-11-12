# P-W5: a standard user can start a SYSTEM service or task (D12 Windows).
# Service: demand-start LocalSystem service whose binary is not a service (a permitted start then
# fails AFTER the access check, 1053 or 1067) with an SDDL granting SERVICE_START to Users; a
# created standard user tries `sc start`. Control: the same service without the Users grant
# returns 5 (access denied). Task: an on-demand SYSTEM scheduled task with an SDDL granting
# Users read+execute; the user runs `schtasks /run`. Control: the same without the grant must
# not run. Verdict PASS when at least one mechanism lets the standard user start it (both
# failing is FAIL). Run under Windows PowerShell 5.1. Named fields only; the password for the
# created user is generated at run time and never recorded.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../lib/result.ps1"
. "$PSScriptRoot/lib-user.ps1"
Test-ProbeGuard

Start-Probe 'P-W5'
$root = 'C:\lunepack-probe-w5'
$out = "$root\out"
$user = $null
$svcGrant = 'lpprobe-svc-grant'
$svcDeny = 'lpprobe-svc-deny'
$taskGrant = 'lpprobe-task-grant'
$taskDeny = 'lpprobe-task-deny'
$sddlSvcGrant = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;RPLCRC;;;BU)'
$sddlSvcDeny = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
$sddlTaskGrant = 'D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)'
$sddlTaskDeny = 'D:(A;;FA;;;SY)(A;;FA;;;BA)'

function Read-Marker([string]$Name) {
    $p = Join-Path $out $Name
    if (Test-Path -LiteralPath $p) { return ((Get-Content -LiteralPath $p -TotalCount 1) + '').Trim().ToLowerInvariant() }
    return ''
}

function New-ProbeService([string]$Name, [string]$Sddl) {
    $marker = Join-Path $out "$Name.who"
    & sc.exe create $Name binPath= "$env:windir\System32\cmd.exe /c whoami > $marker" start= demand obj= LocalSystem | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc create failed (exit $LASTEXITCODE)" }
    & sc.exe sdset $Name $Sddl | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc sdset failed (exit $LASTEXITCODE)" }
}

function New-ProbeTask([string]$Name, [string]$Sddl) {
    $marker = Join-Path $out "$Name.who"
    $action = New-ScheduledTaskAction -Execute "$env:windir\System32\cmd.exe" -Argument "/c whoami > `"$marker`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $Name -Action $action -Principal $principal -Force | Out-Null
    $svc = New-Object -ComObject 'Schedule.Service'
    $svc.Connect()
    $task = $svc.GetFolder('\').GetTask($Name)
    $task.SetSecurityDescriptor($Sddl, 0)
}

try {
    Set-ProbeAcl $root @("${script:ProbeSidSystem}:(OI)(CI)F", "${script:ProbeSidAdmins}:(OI)(CI)F", "${script:ProbeSidUsers}:(OI)(CI)RX")
    Set-ProbeAcl $out @("${script:ProbeSidSystem}:(OI)(CI)F", "${script:ProbeSidAdmins}:(OI)(CI)F", "${script:ProbeSidUsers}:(OI)(CI)M")
    $user = New-ProbeUser
    Add-ProbeDetail 'standard_user_created' $true

    New-ProbeService $svcGrant $sddlSvcGrant
    New-ProbeService $svcDeny $sddlSvcDeny
    New-ProbeTask $taskGrant $sddlTaskGrant
    New-ProbeTask $taskDeny $sddlTaskDeny

    # --- service: with the Users grant -------------------------------------------------
    $r = Invoke-AsUser $user @("sc.exe start $svcGrant > `"$out\svc-grant.out.txt`" 2>&1") $root $out 'svc-grant' 120
    Add-ProbeDetail 'launch_method' $r.Method
    Add-ProbeDetail 'service_grant_exit_code' $r.ExitCode
    Add-ProbeDetail 'service_grant_timed_out' $r.TimedOut
    Start-Sleep -Seconds 2
    Add-ProbeDetail 'service_grant_marker_identity' (Read-Marker "$svcGrant.who")
    $servicePass = ($r.ExitCode -in @(1053, 1067))

    # --- service: control without the grant -------------------------------------------
    $r = Invoke-AsUser $user @("sc.exe start $svcDeny > `"$out\svc-deny.out.txt`" 2>&1") $root $out 'svc-deny' 120
    Add-ProbeDetail 'service_deny_exit_code' $r.ExitCode
    Add-ProbeDetail 'service_deny_marker_identity' (Read-Marker "$svcDeny.who")
    $svcControl = (($r.ExitCode -eq 5) -and ((Read-Marker "$svcDeny.who") -eq ''))

    # --- task: with the Users grant ----------------------------------------------------
    $r = Invoke-AsUser $user @("schtasks.exe /run /tn $taskGrant > `"$out\task-grant.out.txt`" 2>&1") $root $out 'task-grant' 120
    Add-ProbeDetail 'task_grant_exit_code' $r.ExitCode
    Add-ProbeDetail 'task_grant_output' ($r.Output -replace '\s+', ' ')
    $m = ''
    for ($i = 0; $i -lt 20 -and $m -eq ''; $i++) { Start-Sleep -Seconds 1; $m = Read-Marker "$taskGrant.who" }
    Add-ProbeDetail 'task_grant_marker_identity' $m
    $taskPass = (($r.ExitCode -eq 0) -and ($m -like '*system*'))

    # --- task: control without the grant -----------------------------------------------
    $r = Invoke-AsUser $user @("schtasks.exe /run /tn $taskDeny > `"$out\task-deny.out.txt`" 2>&1") $root $out 'task-deny' 120
    Add-ProbeDetail 'task_deny_exit_code' $r.ExitCode
    Add-ProbeDetail 'task_deny_output' ($r.Output -replace '\s+', ' ')
    Start-Sleep -Seconds 3
    $mDeny = Read-Marker "$taskDeny.who"
    Add-ProbeDetail 'task_deny_marker_identity' $mDeny
    $taskControl = (($r.ExitCode -ne 0) -and ($mDeny -eq ''))

    Add-ProbeDetail 'service_start_by_standard_user' $servicePass
    Add-ProbeDetail 'task_start_by_standard_user' $taskPass
    Add-ProbeDetail 'control_service_without_grant_denied' $svcControl
    Add-ProbeDetail 'control_task_without_grant_denied' $taskControl
    $control = 'failed'
    if ($svcControl -and $taskControl) { $control = 'ok' }
    $verdict = 'FAIL'
    if ($servicePass -or $taskPass) { $verdict = 'PASS' }
    Complete-Probe $verdict $control
    Write-Host "p-w5: recorded (requested $verdict, control $control)"
}
catch {
    Add-ProbeDetail 'error' $_.Exception.Message
}
finally {
    foreach ($s in @($svcGrant, $svcDeny)) {
        & sc.exe stop $s 2>&1 | Out-Null
        & sc.exe delete $s 2>&1 | Out-Null
    }
    foreach ($t in @($taskGrant, $taskDeny)) { Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue }
    Remove-ProbeUser $user
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    Stop-ProbeUnfinished
}
