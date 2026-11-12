# P-W6: a named-pipe ACL plus impersonation confine a SYSTEM service to the caller's access (C8).
# A SYSTEM scheduled task serves a named pipe whose ACL admits Users and, while impersonating the
# connected client (RunAsClient), tries to open a file the client names. A created standard user
# asks it to open (a) an admin-only file: must be DENIED for PASS, and (b) a user-readable file:
# the control, which must succeed under the same impersonation. Run under Windows PowerShell 5.1.
# Named fields only; the password for the created user is generated at run time, never recorded.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../lib/result.ps1"
. "$PSScriptRoot/lib-user.ps1"
Test-ProbeGuard

Start-Probe 'P-W6'
$root = 'C:\lunepack-probe-w6'
$srvDir = "$root\srv"
$adminDir = "$root\admin"
$userDir = "$root\user"
$out = "$root\out"
$runId = $env:GITHUB_RUN_ID
if (-not $runId) { $runId = [guid]::NewGuid().ToString('N').Substring(0, 8) }
$pipeName = "lunepack-probe-w6-$runId"
$taskName = 'lpprobe-w6-server'
$user = $null

# Server: runs as SYSTEM under Windows PowerShell 5.1 (Add-Type compiles it with the in-box csc).
$serverScript = @'
param([string]$PipeName, [string]$OutFile, [int]$Requests)
$ErrorActionPreference = 'Stop'
try {
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
public static class LpServer {
    public static string Run(string pipeName, int requests) {
        var ps = new PipeSecurity();
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        var sb = new StringBuilder();
        sb.AppendLine("server_identity=" + WindowsIdentity.GetCurrent().Name);
        for (int i = 0; i < requests; i++) {
            using (var s = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.None, 4096, 4096, ps)) {
                s.WaitForConnection();
                var sr = new StreamReader(s);
                var sw = new StreamWriter(s);
                sw.AutoFlush = true;
                string path = sr.ReadLine();
                string who = "";
                string result = "";
                s.RunAsClient(delegate () {
                    who = WindowsIdentity.GetCurrent().Name;
                    try { using (var f = File.OpenRead(path)) { result = "OK"; } }
                    catch (UnauthorizedAccessException) { result = "DENIED"; }
                    catch (Exception e) { result = "ERROR:" + e.GetType().Name + ":" + e.HResult; }
                });
                sb.AppendLine("request" + i + "=" + who + "|" + result);
                sw.WriteLine(result);
            }
        }
        return sb.ToString();
    }
}
"@
$text = [LpServer]::Run($PipeName, $Requests)
Set-Content -LiteralPath $OutFile -Value $text -Encoding ASCII
}
catch {
    Set-Content -LiteralPath $OutFile -Value ('server_error=' + $_.Exception.Message) -Encoding ASCII
}
'@

$clientScript = @'
param([string]$PipeName, [string]$Path)
$c = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
$c.Connect(30000)
$w = New-Object System.IO.StreamWriter($c)
$w.AutoFlush = $true
$r = New-Object System.IO.StreamReader($c)
$w.WriteLine($Path)
'reply=' + $r.ReadLine()
$c.Dispose()
'@

function Ask-Server([string]$Tag, [string]$Path) {
    $outFile = Join-Path $out "$Tag.out.txt"
    $line = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$srvDir\client.ps1`" -PipeName $pipeName -Path `"$Path`" > `"$outFile`" 2>&1"
    $r = Invoke-AsUser $user @($line) $root $out $Tag 120
    $reply = ''
    if (Test-Path -LiteralPath $outFile) {
        $m = Select-String -LiteralPath $outFile -Pattern '^reply=(.*)$' | Select-Object -First 1
        if ($m) { $reply = $m.Matches[0].Groups[1].Value.Trim() }
    }
    @{ Reply = $reply; Run = $r }
}

try {
    $adminOnly = @("${script:ProbeSidSystem}:(OI)(CI)F", "${script:ProbeSidAdmins}:(OI)(CI)F")
    Set-ProbeAcl $root @("${script:ProbeSidSystem}:(OI)(CI)F", "${script:ProbeSidAdmins}:(OI)(CI)F", "${script:ProbeSidUsers}:(OI)(CI)RX")
    Set-ProbeAcl $srvDir @("${script:ProbeSidSystem}:(OI)(CI)F", "${script:ProbeSidAdmins}:(OI)(CI)F", "${script:ProbeSidUsers}:(OI)(CI)RX")
    Set-ProbeAcl $adminDir $adminOnly
    Set-ProbeAcl $userDir @("${script:ProbeSidSystem}:(OI)(CI)F", "${script:ProbeSidAdmins}:(OI)(CI)F", "${script:ProbeSidUsers}:(OI)(CI)RX")
    Set-ProbeAcl $out @("${script:ProbeSidSystem}:(OI)(CI)F", "${script:ProbeSidAdmins}:(OI)(CI)F", "${script:ProbeSidUsers}:(OI)(CI)M")
    Set-Content -LiteralPath "$adminDir\secret.txt" -Value 'admin-only' -Encoding ASCII
    Set-Content -LiteralPath "$userDir\readable.txt" -Value 'user-readable' -Encoding ASCII
    Set-Content -LiteralPath "$srvDir\server.ps1" -Value $serverScript -Encoding ASCII
    Set-Content -LiteralPath "$srvDir\client.ps1" -Value $clientScript -Encoding ASCII
    $user = New-ProbeUser
    Add-ProbeDetail 'standard_user_created' $true

    # SYSTEM scheduled task running the pipe server for exactly two requests.
    $serverOut = "$root\server.out.txt"
    $action = New-ScheduledTaskAction -Execute "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$srvDir\server.ps1`" -PipeName $pipeName -OutFile `"$serverOut`" -Requests 2"
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName

    # Wait for the pipe to exist.
    $up = $false
    for ($i = 0; $i -lt 60; $i++) {
        if ([System.IO.Directory]::GetFiles('\\.\pipe\') -contains "\\.\pipe\$pipeName") { $up = $true; break }
        Start-Sleep -Milliseconds 500
    }
    Add-ProbeDetail 'pipe_server_up' $up

    $adm = Ask-Server 'admin-file' "$adminDir\secret.txt"
    Add-ProbeDetail 'launch_method' $adm.Run.Method
    Add-ProbeDetail 'admin_file_reply' $adm.Reply
    $usr = Ask-Server 'user-file' "$userDir\readable.txt"
    Add-ProbeDetail 'user_file_reply' $usr.Reply

    # The server records the impersonated identity per request.
    for ($i = 0; $i -lt 20 -and -not (Test-Path -LiteralPath $serverOut); $i++) { Start-Sleep -Milliseconds 500 }
    if (Test-Path -LiteralPath $serverOut) {
        foreach ($l in (Get-Content -LiteralPath $serverOut -TotalCount 6)) {
            if ($l -match '^(server_identity|request0|request1)=(.*)$') { Add-ProbeDetail "server_$($Matches[1])" $Matches[2] }
            elseif ($l -match '^server_error=(.*)$') { Add-ProbeDetail 'server_error' $Matches[1] }
        }
    }
    Add-ProbeDetail 'admin_only_open_denied' ($adm.Reply -eq 'DENIED')
    Add-ProbeDetail 'control_user_readable_open_ok' ($usr.Reply -eq 'OK')
    $control = 'failed'
    if ($usr.Reply -eq 'OK') { $control = 'ok' }
    $verdict = 'FAIL'
    if ($adm.Reply -eq 'DENIED') { $verdict = 'PASS' }
    Complete-Probe $verdict $control
    Write-Host "p-w6: recorded (requested $verdict, control $control)"
}
catch {
    Add-ProbeDetail 'error' $_.Exception.Message
}
finally {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-ProbeUser $user
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    Stop-ProbeUnfinished
}
