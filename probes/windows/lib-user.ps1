# Helpers for Windows probes that need a standard user (P-W5, P-W6). Dot-source after
# result.ps1. Runner-only: the guard in the probe script has already passed.
# The password is generated at run time and lives only in the returned object; it is never
# written to a result, a log or a file.

$script:ProbeSidUsers = '*S-1-5-32-545'
$script:ProbeSidAdmins = '*S-1-5-32-544'
$script:ProbeSidSystem = '*S-1-5-18'

function New-ProbeUser {
    param([string]$Prefix = 'lpprobe')
    $bytes = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    $plain = [Convert]::ToBase64String($bytes) + 'aA1!'
    $name = $Prefix + (Get-Random -Minimum 10000 -Maximum 99999)
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    New-LocalUser -Name $name -Password $secure -AccountNeverExpires -PasswordNeverExpires | Out-Null
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $name
    $cred = New-Object System.Management.Automation.PSCredential($name, $secure)
    [pscustomobject]@{ Name = $name; Credential = $cred; Password = $plain }
}

function Remove-ProbeUser {
    param($User)
    if ($User) { Remove-LocalUser -Name $User.Name -ErrorAction SilentlyContinue }
}

# Directory with the inheritance cut and only the listed grants (icacls SID forms).
function Set-ProbeAcl {
    param([string]$Path, [string[]]$Grants)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    $args2 = @($Path, '/inheritance:r')
    foreach ($g in $Grants) { $args2 += @('/grant:r', $g) }
    & icacls.exe @args2 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on a probe directory (exit $LASTEXITCODE)" }
}

# Run cmd lines as the standard user and return @{Method; ExitCode; Output; TimedOut}.
# `WorkDir` must be admin-owned and readable by Users; `OutDir` must be writable by Users.
# The batch file records its own errorlevel so the exit code does not depend on how the
# process was launched. The redirect comes first: `echo 5> file` is a stream-5 redirect (an
# empty file), so a single-digit errorlevel must never sit directly before the `>`.
# Primary launch: Start-Process -Credential (CreateProcessWithLogonW); fallback if that throws: a scheduled task registered for the user with the password.
function Invoke-AsUser {
    param($User, [string[]]$Lines, [string]$WorkDir, [string]$OutDir, [string]$Tag, [int]$TimeoutSec = 120)
    $bat = Join-Path $WorkDir "$Tag.cmd"
    $outFile = Join-Path $OutDir "$Tag.out.txt"
    $rcFile = Join-Path $OutDir "$Tag.rc.txt"
    Remove-Item -Force -ErrorAction SilentlyContinue $outFile, $rcFile
    $body = @('@echo off') + $Lines + @("> `"$rcFile`" echo %errorlevel%")
    Set-Content -LiteralPath $bat -Value $body -Encoding ASCII
    $method = 'Start-Process -Credential'
    $timedOut = $false
    try {
        $p = Start-Process -FilePath "$env:windir\System32\cmd.exe" -ArgumentList '/c', "`"$bat`"" `
            -Credential $User.Credential -WorkingDirectory $OutDir -WindowStyle Hidden -PassThru
        if (-not $p.WaitForExit($TimeoutSec * 1000)) { $timedOut = $true }
    }
    catch {
        $method = 'scheduled task for the user (Start-Process -Credential threw)'
        $taskName = "lpprobe-run-$Tag"
        $action = New-ScheduledTaskAction -Execute "$env:windir\System32\cmd.exe" -Argument "/c `"$bat`""
        Register-ScheduledTask -TaskName $taskName -Action $action -User $User.Name -Password $User.Password -RunLevel Limited -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        $deadline = (Get-Date).AddSeconds($TimeoutSec)
        while (-not (Test-Path -LiteralPath $rcFile) -and ((Get-Date) -lt $deadline)) { Start-Sleep -Milliseconds 500 }
        if (-not (Test-Path -LiteralPath $rcFile)) { $timedOut = $true }
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    # The launch may return before the batch finishes: wait for a parseable errorlevel.
    $rc = $null
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ($null -eq $rc) {
        if (Test-Path -LiteralPath $rcFile) {
            $txt = ((Get-Content -LiteralPath $rcFile -TotalCount 1) + '').Trim()
            $parsed = 0
            if ([int]::TryParse($txt, [ref]$parsed)) { $rc = $parsed; break }
        }
        if ((Get-Date) -ge $deadline) { $timedOut = $true; break }
        Start-Sleep -Milliseconds 250
    }
    $out = ''
    if (Test-Path -LiteralPath $outFile) { $out = ((Get-Content -LiteralPath $outFile -TotalCount 5) -join ' ') }
    @{ Method = $method; ExitCode = $rc; Output = $out; TimedOut = $timedOut }
}
