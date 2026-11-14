# CI job `os-trust` (Windows): the production transport (ureq + platform verifier + WinINET proxy,
# through crates/lunepack-http/examples/os_trust.rs) honours the operating system's trust store and
# proxy settings. A regression check, ported from probe P-N1 (sub-probes ii and iii).
#   (ii)  a loopback TLS server whose chain ends in a run-time root (rcgen; the root key is never
#         written to disk). Control: the fetch is rejected before the root certificate is added to
#         LocalMachine\Root (certutil). PASS: it is accepted after. The root is removed in finally.
#   (iii) a loopback CONNECT proxy set as the WinINET user proxy (HKCU Internet Settings). Control:
#         with the proxy off the proxy log stays empty. PASS: with it on the log shows CONNECT. The
#         original values are restored in finally.
# Writes one line `os-trust windows (ii)=<verdict> (iii)=<verdict>` to the job summary and stdout.
# Exit: 0 pass, 1 a sub-check failed or the script broke, 3 not on CI.
# Changes the runner's trust store and proxy settings: refuses to run unless CI=true and
# GITHUB_ACTIONS=true, so it never touches a developer machine. Run under PowerShell 7 (pwsh).
$ErrorActionPreference = 'Stop'

if (($env:CI -ne 'true') -or ($env:GITHUB_ACTIONS -ne 'true')) {
    [Console]::Error.WriteLine('os-trust: refusing to run outside CI (it changes the OS trust store and proxy settings)')
    exit 3
}

$tlsPort = 18443
$proxyPort = 18080
$target = "https://127.0.0.1:$tlsPort/"
$inet = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path

function Get-Kv($Lines, [string]$Key) {
    foreach ($l in @($Lines)) {
        $s = [string]$l
        if ($s.StartsWith("$Key=")) { return $s.Substring($Key.Length + 1).Trim() }
    }
    return ''
}

function Get-LineCount([string]$Path) {
    if (Test-Path -LiteralPath $Path) { return @(Get-Content -LiteralPath $Path).Count }
    return 0
}

function Wait-Listening([string]$Path) {
    for ($i = 0; $i -lt 40; $i++) {
        if ((Test-Path -LiteralPath $Path) -and (Select-String -LiteralPath $Path -Pattern '^listening=' -Quiet)) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

# Runs a program with a hard time limit; returns its exit code, or 124 after killing it.
function Invoke-Limited([string]$File, [string[]]$Arguments, [int]$Seconds) {
    $p = Start-Process -FilePath $File -ArgumentList $Arguments -PassThru -WindowStyle Hidden
    if (-not $p.WaitForExit($Seconds * 1000)) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        return 124
    }
    return $p.ExitCode
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ('lp-os-trust-' + [guid]::NewGuid().ToString('N'))
$tls = $null
$proxy = $null
$origEnable = $null
$origServer = $null
$trustAdded = $false
$ii = 'not-run'
$iii = 'not-run'
$notes = ''
try {
    New-Item -ItemType Directory -Path $work | Out-Null

    # --- build -----------------------------------------------------------------------------
    & cargo build --release --locked -p lunepack-http --example os_trust --target-dir (Join-Path $work 'target') *> (Join-Path $work 'build.log')
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath (Join-Path $work 'build.log') -Tail 20 | ForEach-Object { [Console]::Error.WriteLine($_) }
        throw "cargo build failed (exit $LASTEXITCODE)"
    }
    $bin = Join-Path $work 'target\release\examples\os_trust.exe'

    # --- (ii) trust store --------------------------------------------------------------------
    $certs = Join-Path $work 'certs'
    & $bin gen-certs $certs | Out-Null
    $tlsOut = Join-Path $work 'tls.out'
    $tls = Start-Process -FilePath $bin -ArgumentList @('serve-tls', $certs, $tlsPort) -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $tlsOut -RedirectStandardError (Join-Path $work 'tls.err')
    if (-not (Wait-Listening $tlsOut)) { $notes += ' tls server did not report listening;' }

    $before = @(& $bin fetch $target 2>&1)
    $beforeResult = Get-Kv $before 'result'
    Write-Host "(ii) before: result=$beforeResult kind=$(Get-Kv $before 'kind')"

    $trustAdded = $true # set before the add so a half-done add is undone too
    $trustRc = Invoke-Limited 'certutil.exe' @('-addstore', '-f', 'Root', (Join-Path $certs 'root.pem')) 60
    Write-Host "(ii) add to the OS store: exit $trustRc"
    if ($trustRc -eq 0) {
        $after = @(& $bin fetch $target 2>&1)
        $afterResult = Get-Kv $after 'result'
        Write-Host "(ii) after: result=$afterResult status=$(Get-Kv $after 'status')"
        if (($beforeResult -eq 'error') -and ($afterResult -eq 'ok')) { $ii = 'PASS' } else { $ii = 'FAIL' }
    }
    else {
        $ii = 'FAIL'
        $notes += " certutil could not add the root (exit $trustRc);"
    }

    # --- (iii) WinINET user proxy --------------------------------------------------------------
    $proxyLog = Join-Path $work 'proxy.log'
    $proxyOut = Join-Path $work 'proxy.out'
    $proxy = Start-Process -FilePath $bin -ArgumentList @('proxy-serve', $proxyPort, $proxyLog) -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $proxyOut -RedirectStandardError (Join-Path $work 'proxy.err')
    if (-not (Wait-Listening $proxyOut)) { $notes += ' proxy did not report listening;' }
    $props = Get-ItemProperty -Path $inet
    $origEnable = $props.ProxyEnable
    $origServer = $props.ProxyServer
    # An environment proxy would win over WinINET (M4-D14); none may be set for this check.
    foreach ($name in @('HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'HTTP_PROXY', 'http_proxy', 'NO_PROXY', 'no_proxy')) {
        Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
    }

    Set-ItemProperty -Path $inet -Name ProxyEnable -Value 0 -Type DWord
    $off = @(& $bin fetch $target 2>&1)
    $offLines = Get-LineCount $proxyLog
    Set-ItemProperty -Path $inet -Name ProxyServer -Value "127.0.0.1:$proxyPort" -Type String
    Set-ItemProperty -Path $inet -Name ProxyEnable -Value 1 -Type DWord
    $on = @(& $bin fetch $target 2>&1)
    $onLines = Get-LineCount $proxyLog
    Write-Host "(iii) proxy_selected off=$(Get-Kv $off 'proxy_selected') on=$(Get-Kv $on 'proxy_selected')"
    Write-Host "(iii) proxy log lines: off=$offLines on=$onLines"
    $connectLogged = $false
    if ((Test-Path -LiteralPath $proxyLog) -and (Select-String -LiteralPath $proxyLog -Pattern '^CONNECT ' -Quiet)) { $connectLogged = $true }
    if (($offLines -eq 0) -and $connectLogged -and ($onLines -gt 0)) { $iii = 'PASS' } else { $iii = 'FAIL' }
}
catch {
    $notes += " error: $($_.Exception.Message);"
}
finally {
    # Every step is best effort and bounded: a failed undo must not stop the next one.
    if ($null -ne $origEnable) { Set-ItemProperty -Path $inet -Name ProxyEnable -Value $origEnable -Type DWord -ErrorAction SilentlyContinue }
    else { Set-ItemProperty -Path $inet -Name ProxyEnable -Value 0 -Type DWord -ErrorAction SilentlyContinue }
    if ($null -ne $origServer) { Set-ItemProperty -Path $inet -Name ProxyServer -Value $origServer -Type String -ErrorAction SilentlyContinue }
    foreach ($p in @($tls, $proxy)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
    if ($trustAdded) {
        Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like 'CN=Lunepack Probe Root*' } |
            ForEach-Object { Remove-Item -LiteralPath $_.PSPath -Force -ErrorAction SilentlyContinue }
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    $line = "os-trust windows (ii)=$ii (iii)=$iii"
    if ($notes) { $line += ";$notes" }
    Write-Host $line
    if ($env:GITHUB_STEP_SUMMARY) { Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $line -ErrorAction SilentlyContinue }
}
if (($ii -eq 'PASS') -and ($iii -eq 'PASS')) { exit 0 }
exit 1
