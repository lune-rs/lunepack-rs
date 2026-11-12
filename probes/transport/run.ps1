# P-N1 (Windows): does the default transport (ureq + platform verifier + win-system-proxy) meet D23?
# Same three sub-probes as run.sh:
#   (i)   Range: bytes=0-99 on a GitHub release asset (206, content-range bytes 0-99/1787248, 100
#         bytes); control: curl.exe in the same job gets the same.
#   (ii)  a local TLS server with a run-time root; only the root CERTIFICATE is added to
#         LocalMachine\Root (certutil); PASS = accepted after, control = rejected before.
#   (iii) the WinINET user proxy (HKCU Internet Settings) set to a local logging CONNECT proxy;
#         PASS = the proxy log shows CONNECT, control = the log stays empty with the proxy off.
# Verdict FAIL if (ii) or (iii) fails. Runner-only (guard). Run under PowerShell 7 (pwsh).
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../lib/result.ps1"
Test-ProbeGuard

$asset = 'https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-aarch64-apple-darwin.tar.gz'
$tlsPort = 18443
$proxyPort = 18080
$target = "https://127.0.0.1:$tlsPort/"
$inet = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'

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

Start-Probe 'P-N1-windows'
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('lpprobe-n1-' + [guid]::NewGuid().ToString('N'))
$tls = $null
$proxy = $null
$origEnable = $null
$origServer = $null
$trustAdded = $false
try {
    New-Item -ItemType Directory -Path $work | Out-Null
    $repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path

    # --- build ---------------------------------------------------------------------------
    & cargo build --release --locked --manifest-path (Join-Path $repoRoot 'probes\transport\Cargo.toml') --target-dir (Join-Path $work 'target') *> (Join-Path $work 'build.log')
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }
    $bin = Join-Path $work 'target\release\transport-probe.exe'
    Add-ProbeDetail 'build' 'ok'

    # --- (i) Range -------------------------------------------------------------------------
    $out = @(& $bin range $asset 2>&1)
    $rStatus = Get-Kv $out 'status'; $rCr = Get-Kv $out 'content_range'; $rLen = Get-Kv $out 'body_len'
    Add-ProbeDetail 'i_ureq_status' $rStatus
    Add-ProbeDetail 'i_ureq_content_range' $rCr
    Add-ProbeDetail 'i_ureq_body_len' $rLen
    $hdr = Join-Path $work 'curl.hdr'
    $cbin = Join-Path $work 'curl.bin'
    & curl.exe -sL --max-time 90 -r 0-99 -D $hdr -o $cbin $asset
    $cStatus = ''; $cCr = ''
    if (Test-Path -LiteralPath $hdr) {
        $h = @(Get-Content -LiteralPath $hdr)
        $st = @($h | Where-Object { $_ -match '^HTTP/' } | Select-Object -Last 1)
        if ($st.Count -gt 0) { $cStatus = ([string]$st[0] -split ' ')[1] }
        $cr = @($h | Where-Object { $_ -match '^content-range:' } | Select-Object -Last 1)
        if ($cr.Count -gt 0) { $cCr = (([string]$cr[0]) -replace '^[^:]*:\s*', '').Trim() }
    }
    $cLen = 0
    if (Test-Path -LiteralPath $cbin) { $cLen = (Get-Item -LiteralPath $cbin).Length }
    Add-ProbeDetail 'i_curl_status' $cStatus
    Add-ProbeDetail 'i_curl_content_range' $cCr
    Add-ProbeDetail 'i_curl_body_len' $cLen
    $iPass = 'FAIL'
    if (($rStatus -eq '206') -and ($rCr -eq 'bytes 0-99/1787248') -and ($rLen -eq '100')) { $iPass = 'PASS' }
    $iControl = 'failed'
    if (($cStatus -eq '206') -and ($cCr -eq 'bytes 0-99/1787248') -and ($cLen -eq 100)) { $iControl = 'ok' }
    Add-ProbeDetail 'i_result' $iPass
    Add-ProbeDetail 'i_control' $iControl

    # --- (ii) trust store ------------------------------------------------------------------
    $certs = Join-Path $work 'certs'
    & $bin gen-certs $certs | Out-Null
    $tlsOut = Join-Path $work 'tls.out'
    $tls = Start-Process -FilePath $bin -ArgumentList @('serve-tls', $certs, $tlsPort) -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $tlsOut -RedirectStandardError (Join-Path $work 'tls.err')
    if (-not (Wait-Listening $tlsOut)) { Add-ProbeDetail 'note' 'tls server did not report listening' }
    $before = @(& $bin fetch $target 2>&1)
    $iiBefore = Get-Kv $before 'result'
    Add-ProbeDetail 'ii_before_result' $iiBefore
    Add-ProbeDetail 'ii_before_error' (Get-Kv $before 'error')

    & certutil.exe -addstore -f Root (Join-Path $certs 'root.pem') | Out-Null
    $trustRc = $LASTEXITCODE
    Add-ProbeDetail 'ii_add_trust_exit_code' $trustRc
    $iiResult = 'skipped'
    $iiControl = 'ok'
    if ($trustRc -eq 0) {
        $trustAdded = $true
        $after = @(& $bin fetch $target 2>&1)
        $iiAfter = Get-Kv $after 'result'
        Add-ProbeDetail 'ii_after_result' $iiAfter
        Add-ProbeDetail 'ii_after_status' (Get-Kv $after 'status')
        if (($iiBefore -eq 'error') -and ($iiAfter -eq 'ok')) { $iiResult = 'PASS' } else { $iiResult = 'FAIL' }
        if ($iiBefore -ne 'error') { $iiControl = 'failed' }
    }
    else { Add-ProbeDetail 'note' 'certutil could not add the root; (ii) skipped' }
    Add-ProbeDetail 'ii_result' $iiResult

    # --- (iii) WinINET user proxy ------------------------------------------------------------
    $proxyLog = Join-Path $work 'proxy.log'
    $proxyOut = Join-Path $work 'proxy.out'
    $proxy = Start-Process -FilePath $bin -ArgumentList @('proxy-serve', $proxyPort, $proxyLog) -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $proxyOut -RedirectStandardError (Join-Path $work 'proxy.err')
    if (-not (Wait-Listening $proxyOut)) { Add-ProbeDetail 'note' 'proxy did not report listening' }
    $props = Get-ItemProperty -Path $inet
    $origEnable = $props.ProxyEnable
    $origServer = $props.ProxyServer

    Set-ItemProperty -Path $inet -Name ProxyEnable -Value 0 -Type DWord
    $off = @(& $bin fetch-proxy $target 2>&1)
    $offLines = Get-LineCount $proxyLog
    Set-ItemProperty -Path $inet -Name ProxyServer -Value "127.0.0.1:$proxyPort" -Type String
    Set-ItemProperty -Path $inet -Name ProxyEnable -Value 1 -Type DWord
    $on = @(& $bin fetch-proxy $target 2>&1)
    $onLines = Get-LineCount $proxyLog
    Add-ProbeDetail 'iii_kind' 'WinINET user proxy (HKCU Internet Settings) read by ureq win-system-proxy'
    Add-ProbeDetail 'iii_off_proxy_selected' (Get-Kv $off 'proxy_selected')
    Add-ProbeDetail 'iii_on_proxy_selected' (Get-Kv $on 'proxy_selected')
    Add-ProbeDetail 'iii_on_fetch_result' (Get-Kv $on 'result')
    Add-ProbeDetail 'iii_log_lines_with_proxy_off' $offLines
    Add-ProbeDetail 'iii_log_lines_with_proxy_on' $onLines
    $connectLogged = $false
    if ((Test-Path -LiteralPath $proxyLog) -and (Select-String -LiteralPath $proxyLog -Pattern '^CONNECT ' -Quiet)) { $connectLogged = $true }
    Add-ProbeDetail 'iii_connect_logged' $connectLogged
    $iiiResult = 'FAIL'
    if ($connectLogged -and ($onLines -gt $offLines)) { $iiiResult = 'PASS' }
    $iiiControl = 'failed'
    if ($offLines -eq 0) { $iiiControl = 'ok' }
    Add-ProbeDetail 'iii_result' $iiiResult

    # --- verdict --------------------------------------------------------------------------
    $control = 'failed'
    if (($iControl -eq 'ok') -and ($iiControl -eq 'ok') -and ($iiiControl -eq 'ok')) { $control = 'ok' }
    $verdict = 'PASS'
    if (($iiResult -eq 'FAIL') -or ($iiiResult -eq 'FAIL')) { $verdict = 'FAIL' }
    Complete-Probe $verdict $control
    Write-Host "p-n1: P-N1-windows recorded (requested $verdict, control $control; i=$iPass ii=$iiResult iii=$iiiResult)"
}
catch {
    Add-ProbeDetail 'error' $_.Exception.Message
}
finally {
    if ($null -ne $origEnable) { Set-ItemProperty -Path $inet -Name ProxyEnable -Value $origEnable -Type DWord -ErrorAction SilentlyContinue }
    else { Set-ItemProperty -Path $inet -Name ProxyEnable -Value 0 -Type DWord -ErrorAction SilentlyContinue }
    if ($null -ne $origServer) { Set-ItemProperty -Path $inet -Name ProxyServer -Value $origServer -Type String -ErrorAction SilentlyContinue }
    foreach ($p in @($tls, $proxy)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
    if ($trustAdded) {
        Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like 'CN=Lunepack Probe Root*' } |
            ForEach-Object { Remove-Item -LiteralPath $_.PSPath -Force -ErrorAction SilentlyContinue }
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    Stop-ProbeUnfinished
}
