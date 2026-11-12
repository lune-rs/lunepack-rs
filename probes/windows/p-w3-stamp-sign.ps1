# P-W3: editpe stamping survives Authenticode signing (D11).
# A standalone Rust probe crate (probes/pe-stamp) stamps fixed VERSIONINFO values and a generated
# icon into a minimal `hello` exe. A job-generated self-signed code-signing certificate (private
# key NonExportable, never exported or printed; only the public .cer is imported into
# LocalMachine\Root for this job) signs the stamped exe; then `signtool verify /pa`,
# Get-AuthenticodeSignature and (Get-Item).VersionInfo are read back, plus pe-stamp --read for
# the icon. Controls: an unstamped copy reads the original (not the stamped) values, and an
# unsigned copy fails `signtool verify /pa`. Run under Windows PowerShell 5.1. Named fields only.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../lib/result.ps1"
Test-ProbeGuard

$expect = @{
    CompanyName     = 'Lunepack Probe Co'
    FileDescription = 'Lunepack probe hello'
    FileVersion     = '1.2.3.4'
    ProductName     = 'Lunepack Probe'
    ProductVersion  = '5.6.7.8'
}

# Run a native command without 5.1 turning its stderr into a terminating error; returns exit code.
function Invoke-Native([string]$File, [string[]]$Arguments) {
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $File @Arguments 2>&1 | Out-Null; return $LASTEXITCODE }
    finally { $ErrorActionPreference = $eap }
}

function Get-StampedFields([string]$Path) {
    $v = (Get-Item -LiteralPath $Path).VersionInfo
    @{ CompanyName = [string]$v.CompanyName; FileDescription = [string]$v.FileDescription
       FileVersion = [string]$v.FileVersion; ProductName = [string]$v.ProductName
       ProductVersion = [string]$v.ProductVersion }
}

function Test-FieldsMatch($Fields) {
    foreach ($k in $expect.Keys) { if ($Fields[$k] -ne $expect[$k]) { return $false } }
    return $true
}

Start-Probe 'P-W3'
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('lunepack-probe-w3-' + [guid]::NewGuid().ToString('N'))
$thumb = ''
try {
    New-Item -ItemType Directory -Path $work | Out-Null
    $repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path

    # --- build the probe crate (locked) -------------------------------------------------
    $manifest = Join-Path $repoRoot 'probes\pe-stamp\Cargo.toml'
    $target = Join-Path $work 'target'
    $rc = Invoke-Native 'cargo' @('build', '--release', '--locked', '--manifest-path', $manifest, '--target-dir', $target)
    Add-ProbeDetail 'cargo_build_exit_code' $rc
    if ($rc -ne 0) { throw "cargo build failed (exit $rc)" }
    $hello = Join-Path $target 'release\hello.exe'
    $stamper = Join-Path $target 'release\pe-stamp.exe'

    # --- copies -----------------------------------------------------------------------
    $unstamped = Join-Path $work 'unstamped.exe'
    $stamped = Join-Path $work 'stamped.exe'
    $signed = Join-Path $work 'signed.exe'
    Copy-Item -LiteralPath $hello -Destination $unstamped
    $rc = Invoke-Native $stamper @($hello, $stamped)
    Add-ProbeDetail 'pe_stamp_exit_code' $rc
    if ($rc -ne 0) { throw "pe-stamp failed (exit $rc)" }
    Copy-Item -LiteralPath $stamped -Destination $signed

    # --- certificate: private key stays in the store, public part trusted for this job ----
    $runId = $env:GITHUB_RUN_ID
    if (-not $runId) { $runId = [guid]::NewGuid().ToString('N').Substring(0, 8) }
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Lunepack Probe $runId" `
        -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(2)
    $thumb = $cert.Thumbprint
    Add-ProbeDetail 'cert_has_private_key' $cert.HasPrivateKey
    $cer = Join-Path $work 'probe.cer'
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    Add-ProbeDetail 'cert_trusted_in_localmachine_root' (Test-Path "Cert:\LocalMachine\Root\$thumb")

    # --- sign the stamped copy ------------------------------------------------------------
    $sig = Set-AuthenticodeSignature -FilePath $signed -Certificate $cert -HashAlgorithm SHA256
    Add-ProbeDetail 'set_authenticode_status' ([string]$sig.Status)

    # --- signtool ---------------------------------------------------------------------
    $signtool = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw 'signtool.exe not found under the Windows SDK' }
    Add-ProbeDetail 'signtool_sdk_version' (($signtool.FullName -split '\\')[-3])
    $verifySigned = Invoke-Native $signtool.FullName @('verify', '/pa', $signed)
    $verifyUnsigned = Invoke-Native $signtool.FullName @('verify', '/pa', $stamped)
    Add-ProbeDetail 'signtool_verify_signed_exit_code' $verifySigned
    Add-ProbeDetail 'control_signtool_verify_unsigned_exit_code' $verifyUnsigned
    Add-ProbeDetail 'get_authenticode_signature_status' ([string](Get-AuthenticodeSignature -FilePath $signed).Status)

    # --- version info, as the OS reads it ------------------------------------------------
    $fSigned = Get-StampedFields $signed
    $fStamped = Get-StampedFields $stamped
    $fOrig = Get-StampedFields $unstamped
    Add-ProbeDetail 'signed_version_fields_match' (Test-FieldsMatch $fSigned)
    Add-ProbeDetail 'signed_company_name' $fSigned.CompanyName
    Add-ProbeDetail 'signed_file_version' $fSigned.FileVersion
    Add-ProbeDetail 'stamped_version_fields_match' (Test-FieldsMatch $fStamped)
    Add-ProbeDetail 'control_unstamped_version_fields_match' (Test-FieldsMatch $fOrig)
    Add-ProbeDetail 'control_unstamped_company_name' $fOrig.CompanyName

    # --- icon: read the stamped fields back with editpe from the signed and unstamped files --
    $iconSigned = ''
    $iconOrig = ''
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $outSigned = @(& $stamper --read $signed 2>&1)
    $outOrig = @(& $stamper --read $unstamped 2>&1)
    $ErrorActionPreference = $eap
    foreach ($l in $outSigned) { if ([string]$l -match '^icon_pixel0=(.*)$') { $iconSigned = $Matches[1] } }
    foreach ($l in $outOrig) { if ([string]$l -match '^icon_pixel0=(.*)$') { $iconOrig = $Matches[1] } }
    Add-ProbeDetail 'signed_icon_pixel0' $iconSigned
    Add-ProbeDetail 'control_unstamped_icon_pixel0' $iconOrig
    $iconSurvived = ($iconSigned -eq 'C1862EFF')

    # --- verdict and control -----------------------------------------------------------
    $control = 'failed'
    $unstampedReadsOriginal = (-not (Test-FieldsMatch $fOrig)) -and ($iconOrig -ne 'C1862EFF')
    if ($unstampedReadsOriginal -and ($verifyUnsigned -ne 0) -and (Test-FieldsMatch $fStamped)) { $control = 'ok' }
    $verdict = 'FAIL'
    if (($verifySigned -eq 0) -and (Test-FieldsMatch $fSigned) -and $iconSurvived) { $verdict = 'PASS' }
    Complete-Probe $verdict $control
    Write-Host "p-w3: recorded (requested $verdict, control $control)"
}
catch {
    Add-ProbeDetail 'error' $_.Exception.Message
}
finally {
    if ($thumb) {
        Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$thumb" -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$thumb" -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    Stop-ProbeUnfinished
}
