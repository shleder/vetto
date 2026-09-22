param (
    [Parameter(Mandatory=$true)]
    [string]$BinaryPath,
    [string]$CertificateThumbprint,
    [string]$PfxPath,
    [string]$PfxPassword
)

$ErrorActionPreference = "Stop"

Write-Host "==> Signing Windows binary: $BinaryPath"

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found at $BinaryPath"
    exit 1
}

$TimestampServer = "http://timestamp.digicert.com"
$SignToolArgs = @("sign", "/tr", $TimestampServer, "/td", "sha256", "/fd", "sha256")

if ($CertificateThumbprint) {
    Write-Host "Using Certificate Thumbprint: $CertificateThumbprint"
    $SignToolArgs += "/sha1", $CertificateThumbprint
} elseif ($PfxPath) {
    Write-Host "Using PFX File: $PfxPath"
    if (-not (Test-Path $PfxPath)) {
        Write-Error "PFX not found at $PfxPath"
        exit 1
    }
    $SignToolArgs += "/f", $PfxPath
    if ($PfxPassword) {
        $SignToolArgs += "/p", $PfxPassword
    }
} else {
    Write-Error "Must provide either CertificateThumbprint or PfxPath"
    exit 1
}

$SignToolArgs += $BinaryPath

Write-Host "Running SignTool.exe $($SignToolArgs -join ' ')"
# We assume signtool.exe is in PATH or this is run in a VS Dev Cmd / GH Actions setup
signtool.exe $SignToolArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "SignTool failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "==> Successfully signed $BinaryPath"
