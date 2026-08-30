<#
.SYNOPSIS
    Signs vetto.exe with Authenticode digital signature using signtool.exe or osslsigncode.
.DESCRIPTION
    Extracts PFX certificate from environment variable SIGNING_CERT_PFX or cert file,
    signs target binary with SHA-256 and RFC 3161 timestamp.
.PARAMETER TargetPath
    Path to vetto.exe to sign.
#>

param (
    [string]$TargetPath = "target/x86_64-pc-windows-msvc/release/vetto.exe"
)

$ErrorActionPreference = "Stop"

Write-Host "==> Checking Authenticode signing for: $TargetPath"

if (-not (Test-Path $TargetPath)) {
    if (Test-Path "target/release/vetto.exe") {
        $TargetPath = "target/release/vetto.exe"
    } else {
        Write-Error "Binary not found at $TargetPath"
        exit 1
    }
}

$certPfxBase64 = $env:SIGNING_CERT_PFX
$certPassword = $env:SIGNING_CERT_PASSWORD
$timestampUrl = "http://timestamp.digicert.com"

if ([string]::IsNullOrWhiteSpace($certPfxBase64) -or [string]::IsNullOrWhiteSpace($certPassword)) {
    Write-Host "==> SIGNING_CERT_PFX or SIGNING_CERT_PASSWORD not configured. Skipping Authenticode signing."
    exit 0
}

$tempCertPath = [System.IO.Path]::GetTempFileName() + ".pfx"

try {
    Write-Host "==> Decoding certificate PFX"
    [System.IO.File]::WriteAllBytes($tempCertPath, [System.Convert]::FromBase64String($certPfxBase64))

    # Search for signtool.exe in Windows SDK paths or PATH
    $signtool = Get-Command "signtool.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1

    if (-not $signtool) {
        $sdkPaths = @(
            "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
            "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
        )
        $signtool = Resolve-Path $sdkPaths -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -Last 1
    }

    if ($signtool) {
        Write-Host "==> Signing with signtool: $signtool"
        & $signtool sign /f $tempCertPath /p $certPassword /fd SHA256 /tr $timestampUrl /td SHA256 /v $TargetPath
    } else {
        Write-Host "==> signtool.exe not found. Attempting osslsigncode fallback..."
        $osslsigncode = Get-Command "osslsigncode" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1
        if ($osslsigncode) {
            $tempSigned = "$TargetPath.signed"
            & $osslsigncode sign -pkcs12 $tempCertPath -pass $certPassword -h sha256 -ts $timestampUrl -in $TargetPath -out $tempSigned
            Move-Item -Force $tempSigned $TargetPath
        } else {
            Write-Warning "Neither signtool.exe nor osslsigncode found. Cannot sign binary."
            exit 0
        }
    }

    Write-Host "==> Verifying signature on $TargetPath"
    $sig = Get-AuthenticodeSignature -FilePath $TargetPath
    Write-Host "Signature Status: $($sig.Status)"
    Write-Host "Signer Certificate: $($sig.SignerCertificate.Subject)"
    Write-Host "==> Authenticode signing completed successfully!"
}
finally {
    if (Test-Path $tempCertPath) {
        Remove-Item -Force $tempCertPath
    }
}
