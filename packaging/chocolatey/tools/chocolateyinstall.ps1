$ErrorActionPreference = 'Stop'

$archiveUrl = $env:VETTO_WINDOWS_X64_ARCHIVE_URL
$archiveSha256 = $env:VETTO_WINDOWS_X64_SHA256

if ([string]::IsNullOrWhiteSpace($archiveUrl) -or [string]::IsNullOrWhiteSpace($archiveSha256)) {
    throw 'Set VETTO_WINDOWS_X64_ARCHIVE_URL and VETTO_WINDOWS_X64_SHA256 before packing this source-only template.'
}

$packageArgs = @{
    packageName    = 'vetto'
    unzipLocation = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
    url64bit       = $archiveUrl
    checksum64     = $archiveSha256
    checksumType64 = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs
