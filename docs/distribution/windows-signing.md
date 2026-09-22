# Windows Authenticode Signing

The `vetto.exe` binary is signed with an Authenticode certificate and timestamped using RFC 3161.

## Requirements
- `signtool.exe` must be in the `PATH` (e.g., from Windows SDK).
- Either a certificate installed in the Windows Certificate Store, or a `.pfx` file.

## Usage
Run the PowerShell script from the repository root:
```powershell
# Using a certificate thumbprint
.\scripts\sign-windows.ps1 -BinaryPath "target\release\vetto.exe" -CertificateThumbprint "YOUR_THUMBPRINT_HERE"

# Using a PFX file
.\scripts\sign-windows.ps1 -BinaryPath "target\release\vetto.exe" -PfxPath "C:\path\to\cert.pfx" -PfxPassword "your_password"
```

The script uses `http://timestamp.digicert.com` as the RFC 3161 timestamp server.
