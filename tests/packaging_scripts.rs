use std::fs;
use std::path::Path;

#[test]
fn test_macos_pkg_script_exists_and_content() {
    let script_path = Path::new("scripts/package-macos-pkg.sh");
    assert!(script_path.exists(), "macOS packaging script not found");
    
    let content = fs::read_to_string(script_path).unwrap();
    assert!(content.contains("pkgbuild"), "Missing pkgbuild command");
    assert!(content.contains("productbuild"), "Missing productbuild command");
    assert!(content.contains("xcrun notarytool submit"), "Missing notarytool submit");
    assert!(content.contains("--wait"), "Missing --wait flag in notarytool");
    assert!(content.contains("xcrun stapler staple"), "Missing stapler command");
}

#[test]
fn test_windows_signing_script_exists_and_content() {
    let script_path = Path::new("scripts/sign-windows.ps1");
    assert!(script_path.exists(), "Windows signing script not found");
    
    let content = fs::read_to_string(script_path).unwrap();
    assert!(content.contains("signtool.exe"), "Missing signtool.exe command");
    assert!(content.contains("/tr"), "Missing timestamp server flag");
    assert!(content.contains("RFC 3161") || content.contains("timestamp.digicert.com"), "Missing RFC 3161 or Digicert timestamp server");
    assert!(content.contains("CertificateThumbprint"), "Missing CertificateThumbprint parameter");
    assert!(content.contains("PfxPath"), "Missing PfxPath parameter");
}
