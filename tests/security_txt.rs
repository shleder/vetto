use std::fs;
use std::path::Path;

#[test]
fn security_txt_exists_and_conforms_to_rfc9116() {
    let path = Path::new(".well-known/security.txt");
    assert!(path.exists(), "security.txt must exist at .well-known/security.txt");

    let content = fs::read_to_string(path).expect("read security.txt");

    // RFC 9116 required / optional fields we decided to support
    assert!(content.contains("Contact: "), "Must contain Contact");
    assert!(content.contains("Encryption: "), "Must contain Encryption");
    assert!(content.contains("Canonical: "), "Must contain Canonical");
    assert!(content.contains("Policy: "), "Must contain Policy");
    assert!(
        content.contains("Preferred-Languages: en, ru"),
        "Must specify English and Russian languages"
    );
    assert!(
        content.contains("Acknowledgments: "),
        "Must contain Acknowledgments"
    );
}
