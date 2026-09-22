use std::fs;
use std::path::Path;

#[test]
fn test_localized_readmes_exist() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = workspace_root.join("docs").join("README.ru.md");
    assert!(path.exists(), "docs/README.ru.md must exist");
    let content = fs::read_to_string(&path).expect("read localized readme");
    assert!(!content.is_empty(), "docs/README.ru.md must not be empty");
    assert!(content.contains("Vetto"));
}
