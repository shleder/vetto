use std::fs;
use std::path::Path;

#[test]
fn test_localized_readmes_exist() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for lang in &["ru", "zh", "ja"] {
        let path = workspace_root
            .join("docs")
            .join(format!("README.{lang}.md"));
        assert!(path.exists(), "docs/README.{lang}.md must exist");
        let content = fs::read_to_string(&path).expect("read localized readme");
        assert!(
            !content.is_empty(),
            "docs/README.{lang}.md must not be empty"
        );
        assert!(content.contains("Vetto"));
    }
}
