use std::fs;
use std::path::Path;

#[test]
fn test_k8s_manifests_syntax() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifests_dir = workspace_root.join("deploy").join("k8s");

    if !manifests_dir.exists() {
        return;
    }

    let entries = fs::read_dir(manifests_dir).expect("Failed to read deploy/k8s dir");

    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            let content = fs::read_to_string(&path).expect("Failed to read yaml file");

            // Split multi-document yaml
            for doc in content.split("\n---") {
                let doc = doc.trim();
                if doc.is_empty() {
                    continue;
                }

                // Simple validation for required fields
                assert!(doc.contains("apiVersion:"), "Missing apiVersion in {}", path.display());
                assert!(doc.contains("kind:"), "Missing kind in {}", path.display());
                assert!(doc.contains("metadata:"), "Missing metadata in {}", path.display());
                assert!(doc.contains("name:"), "Missing metadata.name in {}", path.display());
            }
        }
    }
}

