use std::path::Path;

#[test]
fn test_vscode_extension_files_exist() {
    let base = Path::new("editors/vscode");
    assert!(base.join("package.json").exists(), "package.json missing");
    assert!(base.join("src/extension.ts").exists(), "src/extension.ts missing");
    assert!(base.join("tsconfig.json").exists(), "tsconfig.json missing");
    assert!(base.join("README.md").exists(), "README.md missing");
}

#[test]
fn test_vscode_package_json_valid() {
    let package_json_path = Path::new("editors/vscode/package.json");
    let content = std::fs::read_to_string(package_json_path).expect("failed to read package.json");
    
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("failed to parse package.json");
    
    assert_eq!(parsed["name"], "vetto");
    assert_eq!(parsed["version"], "0.1.0");
    assert_eq!(parsed["publisher"], "shleder");
    
    let commands = parsed["contributes"]["commands"].as_array().expect("no commands array");
    assert!(!commands.is_empty(), "commands array is empty");
    
    let cmd_ids: Vec<&str> = commands.iter()
        .filter_map(|c| c["command"].as_str())
        .collect();
        
    assert!(cmd_ids.contains(&"vetto.runSandboxed"));
    assert!(cmd_ids.contains(&"vetto.showStatus"));
    assert!(cmd_ids.contains(&"vetto.diffSessions"));
    assert!(cmd_ids.contains(&"vetto.openAudit"));
}
