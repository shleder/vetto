use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn test_markdown_links() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut md_files = Vec::new();
    
    // Find all markdown files
    collect_md_files(workspace_root, &mut md_files);
    
    let mut has_errors = false;
    
    for file in md_files {
        let content = fs::read_to_string(&file).expect("Failed to read file");
        
        let relative_path = file.strip_prefix(workspace_root).unwrap();
        
        let mut i = 0;
        let bytes = content.as_bytes();
        while i < bytes.len() {
            if bytes[i] == b']' && i + 1 < bytes.len() && bytes[i+1] == b'(' {
                let start = i + 2;
                let mut end = start;
                while end < bytes.len() && bytes[end] != b')' && bytes[end] != b' ' && bytes[end] != b'\n' {
                    end += 1;
                }
                if end < bytes.len() && bytes[end] == b')' {
                    let link = std::str::from_utf8(&bytes[start..end]).unwrap_or("");
                    if let Some(path) = link.split('#').next() {
                        if !path.is_empty() && !path.starts_with("http") && !path.starts_with("mailto:") && !path.starts_with("https") {
                            let mut target = file.parent().unwrap().to_path_buf();
                            target.push(path);
                            if !target.exists() {
                                println!("Broken link in {}: '{}' -> not found at {}", 
                                    relative_path.display(), link, target.display());
                                has_errors = true;
                            }
                        }
                    }
                }
            } else if bytes[i] == b's' && i >= 4 && &bytes[i-4..i+1] == b"href=" {
                // Check html links: href="..."
                if i + 2 < bytes.len() && bytes[i+1] == b'"' {
                    let start = i + 2;
                    let mut end = start;
                    while end < bytes.len() && bytes[end] != b'"' {
                        end += 1;
                    }
                    if end < bytes.len() {
                        let link = std::str::from_utf8(&bytes[start..end]).unwrap_or("");
                        if let Some(path) = link.split('#').next() {
                            if !path.is_empty() && !path.starts_with("http") && !path.starts_with("mailto:") && !path.starts_with("https") {
                                let mut target = file.parent().unwrap().to_path_buf();
                                target.push(path);
                                if !target.exists() {
                                    println!("Broken HTML link in {}: '{}' -> not found at {}", 
                                        relative_path.display(), link, target.display());
                                    has_errors = true;
                                }
                            }
                        }
                    }
                }
            }
            i += 1;
        }
    }
    
    assert!(!has_errors, "Broken markdown links found");
}

fn collect_md_files(dir: &Path, md_files: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.file_name().unwrap() != "target" && path.file_name().unwrap() != ".git" {
                collect_md_files(&path, md_files);
            } else if path.extension().and_then(|e| e.to_str()) == Some("md") {
                md_files.push(path);
            }
        }
    }
}
