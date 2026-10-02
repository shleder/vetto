//! Comprehensive unit tests for policy loader decomposition.

use std::collections::BTreeSet;
use std::path::PathBuf;

use super::*;
use crate::policy::types::{PolicySourceKind, Tier};

#[test]
fn test_policy_overrides_tmpfs_tmp() {
    let mut merged = MergedPolicy {
        tmpfs_tmp: Some(false),
        ..Default::default()
    };

    let overrides = PolicyOverrides {
        tmpfs_tmp: Some(true),
        ..Default::default()
    };

    apply_overrides(&mut merged, &overrides).unwrap();
    assert_eq!(merged.tmpfs_tmp, Some(true));
}

#[test]
fn unknown_named_profile_fails_closed_without_a_custom_policy() {
    let root = std::env::temp_dir().join(format!(
        "vetto-policy-unknown-profile-{}",
        std::process::id()
    ));
    let home = root.join("home");
    let project = root.join("project");
    std::fs::create_dir_all(&home).expect("create test home");
    std::fs::create_dir_all(&project).expect("create test project");

    let error = load("definitely-unknown", None, &project, &home, Tier::Full)
        .expect_err("unknown named profile must fail closed");
    assert!(error.to_string().contains("unknown profile"), "{error:#}");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn enumeration_budget_returns_error_instead_of_fallback() {
    let root = std::env::temp_dir().join(format!("vetto-policy-budget-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("ordinary.txt"), "ok").unwrap();

    let mut out = Vec::new();
    let mut count = FS_ONLY_ENUMERATION_BUDGET;
    let mut excluded = 0;
    let result = resolve::enumerate_tree(&root, &BTreeSet::new(), &mut out, &mut count, &mut excluded);

    let _ = std::fs::remove_dir_all(&root);
    assert!(result.is_err(), "budget overflow must be an error");
    assert!(out.is_empty(), "overflow must not emit a read root");
}

#[test]
fn supported_policy_sections_load_and_subtractive_rules_applied() {
    let root = std::env::temp_dir().join(format!(
        "vetto-policy-subtractive-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let policy_path = root.join("policy.toml");
    let valid = r#"
[filesystem]
allow_write = ["$PROJECT"]
allow_read = ["/usr", "/bin"]
deny_write = ["$PROJECT/.git"]
deny_read = ["/usr/secret"]

[metadata]
name = "subtractive-test"
description = "subtractive rules test"

[environment]
pass_through = ["HOME", "SAFE_VAR"]
deny = ["SECRET_*"]
"#;
    std::fs::write(&policy_path, valid).unwrap();
    let loaded = load(
        "subtractive-test",
        Some(&policy_path),
        &root,
        &root,
        Tier::Full,
    )
    .expect("subtractive policy should load");
    assert_eq!(loaded.metadata.name, "subtractive-test");
    assert!(loaded.deny_write.contains(&root.join(".git")));
    assert!(loaded.deny_read.contains(&PathBuf::from("/usr/secret")));
    assert!(loaded
        .environment
        .pass_through
        .contains(&"SAFE_VAR".to_string()));
    assert!(loaded.environment.deny.contains(&"SECRET_*".to_string()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn package_caches_read_only_mounts_are_resolved_correctly() {
    let root = std::env::temp_dir().join(format!("vetto-caches-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let project = root.join("project");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&project).unwrap();

    let mut merged = MergedPolicy::default();
    merged.allow_write.push("$HOME/.npm".to_string());
    merged.read_only_caches = true;

    let policy = build_policy(
        "test-caches",
        false,
        &project,
        &home,
        Tier::Full,
        &merged,
        None,
    )
    .expect("build policy");

    let npm_cache = home.join(".npm");
    assert!(
        policy.allow_read.contains(&npm_cache),
        "should add cache to read allow"
    );
    assert!(
        policy.deny_write.contains(&npm_cache),
        "should add cache to write deny"
    );
    assert!(
        !policy.allow_write.contains(&npm_cache),
        "should strip cache from write allow"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn enterprise_lockdown_mode_rejects_weakening_overrides() {
    let root = std::env::temp_dir().join(format!("vetto-lockdown-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let mut merged = MergedPolicy::default();
    let sec_layer = RawLayer {
        security: Some(RawSecurity {
            immutable: Some(true),
            ..Default::default()
        }),
        ..RawLayer::default()
    };
    merged
        .apply(&sec_layer, PolicySourceKind::SystemGlobal)
        .unwrap();

    assert!(merged.is_immutable);

    let overrides = PolicyOverrides {
        allow_write: vec!["/etc".into()],
        ..Default::default()
    };
    let err = apply_overrides(&mut merged, &overrides)
        .expect_err("lockdown must reject CLI write additions");
    assert!(err.to_string().contains("enterprise lockdown"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn network_presets_expand_correctly() {
    assert_eq!(
        expand_net_preset("npm").unwrap(),
        vec!["registry.npmjs.org".to_string()]
    );
    let git_domains = expand_net_preset("git").unwrap();
    assert!(git_domains.contains(&"github.com".to_string()));
    assert!(git_domains.contains(&"api.github.com".to_string()));
    assert!(git_domains.contains(&"codeload.github.com".to_string()));

    let pip_domains = expand_net_preset("pip").unwrap();
    assert!(pip_domains.contains(&"pypi.org".to_string()));
    assert!(pip_domains.contains(&"files.pythonhosted.org".to_string()));

    let hf_domains = expand_net_preset("huggingface").unwrap();
    assert!(hf_domains.contains(&"huggingface.co".to_string()));
    assert!(hf_domains.contains(&"cdn-lfs.huggingface.co".to_string()));

    let cargo_domains = expand_net_preset("cargo").unwrap();
    assert!(cargo_domains.contains(&"crates.io".to_string()));
    assert!(cargo_domains.contains(&"static.crates.io".to_string()));

    let go_domains = expand_net_preset("go").unwrap();
    assert!(go_domains.contains(&"proxy.golang.org".to_string()));
    assert!(go_domains.contains(&"sum.golang.org".to_string()));

    let maven_domains = expand_net_preset("maven").unwrap();
    assert!(maven_domains.contains(&"repo1.maven.org".to_string()));

    let nuget_domains = expand_net_preset("nuget").unwrap();
    assert!(nuget_domains.contains(&"api.nuget.org".to_string()));

    assert!(expand_net_preset("unknown-preset").is_err());
}

#[test]
fn parse_quota_bytes_handles_units() {
    assert_eq!(parse_quota_bytes("1024").unwrap(), 1024);
    assert_eq!(parse_quota_bytes("1024b").unwrap(), 1024);
    assert_eq!(parse_quota_bytes("500kb").unwrap(), 500_000);
    assert_eq!(parse_quota_bytes("500kib").unwrap(), 500 * 1024);
    assert_eq!(parse_quota_bytes("100mb").unwrap(), 100_000_000);
    assert_eq!(parse_quota_bytes("100mib").unwrap(), 100 * 1024 * 1024);
    assert_eq!(parse_quota_bytes("1gb").unwrap(), 1_000_000_000);
    assert_eq!(parse_quota_bytes("1gib").unwrap(), 1024 * 1024 * 1024);
    assert_eq!(
        parse_quota_bytes("2tb").unwrap(),
        2_000_000_000_000
    );
    assert_eq!(
        parse_quota_bytes("2tib").unwrap(),
        2 * 1024 * 1024 * 1024 * 1024
    );
    assert!(parse_quota_bytes("invalid").is_err());
}

#[test]
fn network_policy_sections_load_and_resolve() {
    let root = std::env::temp_dir().join(format!("vetto-policy-net-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let policy_path = root.join("policy.toml");
    let toml_content = r#"
[filesystem]
allow_write = ["$PROJECT"]
allow_read = ["/usr"]

[network]
net_presets = ["npm", "git"]
allow_cidr = ["10.0.0.0/8", "192.168.0.0/16"]
net_quota = { "api.openai.com" = "100mb" }
allow_tcp_connect = [443, 80]
allow_tcp_bind = [8080]

[unix_sockets]
allow = ["$PROJECT/test.sock"]
"#;
    std::fs::write(&policy_path, toml_content).unwrap();
    let loaded = load("net-test", Some(&policy_path), &root, &root, Tier::Full)
        .expect("network policy should load");

    assert!(loaded.allow_cidr.contains(&"10.0.0.0/8".to_string()));
    assert_eq!(
        loaded.net_quota.get("api.openai.com"),
        Some(&(100 * 1024 * 1024))
    );
    assert_eq!(loaded.net_connect_ports, vec![80, 443]);
    assert_eq!(loaded.net_bind_ports, vec![8080]);
    assert!(loaded
        .allow_unix_sockets
        .contains(&"$PROJECT/test.sock".to_string()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn test_require_signed_policy_enforcement() {
    let root = std::env::temp_dir().join(format!("vetto-signed-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let policy_path = root.join("vetto.toml");
    let content = r#"
[metadata]
name = "signed-test"

[filesystem]
allow_write = ["${PROJECT}"]
allow_read = ["/usr", "${PROJECT}"]
"#;
    std::fs::write(&policy_path, content).unwrap();

    let mut loader = LayeredPolicyLoader::new();
    loader.require_signed = true;
    let options = PolicyLoadOptions {
        require_signed: true,
        ..Default::default()
    };

    let err = loader.load(
        "default",
        Some(&policy_path),
        &root,
        &root,
        Tier::Full,
        &options,
    );
    assert!(
        err.is_err(),
        "unsigned policy must fail when require_signed=true"
    );

    use ed25519_dalek::Signer;
    let keys_dir = root.join(".vetto");
    let (signing_key, verifying_key) =
        crate::policy::crypto::ensure_signing_keypair(&keys_dir).unwrap();
    let sig = signing_key.sign(content.as_bytes());
    let sig_text = crate::policy::crypto::create_signature_file_content(&sig, &verifying_key);
    std::fs::write(root.join("vetto.toml.sig"), sig_text).unwrap();

    let loaded = loader.load(
        "default",
        Some(&policy_path),
        &root,
        &root,
        Tier::Full,
        &options,
    );
    assert!(loaded.is_ok(), "signed policy must load successfully");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn claude_agent_preset_policy_loading() {
    let root = std::env::temp_dir().join(format!("vetto-claude-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let ssh_dir = root.join(".ssh");
    let env_file = root.join(".env");
    let codex_dir = root.join(".codex");
    let claude_json = root.join(".claude.json");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::create_dir_all(&codex_dir).unwrap();
    std::fs::write(&env_file, "SECRET=1").unwrap();
    std::fs::write(&claude_json, "{}").unwrap();

    let claude_dir = root.join(".claude");

    let options = PolicyLoadOptions {
        agent: Some("claude-code".to_string()),
        ..Default::default()
    };

    let pol = load_with_options("default", None, &root, &root, Tier::Full, &options)
        .expect("claude preset must load");

    use std::ffi::OsStr;
    assert!(pol.environment.allows(OsStr::new("ANTHROPIC_API_KEY")));
    assert!(pol.environment.allows(OsStr::new("ANTHROPIC_BASE_URL")));
    assert!(pol.environment.allows(OsStr::new("CLAUDE_TEST_FLAG")));
    assert!(pol.environment.allows(OsStr::new("PATH")));
    assert!(!pol.environment.allows(OsStr::new("AWS_SECRET_ACCESS_KEY")));
    assert!(!pol.environment.allows(OsStr::new("GH_TOKEN")));

    assert!(pol.allow_write.contains(&claude_dir));
    assert!(pol.allow_read.contains(&claude_json));

    let deny_paths: Vec<_> = pol.deny_resolved.iter().map(|d| &d.path).collect();
    assert!(deny_paths.contains(&&ssh_dir));
    assert!(deny_paths.contains(&&env_file));
    assert!(deny_paths.contains(&&codex_dir));
    assert!(!deny_paths.contains(&&claude_dir));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn codex_agent_preset_policy_loading() {
    let root = std::env::temp_dir().join(format!("vetto-codex-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let ssh_dir = root.join(".ssh");
    let env_file = root.join(".env");
    let claude_dir = root.join(".claude");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(&env_file, "SECRET=1").unwrap();

    let codex_dir = root.join(".codex");

    let options = PolicyLoadOptions {
        agent: Some("codex-cli".to_string()),
        ..Default::default()
    };

    let pol = load_with_options("default", None, &root, &root, Tier::Full, &options)
        .expect("codex preset must load");

    use std::ffi::OsStr;
    assert!(pol.environment.allows(OsStr::new("OPENAI_API_KEY")));
    assert!(pol.environment.allows(OsStr::new("OPENAI_BASE_URL")));
    assert!(pol.environment.allows(OsStr::new("CODEX_TEST_FLAG")));
    assert!(pol.environment.allows(OsStr::new("PATH")));
    assert!(!pol.environment.allows(OsStr::new("AWS_SECRET_ACCESS_KEY")));
    assert!(!pol.environment.allows(OsStr::new("GH_TOKEN")));

    assert!(pol.allow_write.contains(&codex_dir));

    let deny_paths: Vec<_> = pol.deny_resolved.iter().map(|d| &d.path).collect();
    assert!(deny_paths.contains(&&ssh_dir));
    assert!(deny_paths.contains(&&env_file));
    assert!(deny_paths.contains(&&claude_dir));
    assert!(!deny_paths.contains(&&codex_dir));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn amp_agent_preset_policy_loading() {
    let root = std::env::temp_dir().join(format!("vetto-amp-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let ssh_dir = root.join(".ssh");
    let env_file = root.join(".env");
    let claude_dir = root.join(".claude");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(&env_file, "SECRET=1").unwrap();

    let amp_dir = root.join(".amp");

    let options = PolicyLoadOptions {
        agent: Some("amp".to_string()),
        ..Default::default()
    };

    let pol = load_with_options("default", None, &root, &root, Tier::Full, &options)
        .expect("amp preset must load without bail");

    use std::ffi::OsStr;
    assert!(pol.environment.allows(OsStr::new("AMP_TEST_FLAG")));
    assert!(pol.environment.allows(OsStr::new("SRC_ACCESS_TOKEN")));
    assert!(pol.environment.allows(OsStr::new("SOURCEGRAPH_URL")));
    assert!(pol.environment.allows(OsStr::new("ANTHROPIC_API_KEY")));
    assert!(pol.environment.allows(OsStr::new("OPENAI_API_KEY")));
    assert!(pol.environment.allows(OsStr::new("PATH")));
    assert!(!pol.environment.allows(OsStr::new("AWS_SECRET_ACCESS_KEY")));
    assert!(!pol.environment.allows(OsStr::new("GH_TOKEN")));

    assert!(pol.allow_write.contains(&amp_dir));
    assert!(pol.network_allow.contains(&"ampcode.com".to_string()));
    assert!(pol.network_allow.contains(&"sourcegraph.com".to_string()));

    let deny_paths: Vec<_> = pol.deny_resolved.iter().map(|d| &d.path).collect();
    assert!(deny_paths.contains(&&ssh_dir));
    assert!(deny_paths.contains(&&env_file));
    assert!(deny_paths.contains(&&claude_dir));
    assert!(!deny_paths.contains(&&amp_dir));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn omp_agent_preset_policy_loading() {
    let root = std::env::temp_dir().join(format!("vetto-omp-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let ssh_dir = root.join(".ssh");
    let env_file = root.join(".env");
    let claude_dir = root.join(".claude");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::create_dir_all(&claude_dir).unwrap();
    std::fs::write(&env_file, "SECRET=1").unwrap();

    let omp_dir = root.join(".omp");

    let options = PolicyLoadOptions {
        agent: Some("omp".to_string()),
        ..Default::default()
    };

    let pol = load_with_options("default", None, &root, &root, Tier::Full, &options)
        .expect("omp preset must load");

    use std::ffi::OsStr;
    assert!(pol.environment.allows(OsStr::new("OMP_CONFIG")));
    assert!(pol.environment.allows(OsStr::new("ANTHROPIC_API_KEY")));
    assert!(pol.environment.allows(OsStr::new("OPENAI_API_KEY")));
    assert!(pol.environment.allows(OsStr::new("GEMINI_API_KEY")));
    assert!(pol.environment.allows(OsStr::new("OPENROUTER_API_KEY")));
    assert!(pol.environment.allows(OsStr::new("PATH")));
    assert!(!pol.environment.allows(OsStr::new("AWS_SECRET_ACCESS_KEY")));
    assert!(!pol.environment.allows(OsStr::new("GH_TOKEN")));

    assert!(pol.allow_write.contains(&omp_dir));

    let deny_paths: Vec<_> = pol.deny_resolved.iter().map(|d| &d.path).collect();
    assert!(deny_paths.contains(&&ssh_dir));
    assert!(deny_paths.contains(&&env_file));
    assert!(deny_paths.contains(&&claude_dir));
    assert!(!deny_paths.contains(&&omp_dir));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn opencode_agent_preset_policy_loading() {
    let root = std::env::temp_dir().join(format!("vetto-opencode-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let options = PolicyLoadOptions {
        agent: Some("opencode".to_string()),
        ..Default::default()
    };

    let pol = load_with_options("default", None, &root, &root, Tier::Full, &options)
        .expect("opencode preset must load");

    assert_eq!(pol.limits.file_size_bytes, Some(2147483648));
    assert!(pol.network_allow.contains(&"opencode.ai".to_string()));
    assert!(pol.network_allow.contains(&"api.openai.com".to_string()));
    assert!(pol
        .network_allow
        .contains(&"integrate.api.nvidia.com".to_string()));
    assert!(pol.network_allow.contains(&"agentrouter.org".to_string()));
    assert!(pol.network_allow.contains(&"localhost".to_string()));
    assert!(pol.network_allow.contains(&"127.0.0.1".to_string()));

    assert!(pol
        .allow_write
        .contains(&root.join(".local/share/opencode")));
    assert!(pol.allow_read.contains(&root.join(".local/share/opencode")));
    assert!(pol.allow_write.contains(&root.join(".config/opencode")));
    assert!(pol.allow_read.contains(&root.join(".config/opencode")));
    assert!(root.join(".local/share/opencode").exists());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cline_agent_preset_policy_loading() {
    let root = std::env::temp_dir().join(format!("vetto-cline-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let options = PolicyLoadOptions {
        agent: Some("cline".to_string()),
        ..Default::default()
    };

    let pol = load_with_options("default", None, &root, &root, Tier::Full, &options)
        .expect("cline preset must load");

    assert!(pol.network_allow.contains(&"api.cline.bot".to_string()));
    assert!(pol.network_allow.contains(&"data.cline.bot".to_string()));
    assert!(pol.network_allow.contains(&"otel.cline.bot".to_string()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn merged_policy_cgroup_and_cpu_max_strictest_merge() {
    let mut merged = MergedPolicy::default();
    let layer1 = RawLayer {
        limits: Some(RawLimits {
            cgroup: Some(RawCgroup {
                memory_max: Some(RawValueOrString::Str("1G".into())),
                pids_max: Some(RawValueOrString::Num(100)),
                swap_max: None,
                cpu_max: Some(RawValueOrString::Str("80%".into())),
            }),
            cpu_max: Some("80%".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    merged
        .apply(&layer1, PolicySourceKind::SystemGlobal)
        .unwrap();

    let layer2 = RawLayer {
        limits: Some(RawLimits {
            cgroup: Some(RawCgroup {
                memory_max: Some(RawValueOrString::Str("512M".into())),
                pids_max: Some(RawValueOrString::Num(50)),
                swap_max: None,
                cpu_max: Some(RawValueOrString::Str("50%".into())),
            }),
            cpu_max: Some("50%".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    merged.apply(&layer2, PolicySourceKind::Repository).unwrap();

    let cg = merged.cgroup.as_ref().expect("cgroup present");
    assert_eq!(cg.memory_max.as_deref(), Some("512M"));
    assert_eq!(cg.pids_max.as_deref(), Some("50"));
    assert_eq!(cg.cpu_max.as_deref(), Some("50%"));
    assert_eq!(merged.cpu_max.as_deref(), Some("50%"));

    let layer3 = RawLayer {
        limits: Some(RawLimits {
            cgroup: Some(RawCgroup {
                memory_max: Some(RawValueOrString::Str("max".into())),
                pids_max: Some(RawValueOrString::Num(200)),
                swap_max: None,
                cpu_max: Some(RawValueOrString::Str("100%".into())),
            }),
            cpu_max: Some("100%".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    merged
        .apply(&layer3, PolicySourceKind::CliOverride)
        .unwrap();

    let cg = merged.cgroup.as_ref().expect("cgroup present");
    assert_eq!(cg.memory_max.as_deref(), Some("512M"));
    assert_eq!(cg.pids_max.as_deref(), Some("50"));
    assert_eq!(cg.cpu_max.as_deref(), Some("50%"));
    assert_eq!(merged.cpu_max.as_deref(), Some("50%"));
}

#[test]
fn test_parse_deny_unix_sockets_in_policy_toml() {
    let root =
        std::env::temp_dir().join(format!("vetto-policy-deny-sock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let policy_path = root.join("policy.toml");
    let toml_content = r#"
[filesystem]
allow_write = ["$PROJECT"]
allow_read = ["/usr"]

[unix_sockets]
allow = ["$PROJECT/test.sock"]
deny = ["$PROJECT/denied.sock", "/var/run/custom-unix.sock"]
"#;
    std::fs::write(&policy_path, toml_content).unwrap();
    let loaded = load(
        "deny-sock-test",
        Some(&policy_path),
        &root,
        &root,
        Tier::Full,
    )
    .expect("policy with deny unix sockets should load");

    assert!(loaded
        .deny_unix_sockets
        .contains(&"$PROJECT/denied.sock".to_string()));
    assert!(loaded
        .deny_unix_sockets
        .contains(&"/var/run/custom-unix.sock".to_string()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn test_shadow_mode_parsing() {
    let root = std::env::temp_dir().join(format!("vetto-shadow-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let policy_path = root.join("policy.toml");
    let toml_content = r#"
[filesystem]
allow_write = ["/tmp"]
shadow = true
"#;
    std::fs::write(&policy_path, toml_content).unwrap();

    let loaded = load("shadow-test", Some(&policy_path), &root, &root, Tier::Full)
        .expect("policy with shadow should load");

    assert!(loaded.shadow, "shadow field should be parsed as true");
    let _ = std::fs::remove_dir_all(root);
}
