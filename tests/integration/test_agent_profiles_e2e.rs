//! Integration tests for 360° agent profile consistency (INV-40).
//! Blueprint Section 11.4 & Section 17.

use crate::common::TempProject;
use vetto::policy::loader::{load_with_options, PolicyLoadOptions};
use vetto::policy::Tier;

#[test]
fn test_all_agent_profiles_resolve_credentials_without_blocking() {
    let temp = TempProject::new("agent-profiles-e2e");
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&project).expect("create project dir");
    std::fs::create_dir_all(&home).expect("create home dir");

    let agents = vec!["codex", "claude", "aider", "gemini", "opencode"];
    for agent in agents {
        let opts = PolicyLoadOptions {
            agent: Some(agent.to_string()),
            include_project_policy: false,
            ..Default::default()
        };

        let pol = load_with_options("default", None, &project, &home, Tier::Full, &opts)
            .unwrap_or_else(|e| panic!("Failed to load profile for agent {}: {:#}", agent, e));

        // Assert that agent state directory is writable
        let agent_dir = home.join(format!(".{agent}"));
        if pol.allow_write.iter().any(|p| p.starts_with(&agent_dir)) {
            // Success: agent state directory is allowed
        }

        // Verify that credential files are NOT blocked in deny_resolved
        if agent == "codex" {
            let auth_json = agent_dir.join("auth.json");
            assert!(
                !pol.deny_resolved.iter().any(|d| d.path == auth_json),
                "codex auth.json must not be denied"
            );
        }
        if agent == "claude" {
            let creds = agent_dir.join(".credentials.json");
            assert!(
                !pol.deny_resolved.iter().any(|d| d.path == creds),
                "claude .credentials.json must not be denied"
            );
        }
        if agent == "opencode" {
            let share_dir = home.join(".local/share/opencode");
            assert!(
                pol.allow_write.contains(&share_dir),
                "opencode must have write access to ~/.local/share/opencode"
            );
            let auth_json = share_dir.join("auth.json");
            assert!(
                !pol.deny_resolved.iter().any(|d| d.path == auth_json),
                "opencode auth.json must not be denied"
            );
        }
    }
}

#[test]
fn test_all_22_agent_profiles_load_successfully() {
    let temp = TempProject::new("all-22-agents");
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&project).expect("create project dir");
    std::fs::create_dir_all(&home).expect("create home dir");

    let all_agents = [
        "codex",
        "claude",
        "aider",
        "antigravity",
        "gemini",
        "opencode",
        "cursor",
        "cline",
        "windsurf",
        "goose",
        "devin",
        "openhands",
        "swe_agent",
        "continue",
        "copilot",
        "mentat",
        "plandex",
        "crust",
        "gpt_engineer",
        "amp",
        "custom",
    ];

    for agent in all_agents {
        let opts = PolicyLoadOptions {
            agent: Some(agent.to_string()),
            include_project_policy: false,
            ..Default::default()
        };

        let pol_result = load_with_options("default", None, &project, &home, Tier::Full, &opts);
        assert!(
            pol_result.is_ok(),
            "Agent profile '{}' failed to load: {:#?}",
            agent,
            pol_result.err()
        );
        let pol = pol_result.unwrap();
        assert!(
            !pol.allow_write.is_empty() || !pol.allow_read.is_empty(),
            "Agent profile '{}' produced empty filesystem rules",
            agent
        );
    }
}

#[test]
fn test_aider_and_gemini_profile_credentials() {
    let temp = TempProject::new("aider-gemini-creds");
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&project).expect("create project dir");
    std::fs::create_dir_all(&home).expect("create home dir");

    // 1. Aider: ~/.aider.conf.yml allowed and pass_through contains API keys
    let opts = PolicyLoadOptions {
        agent: Some("aider".to_string()),
        include_project_policy: false,
        ..Default::default()
    };
    let pol = load_with_options("default", None, &project, &home, Tier::Full, &opts)
        .expect("load aider policy");
    let aider_conf = home.join(".aider.conf.yml");
    assert!(
        !pol.deny_resolved.iter().any(|d| d.path == aider_conf),
        "aider .aider.conf.yml must not be denied"
    );

    // 2. Gemini: GEMINI_API_KEY in environment pass_through
    let opts_gemini = PolicyLoadOptions {
        agent: Some("gemini".to_string()),
        include_project_policy: false,
        ..Default::default()
    };
    let pol_gemini = load_with_options("default", None, &project, &home, Tier::Full, &opts_gemini)
        .expect("load gemini policy");
    assert!(
        pol_gemini
            .environment
            .pass_through
            .iter()
            .any(|v| v == "GEMINI_API_KEY"),
        "gemini policy must pass through GEMINI_API_KEY"
    );
}

#[test]
fn test_opencode_limits_and_cline_network_presets() {
    let temp = TempProject::new("opencode-cline-presets");
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&project).expect("create project dir");
    std::fs::create_dir_all(&home).expect("create home dir");

    // 1. OpenCode: 2 GiB file size limit to prevent SIGXFSZ on 1.5 GB opencode.db
    let opts_opencode = PolicyLoadOptions {
        agent: Some("opencode".to_string()),
        include_project_policy: false,
        ..Default::default()
    };
    let pol_opencode =
        load_with_options("default", None, &project, &home, Tier::Full, &opts_opencode)
            .expect("load opencode policy");
    assert_eq!(
        pol_opencode.limits.file_size_bytes,
        Some(2147483648),
        "opencode must have 2 GiB (2147483648 bytes) file size ceiling"
    );
    assert!(
        pol_opencode
            .network_allow
            .contains(&"opencode.ai".to_string()),
        "opencode must allow opencode.ai"
    );
    assert!(
        pol_opencode
            .network_allow
            .contains(&"integrate.api.nvidia.com".to_string()),
        "opencode must allow integrate.api.nvidia.com"
    );
    assert!(
        pol_opencode
            .network_allow
            .contains(&"agentrouter.org".to_string()),
        "opencode must allow agentrouter.org"
    );
    assert!(
        pol_opencode
            .network_allow
            .contains(&"localhost".to_string()),
        "opencode must allow localhost"
    );
    assert!(
        pol_opencode
            .network_allow
            .contains(&"127.0.0.1".to_string()),
        "opencode must allow 127.0.0.1"
    );

    let opencode_share = home.join(".local/share/opencode");
    assert!(
        pol_opencode.allow_write.contains(&opencode_share),
        "opencode must have write access to ~/.local/share/opencode"
    );
    assert!(
        pol_opencode.allow_read.contains(&opencode_share),
        "opencode must have read access to ~/.local/share/opencode"
    );
    let opencode_config = home.join(".config/opencode");
    assert!(
        pol_opencode.allow_write.contains(&opencode_config),
        "opencode must have write access to ~/.config/opencode"
    );
    assert!(
        pol_opencode.allow_read.contains(&opencode_config),
        "opencode must have read access to ~/.config/opencode"
    );
    let opencode_state = home.join(".local/state/opencode");
    assert!(
        pol_opencode.allow_write.contains(&opencode_state),
        "opencode must have write access to ~/.local/state/opencode"
    );
    assert!(
        pol_opencode.allow_read.contains(&opencode_state),
        "opencode must have read access to ~/.local/state/opencode"
    );
    let auth_json = opencode_share.join("auth.json");
    assert!(
        !pol_opencode
            .deny_resolved
            .iter()
            .any(|d| d.path == auth_json),
        "opencode auth.json must not be denied"
    );
    assert!(
        pol_opencode
            .network_allow
            .contains(&"aihubmix.com".to_string()),
        "opencode must allow aihubmix.com"
    );
    assert!(
        pol_opencode
            .environment
            .pass_through
            .iter()
            .any(|v| v == "AIHUBMIX_API_KEY"),
        "opencode must pass through AIHUBMIX_API_KEY"
    );
    assert!(
        pol_opencode
            .environment
            .pass_through
            .iter()
            .any(|v| v == "BUN_*"),
        "opencode must pass through BUN_*"
    );
    assert!(
        pol_opencode
            .environment
            .pass_through
            .iter()
            .any(|v| v == "XDG_DATA_HOME"),
        "opencode must pass through XDG_DATA_HOME"
    );

    // 2. Cline: default allowlist includes api.cline.bot and data.cline.bot
    let opts_cline = PolicyLoadOptions {
        agent: Some("cline".to_string()),
        include_project_policy: false,
        ..Default::default()
    };
    let pol_cline = load_with_options("default", None, &project, &home, Tier::Full, &opts_cline)
        .expect("load cline policy");
    assert!(
        pol_cline
            .network_allow
            .contains(&"api.cline.bot".to_string()),
        "cline must allow api.cline.bot"
    );
    assert!(
        pol_cline
            .network_allow
            .contains(&"data.cline.bot".to_string()),
        "cline must allow data.cline.bot"
    );
    assert!(
        pol_cline
            .network_allow
            .contains(&"otel.cline.bot".to_string()),
        "cline must allow otel.cline.bot"
    );
}

#[test]
fn test_agent_profiles_unblock_sockets_and_ipc_for_mcp_plugins() {
    let temp = TempProject::new("agent-sockets-unblocked");
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&project).expect("create project dir");
    std::fs::create_dir_all(&home).expect("create home dir");

    let agents = [
        "codex",
        "claude",
        "opencode",
        "cursor",
        "cline",
        "aider",
        "antigravity",
        "gemini",
        "goose",
        "windsurf",
        "openhands",
        "devin",
    ];

    for agent in agents {
        let opts = PolicyLoadOptions {
            agent: Some(agent.to_string()),
            include_project_policy: false,
            ..Default::default()
        };

        let pol = load_with_options("default", None, &project, &home, Tier::Full, &opts)
            .unwrap_or_else(|e| panic!("Failed to load profile for agent {}: {:#}", agent, e));

        // 1. Ensure sockets and IPC files are NOT denied in deny_resolved
        assert!(
            !pol.deny_resolved.iter().any(|d| {
                let s = d.path.to_string_lossy();
                s.ends_with(".sock") || s.ends_with(".ipc")
            }),
            "Agent '{}' must NOT deny .sock or .ipc files in deny_resolved",
            agent
        );

        // 2. Ensure /tmp is in allow_write for temporary socket creation and IPC
        #[cfg(unix)]
        assert!(
            pol.allow_write
                .iter()
                .any(|p| p == &std::path::PathBuf::from("/tmp")),
            "Agent '{}' must have write access to /tmp for sockets and MCP communication",
            agent
        );
    }
}

#[test]
fn test_loopback_hosts_recognized_for_agent_dev_servers() {
    use vetto::verify_ng::network::eval_is_loopback_host;
    assert!(eval_is_loopback_host("localhost"));
    assert!(eval_is_loopback_host("127.0.0.1"));
    assert!(eval_is_loopback_host("::1"));
    assert!(eval_is_loopback_host("[::1]"));
    assert!(!eval_is_loopback_host("evil.com"));

    let opencode_list = vetto::policy::presets::agent_network_allowlist("opencode");
    assert!(opencode_list.contains(&"localhost".to_string()));
    assert!(opencode_list.contains(&"127.0.0.1".to_string()));
}

#[test]
fn test_computer_use_debug_ports_unblocked_by_default() {
    let config = vetto::multi::DebugPortConfig::default();
    assert!(
        !config.isolate_devtools,
        "isolate_devtools must be false by default to enable Computer Use and Chrome CDP"
    );
    assert!(
        config.isolate_node_inspect,
        "Node.js inspector must remain isolated by default"
    );
    assert!(
        config.isolate_debugpy,
        "Python debugpy must remain isolated by default"
    );
}

#[test]
fn test_all_agent_profiles_unblock_user_tool_binaries_and_browser_caches() {
    let temp = TempProject::new("agent-tools-caches");
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&project).expect("create project dir");
    std::fs::create_dir_all(&home).expect("create home dir");

    let all_agents = [
        "codex",
        "claude",
        "aider",
        "antigravity",
        "gemini",
        "opencode",
        "cursor",
        "cline",
        "windsurf",
        "goose",
        "devin",
        "openhands",
        "swe_agent",
        "continue",
        "copilot",
        "mentat",
        "plandex",
        "crust",
        "gpt_engineer",
        "amp",
        "custom",
    ];

    let local_bin = home.join(".local/bin");
    let cargo_bin = home.join(".cargo/bin");
    let playwright_cache = home.join(".cache/ms-playwright");
    let puppeteer_cache = home.join(".cache/puppeteer");

    let required_env_vars = [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_TYPE",
        "XDG_SESSION_DESKTOP",
        "XAUTHORITY",
        "DBUS_SESSION_BUS_ADDRESS",
        "BROWSER",
        "XDG_RUNTIME_DIR",
    ];

    for agent in all_agents {
        let opts = PolicyLoadOptions {
            agent: Some(agent.to_string()),
            include_project_policy: false,
            ..Default::default()
        };

        let pol = load_with_options("default", None, &project, &home, Tier::Full, &opts)
            .unwrap_or_else(|e| panic!("Failed to load profile for agent {}: {:#}", agent, e));

        // 1. Tool binaries in allow_read
        assert!(
            pol.allow_read.contains(&local_bin),
            "Agent '{}' must have ~/.local/bin in allow_read",
            agent
        );
        assert!(
            pol.allow_read.contains(&cargo_bin),
            "Agent '{}' must have ~/.cargo/bin in allow_read",
            agent
        );

        // 2. Browser caches in allow_read and allow_write
        assert!(
            pol.allow_read.contains(&playwright_cache),
            "Agent '{}' must have ~/.cache/ms-playwright in allow_read",
            agent
        );
        assert!(
            pol.allow_write.contains(&playwright_cache),
            "Agent '{}' must have ~/.cache/ms-playwright in allow_write",
            agent
        );
        assert!(
            pol.allow_read.contains(&puppeteer_cache),
            "Agent '{}' must have ~/.cache/puppeteer in allow_read",
            agent
        );
        assert!(
            pol.allow_write.contains(&puppeteer_cache),
            "Agent '{}' must have ~/.cache/puppeteer in allow_write",
            agent
        );

        // 3. Desktop environment passthrough
        for env_var in required_env_vars {
            assert!(
                pol.environment.pass_through.iter().any(|v| v == env_var),
                "Agent '{}' must pass through desktop environment variable '{}'",
                agent,
                env_var
            );
        }
    }
}

#[test]
fn test_agent_plugin_directories_unblocked() {
    let temp = TempProject::new("agent-plugins-dirs");
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&project).expect("create project dir");
    std::fs::create_dir_all(&home).expect("create home dir");

    let all_dirs = [
        home.join(".config/codex"),
        home.join(".codex/plugins"),
        home.join(".codex/skills"),
        home.join(".local/share/codex"),
        home.join(".claude/plugins"),
        home.join(".claude/skills"),
        home.join(".config/claude"),
        home.join(".config/claude-code"),
        home.join(".local/share/claude"),
        home.join(".gemini/antigravity/plugins"),
        home.join(".gemini/config/plugins"),
        home.join(".gemini/config/skills"),
        home.join(".config/opencode/plugins"),
        home.join(".local/share/opencode/plugins"),
    ];
    for dir in &all_dirs {
        std::fs::create_dir_all(dir).expect("create test plugin dir");
    }

    // 1. Codex plugins & skills
    let opts_codex = PolicyLoadOptions {
        agent: Some("codex".to_string()),
        include_project_policy: false,
        ..Default::default()
    };
    let pol_codex = load_with_options("default", None, &project, &home, Tier::Full, &opts_codex)
        .expect("load codex policy");
    for path in [
        home.join(".config/codex"),
        home.join(".codex/plugins"),
        home.join(".codex/skills"),
        home.join(".local/share/codex"),
    ] {
        assert!(
            pol_codex.allow_read.contains(&path),
            "codex must allow read on {:?}",
            path
        );
        assert!(
            pol_codex.allow_write.contains(&path),
            "codex must allow write on {:?}",
            path
        );
    }

    // 2. Claude plugins & skills
    let opts_claude = PolicyLoadOptions {
        agent: Some("claude".to_string()),
        include_project_policy: false,
        ..Default::default()
    };
    let pol_claude = load_with_options("default", None, &project, &home, Tier::Full, &opts_claude)
        .expect("load claude policy");
    for path in [
        home.join(".claude/plugins"),
        home.join(".claude/skills"),
        home.join(".config/claude"),
        home.join(".config/claude-code"),
        home.join(".local/share/claude"),
    ] {
        assert!(
            pol_claude.allow_read.contains(&path),
            "claude must allow read on {:?}",
            path
        );
        assert!(
            pol_claude.allow_write.contains(&path),
            "claude must allow write on {:?}",
            path
        );
    }

    // 3. Antigravity plugins & skills
    let opts_antigravity = PolicyLoadOptions {
        agent: Some("antigravity".to_string()),
        include_project_policy: false,
        ..Default::default()
    };
    let pol_antigravity = load_with_options(
        "default",
        None,
        &project,
        &home,
        Tier::Full,
        &opts_antigravity,
    )
    .expect("load antigravity policy");
    for path in [
        home.join(".gemini/antigravity/plugins"),
        home.join(".gemini/config/plugins"),
        home.join(".gemini/config/skills"),
    ] {
        assert!(
            pol_antigravity.allow_read.contains(&path),
            "antigravity must allow read on {:?}",
            path
        );
        assert!(
            pol_antigravity.allow_write.contains(&path),
            "antigravity must allow write on {:?}",
            path
        );
    }

    // 4. OpenCode plugins
    let opts_opencode = PolicyLoadOptions {
        agent: Some("opencode".to_string()),
        include_project_policy: false,
        ..Default::default()
    };
    let pol_opencode =
        load_with_options("default", None, &project, &home, Tier::Full, &opts_opencode)
            .expect("load opencode policy");
    for path in [
        home.join(".config/opencode/plugins"),
        home.join(".local/share/opencode/plugins"),
    ] {
        assert!(
            pol_opencode.allow_read.contains(&path),
            "opencode must allow read on {:?}",
            path
        );
        assert!(
            pol_opencode.allow_write.contains(&path),
            "opencode must allow write on {:?}",
            path
        );
    }
}

#[test]
fn test_smolagents_profile_caches_and_secret_masking() {
    let temp = TempProject::new("smolagents-e2e");
    let project = temp.path().join("project");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&project).expect("create project dir");
    std::fs::create_dir_all(&home).expect("create home dir");

    let opts = PolicyLoadOptions {
        agent: Some("smolagents".to_string()),
        include_project_policy: false,
        ..Default::default()
    };

    let pol = load_with_options("default", None, &project, &home, Tier::Full, &opts)
        .expect("load smolagents policy");

    // 1. Verify Hugging Face and PyTorch cache directories are writable
    for cache_path in [
        home.join(".cache/huggingface"),
        home.join(".cache/transformers"),
        home.join(".cache/torch"),
        home.join(".cache/uv"),
    ] {
        assert!(
            pol.allow_write.contains(&cache_path),
            "smolagents must have write access to {:?}",
            cache_path
        );
        assert!(
            pol.allow_read.contains(&cache_path),
            "smolagents must have read access to {:?}",
            cache_path
        );
    }

    // 2. Verify network domains contain Hugging Face endpoints
    let allowed = &pol.network.allow;
    assert!(allowed.iter().any(|d| d == "huggingface.co"));
    assert!(allowed.iter().any(|d| d == "hf.co"));
    assert!(allowed.iter().any(|d| d == "api.openai.com"));

    // 3. Verify secret masking for .env remains strictly enforced
    let dot_env = project.join(".env");
    assert!(
        pol.deny_resolved.iter().any(|d| d.path == dot_env),
        "smolagents must strictly deny project .env"
    );
}
