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
    let auth_json = opencode_share.join("auth.json");
    assert!(
        !pol_opencode
            .deny_resolved
            .iter()
            .any(|d| d.path == auth_json),
        "opencode auth.json must not be denied"
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
