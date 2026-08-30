//! Policy loading: profiles, custom TOML, init, profiles listing.

use crate::common::*;

#[cfg(unix)]
#[test]
fn unknown_profile_fails_closed() {
    let proj = TempProject::new("badprofile");
    let out = run_vetto_in(proj.path(), &["--profile", "nope", "--", "/bin/true"]);
    assert!(!out.status.success(), "unknown profile must fail");
    assert!(
        stderr(&out).contains("unknown profile") || stderr(&out).contains("profile"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn custom_policy_file_is_loaded() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("custompol");
    write_file(
        &proj.path().join(".env"),
        "X=1
",
    );
    write_file(
        &proj.path().join("vetto-test.toml"),
        r#"
[filesystem]
allow_write = ["$PROJECT"]
allow_read = ["/usr", "/bin", "/lib", "/dev/null"]

[display_only_deny]
paths = ["$PROJECT/.env"]
"#,
    );
    let out = run_vetto_in(
        proj.path(),
        &[
            "--policy",
            "vetto-test.toml",
            "--dry-run",
            "--",
            "/bin/true",
        ],
    );
    let text = stdout(&out);
    assert!(text.contains("custom:"), "policy name: {text}");
    assert!(text.contains("1 deny path"), "deny count: {text}");
}

#[test]
fn custom_environment_pass_through_is_explicit() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("customenv");
    write_file(
        &proj.path().join("vetto-test.toml"),
        r#"
[filesystem]
allow_write = ["$PROJECT"]
allow_read = ["/usr", "/bin", "/lib", "/dev/null"]

[environment]
pass_through = ["VETTO_TEST_ALLOWED"]
"#,
    );
    let out = run_vetto_env_in(
        proj.path(),
        &[
            "--policy",
            "vetto-test.toml",
            "--tui=none",
            "--",
            "sh",
            "-c",
            "printf '%s|%s' \"$VETTO_TEST_ALLOWED\" \"$GH_TOKEN\"",
        ],
        &[("VETTO_TEST_ALLOWED", "explicit"), ("GH_TOKEN", "secret")],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "explicit|", "environment output");
}

#[test]
fn init_writes_starter_policy() {
    let proj = TempProject::new("init");
    let out = run_vetto_in(proj.path(), &["init"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let toml = if proj.path().join("policy.toml").exists() {
        proj.path().join("policy.toml")
    } else {
        proj.path().join("vetto.toml")
    };
    assert!(toml.exists());
    let body = std::fs::read_to_string(&toml).unwrap();
    assert!(body.contains("allow_write"));

    // Second init must refuse to clobber.
    let again = run_vetto_in(proj.path(), &["init"]);
    assert!(!again.status.success(), "init must not overwrite");
}

#[test]
fn profiles_lists_builtins() {
    let proj = TempProject::new("profiles");
    let out = run_vetto_in(proj.path(), &["profiles"]);
    let text = stdout(&out);
    for name in ["default", "strict", "audit", "permissive"] {
        assert!(text.contains(name), "missing profile {name}: {text}");
    }
}

#[test]
fn test_subtractive_and_lockdown() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("subtractive");
    write_file(&proj.path().join("allowed.txt"), "hello\n");
    write_file(&proj.path().join("secret.key"), "secret-key-data\n");
    write_file(
        &proj.path().join("vetto-subtractive.toml"),
        r#"
[filesystem]
allow_write = ["$PROJECT"]
allow_read = ["$PROJECT", "/usr", "/bin", "/lib", "/dev/null"]
deny_read = ["$PROJECT/secret.key"]
deny_write = ["$PROJECT/.git"]

[environment]
pass_through = ["SAFE_TEST_VAR"]
deny = ["SECRET_*"]
"#,
    );
    let out = run_vetto_in(
        proj.path(),
        &[
            "--policy",
            "vetto-subtractive.toml",
            "--dry-run",
            "--",
            "/bin/true",
        ],
    );
    let text = stdout(&out);
    assert!(text.contains("deny path"), "deny count in output: {text}");
}
