//! Credential-like host variables are absent unless the policy names the
//! exact variable in `[environment].pass_through`.

use crate::common::*;

#[test]
fn secret_environment_is_default_deny_and_explicit_pass_through_is_exact() {
    if cfg!(target_os = "linux") && !have_landlock() {
        eprintln!("SKIP: no enforcement tier on this machine");
        return;
    }
    let project = TempProject::new("env-policy");
    let probe = "printf '%s|%s|%s' \"${VETTO_TEST_ALLOWED-}\" \"${GH_TOKEN-}\" \"${AWS_SECRET_ACCESS_KEY-}\"";
    let host_env = [
        ("VETTO_TEST_ALLOWED", "explicit-value"),
        ("GH_TOKEN", "must-not-pass"),
        ("AWS_SECRET_ACCESS_KEY", "must-not-pass-either"),
    ];

    let denied = run_vetto_env_in(
        project.path(),
        &["--tui=none", "--", "sh", "-c", probe],
        &host_env,
    );
    assert!(denied.status.success(), "stderr={}", stderr(&denied));
    assert_eq!(stdout(&denied), "||");

    write_file(
        &project.path().join("vetto.toml"),
        "[environment]\npass_through = [\"VETTO_TEST_ALLOWED\"]\n",
    );
    let allowed = run_vetto_env_in(
        project.path(),
        &["--tui=none", "--", "sh", "-c", probe],
        &host_env,
    );
    assert!(allowed.status.success(), "stderr={}", stderr(&allowed));
    assert_eq!(stdout(&allowed), "explicit-value||");
}
