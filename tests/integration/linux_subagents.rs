//! Descendants inherit filesystem and network enforcement.  A setsid child is
//! intentionally included: FS-ONLY may not be able to reap it, but it still
//! must not escape Landlock or inherited seccomp.

#[cfg(target_os = "linux")]
use crate::common::*;

#[test]
#[cfg(target_os = "linux")]
fn detached_subagent_cannot_read_secrets_or_use_network() {
    if !have_landlock() {
        eprintln!("SKIP: no Linux enforcement tier on this machine");
        return;
    }
    ensure_fake_ssh_key();
    let project = TempProject::new("subagent");
    write_file(&project.path().join(".env"), "SUBAGENT_SECRET=1\n");
    let script = stage_fixture(project.path(), "subagent_attack.sh");
    let out = run_vetto_in(project.path(), &["--tui=none", "--", "sh", &script]);
    let text = stdout(&out);
    for marker in [
        "LEAK-SUBAGENT-SSH",
        "LEAK-SUBAGENT-ENV",
        "LEAK-SUBAGENT-NET",
    ] {
        assert!(
            !text.contains(marker),
            "subagent leaked via {marker}: {text}"
        );
    }
    assert!(
        text.contains("subagent-finished"),
        "stdout={text} stderr={}",
        stderr(&out)
    );
}

#[test]
#[cfg(not(target_os = "linux"))]
fn linux_only() {}
