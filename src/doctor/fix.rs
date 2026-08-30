//! Concrete remediation commands and steps for missing sandbox primitives.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorFix {
    pub primitive: &'static str,
    pub issue: String,
    pub commands: Vec<String>,
    pub explanation: String,
}

#[cfg(target_os = "linux")]
pub fn collect_linux_fixes(p: &crate::sandbox::linux::Probe) -> Vec<DoctorFix> {
    let mut fixes = Vec::new();

    if p.landlock_abi.is_none() {
        fixes.push(DoctorFix {
            primitive: "Landlock LSM",
            issue: "Landlock is unavailable (requires Linux kernel >= 5.13 with Landlock enabled)".into(),
            commands: vec![
                "# Update kernel to >= 5.13 and add landlock to LSM boot parameters in /etc/default/grub:".into(),
                "GRUB_CMDLINE_LINUX=\"lsm=landlock,lockdown,yama,apparmor,bpf\"".into(),
                "sudo update-grub && sudo reboot".into(),
            ],
            explanation: "Landlock is the primary in-process filesystem isolation layer on Linux.".into(),
        });
    }

    if !p.userns_available {
        fixes.push(DoctorFix {
            primitive: "Unprivileged User Namespaces",
            issue: "Unprivileged user namespaces (CLONE_NEWUSER) are disabled or restricted".into(),
            commands: vec![
                "sudo sysctl -w kernel.unprivileged_userns_clone=1".into(),
                "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 # (Ubuntu 24.04 / Debian 12)".into(),
                "echo \"kernel.unprivileged_userns_clone=1\" | sudo tee /etc/sysctl.d/99-vetto-userns.conf".into(),
                "sudo sysctl --system".into(),
            ],
            explanation: "User namespaces allow vetto to mount secret-masking overlays and isolate network without root permissions. Note: vetto does NOT use bubblewrap (bwrap); AppArmor bwrap restrictions do not apply.".into(),
        });
    }

    if !p.seccomp_filter_available {
        fixes.push(DoctorFix {
            primitive: "Seccomp BPF Filter",
            issue: "Seccomp BPF syscall filtering is unavailable in current kernel".into(),
            commands: vec![
                "# Recompile or install a standard kernel with CONFIG_SECCOMP=y and CONFIG_SECCOMP_FILTER=y".into(),
            ],
            explanation: "Seccomp is used for socket blocking on Tier FS-ONLY and syscall observation.".into(),
        });
    }

    if !p.audit_feed_readable {
        fixes.push(DoctorFix {
            primitive: "Kernel Audit Feed",
            issue: "Audit log feed is unreadable by current user (optional observation)".into(),
            commands: vec![
                "sudo setfacl -m u:$USER:r /var/log/audit/audit.log".into(),
                "sudo systemctl enable --now auditd".into(),
            ],
            explanation: "The audit feed provides best-effort real-time logging of blocked Landlock file access attempts.".into(),
        });
    }

    fixes
}

#[cfg(not(target_os = "linux"))]
pub fn collect_generic_fixes() -> Vec<DoctorFix> {
    Vec::new()
}

pub fn print_fixes(fixes: &[DoctorFix]) {
    if fixes.is_empty() {
        println!("doctor --fix: all core sandbox primitives are available! No remediation needed.");
        return;
    }

    println!("doctor remediation steps:");
    for (idx, fix) in fixes.iter().enumerate() {
        println!("\n{}. [Missing: {}]", idx + 1, fix.primitive);
        println!("   Problem:     {}", fix.issue);
        println!("   Explanation: {}", fix.explanation);
        println!("   Fix command(s):");
        for cmd in &fix.commands {
            println!("     {cmd}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_fixes_handles_empty_and_populated_lists() {
        print_fixes(&[]);

        let fixes = vec![DoctorFix {
            primitive: "User Namespaces",
            issue: "disabled".into(),
            commands: vec!["sudo sysctl -w kernel.unprivileged_userns_clone=1".into()],
            explanation: "needed for overlay masking".into(),
        }];
        print_fixes(&fixes);
    }
}
