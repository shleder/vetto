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

#[cfg(target_os = "macos")]
pub fn collect_macos_fixes(seatbelt_available: bool, sbpl_broken: bool) -> Vec<DoctorFix> {
    let mut fixes = Vec::new();

    if !seatbelt_available {
        fixes.push(DoctorFix {
            primitive: "macOS Seatbelt (sandbox-exec)",
            issue: "Seatbelt framework or /usr/bin/sandbox-exec is unavailable or restricted".into(),
            commands: vec![
                "# Ensure macOS version is 12 (Monterey) or newer:".into(),
                "sw_vers".into(),
                "# Check System Integrity Protection (SIP) status (must be enabled for default entitlements):".into(),
                "csrutil status".into(),
                "# If running inside an unprivileged virtual machine or container, ensure host virtualization entitlements are granted.".into(),
                "# For 100% kernel Landlock confinement on macOS, consider running inside OrbStack or a Linux VM:".into(),
                "orb".into(),
            ],
            explanation: "Seatbelt (via libsandbox and /usr/bin/sandbox-exec) is the core process and filesystem restriction mechanism on macOS.".into(),
        });
    }

    if sbpl_broken {
        fixes.push(DoctorFix {
            primitive: "SBPL Fragmented Read Profiles",
            issue: "Fragmented SBPL read-isolation profiles trigger libSystem/dyld aborts on this macOS build".into(),
            commands: vec![
                "# Check for macOS system updates:".into(),
                "softwareupdate -l".into(),
                "# Or run workloads requiring strict read-masking inside an isolated Linux container via OrbStack:".into(),
                "orb".into(),
            ],
            explanation: "Certain macOS builds terminate processes when complex deny rules are evaluated during dyld initialization. Vetto falls back to write-only deny and process limits on this host.".into(),
        });
    }

    fixes
}

#[cfg(target_os = "windows")]
pub fn collect_windows_fixes(
    caps: &crate::sandbox::windows::WindowsCapabilities,
    opt: &crate::sandbox::windows::OptionalBackendReport,
) -> Vec<DoctorFix> {
    let mut fixes = Vec::new();

    if !caps.job_object_kill_on_close {
        fixes.push(DoctorFix {
            primitive: "Windows Job Objects",
            issue: "Unable to create or assign Job Objects with kill-on-close policy".into(),
            commands: vec![
                "# Verify Windows build is Windows 10 (Build 19041+) or Windows 11:".into(),
                "cmd /c ver".into(),
                "# Ensure the process is not running inside an outer restrictive Job Object prohibiting nested jobs.".into(),
            ],
            explanation: "Job Objects provide process tree containment and guaranteed cleanup of child processes on Windows.".into(),
        });
    }

    if !caps.restricted_token || !caps.low_integrity_token {
        fixes.push(DoctorFix {
            primitive: "Restricted & Low-Integrity Tokens",
            issue: "Failed to create restricted or low-integrity security tokens".into(),
            commands: vec![
                "# Check Local Security Policy / Group Policy (gpedit.msc) for token restriction policies:".into(),
                "gpresult /Scope Computer /v".into(),
                "# Ensure current user account has standard token manipulation rights and UAC is enabled:".into(),
                "powershell -NoProfile -Command \"Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name EnableLUA\"".into(),
            ],
            explanation: "Restricted tokens strip dangerous privileges and lower integrity level to prevent privilege escalation.".into(),
        });
    }

    if !caps.appcontainer_api || !caps.experimental_create_process_in_sandbox {
        fixes.push(DoctorFix {
            primitive: "AppContainer Process Sandbox",
            issue: "AppContainer capability APIs or processmodel.dll sandbox exports are unavailable".into(),
            commands: vec![
                "# Update to Windows 11 (Build 22000+) or install Windows SDK:".into(),
                "cmd /c ver".into(),
                "# Alternatively, run vetto inside WSL2 for full Landlock/seccomp kernel confinement:".into(),
                "wsl --install".into(),
            ],
            explanation: "AppContainer process sandbox provides filesystem ACL isolation and network isolation on Windows.".into(),
        });
    }

    if !opt.windows_sandbox.feature_enabled || !opt.windows_sandbox.virtualization_firmware_enabled
    {
        let mut cmds = Vec::new();
        if !opt.windows_sandbox.feature_enabled {
            cmds.push("powershell -NoProfile -Command \"Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All\"".into());
            cmds.push("powershell -NoProfile -Command \"Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All\"".into());
        }
        if !opt.windows_sandbox.virtualization_firmware_enabled {
            cmds.push("# Enable Hardware Virtualization (Intel VT-x or AMD SVM) in motherboard BIOS/UEFI firmware settings.".into());
            cmds.push(
                "powershell -NoProfile -Command \"Get-ComputerInfo -Property HyperVisorPresent\""
                    .into(),
            );
        }
        fixes.push(DoctorFix {
            primitive: "Windows Sandbox & Virtualization",
            issue: "Windows Sandbox optional feature is disabled or hardware virtualization is turned off in BIOS/UEFI".into(),
            commands: cmds,
            explanation: "Windows Sandbox (Hyper-V micro-VM) enables throwaway disposable VM isolation on Windows.".into(),
        });
    }

    fixes
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
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
